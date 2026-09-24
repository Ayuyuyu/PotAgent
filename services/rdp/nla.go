package rdp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"potAgent/logger"
)

// NLA（CredSSP，MS-CSSP）里我们只做一件事：把客户端的 NTLM Type3 收下来。
//
// 为什么不能进一步：要"通过"认证需要用户的 NTLM 响应校验值（或口令）才能算出会话密钥，
// 蜜罐没有这些。所以抓到 Type3 后我们回一个错误码，客户端显示"凭据不正确"。
// 拿到的 NetNTLMv2 响应可以做两件事：
//   1. hashcat -m 5600 离线爆破；
//   2. 配合中继（例如把它转给 SMB/LDAP）——这是 NLA 路径比标准 RDP 更有价值的地方。

// ---------------------------------------------------------------------------
// 最小 DER 读写（CredSSP 的 TSRequest）
// ---------------------------------------------------------------------------

const (
	derSeq      = 0x30
	derInt      = 0x02
	derOctetStr = 0x04
	derCtxTag0  = 0xA0
	derCtxTag1  = 0xA1
	derCtxTag2  = 0xA2
	derCtxStr2  = 0x82
	derCtxTag3  = 0xA3
	derCtxStr3  = 0x83
	derCtxTag4  = 0xA4
	derCtxStr5  = 0x85
)

func derWriteLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n <= 0xFF {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func derTLV(tag byte, content []byte) []byte {
	out := make([]byte, 0, len(content)+3)
	out = append(out, tag)
	out = append(out, derWriteLen(len(content))...)
	return append(out, content...)
}

func derInteger(v int) []byte {
	b := []byte{}
	for v > 0 {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
	}
	if len(b) == 0 {
		b = []byte{0}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return derTLV(derInt, b)
}

// derReadTLV 从流里读一个 TLV，返回 tag 与内容
func derReadTLV(br *bufio.Reader) (byte, []byte, error) {
	tag, err := br.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	l0, err := br.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	n := int(l0)
	if l0&0x80 != 0 {
		cnt := int(l0 & 0x7f)
		if cnt == 0 || cnt > 4 {
			return 0, nil, errors.New("rdp: DER 长度非法")
		}
		n = 0
		for i := 0; i < cnt; i++ {
			b, err := br.ReadByte()
			if err != nil {
				return 0, nil, err
			}
			n = n<<8 | int(b)
		}
	}
	if n < 0 || n > 1<<20 {
		return 0, nil, errors.New("rdp: DER 长度越界")
	}
	content := make([]byte, n)
	if _, err := io.ReadFull(br, content); err != nil {
		return 0, nil, err
	}
	return tag, content, nil
}

type tsRequest struct {
	version    int
	negoTokens [][]byte
	authInfo   []byte
	pubKeyAuth []byte
	errorCode  int
}

// parseTSRequest 解析 CredSSP 的 TSRequest（[0] version、[1] negoTokens、[2] authInfo、
// [3] pubKeyAuth、[4] errorCode、[5] clientNonce）
func parseTSRequest(content []byte) *tsRequest {
	tr := &tsRequest{version: 6}
	for _, n := range derChildren(content) {
		switch n.tag {
		case derCtxTag0: // [0] version（EXPLICIT INTEGER）
			if len(n.val) >= 3 {
				tr.version = int(n.val[2])
			}
		case derCtxTag1: // [1] SEQUENCE OF NegoData
			tr.negoTokens = parseNegoTokens(n.val)
		case derCtxTag2, derCtxStr2:
			tr.authInfo = n.val
		case derCtxTag3, derCtxStr3:
			tr.pubKeyAuth = n.val
		case derCtxTag4: // [4] errorCode（EXPLICIT INTEGER）
			if len(n.val) >= 3 {
				tr.errorCode = int(n.val[2])
			}
		}
	}
	return tr
}

type derNode struct {
	tag byte
	val []byte
}

// derChildren 把一段 BER/DER 内容切成若干 TLV
func derChildren(b []byte) []derNode {
	out := []derNode{}
	i := 0
	for i < len(b) {
		tag := b[i]
		i++
		if i >= len(b) {
			break
		}
		n := int(b[i])
		i++
		if n&0x80 != 0 {
			cnt := int(n & 0x7f)
			n = 0
			for j := 0; j < cnt && i < len(b); j++ {
				n = n<<8 | int(b[i])
				i++
			}
		}
		if i+n > len(b) {
			break
		}
		out = append(out, derNode{tag, b[i : i+n]})
		i += n
	}
	return out
}

// unwrapOctetString [0]/[2]/[3] 这类标注是 EXPLICIT 的，里面还会套一层 OCTET STRING，
// 这里把它剥掉；如果节点本身就是原始 OCTET STRING 则原样返回。
func unwrapOctetString(v []byte) []byte {
	if len(v) >= 2 && v[0] == derOctetStr {
		n := int(v[1])
		if n&0x80 == 0 && 2+n <= len(v) {
			return v[2 : 2+n]
		}
	}
	return v
}

// parseNegoTokens 取出 NegoData 里的各个 NTLM 令牌。
// 真实编码（FreeRDP/Windows/grdp 一致）：
//
//	[1] SEQUENCE OF NegoData{ SEQUENCE{ negoToken [0] EXPLICIT OCTET STRING } }
func parseNegoTokens(b []byte) [][]byte {
	out := [][]byte{}
	var walk func(bs []byte, depth int)
	walk = func(bs []byte, depth int) {
		if depth > 4 {
			return
		}
		for _, n := range derChildren(bs) {
			switch n.tag {
			case 0xA0, derOctetStr:
				out = append(out, unwrapOctetString(n.val))
			case derSeq, derCtxTag1, derCtxTag2:
				walk(n.val, depth+1)
			}
		}
	}
	walk(b, 0)
	return out
}

// buildTSRequest 回包：带 negoToken（Type2）或 errorCode。
// negoTokens 必须编成 [1] SEQ OF SEQ { [0] EXPLICIT OCTET STRING }，少一层客户端就解析失败。
func buildTSRequest(version int, negoToken []byte, errorCode int) []byte {
	body := []byte{}
	body = append(body, derTLV(derCtxTag0, derInteger(version))...)
	if negoToken != nil {
		negoData := derTLV(derSeq, derTLV(0xA0, derTLV(derOctetStr, negoToken)))
		body = append(body, derTLV(derCtxTag1, derTLV(derSeq, negoData))...)
	}
	if errorCode != 0 {
		body = append(body, derTLV(derCtxTag4, derInteger(errorCode))...)
	}
	return derTLV(derSeq, body)
}

// ---------------------------------------------------------------------------
// NTLMSSP
// ---------------------------------------------------------------------------

const (
	ntlmNegotiateUnicode     uint32 = 0x00000001
	ntlmNegotiateOEM         uint32 = 0x00000002
	ntlmRequestTarget        uint32 = 0x00000004
	ntlmNegotiateSign        uint32 = 0x00000010
	ntlmNegotiateNTLM        uint32 = 0x00000200
	ntlmNegotiateAlwaysSign  uint32 = 0x00008000
	ntlmTargetTypeDomain     uint32 = 0x00010000
	ntlmNegotiateExtendedSec uint32 = 0x00080000
	ntlmNegotiateTargetInfo  uint32 = 0x00800000
	ntlmNegotiateVersion     uint32 = 0x02000000
	ntlmNegotiate128         uint32 = 0x20000000
	ntlmNegotiateKeyExch     uint32 = 0x40000000
	ntlmNegotiate56          uint32 = 0x80000000

	ntlmMessageTypeChallenge    uint32 = 2
	ntlmMessageTypeAuthenticate uint32 = 3
)

// AV pair 类型
const (
	avEOL             uint16 = 0
	avNbComputerName  uint16 = 1
	avNbDomainName    uint16 = 2
	avDNSComputerName uint16 = 3
	avDNSDomainName   uint16 = 4
	avDNSTreeName     uint16 = 5
	avTimestamp       uint16 = 7
)

func avPair(id uint16, val []byte) []byte {
	out := make([]byte, 4+len(val))
	binary.LittleEndian.PutUint16(out[0:], id)
	binary.LittleEndian.PutUint16(out[2:], uint16(len(val)))
	copy(out[4:], val)
	return out
}

// buildNTLMType2 生成 CHALLENGE_MESSAGE：8 字节随机挑战 + 目标信息（域/主机名/时间戳）
func buildNTLMType2(domain, hostname string) ([]byte, []byte) {
	challenge := randomBytes(8)
	flags := ntlmNegotiateUnicode | ntlmNegotiateOEM | ntlmRequestTarget | ntlmNegotiateSign |
		ntlmNegotiateNTLM | ntlmNegotiateAlwaysSign | ntlmTargetTypeDomain |
		ntlmNegotiateExtendedSec | ntlmNegotiateTargetInfo | ntlmNegotiateVersion |
		ntlmNegotiate128 | ntlmNegotiateKeyExch | ntlmNegotiate56

	target := utf16leEncode(domain)
	// 时间戳让客户端使用我们给的时间（否则它用本地时间，两者都可被破解，但给时间更真实）
	ft := uint64(time.Now().Unix()+11644473600) * 10000000
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, ft)

	info := []byte{}
	info = append(info, avPair(avNbComputerName, utf16leEncode(hostname))...)
	info = append(info, avPair(avNbDomainName, utf16leEncode(domain))...)
	info = append(info, avPair(avDNSComputerName, utf16leEncode(hostname+"."+domain))...)
	info = append(info, avPair(avDNSDomainName, utf16leEncode(domain))...)
	info = append(info, avPair(avDNSTreeName, utf16leEncode(domain))...)
	info = append(info, avPair(avTimestamp, ts)...)
	info = append(info, avPair(avEOL, nil)...)

	const headerLen = 48 // Signature(8)+Type(4)+TargetNameFields(8)+Flags(4)+Challenge(8)+Reserved(8)+TargetInfoFields(8)
	targetOff := headerLen + 8
	infoOff := targetOff + len(target)

	out := make([]byte, headerLen+8)
	copy(out, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(out[8:], ntlmMessageTypeChallenge)
	binary.LittleEndian.PutUint16(out[12:], uint16(len(target)))
	binary.LittleEndian.PutUint16(out[14:], uint16(len(target)))
	binary.LittleEndian.PutUint32(out[16:], uint32(targetOff))
	binary.LittleEndian.PutUint32(out[20:], flags)
	copy(out[24:32], challenge)
	binary.LittleEndian.PutUint16(out[40:], uint16(len(info)))
	binary.LittleEndian.PutUint16(out[42:], uint16(len(info)))
	binary.LittleEndian.PutUint32(out[44:], uint32(infoOff))
	// Version 字段（NEGOTIATE_VERSION 置位时必须带）：Windows Server 2016 = 10.0 build 14393(0x3839)
	copy(out[48:56], []byte{0x0A, 0x00, 0x38, 0x39, 0x00, 0x00, 0x00, 0x0F})

	out = append(out, target...)
	out = append(out, info...)
	return out, challenge
}

type ntlmType3 struct {
	domain      string
	user        string
	workstation string
	lmResponse  []byte
	ntResponse  []byte
	flags       uint32
}

func ntlmField(b []byte, off int) ([]byte, bool) {
	if off+8 > len(b) {
		return nil, false
	}
	l := int(binary.LittleEndian.Uint16(b[off:]))
	o := int(binary.LittleEndian.Uint32(b[off+4:]))
	if l == 0 {
		return nil, true
	}
	if o < 0 || o+l > len(b) {
		return nil, false
	}
	return b[o : o+l], true
}

// parseNTLMType3 解析 AUTHENTICATE_MESSAGE，取出域/用户/主机名与 NT 响应。
// 令牌可能被 SPNEGO/NegTokenResp 包一层，所以先定位 NTLMSSP 签名。
func parseNTLMType3(b []byte) (*ntlmType3, error) {
	if off := bytes.Index(b, []byte("NTLMSSP\x00")); off >= 0 {
		b = b[off:]
	}
	if len(b) < 64 || string(b[:8]) != "NTLMSSP\x00" {
		return nil, errors.New("rdp: 不是 NTLMSSP 报文")
	}
	if binary.LittleEndian.Uint32(b[8:]) != ntlmMessageTypeAuthenticate {
		return nil, errors.New("rdp: 不是 NTLM Type3")
	}
	t := &ntlmType3{}
	var ok bool
	if t.lmResponse, ok = ntlmField(b, 12); !ok {
		return nil, errors.New("rdp: Type3 LM 响应字段越界")
	}
	if t.ntResponse, ok = ntlmField(b, 20); !ok {
		return nil, errors.New("rdp: Type3 NT 响应字段越界")
	}
	dom, _ := ntlmField(b, 28)
	usr, _ := ntlmField(b, 36)
	wks, _ := ntlmField(b, 44)
	t.domain = utf16leDecode(dom)
	t.user = utf16leDecode(usr)
	t.workstation = utf16leDecode(wks)
	if len(b) >= 64 {
		t.flags = binary.LittleEndian.Uint32(b[60:])
	}
	return t, nil
}

// headOf 截取前 n 字节用于调试日志
func headOf(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

// hashcatFormat 输出 hashcat -m 5600 可直接吃的字符串
func (t *ntlmType3) hashcatFormat(challenge []byte) string {
	if len(t.ntResponse) < 16+1 {
		return ""
	}
	proof := hex.EncodeToString(t.ntResponse[:16])
	blob := hex.EncodeToString(t.ntResponse[16:])
	user := t.user
	if user == "" {
		user = "unknown"
	}
	domain := t.domain
	if domain == "" {
		domain = "."
	}
	return fmt.Sprintf("%s::%s:%s:%s:%s", user, domain, hex.EncodeToString(challenge), proof, blob)
}

// ---------------------------------------------------------------------------
// CredSSP 主流程
// ---------------------------------------------------------------------------

// credSSP 在 TLS 之上跑 CredSSP：客户端 CredSSP 版本 > 6 时钳到 6。
// 抓到 Type3 后一定返回错误（我们无从完成认证），但凭据已经落事件。
func (s *rdpSession) credSSP(ctx context.Context) error {
	if s.br == nil {
		return errors.New("rdp: CredSSP 需要 TLS 之上的缓冲读取器")
	}
	// 第 1 条：Negotiate（NTLM Type1）
	tag, content, err := derReadTLV(s.br)
	if err != nil {
		return err
	}
	if tag != derSeq {
		return errors.New("rdp: CredSSP 首条报文不是 SEQUENCE")
	}
	req := parseTSRequest(content)
	if len(req.negoTokens) == 0 || req.authInfo != nil {
		return errors.New("rdp: CredSSP 首条报文没有 NTLM Type1")
	}
	version := req.version
	if version < 2 {
		version = 2
	}
	if version > 6 {
		version = 6
	}
	logger.Log.Debugf("[rdp] CredSSP version=%d, Type1=%s", version,
		hex.EncodeToString(headOf(req.negoTokens[0], 16)))

	// 第 2 条：把我们的 Type2 发回去，客户端据此计算 NetNTLMv2 响应
	type2, challenge := buildNTLMType2(s.cfg.Domain, s.cfg.Hostname)
	resp := buildTSRequest(version, type2, 0)
	logger.Log.Debugf("[rdp] CredSSP 回 Type2 共 %d 字节: %s", len(resp), hex.EncodeToString(headOf(resp, 24)))
	if _, err := s.rw.Write(resp); err != nil {
		return err
	}

	// 第 3 条：Authenticate（NTLM Type3）——目标就是它
	tag, content, err = derReadTLV(s.br)
	if err != nil {
		return err
	}
	if tag != derSeq {
		return errors.New("rdp: CredSSP 第三条报文不是 SEQUENCE")
	}
	req = parseTSRequest(content)
	if len(req.negoTokens) == 0 {
		return errors.New("rdp: CredSSP 没有收到 NTLM Type3")
	}
	for i, tk := range req.negoTokens {
		logger.Log.Debugf("[rdp] CredSSP Type3[%d] %d 字节: %s", i, len(tk), hex.EncodeToString(headOf(tk, 16)))
	}
	var t3 *ntlmType3
	for _, tk := range req.negoTokens {
		if t3, err = parseNTLMType3(tk); err == nil {
			break
		}
	}
	if t3 == nil {
		if err == nil {
			err = errors.New("rdp: CredSSP 没有收到 NTLM Type3")
		}
		return err
	}

	details := map[string]interface{}{
		"application":      s.name,
		"auth":             "ntlm",
		"client_name":      s.clientName,
		"domain":           t3.domain,
		"user":             t3.user,
		"workstation":      t3.workstation,
		"ntlm_flags":       fmt.Sprintf("0x%08x", t3.flags),
		"ntlm_response":    hex.EncodeToString(t3.ntResponse),
		"server_challenge": hex.EncodeToString(challenge),
		"pubkey_auth":      len(req.pubKeyAuth) > 0,
		"hashcat":          t3.hashcatFormat(challenge),
	}
	s.push("rdp-login", details)
	logger.Log.Infof("[rdp] NLA 捕获凭据: %s\\%s (%s)", t3.domain, t3.user, t3.workstation)

	// 明确的失败回执：NLA 下我们不可能继续，给 STATUS_LOGON_FAILURE 让客户端如实报错
	_, _ = s.rw.Write(buildTSRequest(version, nil, 0xC000006D))
	return errors.New("rdp: CredSSP 认证失败（蜜罐只取凭据）")
}
