package rdp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
)

// 本文件实现 MS-RDPBCGR 连接序列里"字节级"的那几层：
// TPKT 分帧 → X.224 → MCS(T.125) → GCC 用户数据块，以及服务器专有证书（含 RSA 公钥）。
//
// 报文布局依据：MS-RDPBCGR 2.2.1（Connection Sequence）+ 纯 Go 客户端实现
// github.com/tomatome/grdp（v0.1.0）的 t125/gcc/sec 包，后者用于交叉校验。

var errShortPkt = errors.New("rdp: 报文长度不足")

// ---------------------------------------------------------------------------
// 带边界检查的读取器：蜜罐面对的是构造过的畸形报文，任何字段都不能越界 panic
// ---------------------------------------------------------------------------

type pktReader struct {
	b   []byte
	off int
}

func newPktReader(b []byte) *pktReader { return &pktReader{b: b} }

func (r *pktReader) remaining() int { return len(r.b) - r.off }

func (r *pktReader) u8() (uint8, error) {
	if r.remaining() < 1 {
		return 0, errShortPkt
	}
	v := r.b[r.off]
	r.off++
	return v, nil
}

func (r *pktReader) u16le() (uint16, error) {
	if r.remaining() < 2 {
		return 0, errShortPkt
	}
	v := binary.LittleEndian.Uint16(r.b[r.off:])
	r.off += 2
	return v, nil
}

func (r *pktReader) u16be() (uint16, error) {
	if r.remaining() < 2 {
		return 0, errShortPkt
	}
	v := binary.BigEndian.Uint16(r.b[r.off:])
	r.off += 2
	return v, nil
}

func (r *pktReader) u32le() (uint32, error) {
	if r.remaining() < 4 {
		return 0, errShortPkt
	}
	v := binary.LittleEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v, nil
}

func (r *pktReader) bytes(n int) ([]byte, error) {
	if n < 0 || r.remaining() < n {
		return nil, errShortPkt
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v, nil
}

func (r *pktReader) skip(n int) error {
	_, err := r.bytes(n)
	return err
}

func (r *pktReader) rest() []byte { return r.b[r.off:] }

// ---------------------------------------------------------------------------
// TPKT（RFC 1006 / MS-RDPBCGR 2.2.1.1）
// ---------------------------------------------------------------------------

const tpktVersion = 0x03

func buildTPKT(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	out[0] = tpktVersion
	out[1] = 0x00
	binary.BigEndian.PutUint16(out[2:], uint16(len(payload)+4))
	copy(out[4:], payload)
	return out
}

// ---------------------------------------------------------------------------
// X.224（MS-RDPBCGR 2.2.1.2）
// ---------------------------------------------------------------------------

const (
	x224CR   = 0xE0 // Connection Request
	x224CC   = 0xD0 // Connection Confirm
	x224Data = 0xF0 // Data
)

const (
	negTypeReq     = 0x01
	negTypeRsp     = 0x02
	negTypeFailure = 0x03
)

// 协商协议位
const (
	protoRDP      uint32 = 0x00000000 // 标准 RDP 安全
	protoSSL      uint32 = 0x00000001 // TLS
	protoHybrid   uint32 = 0x00000002 // CredSSP / NLA
	protoHybridEx uint32 = 0x00000008 // CredSSP + 远程凭据保护（不支持）
)

// 协商失败码
const (
	negFailSSLRequiredByServer     uint32 = 0x00000001
	negFailSSLNotAllowedByServer   uint32 = 0x00000002
	negFailSSLCertNotOnServer      uint32 = 0x00000003
	negFailInconsistentFlags       uint32 = 0x00000004
	negFailHybridRequiredByServer  uint32 = 0x00000005
	negFailSSLWithUserAuthRequired uint32 = 0x00000006
)

type x224ConnReq struct {
	srcRef             uint16
	cookie             string
	hasNegotiation     bool
	requestedProtocols uint32
}

// parseX224ConnReq 解析 X.224 Connection Request：定位 Cookie（mstshash，可用于识别扫描器）
// 与 RDP Negotiation Request（请求的安全协议位）。
func parseX224ConnReq(b []byte) (*x224ConnReq, error) {
	r := newPktReader(b)
	if _, err := r.u8(); err != nil { // Length Indicator
		return nil, err
	}
	code, err := r.u8()
	if err != nil {
		return nil, err
	}
	if code != x224CR {
		return nil, errors.New("rdp: 不是 X.224 Connection Request")
	}
	req := &x224ConnReq{}
	if _, err := r.u16be(); err != nil { // destination reference
		return nil, err
	}
	if req.srcRef, err = r.u16be(); err != nil {
		return nil, err
	}
	if _, err := r.u8(); err != nil { // class option
		return nil, err
	}
	rest := r.rest()
	// 协商块可能在 Cookie 之后：扫描 01 00 08 00 的固定头
	for i := 0; i+8 <= len(rest); i++ {
		if rest[i] == negTypeReq && rest[i+1] == 0x00 && rest[i+2] == 0x08 && rest[i+3] == 0x00 {
			req.hasNegotiation = true
			req.requestedProtocols = binary.LittleEndian.Uint32(rest[i+4:])
			rest = rest[:i]
			break
		}
	}
	req.cookie = strings.TrimSpace(string(rest))
	return req, nil
}

func buildX224ConnConfirm(selectedProtocol uint32) []byte {
	// X.224 Connection Confirm（与真实 Windows 服务器一致）：
	//   LI=0x0E，固定头 6 字节 d0 00 00 00 00 00（code + dstRef(2) + srcRef(2) + class），
	//   LI 覆盖整段（含随后的 RDP 协商响应）。不要改成"只算固定头"——mstsc 严格按 LI 分帧。
	body := []byte{x224CC, 0x00, 0x00, 0x00, 0x00, 0x00}
	body = append(body, negTypeRsp, 0x00, 0x08, 0x00)
	body = append(body, byte(selectedProtocol), byte(selectedProtocol>>8), byte(selectedProtocol>>16), byte(selectedProtocol>>24))
	return append([]byte{byte(len(body))}, body...)
}

func buildX224NegFailure(code uint32) []byte {
	body := []byte{x224CC, 0x00, 0x00, 0x00, 0x00, 0x00}
	body = append(body, negTypeFailure, 0x00, 0x08, 0x00)
	body = append(body, byte(code), byte(code>>8), byte(code>>16), byte(code>>24))
	return append([]byte{byte(len(body))}, body...)
}

func buildX224Data(payload []byte) []byte {
	out := make([]byte, 3+len(payload))
	out[0] = 0x02
	out[1] = x224Data
	out[2] = 0x80
	copy(out[3:], payload)
	return out
}

// ---------------------------------------------------------------------------
// MCS / T.125（MS-RDPBCGR 2.2.1.3~2.2.1.5）
// ---------------------------------------------------------------------------

const (
	mcsErectDomainRequest  = 1
	mcsDisconnectUltimatum = 8
	mcsAttachUserRequest   = 10
	mcsAttachUserConfirm   = 11
	mcsChannelJoinRequest  = 14
	mcsChannelJoinConfirm  = 15
	mcsSendDataRequest     = 25
	mcsSendDataIndication  = 26

	mcsGlobalChannelID uint16 = 1003
	mcsUserChannelBase uint16 = 1001
)

func mcsPDUType(b []byte) (uint8, error) {
	if len(b) < 1 {
		return 0, errShortPkt
	}
	return b[0] >> 2, nil
}

// PER 编码（T.125 用的那几种）
func perWriteLength(n int, out []byte) []byte {
	if n > 0x7f {
		return append(out, byte(n>>8)|0x80, byte(n))
	}
	return append(out, byte(n))
}

func perReadLength(r *pktReader) (int, error) {
	b, err := r.u8()
	if err != nil {
		return 0, err
	}
	if b&0x80 != 0 {
		lo, err := r.u8()
		if err != nil {
			return 0, err
		}
		return int(b&^0x80)<<8 | int(lo), nil
	}
	return int(b), nil
}

// buildMCSSendData 组装 MCS Send Data Indication：塞入共享控制/数据 PDU 的通用外壳。
func buildMCSSendData(userID, channelID uint16, data []byte) []byte {
	out := []byte{(mcsSendDataIndication << 2), byte(userID >> 8), byte(userID), byte(channelID >> 8), byte(channelID), 0x70}
	out = perWriteLength(len(data), out)
	return append(out, data...)
}

type mcsSendData struct {
	userID    uint16
	channelID uint16
	data      []byte
}

// parseMCSSendData 解析客户端的 MCS Send Data Request（客户端→服务器统一走这个壳）。
func parseMCSSendData(b []byte) (*mcsSendData, error) {
	r := newPktReader(b)
	op, err := r.u8()
	if err != nil {
		return nil, err
	}
	if op>>2 != mcsSendDataRequest {
		return nil, errors.New("rdp: 不是 MCS Send Data Request")
	}
	d := &mcsSendData{}
	if d.userID, err = r.u16be(); err != nil {
		return nil, err
	}
	if d.channelID, err = r.u16be(); err != nil {
		return nil, err
	}
	if _, err = r.u8(); err != nil { // data priority / segmentation
		return nil, err
	}
	n, err := perReadLength(r)
	if err != nil {
		return nil, err
	}
	if d.data, err = r.bytes(n); err != nil {
		// 少数客户端声明的长度比实际长，能取多少取多少，避免整条连接作废
		d.data = r.rest()
	}
	return d, nil
}

// ---------------------------------------------------------------------------
// BER：MCS Connect Initial 的解析与 Connect Response 的构造
// （MS-RDPBCGR 2.2.1.3：ConnectInitial 是 [APPLICATION 101]，ConnectResponse 是 [APPLICATION 102]）
// ---------------------------------------------------------------------------

func berReadLength(r *pktReader) (int, error) {
	b, err := r.u8()
	if err != nil {
		return 0, err
	}
	if b&0x80 == 0 {
		return int(b), nil
	}
	switch b &^ 0x80 {
	case 1:
		v, err := r.u8()
		return int(v), err
	case 2:
		v, err := r.u16be()
		return int(v), err
	case 4:
		v, err := r.u32le()
		return int(v), err
	default:
		return 0, errors.New("rdp: 不支持的 BER 长度形式")
	}
}

func berWriteLength(n int, out []byte) []byte {
	if n > 0x7f {
		return append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, byte(n))
}

// skipBERTLV 跳过一个 tag 已知的 TLV
func skipBERTLV(r *pktReader, tag byte) error {
	t, err := r.u8()
	if err != nil {
		return err
	}
	if t != tag {
		return errors.New("rdp: BER tag 不匹配")
	}
	n, err := berReadLength(r)
	if err != nil {
		return err
	}
	return r.skip(n)
}

// parseConnectInitialUserData 从 Connect Initial 里取出最后一个 OCTET STRING，即 GCC 用户数据。
// 中间三段 DomainParameters 是定长 ASN.1 结构，按 TLV 跳过即可（不需要理解内容）。
func parseConnectInitialUserData(b []byte) ([]byte, error) {
	r := newPktReader(b)
	t1, err := r.u8()
	if err != nil {
		return nil, err
	}
	if t1 != 0x7f {
		return nil, errors.New("rdp: 不是 BER 应用标签")
	}
	if t2, err := r.u8(); err != nil || t2 != 101 {
		return nil, errors.New("rdp: 不是 MCS Connect Initial")
	}
	if _, err := berReadLength(r); err != nil {
		return nil, err
	}
	// ConnectInitial（隐式 SEQUENCE）内容
	for _, tag := range []byte{0x04, 0x04, 0x01, 0x30, 0x30, 0x30} {
		if err := skipBERTLV(r, tag); err != nil {
			return nil, err
		}
	}
	// userData OCTET STRING
	if t, err := r.u8(); err != nil || t != 0x04 {
		return nil, errors.New("rdp: Connect Initial 的 userData 缺失")
	}
	n, err := berReadLength(r)
	if err != nil {
		return nil, err
	}
	if n > r.remaining() {
		n = r.remaining()
	}
	return r.bytes(n)
}

// T.125 ConferenceCreate 的 H.221 非标准键（MS-RDPBCGR 2.2.1.3.1/2.2.1.4.1）
const (
	h221KeyClient = "Duca"
	h221KeyServer = "McDn"
)

// splitConferenceCreate 剥掉 T.125 ConferenceCreateRequest/Response 的 PER 前缀。
// 结构：choice(1) + OID(6) + 长度 + choice/selection/数字串/padding/numberOfSet(共6字节)
//   - choice(1) + octetStream(长度1 + "Duca"/"McDn" 4 字节) + userData 长度 + 块数据。
//
// 这里用 H.221 键定位，比逐字段推算更抗客户端差异。
func splitConferenceCreate(b []byte, key string) []byte {
	limit := len(b)
	if limit > 64 {
		limit = 64
	}
	idx := -1
	for i := 0; i+4 <= limit; i++ {
		if string(b[i:i+4]) == key {
			idx = i
			break
		}
	}
	if idx < 0 {
		return b
	}
	rest := b[idx+4:]
	if len(rest) == 0 {
		return rest
	}
	if rest[0]&0x80 != 0 && len(rest) >= 2 {
		return rest[2:]
	}
	return rest[1:]
}

// buildConferenceCreateResponse 按 T.125 组 Connect Response 的 GCC 容器。
//
// 字段顺序（与 FreeRDP 的 gcc_write_conference_create_response 逐字节对齐）：
//
//	choice(00) + OID(05 00 14 7c 00 01) + length(2a，客户端必须忽略)
//	+ choice(14) + nodeID(integer16) + tag(integer) + result(enumerated)
//	+ numberOfSets(01) + choice(c0) + octetStream(00 "McDn") + userData 长度 + 块
//
// 注意这里不能用"数字串 '1'"那种写法：FreeRDP 的 per_read_integer 会校验 PER 长度字节，
// 遇到非 1/2/4 的值直接判失败。
func buildConferenceCreateResponse(blocks []byte) []byte {
	out := []byte{0x00}                                   // choice
	out = append(out, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01) // t124_02_98_oid
	out = perWriteLength(0x2A, out)                       // 该长度字段客户端会忽略
	out = append(out, 0x14)                               // choice（ConnectGCCPDU）
	out = append(out, 0x76, 0x0A)                         // nodeID：integer16，min=1001（= 0x79F3 - 1001）
	out = append(out, 0x01, 0x01)                         // tag：PER integer = 1
	out = append(out, 0x00)                               // result：ENUMERATED = 0（成功）
	out = append(out, 0x01)                               // numberOfSets = 1
	out = append(out, 0xC0)                               // choice：h221NonStandard
	out = append(out, 0x00)                               // octetStream 长度（min = 4，与 4 字节键相抵）
	out = append(out, h221KeyServer...)
	out = perWriteLength(len(blocks), out)
	return append(out, blocks...)
}

// buildConferenceCreateRequest 只在测试/回环场景构造客户端请求时使用
func buildConferenceCreateRequest(blocks []byte) []byte {
	out := []byte{0x00}
	out = append(out, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01)
	out = perWriteLength(0x2A, out)
	out = append(out, 0x14)
	out = append(out, 0x76, 0x0A)
	out = append(out, 0x01, 0x01)
	out = append(out, 0x00)
	out = append(out, 0x01)
	out = append(out, 0xC0)
	out = append(out, 0x00)
	out = append(out, h221KeyClient...)
	out = perWriteLength(len(blocks), out)
	return append(out, blocks...)
}

// buildConnectResponse 组装 MCS Connect Response（含 GCC：SC_CORE / SC_NET / SC_SEC1）
func buildConnectResponse(userData []byte) []byte {
	body := []byte{0x0a, 0x01, 0x00}      // result ENUMERATED = 0
	body = append(body, 0x02, 0x01, 0x00) // calledConnectId INTEGER = 0
	params := []byte{}
	params = append(params, 0x02, 0x01, 34)         // maxChannelIds
	params = append(params, 0x02, 0x01, 3)          // maxUserIds
	params = append(params, 0x02, 0x01, 0)          // maxTokenIds
	params = append(params, 0x02, 0x01, 1)          // numPriorities
	params = append(params, 0x02, 0x01, 0)          // minThroughput
	params = append(params, 0x02, 0x01, 1)          // maxHeight
	params = append(params, 0x02, 0x02, 0xff, 0xf8) // maxMCSPDUsize
	params = append(params, 0x02, 0x01, 2)          // protocolVersion
	body = append(body, 0x30)
	body = berWriteLength(len(params), body)
	body = append(body, params...)
	blocks := buildConferenceCreateResponse(userData)
	body = append(body, 0x04)
	body = berWriteLength(len(blocks), body)
	body = append(body, blocks...)

	out := []byte{0x7f, 102}
	out = berWriteLength(len(body), out)
	return append(out, body...)
}

// ---------------------------------------------------------------------------
// GCC 用户数据块（MS-RDPBCGR 2.2.1.4）
// ---------------------------------------------------------------------------

const (
	csCore     uint16 = 0xC001
	csSecurity uint16 = 0xC002
	csNet      uint16 = 0xC003
	csCluster  uint16 = 0xC004
	csMonitor  uint16 = 0xC005

	scCore     uint16 = 0x0C01
	scNet      uint16 = 0x0C03
	scSecurity uint16 = 0x0C02
)

// clientCore 是客户端能力宣告里我们关心的部分（CS_CORE）
type clientCore struct {
	rdpVersion             uint32
	desktopWidth           uint16
	desktopHeight          uint16
	colorDepth             uint16
	kbdLayout              uint32
	clientName             string // 攻击者机器名，情报价值高
	keyboardType           uint32
	keyboardSubType        uint32
	keyboardFnKeys         uint32
	postBeta2ColorDepth    uint16
	highColorDepth         uint16
	supportedColorDepths   uint16
	earlyCapabilityFlags   uint16
	connectionType         uint8
	serverSelectedProtocol uint32
}

func parseClientCoreData(b []byte) *clientCore {
	c := &clientCore{desktopWidth: 1024, desktopHeight: 768, highColorDepth: 16}
	r := newPktReader(b)
	read := func(f func() error) { _ = f() }
	read(func() error { v, err := r.u32le(); c.rdpVersion = v; return err })
	read(func() error { v, err := r.u16le(); c.desktopWidth = v; return err })
	read(func() error { v, err := r.u16le(); c.desktopHeight = v; return err })
	read(func() error { v, err := r.u16le(); c.colorDepth = v; return err })
	read(func() error { _, err := r.u16le(); return err }) // sasSequence
	read(func() error { v, err := r.u32le(); c.kbdLayout = v; return err })
	read(func() error { _, err := r.u32le(); return err }) // clientBuild
	read(func() error {
		v, err := r.bytes(32)
		c.clientName = utf16leTrim(v)
		return err
	})
	read(func() error { v, err := r.u32le(); c.keyboardType = v; return err })
	read(func() error { v, err := r.u32le(); c.keyboardSubType = v; return err })
	read(func() error { v, err := r.u32le(); c.keyboardFnKeys = v; return err })
	read(func() error { return r.skip(64) }) // imeFileName
	read(func() error { v, err := r.u16le(); c.postBeta2ColorDepth = v; return err })
	read(func() error { return r.skip(2) }) // clientProductId
	read(func() error { return r.skip(4) }) // serialNumber
	read(func() error { v, err := r.u16le(); c.highColorDepth = v; return err })
	read(func() error { v, err := r.u16le(); c.supportedColorDepths = v; return err })
	read(func() error { v, err := r.u16le(); c.earlyCapabilityFlags = v; return err })
	read(func() error { return r.skip(64) }) // clientDigProductId
	read(func() error { v, err := r.u8(); c.connectionType = v; return err })
	read(func() error { return r.skip(1) })
	read(func() error { v, err := r.u32le(); c.serverSelectedProtocol = v; return err })

	if c.desktopWidth == 0 {
		c.desktopWidth = 1024
	}
	if c.desktopHeight == 0 {
		c.desktopHeight = 768
	}
	if c.highColorDepth == 0 {
		c.highColorDepth = 16
	}
	return c
}

func (c *clientCore) wants32BPP() bool {
	return c.highColorDepth == 24 && c.earlyCapabilityFlags&0x0002 != 0 // RNS_UD_CS_WANT_32BPP_SESSION
}

type clientNetwork struct {
	channelNames   []string
	channelOptions []uint32
}

func parseClientNetworkData(b []byte) *clientNetwork {
	n := &clientNetwork{}
	r := newPktReader(b)
	count, err := r.u32le()
	if err != nil {
		return n
	}
	for i := 0; i < int(count); i++ {
		name, err := r.bytes(8)
		if err != nil {
			break
		}
		opt, err := r.u32le()
		if err != nil {
			break
		}
		n.channelNames = append(n.channelNames, strings.TrimRight(string(name), "\x00"))
		n.channelOptions = append(n.channelOptions, opt)
	}
	return n
}

// parseGCCUserData 解析客户端 GCC 容器里的各个块（块格式：LE16 类型 + LE16 长度 + 数据）
func parseGCCUserData(b []byte) (core *clientCore, net *clientNetwork, encMethods, extEncMethods uint32) {
	r := newPktReader(b)
	for r.remaining() >= 4 {
		typ, err := r.u16le()
		if err != nil {
			break
		}
		l, err := r.u16le()
		if err != nil {
			break
		}
		if l < 4 || int(l)-4 > r.remaining() {
			break
		}
		data, _ := r.bytes(int(l) - 4)
		switch typ {
		case csCore:
			core = parseClientCoreData(data)
		case csNet:
			net = parseClientNetworkData(data)
		case csSecurity:
			sr := newPktReader(data)
			if v, err := sr.u32le(); err == nil {
				encMethods = v
			}
			if v, err := sr.u32le(); err == nil {
				extEncMethods = v
			}
		}
	}
	if core == nil {
		core = parseClientCoreData(nil)
	}
	if net == nil {
		net = &clientNetwork{}
	}
	return core, net, encMethods, extEncMethods
}

// gccBlock 组装单个 GCC 块
func gccBlock(typ uint16, data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint16(out[0:], typ)
	binary.LittleEndian.PutUint16(out[2:], uint16(4+len(data)))
	copy(out[4:], data)
	return out
}

// buildServerGCC 组装 Connect Response 的 GCC 用户数据：SC_CORE + SC_NET + SC_SEC1[+ 证书]
func buildServerGCC(clientRequestedProtocols uint32, channelIDs []uint16, sec *securityData, hostname string) []byte {
	var out []byte

	// SC_CORE：数据写满 12 字节（rdpVersion + clientRequestedProtocols + earlyCapabilityFlags）。
	// 客户端按"块声明长度 > 8"判断是否存在 earlyCapabilityFlags，只写 8 字节会让它越界
	// 读进下一个块的块头，进而在解析 Connect Response 时失败（FreeRDP 实测如此）。
	scCoreData := make([]byte, 12)
	binary.LittleEndian.PutUint32(scCoreData[0:], 0x00080004) // RDP 5.0+
	binary.LittleEndian.PutUint32(scCoreData[4:], clientRequestedProtocols)
	binary.LittleEndian.PutUint32(scCoreData[8:], 0) // earlyCapabilityFlags
	out = append(out, gccBlock(scCore, scCoreData)...)

	// SC_NET：MCS I/O 通道 ID + 为客户端请求的每条虚拟通道分配的 ID。
	// 数据长度必须补齐到 4 字节对齐（channelCount 为奇数时补 2 字节 Pad）——MS-RDPBCGR
	// 2.2.1.4.4 的 SC_NET 结构就是 MCSChannelId(2)+channelCount(2)+channelIdArray(2N)+Pad。
	// mstsc 严格按此结构读；缺 Pad 会让它多读 2 字节、把下一个块（SC_SECURITY）的块头读坏而 RST。
	scNetData := make([]byte, 4+2*len(channelIDs))
	binary.LittleEndian.PutUint16(scNetData[0:], mcsGlobalChannelID)
	binary.LittleEndian.PutUint16(scNetData[2:], uint16(len(channelIDs)))
	for i, id := range channelIDs {
		binary.LittleEndian.PutUint16(scNetData[4+2*i:], id)
	}
	if pad := len(scNetData) % 4; pad != 0 {
		scNetData = append(scNetData, make([]byte, 4-pad)...)
	}
	out = append(out, gccBlock(scNet, scNetData)...)

	// SC_SEC1
	scSec := make([]byte, 0, 8+4+4+32+512)
	scSec = appendLE32(scSec, sec.encryptionMethod)
	scSec = appendLE32(scSec, sec.encryptionLevel)
	if sec.encryptionMethod != 0 || sec.encryptionLevel != 0 {
		scSec = appendLE32(scSec, uint32(len(sec.serverRandom)))
		scSec = appendLE32(scSec, uint32(len(sec.certificate)))
		scSec = append(scSec, sec.serverRandom...)
		scSec = append(scSec, sec.certificate...)
	}
	out = append(out, gccBlock(scSecurity, scSec)...)
	_ = hostname
	return out
}

func appendLE32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// ---------------------------------------------------------------------------
// 服务器专有证书（MS-RDPBCGR 2.2.1.4.3.1.1，CERT_CHAIN_VERSION_1）
//
// 标准 RDP 安全下客户端用它带来的公钥加密 32 字节 client random；TLS 模式不带这段，
// 但口令字段仍可能用它加密。模数以小端存放，是这套老协议的"怪癖"之一。
// ---------------------------------------------------------------------------

func buildProprietaryCert(priv *rdpPrivateKey) []byte {
	modLen := priv.modulusLen()
	modulus := make([]byte, modLen)
	priv.n.FillBytes(modulus)
	reverseInPlace(modulus) // 小端存放

	pub := []byte{}
	pub = appendLE32(pub, 0x31415352)       // magic 'RSA1'
	pub = appendLE32(pub, uint32(modLen+8)) // keylen = datalen + 8
	pub = appendLE32(pub, uint32(priv.n.BitLen()))
	pub = appendLE32(pub, uint32(modLen)) // datalen
	pub = appendLE32(pub, uint32(priv.e)) // pubexp（65537）
	pub = append(pub, modulus...)
	pub = append(pub, make([]byte, 8)...) // padding

	// 签名：协议里是"公钥块的 MD5 反过来做 RSA 私钥运算再反过来"。
	// 客户端都不校验它（FreeRDP 源码里这段校验是关掉的），但按同样算法生成不留破绽。
	sig := padTo(rdpSign(priv, pub), modLen)

	out := []byte{}
	out = appendLE32(out, 0x00000001) // dwVersion = CERT_CHAIN_VERSION_1（漏了它客户端直接拒绝）
	out = appendLE32(out, 0x00000001) // dwSigAlgId = RSA
	out = appendLE32(out, 0x00000001) // dwKeyAlgId = RSA
	out = append(out, 0x06, 0x00)     // wPublicKeyBlobType = BB_RSA_KEY_BLOB
	out = append(out, byte(len(pub)), byte(len(pub)>>8))
	out = append(out, pub...)
	out = append(out, 0x08, 0x00) // wSignatureBlobType = BB_RSA_SIGNATURE_BLOB
	sigLen := len(sig) + 8
	out = append(out, byte(sigLen), byte(sigLen>>8))
	out = append(out, sig...)
	out = append(out, make([]byte, 8)...) // padding（最后 8 字节为 0）
	return out
}

func padTo(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func reverseInPlace(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

// rdpSign 复刻 RDP 私钥运算的字节序：m = reverse(md5(data))，sig = reverse(m^d mod n)
func rdpSign(priv *rdpPrivateKey, data []byte) []byte {
	h := md5Sum(data)
	m := new(big.Int).SetBytes(reverseBytes(h))
	s := new(big.Int).Exp(m, priv.d, priv.n)
	return reverseBytes(padTo(s.Bytes(), priv.modulusLen()))
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 出错基本意味着系统熵源有问题，这里退化为可预测随机数即可（蜜罐不依赖它保密）
		for i := range b {
			b[i] = byte(i * 7)
		}
	}
	return b
}
