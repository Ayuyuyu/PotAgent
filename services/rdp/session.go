package rdp

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"io"
	"net"
	"time"

	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
)

// 本文件是 RDP 连接序列的状态机：
//
//	X.224 协商 → [TLS/NLA] → MCS(GCC) → [安全交换] → Client Info → Licensing →
//	Demand Active / Confirm Active → Synchronize/Control/Font Map → 位图 + 输入循环
//
// 每一步都必须按 MS-RDPBCGR 的顺序与字节布局来，否则客户端在会话建立前就断了。

// 分帧类型：同一个 TCP 流里 TPKT 与快速路径混在一起
const (
	packetTPKT = iota
	packetFastPath
)

// packetReader 负责判别并按帧读出完整载荷
type packetReader struct {
	br *bufio.Reader
}

func (p *packetReader) next() (int, byte, []byte, error) {
	head, err := p.br.Peek(1)
	if err != nil {
		return 0, 0, nil, err
	}
	if head[0] == tpktVersion {
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(p.br, hdr); err != nil {
			return 0, 0, nil, err
		}
		total := int(binary.BigEndian.Uint16(hdr[2:]))
		if total < 7 {
			return 0, 0, nil, errors.New("rdp: TPKT 长度非法")
		}
		payload := make([]byte, total-4)
		if _, err := io.ReadFull(p.br, payload); err != nil {
			return 0, 0, nil, err
		}
		return packetTPKT, 0, payload, nil
	}

	// 快速路径：首字节低 2 位是 action，高 2 位是安全标志，其余位与后续字节表示长度
	b0, err := p.br.ReadByte()
	if err != nil {
		return 0, 0, nil, err
	}
	secFlag := (b0 >> 6) & 0x03
	var total, hdrLen int
	if l := int(b0>>2) & 0x3f; l != 0 {
		total, hdrLen = l, 1
	} else {
		b1, err := p.br.ReadByte()
		if err != nil {
			return 0, 0, nil, err
		}
		if b1&0x80 != 0 {
			b2, err := p.br.ReadByte()
			if err != nil {
				return 0, 0, nil, err
			}
			total, hdrLen = int(b1&0x7f)<<8|int(b2), 3
		} else {
			total, hdrLen = int(b1), 2
		}
	}
	if total < hdrLen {
		return 0, 0, nil, errors.New("rdp: 快速路径长度非法")
	}
	payload := make([]byte, total-hdrLen)
	if _, err := io.ReadFull(p.br, payload); err != nil {
		return 0, 0, nil, err
	}
	return packetFastPath, secFlag, payload, nil
}

// rdpSession 一条 RDP 连接的全部状态
type rdpSession struct {
	cfg       *rdpConfig
	rdpKey    *rdpPrivateKey // 标准 RDP 安全的专有证书密钥（512 位，协议约定）
	tlsKey    *rsa.PrivateKey
	tlsPair   tls.Certificate
	srvImg    image.Image
	name      string
	stage     string   // 连接进度标记，用于失败时在 rdp-error 事件里定位断点
	loginUser string   // Client Info 里解析出的用户名（用于 Save Session Info 收尾）
	mcsTrace  []string // MCS 报文轨迹，失败时随 rdp-error 事件输出，便于在无 Debug 版时定位 mstsc 严格点

	srcAddr, dstAddr common.Addr
	conn             net.Conn
	rw               io.ReadWriter // TLS 之后指向 tls.Conn
	br               *bufio.Reader // CredSSP 阶段按 DER 读，之后交给 packetReader 复用
	reader           *packetReader

	// 协商结果
	negotiated         uint32
	requestedProtocols uint32
	standardSec        bool
	crypto             *rdpCrypto

	// MCS / GCC
	core        *clientCore
	channels    []string
	channelIDs  []uint16
	mcsInit     uint16 // MCS 头里的 initiator（= 用户通道 ID - 1001，值为 1）
	userChannel uint16 // 用户通道全局 ID（1002），也是共享控制头里的 pduSource

	// 会话
	shareID      uint32
	caps         *clientCaps
	clientRandom []byte
	serverRandom []byte
	bpp          int
	desktopW     int
	desktopH     int
	fastPathOut  bool

	keyboard   keyTracker
	clientName string
	// finalized 在收到 Font List 并回 Font Map 后置位；这是连接收尾完成、允许
	// 开始发送图形输出的唯一时机。
	finalized    bool
	fontMapTimer *time.Timer
}

const defaultShareID uint32 = 0x000103EA

func (s *rdpSession) srcIP() string { return s.srcAddr.IP }

func (s *rdpSession) push(eventType string, details map[string]interface{}) {
	if details == nil {
		details = map[string]interface{}{}
	}
	details["application"] = s.name
	event.EventPush(event.NewEvent(serviceName, eventType, s.srcAddr, s.dstAddr, details))
}

// tracef 记录一条 MCS 报文轨迹（保留最近若干条），失败时由 rdp-error 事件输出。
func (s *rdpSession) tracef(format string, args ...interface{}) {
	if len(s.mcsTrace) > 24 {
		s.mcsTrace = s.mcsTrace[len(s.mcsTrace)-24:]
	}
	s.mcsTrace = append(s.mcsTrace, fmt.Sprintf(format, args...))
}

// ---------------------------------------------------------------------------
// 总体流程
// ---------------------------------------------------------------------------

func (s *rdpSession) run(ctx context.Context) error {
	// MCS 头里的 initiator 是"用户通道 ID - 1001"；1002 是 RDP 约定的用户通道
	s.mcsInit = 1
	s.userChannel = mcsUserChannelBase + 1
	if err := s.negotiate(ctx); err != nil {
		return err
	}
	pending, err := s.mcsConnect()
	if err != nil {
		return err
	}
	s.stage = "mcs:setup-done"
	if s.standardSec {
		s.stage = "security-exchange"
		if pending, err = s.securityExchange(pending); err != nil {
			return err
		}
	}
	s.stage = "client-info"
	if pending, err = s.clientInfoPhase(pending); err != nil {
		return err
	}
	if err := s.licensingPhase(pending); err != nil {
		return err
	}
	// 许可通过后，服务器紧接着发 Demand Active（能力协商的发起方是服务器）
	if err := s.sendDemandActive(); err != nil {
		return err
	}
	s.loop(ctx)
	return nil
}

// prepareDesktop 确定色深与分辨率（配置优先，其次客户端宣告）
func (s *rdpSession) prepareDesktop() {
	s.bpp = pickBPP(s.core)
	s.desktopW = int(s.core.desktopWidth)
	s.desktopH = int(s.core.desktopHeight)
	if s.cfg.Width > 0 {
		s.desktopW = s.cfg.Width
	}
	if s.cfg.Height > 0 {
		s.desktopH = s.cfg.Height
	}
}

// sendDemandActive 发送服务器能力协商（MS-RDPBCGR 2.2.1.6.1）
func (s *rdpSession) sendDemandActive() error {
	s.prepareDesktop()
	s.shareID = defaultShareID
	if s.core == nil {
		return errors.New("rdp: 缺少客户端能力数据")
	}
	// Demand Active 的位图能力集必须与后续实际位图使用同一套参数；配置指定
	// 分辨率时不能继续把客户端原始请求尺寸写回能力集。
	demandCore := *s.core
	demandCore.desktopWidth = uint16(s.desktopW)
	demandCore.desktopHeight = uint16(s.desktopH)
	pdu := buildDemandActive(s.shareID, s.userChannel, &demandCore, s.bpp)
	if s.standardSec {
		pdu = s.crypto.encryptPDU(secEncrypt, pdu)
	}
	logger.Log.Debugf("[rdp] 发送 Demand Active：色深=%d 分辨率=%dx%d 通道=%v",
		s.bpp, s.desktopW, s.desktopH, s.channels)
	s.tracef("send demand-active %x", headOf(pdu, 40))
	return s.sendMCS(mcsGlobalChannelID, pdu)
}

// negotiate X.224 协商：决定标准 RDP 安全 / TLS / NLA，并在 TLS 之上跑 CredSSP
func (s *rdpSession) negotiate(ctx context.Context) error {
	s.stage = "negotiating"
	_ = s.conn.SetReadDeadline(time.Now().Add(phaseTimeout))
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(s.conn, hdr); err != nil {
		return err
	}
	if hdr[0] != tpktVersion {
		return errors.New("rdp: 首个报文不是 TPKT")
	}
	total := int(binary.BigEndian.Uint16(hdr[2:]))
	if total < 11 || total > 8192 {
		return fmt.Errorf("rdp: 协商报文长度异常 %d", total)
	}
	body := make([]byte, total-4)
	if _, err := io.ReadFull(s.conn, body); err != nil {
		return err
	}
	req, err := parseX224ConnReq(body)
	if err != nil {
		return err
	}

	s.requestedProtocols = req.requestedProtocols
	if !req.hasNegotiation {
		s.requestedProtocols = 0
	}
	selected, failCode := s.selectProtocol(req)
	if failCode != 0 {
		_, _ = s.conn.Write(buildTPKT(buildX224NegFailure(failCode)))
		return fmt.Errorf("rdp: 拒绝了客户端请求的协议（code=%d, requested=0x%x）", failCode, req.requestedProtocols)
	}
	s.negotiated = selected
	if _, err := s.conn.Write(buildTPKT(buildX224ConnConfirm(selected))); err != nil {
		return err
	}
	mode := map[uint32]string{protoRDP: "rdp", protoSSL: "tls", protoHybrid: "hybrid"}[selected]
	details := map[string]interface{}{
		"requested_protocols": fmt.Sprintf("0x%08x", req.requestedProtocols),
		"selected_protocol":   mode,
	}
	if req.cookie != "" {
		// 扫描器/工具常带 mstshash=用户名 这类 cookie
		details["cookie"] = req.cookie
	}
	s.push("rdp-negotiation", details)
	logger.Log.Debugf("[rdp] %s 协商: requested=0x%x selected=%s cookie=%q",
		s.srcIP(), req.requestedProtocols, mode, req.cookie)

	s.rw = s.conn
	if selected == protoSSL || selected == protoHybrid {
		tlsConn := tls.Server(s.conn, tlsServerConfig(s.tlsPair))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("rdp: TLS 握手失败: %w", err)
		}
		s.stage = "tls-handshake-ok"
		s.rw = tlsConn
		s.br = bufio.NewReaderSize(tlsConn, 8192)
		if selected == protoHybrid {
			// CredSSP 抓完凭据必然失败（我们没有口令），这条连接到此为止
			if err := s.credSSP(ctx); err != nil {
				s.push("rdp-disconnect", map[string]interface{}{"stage": "nla", "reason": err.Error()})
				return err
			}
		}
	} else {
		s.standardSec = true
		s.br = bufio.NewReaderSize(s.conn, 8192)
	}
	s.reader = &packetReader{br: s.br}
	_ = s.conn.SetReadDeadline(time.Time{})
	return nil
}

// selectProtocol 依据配置与客户端请求的协议位选一个；返回 (协议, 失败码)
func (s *rdpSession) selectProtocol(req *x224ConnReq) (uint32, uint32) {
	rp := req.requestedProtocols
	if !req.hasNegotiation {
		rp = 0
	}
	switch s.cfg.Security {
	case secModeRDP:
		return protoRDP, 0
	case secModeTLS:
		if rp&protoSSL != 0 {
			return protoSSL, 0
		}
		return 0, negFailSSLRequiredByServer
	case secModeHybrid:
		if rp&protoHybrid != 0 {
			return protoHybrid, 0
		}
		return 0, negFailHybridRequiredByServer
	default: // negotiate：优先 NLA，其次 TLS，最后标准安全
		if rp&protoHybrid != 0 {
			return protoHybrid, 0
		}
		if rp&protoSSL != 0 {
			return protoSSL, 0
		}
		return protoRDP, 0
	}
}

// ---------------------------------------------------------------------------
// MCS：Connect Initial/Response + Erect Domain / Attach User / Channel Join
// ---------------------------------------------------------------------------

func (s *rdpSession) nextPacket(timeout time.Duration) (int, byte, []byte, error) {
	if timeout > 0 {
		_ = s.conn.SetReadDeadline(time.Now().Add(timeout))
	} else {
		_ = s.conn.SetReadDeadline(time.Time{})
	}
	return s.reader.next()
}

// readSendData 一直读到一条 MCS Send Data Request（期间把该应答的 MCS 请求应答掉）
func (s *rdpSession) readSendData(timeout time.Duration) (*mcsSendData, error) {
	for {
		kind, _, payload, err := s.nextPacket(timeout)
		if err != nil {
			return nil, err
		}
		if kind != packetTPKT {
			continue // 握手阶段不该有快速路径报文，忽略
		}
		data, err := stripX224Data(payload)
		if err != nil {
			continue
		}
		op, err := mcsPDUType(data)
		if err != nil {
			return nil, err
		}
		s.tracef("recv op=%d pdu=%x", op, headOf(data, 40))
		switch op {
		case mcsErectDomainRequest:
			// 无需应答
			s.stage = "mcs:erect-domain"
		case mcsAttachUserRequest:
			if err := s.sendMCSAttachConfirm(); err != nil {
				return nil, err
			}
			s.stage = "mcs:attach-confirm-sent"
		case mcsChannelJoinRequest:
			if err := s.sendMCSJoinConfirm(data); err != nil {
				return nil, err
			}
			s.stage = "mcs:join-confirm-sent"
		case mcsSendDataRequest:
			s.stage = "mcs:client-info"
			return parseMCSSendData(data)
		case mcsDisconnectUltimatum:
			return nil, errors.New("rdp: 客户端发送 MCS 断开通知")
		}
	}
}

func (s *rdpSession) sendMCSAttachConfirm() error {
	// result=0，initiator=1（用户通道 = 1001 + initiator）
	// choice 字节 = (PDU<<2) | options，Attach User Confirm 的 options=2 → 0x2E。
	// 写成 0x2C 会被 mstsc 拒（xfreerdp 用 choice>>2 忽略低 2 位故能连）。
	out := buildTPKT(buildX224Data([]byte{(mcsAttachUserConfirm << 2) | 2, 0x00, 0x00, byte(s.mcsInit)}))
	s.tracef("send attach-confirm %x", headOf(out, 16))
	_, err := s.rw.Write(out)
	return err
}

func (s *rdpSession) sendMCSJoinConfirm(req []byte) error {
	r := newPktReader(req)
	if _, err := r.u8(); err != nil {
		return err
	}
	initiator, err := r.u16be()
	if err != nil {
		return err
	}
	requested, err := r.u16be()
	if err != nil {
		return err
	}
	// result=0，initiator/requested 原样回，channelId = 请求的通道
	// choice 字节 = (PDU<<2) | options，Channel Join Confirm 的 options=2 → 0x3E。
	payload := []byte{(mcsChannelJoinConfirm << 2) | 2, 0x00,
		byte(initiator >> 8), byte(initiator),
		byte(requested >> 8), byte(requested),
		byte(requested >> 8), byte(requested)}
	out := buildTPKT(buildX224Data(payload))
	s.tracef("send join-confirm chan=%d pdu=%x", requested, headOf(out, 16))
	_, err = s.rw.Write(out)
	return err
}

// mcsConnect 解析 Connect Initial、回 Connect Response，并处理随后的通道请求；
// 返回第一条 Send Data Request（安全交换或 Client Info）。
func (s *rdpSession) mcsConnect() (*mcsSendData, error) {
	s.stage = "mcs:waiting-connect-initial"
	kind, _, payload, err := s.nextPacket(phaseTimeout)
	if err != nil {
		return nil, err
	}
	if kind != packetTPKT {
		return nil, errors.New("rdp: Connect Initial 不是 TPKT")
	}
	data, err := stripX224Data(payload)
	if err != nil {
		return nil, err
	}
	userData, err := parseConnectInitialUserData(data)
	if err != nil {
		return nil, err
	}
	// 去掉 T.125 ConferenceCreateRequest 的 PER 前缀，剩下的才是 GCC 各数据块
	core, netw, encMethods, _ := parseGCCUserData(splitConferenceCreate(userData, h221KeyClient))
	s.core = core
	s.clientName = core.clientName
	s.channels = netw.channelNames
	s.mcsTrace = append(s.mcsTrace, fmt.Sprintf("client-channels(%d)=%v assigned=%v", len(netw.channelNames), netw.channelNames, s.channelIDs))

	// 为客户端请求的每条虚拟通道分配 MCS 通道号（从 1004 起）
	s.channelIDs = make([]uint16, len(netw.channelNames))
	for i := range s.channelIDs {
		s.channelIDs[i] = uint16(1004 + i)
	}

	sec := &securityData{}
	if s.standardSec {
		sec.encryptionMethod = pickEncryptionMethod(encMethods)
		sec.encryptionLevel = 2 // ENCRYPTION_LEVEL_CLIENT_COMPATIBLE
		sec.serverRandom = randomBytes(32)
		sec.certificate = buildProprietaryCert(s.rdpKey)
		s.serverRandom = sec.serverRandom
		s.crypto = &rdpCrypto{}
	}

	resp := buildConnectResponse(buildServerGCC(s.requestedProtocols, s.channelIDs, sec, s.cfg.Hostname))
	logger.Log.Debugf("[rdp] Connect Response %d 字节: %x", len(resp), headOf(resp, 32))
	s.mcsTrace = append(s.mcsTrace, fmt.Sprintf("connect-response: %x", headOf(resp, 160)))
	if _, err := s.rw.Write(buildTPKT(buildX224Data(resp))); err != nil {
		return nil, err
	}
	s.stage = "mcs:connect-response-sent"
	logger.Log.Debugf("[rdp] %s 客户端=%q 分辨率=%dx%d 色深=%d 通道=%v",
		s.srcIP(), core.clientName, core.desktopWidth, core.desktopHeight, core.highColorDepth, netw.channelNames)

	return s.readSendData(phaseTimeout)
}

// pickEncryptionMethod 声明 128 位密钥（现代客户端都支持；40/56 位需要截断密钥，本服务不实现）
func pickEncryptionMethod(clientMethods uint32) uint32 {
	const flag128 = 0x00000002
	_ = clientMethods
	return flag128
}

// ---------------------------------------------------------------------------
// 安全交换与 Client Info
// ---------------------------------------------------------------------------

// securityExchange 解出 client random 并派生 RC4 密钥（仅标准 RDP 安全需要）
func (s *rdpSession) securityExchange(pending *mcsSendData) (*mcsSendData, error) {
	if pending == nil {
		var err error
		if pending, err = s.readSendData(phaseTimeout); err != nil {
			return nil, err
		}
	}
	flags, payload, _ := s.splitSecurity(pending.data)
	if flags&secExchangePkt == 0 {
		// 不是安全交换报文（少数客户端直接用 Client Info 开头），原样留给下一阶段
		return pending, nil
	}
	r := newPktReader(payload)
	ln, err := r.u32le()
	if err != nil || ln < 8 {
		return nil, errors.New("rdp: 安全交换报文长度非法")
	}
	enc, err := r.bytes(int(ln) - 8)
	if err != nil {
		return nil, err
	}
	cr := s.decryptClientRandom(enc)
	s.clientRandom = cr
	s.crypto.macKey, s.crypto.encryptKey, s.crypto.decryptKey = deriveStandardKeys(cr, s.serverRandom)
	if s.crypto.macKey == nil {
		return nil, errors.New("rdp: 派生会话密钥失败")
	}
	logger.Log.Debugf("[rdp] 已完成客户端随机数交换，会话密钥就绪")
	return s.readSendData(phaseTimeout)
}

// splitSecurity 拆掉 TS_SECURITY_HEADER（标准安全下必带；TLS 下按规范不带，做兼容处理）
func (s *rdpSession) splitSecurity(raw []byte) (uint16, []byte, bool) {
	if !s.standardSec {
		if len(raw) >= 4 {
			flags := binary.LittleEndian.Uint16(raw)
			if flags&(secInfoPkt|secLicensePkt|secExchangePkt) != 0 {
				return flags, raw[4:], true
			}
		}
		return 0, raw, false
	}
	if s.crypto == nil || len(raw) < 4 {
		return 0, raw, false
	}
	flags, data := s.crypto.decryptPDU(raw)
	return flags, data, true
}

// clientInfoPhase 抓 Client Info（域/用户名/口令）
//
// 时序上这条报文一定紧跟在安全交换之后：标准 RDP 安全带 INFO_PKT 安全头，
// TLS/NLA 下按规范不带安全头（部分客户端仍会带，这里两种都兼容）。
func (s *rdpSession) clientInfoPhase(pending *mcsSendData) (*mcsSendData, error) {
	if pending == nil {
		var err error
		if pending, err = s.readSendData(phaseTimeout); err != nil {
			return nil, err
		}
	}
	flags, body, _ := s.splitSecurity(pending.data)
	if flags&secLicensePkt != 0 || looksLikeLicense(body) {
		return pending, nil // 客户端直接进许可阶段，交给下一阶段
	}

	ci := s.parseClientInfo(body)
	s.loginUser = ci.user
	details := map[string]interface{}{
		"auth":            "client-info",
		"client_name":     s.clientName,
		"domain":          ci.domain,
		"user":            ci.user,
		"password_source": ci.decodedBy,
		"desktop":         fmt.Sprintf("%dx%d", s.core.desktopWidth, s.core.desktopHeight),
		"kbd_layout":      fmt.Sprintf("0x%04x", s.core.kbdLayout),
	}
	if s.cfg.LogPassword {
		details["password"] = ci.password
	}
	s.push("rdp-login", details)
	if ci.user != "" || ci.password != "" {
		logger.Log.Infof("[rdp] %s 凭据: %s\\%s 口令=%q(%s)",
			s.srcIP(), ci.domain, ci.user, ci.password, ci.decodedBy)
	}
	// Client Info 之后客户端就在等服务端的许可 PDU，这里不能再等它的下一条报文
	return nil, nil
}

// looksLikeLicense 判断是否为许可报文（bMsgType=0x01/0x13，flags=0x03）
func looksLikeLicense(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	if b[1] != 0x03 {
		return false
	}
	switch b[0] {
	case 0x01, 0x02, 0x13, 0x15, 0xFF:
		return true
	}
	return false
}

// licensingPhase 主动回一个"客户端有效"的许可错误，跳过整套许可流程。
//
// 注意两点（都来自 FreeRDP 客户端的实际行为）：
//  1. 客户端在 LICENSING 状态是**等服务端先发**（license_recv），不先发请求；
//  2. 无论是否走标准 RDP 安全，许可 PDU 都必须带 TS_SECURITY_HEADER（SEC_LICENSE_PKT），
//     否则客户端会把许可前导当作安全头读掉，然后解析失败。
func (s *rdpSession) licensingPhase(pending *mcsSendData) error {
	_ = pending
	// ERROR_ALERT：bMsgType=FF, flags=03, wMsgSize=0x000C,
	// dwErrorCode=STATUS_VALID_CLIENT(7), dwStateTransition=ST_NO_TRANSITION(2),
	// bbErrorInfo：type=BB_ERROR_BLOB(4), length=0
	// wMsgSize 是"含 4 字节 LICENSE_PREAMBLE 在内的整包长度"（MS-RDPBCGR 4.1.11 官方实例：
	// ff 03 10 00 07 00 00 00 02 00 00 00 04 00 00 00），写成 0x0C 会让 mstsc 错位解析而断开。
	lic := []byte{
		0xFF, 0x03, 0x10, 0x00,
		0x07, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00,
		0x04, 0x00, 0x00, 0x00,
	}
	// 标准安全下许可报文不加密（encryptionLevel=CLIENT_COMPATIBLE），只带安全头
	out := append([]byte{byte(secLicensePkt), 0x00, 0x00, 0x00}, lic...)
	s.tracef("send license-alert %x", out)
	return s.sendMCS(mcsGlobalChannelID, out)
}

// ---------------------------------------------------------------------------
// 发送
// ---------------------------------------------------------------------------

func (s *rdpSession) sendMCS(channelID uint16, data []byte) error {
	msg := buildTPKT(buildX224Data(buildMCSSendData(s.mcsInit, channelID, data)))
	s.tracef("send mcs chan=%d len=%d full=%x", channelID, len(msg), headOf(msg, 48))
	_ = s.conn.SetWriteDeadline(time.Now().Add(phaseTimeout))
	_, err := s.rw.Write(msg)
	_ = s.conn.SetWriteDeadline(time.Time{})
	return err
}

// sendShare 发送共享控制 PDU；标准安全下自动加密
func (s *rdpSession) sendShare(pdu []byte) error {
	if s.standardSec {
		return s.sendMCS(mcsGlobalChannelID, s.crypto.encryptPDU(secEncrypt, pdu))
	}
	return s.sendMCS(mcsGlobalChannelID, pdu)
}

func stripX224Data(b []byte) ([]byte, error) {
	if len(b) < 3 {
		return nil, errShortPkt
	}
	if b[1] != x224Data {
		return nil, errors.New("rdp: 不是 X.224 Data 报文")
	}
	return b[3:], nil
}

// ---------------------------------------------------------------------------
// 会话主循环
// ---------------------------------------------------------------------------

type incoming struct {
	kind    int
	secFlag byte
	payload []byte
}

func (s *rdpSession) loop(ctx context.Context) {
	// mcsConnect/readSendData 为握手设过 phaseTimeout。net.Conn 的 deadline 是
	// 连接级状态，若不清除会在会话建立约 30 秒后让 reader.next 返回 i/o timeout，
	// mstsc 对应显示“无法连接”(0x904/0x7)，而不是正常的 idle timeout。
	_ = s.conn.SetReadDeadline(time.Time{})
	defer func() {
		if s.fontMapTimer != nil {
			s.fontMapTimer.Stop()
		}
	}()
	timeout := defaultIdleTimeout
	if s.cfg.IdleTimeoutSeconds > 0 {
		timeout = time.Duration(s.cfg.IdleTimeoutSeconds) * time.Second
	}
	pkts := make(chan incoming, 16)
	errCh := make(chan error, 1)
	go func() {
		for {
			kind, secFlag, payload, err := s.reader.next()
			if err != nil {
				errCh <- err
				return
			}
			select {
			case pkts <- incoming{kind, secFlag, payload}:
			case <-ctx.Done():
				return
			}
		}
	}()

	idle := time.NewTimer(timeout)
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case err := <-errCh:
			s.flushTyping()
			s.push("rdp-disconnect", map[string]interface{}{"stage": "session", "reason": err.Error(), "mcs_trace": s.mcsTrace})
			return
		case <-idle.C:
			logger.Log.Debugf("[rdp] %s 空闲超时，断开", s.srcIP())
			s.flushTyping()
			_ = s.conn.Close()
			return
		case <-s.fontMapTimerChan():
			// 部分 mstsc 组合在收到了 Granted Control 后不发 Font List，但也不把
			// 连接视为失败；短暂等待后做兼容收尾，避免会话永久黑屏。正常客户端
			// 会先走 Font List 分支，届时 timer 已被停止。
			s.fontMapTimer = nil
			logger.Log.Debugf("[rdp] Font List 未到，使用兼容收尾")
			s.finishFinalization()
		case p := <-pkts:
			idle.Reset(timeout)
			if p.kind == packetFastPath {
				s.tracef("recv fastpath %x", headOf(p.payload, 24))
				s.handleFastPathInput(p.payload)
				continue
			}
			data, err := stripX224Data(p.payload)
			if err != nil {
				continue
			}
			mcs, err := parseMCSSendData(data)
			if err != nil {
				continue
			}
			s.handleSendData(mcs)
		}
	}
}

func (s *rdpSession) fontMapTimerChan() <-chan time.Time {
	if s.fontMapTimer == nil {
		return nil
	}
	return s.fontMapTimer.C
}

// isShareControl 判断一段载荷是否以共享控制头开头（低 4 位是 PDU 类型，高 4 位是版本）
func isShareControl(b []byte) bool {
	if len(b) < 6 {
		return false
	}
	switch binary.LittleEndian.Uint16(b[2:]) & 0x000f {
	case pduTypeDemandActive, pduTypeConfirmActive, pduTypeDeactivateAll, pduTypeData:
		return true
	}
	return false
}

func (s *rdpSession) handleSendData(mcs *mcsSendData) {
	// 无论是不是全局通道都要走一次解密：标准安全下 RC4 是连续流，
	// 漏掉一条（例如虚拟通道数据）就会让后续所有报文错位。
	var body []byte
	if s.standardSec {
		if _, body = s.crypto.decryptPDU(mcs.data); body == nil {
			return
		}
	} else {
		body = mcs.data
	}
	if mcs.channelID != mcsGlobalChannelID {
		return // 虚拟通道数据（剪贴板/音频等）不处理
	}
	s.tracef("recv mcs chan=%d body=%x", mcs.channelID, headOf(body, 24))
	if len(body) < 6 {
		return
	}
	if !isShareControl(body) {
		// 增强安全下按规范不带 TS_SECURITY_HEADER；个别客户端仍会带，两种都兼容
		if len(body) >= 10 && !looksLikeLicense(body) && isShareControl(body[4:]) {
			body = body[4:]
		} else {
			return
		}
	}
	pduType := binary.LittleEndian.Uint16(body[2:]) & 0x000f
	payload := body[6:]
	switch pduType {
	case pduTypeConfirmActive:
		s.onConfirmActive(payload)
	case pduTypeData:
		s.onDataPDU(payload)
	case pduTypeDeactivateAll:
		logger.Log.Debugf("[rdp] 客户端请求 Deactivate All")
	}
}

func (s *rdpSession) onDataPDU(payload []byte) {
	if len(payload) < 12 {
		return
	}
	switch payload[8] {
	case pduType2Input:
		s.handleInput(parseSlowPathInput(payload[12:]))
	case pduType2FontList:
		// Font Map 必须响应 Font List，且它是连接收尾的最后一个 PDU；只有此后
		// 才允许发送图形输出。此前提前发 Font Map、又在 Client Synchronize 时推图，
		// mstsc 会保持黑屏并以 0x2904 主动断开。
		logger.Log.Debugf("[rdp] 收到客户端 Font List，完成连接收尾并回 Font Map")
		s.finishFinalization()
	case pduType2Control:
		// 客户端会发 Control-Cooperate / Control-RequestControl；
		// 收到 RequestControl 必须回 GrantedControl，否则 mstsc 会静默断开（报"会话即将断开"）。
		if len(payload) >= 14 {
			action := binary.LittleEndian.Uint16(payload[12:])
			s.tracef("recv control action=0x%04x", action)
			if action == ctrlActionRequestControl {
				_ = s.sendShare(buildControlPDU(s.shareID, s.userChannel, ctrlActionGrantedControl))
				if !s.finalized && s.fontMapTimer == nil {
					s.fontMapTimer = time.NewTimer(750 * time.Millisecond)
				}
			}
		}
	case pduType2Synchronize:
		// 客户端 Synchronize 仅是收尾阶段的确认；图形输出必须等 Font List / Font Map
		// 配对完成后再开始（见 pduType2FontList）。
	case pduType2SuppressOutput, pduType2Pointer, pduType2Update:
		// 抑制输出/指针等无需处理
	}
}

// finishFinalization 发送 Font Map 并开启图形输出。正常路径由 Client Font List
// 触发；兼容路径仅在客户端等待片刻后仍未发送 Font List 时触发一次。
func (s *rdpSession) finishFinalization() {
	if s.finalized {
		return
	}
	s.finalized = true
	if s.fontMapTimer != nil {
		s.fontMapTimer.Stop()
		s.fontMapTimer = nil
	}
	_ = s.sendShare(buildFontMapPDU(s.shareID, s.userChannel))
	if s.srvImg != nil {
		s.sendBitmap(s.desktopW, s.desktopH)
	}
}

// onConfirmActive 客户端确认能力，随后服务器发 Synchronize/Control/Font Map + 首帧
func (s *rdpSession) onConfirmActive(payload []byte) {
	ca := parseConfirmActive(payload)
	s.caps = ca
	if ca.shareID != 0 {
		s.shareID = ca.shareID
	}
	s.fastPathOut = ca.fastPathOut

	// 色深和桌面尺寸已由我们先前的 Demand Active 宣告，不能按 Confirm Active
	// 回包再覆盖。mstsc 常回 preferredBPP=32，而本服务宣告的是 24bpp；若在
	// 这里改成 32 就形成“宣告 24 / 实发 32”的不一致，表现为黑屏后 0x2904。
	// 客户端回包仅用于确认它可接受的能力，服务端仍按自己宣告的参数出图。

	logger.Log.Debugf("[rdp] Confirm Active: shareId=0x%x 色深=%d 分辨率=%dx%d fastpath=%v",
		s.shareID, s.bpp, s.desktopW, s.desktopH, s.fastPathOut)

	// 连接收尾严格遵循 MS-RDPBCGR：先响应 Confirm Active 发送 Synchronize 与
	// Cooperate；Granted Control 必须等 Client Request Control，Font Map 必须等
	// Client Font List。Font Map 前发送图形会被 mstsc 判为协议错误。
	_ = s.sendShare(buildSynchronizePDU(s.shareID, s.userChannel, s.userChannel))
	_ = s.sendShare(buildControlPDU(s.shareID, s.userChannel, ctrlActionCooperate))
	// Save Session Info 属于登录信息，需在图形连接收尾前给出；V2 结构已按 Windows
	// 实际报文实现。它不是 Font Map，不能放到 Font Map 之后破坏其“最后一个收尾 PDU”语义。
	_ = s.sendShare(buildSaveSessionInfoPDU(s.shareID, s.userChannel, s.core.clientName, s.loginUser))
	s.push("rdp-session", map[string]interface{}{
		"stage":    "desktop",
		"desktop":  fmt.Sprintf("%dx%d", s.desktopW, s.desktopH),
		"bpp":      s.bpp,
		"fastpath": s.useFastPathBitmap(),
	})
}

// bppMask 客户端 supportedColorDepths 里的位（MS-RDPBCGR 2.2.1.3.2）
var bppMask = map[int]uint16{24: 0x0001, 16: 0x0002, 15: 0x0004, 32: 0x0008}

// sendBitmap 推一帧"静态桌面"——按行切条逐个发送
func (s *rdpSession) sendBitmap(w, h int) {
	if s.srvImg == nil || w <= 0 || h <= 0 {
		return
	}
	if s.bpp == 0 {
		s.bpp = 16
	}
	img := scaleNearest(s.srvImg, w, h)
	useFastPath := s.useFastPathBitmap()
	maxBytes := maxStripBytes
	if useFastPath {
		maxBytes = maxFastPathStripBytes // 快速路径长度字段仅 14 位，条带必须更小
	}
	strips := bitmapStrips(img, s.bpp, maxBytes)
	sent := 0
	for _, bitmap := range strips {
		var err error
		if useFastPath {
			fp := buildFastPathBitmapUpdate(bitmap)
			s.tracef("send fastpath len=%d head=%x", len(fp), headOf(fp, 24))
			_ = s.conn.SetWriteDeadline(time.Now().Add(phaseTimeout))
			_, err = s.rw.Write(fp)
			_ = s.conn.SetWriteDeadline(time.Time{})
		} else {
			// 标准 RDP 安全下走慢路径：避免在 RC4 连续流里再叠一层快速路径加密规则
			err = s.sendShare(buildSlowPathBitmapUpdate(s.shareID, s.userChannel, bitmap))
		}
		if err != nil {
			logger.Log.Debugf("[rdp] 发送位图失败(%d/%d): %v", sent, len(strips), err)
			return
		}
		sent++
	}
	logger.Log.Debugf("[rdp] 桌面已推送：%d 个矩形条带", sent)
	s.tracef("bitmap done: %d/%d strips fastpath=%v", sent, len(strips), useFastPath)
}

// ---------------------------------------------------------------------------
// 输入
// ---------------------------------------------------------------------------

func (s *rdpSession) handleFastPathInput(payload []byte) {
	s.handleInput(parseFastPathInput(payload))
}

func (s *rdpSession) handleInput(events []inputEvent) {
	for _, ev := range events {
		switch ev.messageType {
		case inputEventScanCode:
			ks := s.keyboard.feed(uint8(ev.keyCode), ev.flags&kbdFlagsRelease != 0, ev.flags&kbdFlagsExtended != 0)
			if !ks.isKey {
				continue
			}
			if ks.special != "" || len(s.keyboard.line) >= typedBufferLimit {
				s.flushTyping()
			}
		case inputEventUnicode:
			if ev.flags&kbdFlagsRelease != 0 {
				continue
			}
			s.keyboard.line = append(s.keyboard.line, rune(ev.unicode))
			if len(s.keyboard.line) >= typedBufferLimit {
				s.flushTyping()
			}
		case inputEventMouse:
			if ev.flags&ptrFlagsDown != 0 {
				s.push("rdp-input", map[string]interface{}{
					"mouse": "down",
					"x":     ev.x,
					"y":     ev.y,
				})
			}
		}
	}
}

// flushTyping 把累计的按键落成事件
func (s *rdpSession) flushTyping() {
	txt := s.keyboard.typed()
	if txt == "" {
		return
	}
	s.push("rdp-input", map[string]interface{}{"keystrokes": txt})
	logger.Log.Infof("[rdp] %s 输入: %q", s.srcIP(), txt)
	s.keyboard.line = nil
}
