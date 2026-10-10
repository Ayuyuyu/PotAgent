package sip

/*
SIP 蜜罐服务（UDP 5060，RFC 3261 文本协议）。

低交互策略：
  - 解析请求行（METHOD URI SIP/2.0）与首部（Via/From/To/Contact/Call-ID/CSeq/
    Authorization/User-Agent 等），逐数据报处理。
  - 核心情报是凭证：REGISTER 与 INVITE 一律回 401 + WWW-Authenticate 摘要质询，
    诱导客户端重发带 Authorization 的请求，从而把 Digest 的 username/realm/nonce/
    uri/response 原样落进事件，便于还原 SIP 爆破/SIPVicious 攻击链。
  - OPTIONS 回 200（带 Allow），其余已识别方法回 200，未知方法回 501；
    请求本身无论是否挑战均已落事件。
  - 事件 sip-request 含方法、URI、call-id、from/to（及提取的用户）、contact、via、
    cseq、user-agent、authorization 原文与解析后的摘要字段。
*/

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"

	"github.com/rs/xid"
)

const defaultRealm = "PotAgent"

var (
	serviceName = "sip"
	_           = services.Register(serviceName, SipServiceInit)
)

func SipServiceInit() services.Service {
	return services.Service{
		WorkerHandle:   sipHandle,
		ServiceOptions: sipConfig{},
	}
}

// sipConfig 协议专属配置。Realm 为 401 质询返回的 realm；留空回退内置 defaultRealm。
type sipConfig struct {
	Realm string `mapstructure:"realm"`
}

// sipMsg 解析后的 SIP 请求。
type sipMsg struct {
	Method  string
	URI     string
	Version string
	Headers map[string]string // 键为小写首部名，值为（折叠合并后的）首部值
	Raw     string
}

// addrOf 从 net.Addr 构造 common.Addr。
func addrOf(a net.Addr) common.Addr {
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return common.Addr{}
	}
	pn, _ := strconv.ParseUint(port, 10, 16)
	return common.Addr{IP: host, Port: uint16(pn)}
}

// randomHex 返回 n 字节的十六进制随机串（用于 To tag / nonce）。
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b)
}

// ---- 解析 ----

// parseSIPRequest 解析一段 SIP 请求文本；ok=false 表示首行格式非法。
func parseSIPRequest(data string) (m sipMsg, ok bool) {
	m.Headers = make(map[string]string)
	m.Raw = data
	lines := strings.Split(data, "\n")
	fields := strings.Fields(lines[0])
	if len(fields) < 3 || !strings.HasPrefix(fields[2], "SIP/2.0") {
		return m, false
	}
	m.Method = strings.ToUpper(fields[0])
	m.URI = fields[1]
	m.Version = fields[2]

	// 解析首部，处理折叠行（续行以空格/制表符开头）
	for i := 1; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r")
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			// 折叠到上一个首部
			if i > 1 {
				prev := strings.TrimRight(lines[i-1], "\r")
				if idx := strings.Index(prev, ":"); idx >= 0 {
					name := strings.ToLower(strings.TrimSpace(prev[:idx]))
					m.Headers[name] = m.Headers[name] + " " + strings.TrimSpace(line)
				}
			}
			continue
		}
		if idx := strings.Index(line, ":"); idx >= 0 {
			name := strings.ToLower(strings.TrimSpace(line[:idx]))
			val := strings.TrimSpace(line[idx+1:])
			if _, exists := m.Headers[name]; exists {
				m.Headers[name] += ", " + val
			} else {
				m.Headers[name] = val
			}
		}
	}
	return m, true
}

// extractSipUser 从 sip URI（如 "Disp" <sip:alice@host> 或 sip:alice@host）提取用户部分。
func extractSipUser(s string) string {
	s = strings.TrimSpace(s)
	// 优先提取尖括号内的 URI（<sip:...>）
	if i := strings.Index(s, "<"); i >= 0 {
		if j := strings.Index(s[i:], ">"); j >= 0 {
			s = s[i+1 : i+j]
		}
	}
	s = strings.TrimPrefix(s, "sip:")
	s = strings.TrimPrefix(s, "sips:")
	// 去掉参数 (;...) 与查询 (?...)
	if i := strings.IndexAny(s, ";?"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "@"); i >= 0 {
		return s[:i]
	}
	return s
}

// parseAuthDigest 解析 Authorization/Proxy-Authorization 的 Digest 参数（key=value，值可带引号）。
func parseAuthDigest(value string) map[string]string {
	out := make(map[string]string)
	value = strings.TrimSpace(value)
	if i := strings.Index(value, " "); i >= 0 {
		if strings.ToLower(value[:i]) != "digest" {
			return out
		}
		value = value[i+1:]
	}
	// 按逗号切分，但值内不含逗号（nonce/response 为 hex）
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(part[:eq]))
		v := strings.TrimSpace(part[eq+1:])
		v = strings.Trim(v, `"`)
		out[k] = v
	}
	return out
}

// ---- 响应构造 ----

// headerVal 取请求首部（小写名），缺失返回默认。
func (m sipMsg) header(name, def string) string {
	if v, ok := m.Headers[name]; ok {
		return v
	}
	return def
}

// toHeaderWithTag 回显 To 首部，若无 tag 则补一个随机 tag。
func toHeaderWithTag(to string) string {
	if strings.Contains(strings.ToLower(to), "tag=") {
		return to
	}
	return to + ";tag=" + randomHex(8)
}

// buildResponse 构造 SIP 响应；status=200 或 401。realm 用于 401 质询。
func buildResponse(m sipMsg, status int, realm string) string {
	statusText := map[int]string{
		200: "OK",
		400: "Bad Request",
		401: "Unauthorized",
		501: "Not Implemented",
	}
	text := statusText[status]
	if text == "" {
		text = "OK"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "SIP/2.0 %d %s\r\n", status, text)
	b.WriteString("Via: " + m.header("via", "SIP/2.0/UDP 0.0.0.0") + "\r\n")
	b.WriteString("From: " + m.header("from", "<sip:anonymous@anonymous.invalid>") + "\r\n")
	b.WriteString("To: " + toHeaderWithTag(m.header("to", "<sip:anonymous@anonymous.invalid>")) + "\r\n")
	b.WriteString("Call-ID: " + m.header("call-id", "00000000@potagent") + "\r\n")
	b.WriteString("CSeq: " + m.header("cseq", "1 UNKNOWN") + "\r\n")
	b.WriteString("Server: PotAgent\r\n")
	if status == 200 {
		b.WriteString("Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE, REGISTER\r\n")
	}
	if status == 401 {
		b.WriteString("WWW-Authenticate: Digest realm=\"" + realm + "\", nonce=\"" + randomHex(16) + "\", algorithm=MD5\r\n")
	}
	b.WriteString("Content-Length: 0\r\n")
	b.WriteString("\r\n")
	return b.String()
}

// ---- 连接处理 ----

func sipHandle(ctx context.Context, service *services.Service) {
	baseOptions := service.BaseOptions
	address := fmt.Sprintf("%v:%v", baseOptions.Host, baseOptions.Port)
	udpAddr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		logger.Log.Fatalln(err)
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		logger.Log.Fatalln(err)
	}
	defer conn.Close()
	logger.Log.Info(baseOptions.Application, " listen on ", address)

	packetChan := common.ForwardUDPPacketToChan(conn)
	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", serviceName)
			return
		case p := <-packetChan:
			go handlePacket(p, service)
		}
	}
}

func handlePacket(p *common.DummyUDPConn, service *services.Service) {
	id := xid.New()
	baseOptions := service.BaseOptions
	cfg := service.ServiceOptions.(sipConfig)
	realm := cfg.Realm
	if realm == "" {
		realm = defaultRealm
	}

	srcAddr := addrOf(p.UDPAddr)
	dstAddr := addrOf(p.UDPConn.LocalAddr())

	msg, ok := parseSIPRequest(string(p.Data))

	details := map[string]interface{}{
		"ip_protocol":      "udp",
		"protocol":         baseOptions.Protocol,
		"application":      baseOptions.Application,
		"sip.session-id":   id.String(),
		"sip.method":       msg.Method,
		"sip.uri":          msg.URI,
		"sip.call_id":      msg.header("call-id", ""),
		"sip.from":         msg.header("from", ""),
		"sip.to":           msg.header("to", ""),
		"sip.contact":      msg.header("contact", ""),
		"sip.via":          msg.header("via", ""),
		"sip.cseq":         msg.header("cseq", ""),
		"sip.user_agent":   msg.header("user-agent", ""),
		"sip.max_forwards": msg.header("max-forwards", ""),
	}
	if ok {
		details["sip.from_user"] = extractSipUser(msg.header("from", ""))
		details["sip.to_user"] = extractSipUser(msg.header("to", ""))
		if auth := msg.header("authorization", ""); auth != "" {
			details["sip.authorization"] = auth
			for k, v := range parseAuthDigest(auth) {
				details["sip.auth_"+k] = v
			}
		}
	} else {
		details["sip.raw"] = msg.Raw
	}

	event.EventPush(event.NewEvent(serviceName, "sip-request", srcAddr, dstAddr, details))

	// 构造响应
	var resp string
	switch msg.Method {
	case "OPTIONS":
		resp = buildResponse(msg, 200, realm)
	case "REGISTER", "INVITE":
		// 401 摘要质询以捕获凭证
		resp = buildResponse(msg, 401, realm)
	case "BYE", "CANCEL", "ACK", "SUBSCRIBE", "NOTIFY", "MESSAGE", "INFO",
		"REFER", "PRACK", "PUBLISH":
		resp = buildResponse(msg, 200, realm)
	default:
		if ok {
			resp = buildResponse(msg, 501, realm)
		} else {
			resp = buildResponse(msg, 400, realm)
		}
	}

	if _, err := p.WriteToUDP([]byte(resp), p.UDPAddr); err != nil {
		logger.Log.Debug("sip write error:", err)
	}
}
