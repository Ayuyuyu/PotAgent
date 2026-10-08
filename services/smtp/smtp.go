package smtp

/*
SMTP 蜜罐服务（TCP，RFC 5321 文本协议）。

低交互策略：
  - 服务端在连接建立时回 220 欢迎语，连接级循环读取命令（行尾 \r\n）。
  - 主要仿真 EHLO/HELO/MAIL/RCPT/DATA/RSET/NOOP/VRFY/QUIT，并支持 AUTH LOGIN/PLAIN
    （不校验口令，永远回 235 成功），把上送的用户名/口令原样落进事件，便于还原爆破攻击链。
  - DATA 完整接收邮件正文（含 dot-stuffing 还原），把 from/to/subject/全文落进 smtp-mail 事件，
    攻击投递的钓鱼/恶意载荷是核心情报。
  - STARTTLS（需配置 cert_file/key_file，或自动生成自签证书）将明文连接升级为 TLS，
    升级后继续同一命令循环；未配置证书时 STARTTLS 回 502。

Serve 被 smtp（明文+STARTTLS，端口 25/587）与 smtps（隐式 TLS，端口 465）两个服务共用，
通过 prefix 区分事件名前缀、allowStartTLS 控制是否响应 STARTTLS。
*/

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"

	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"

	"github.com/rs/xid"
)

// DefaultBanner 为 220 欢迎语中主机名之后的默认内容（取首词作自称主机名）。
const DefaultBanner = "mail ESMTP PotAgent"

var (
	serviceName = "smtp"
	_           = services.Register(serviceName, SmtpServiceInit)
)

// GreetingHost 从 banner 取首词作为 220/EHLO 自称的主机名。
func GreetingHost(banner string) string {
	fields := strings.Fields(banner)
	if len(fields) == 0 {
		return "mail"
	}
	return fields[0]
}

func SmtpServiceInit() services.Service {
	return services.Service{
		WorkerHandle:   smtpHandle,
		ServiceOptions: smtpConfig{},
	}
}

// TLSConfig 是 smtp 与 smtps 共用的配置（banner + 证书）。
// Banner 为 220 欢迎语中主机名之后的内容；留空回退内置默认。
// cert_file/key_file 同时配置时使用文件证书，否则 STARTTLS/smtps 时自动生成自签 RSA2048。
type TLSConfig struct {
	Banner   string `mapstructure:"banner"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

// smtpConfig 与 TLSConfig 同一类型（别名），便于 smtp 自身使用。
type smtpConfig = TLSConfig

// ---- 纯逻辑辅助（可单测，不触碰 socket/事件）----

// ehloResponse 返回 EHLO 的多行能力声明；host 为自称主机名。
func ehloResponse(host string) string {
	var b strings.Builder
	b.WriteString("250-" + host + "\r\n")
	b.WriteString("250-AUTH LOGIN PLAIN\r\n")
	b.WriteString("250-STARTTLS\r\n")
	b.WriteString("250-PIPELINING\r\n")
	b.WriteString("250-8BITMIME\r\n")
	b.WriteString("250 OK\r\n")
	return b.String()
}

// decodeB64Safe 解码 base64，失败返回原串（容错，便于还原攻击链）。
func decodeB64Safe(s string) string {
	if s == "" {
		return ""
	}
	if dec, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(dec)
	}
	return s
}

// parseAddr 从 MAIL FROM:/RCPT TO: 的参数里提取 <...> 之间的地址；无尖括号时回退整段去空格。
func parseAddr(s string) string {
	// 去掉前导 "FROM:" / "TO:" 等关键字（取首个冒号之后）
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "<"); i >= 0 {
		if j := strings.Index(s[i:], ">"); j >= 0 {
			return s[i+1 : i+j]
		}
	}
	return s
}

// authPlainCreds 从 AUTH PLAIN 的 base64 解码出 user/pass。
// 编码为 [\0authz\0user\0pass]；常见为 3 段（取 1=user,2=pass）或 2 段（取 0,1）。
func authPlainCreds(b64 string) (user, pass string) {
	dec := decodeB64Safe(b64)
	parts := strings.Split(dec, "\x00")
	switch len(parts) {
	case 3:
		return parts[1], parts[2]
	case 2:
		return parts[0], parts[1]
	default:
		// 退化：把整串当 user
		return dec, ""
	}
}

// extractHeaderField 从邮件原文中提取指定首部字段的值（大小写不敏感）。
// 仅扫描头部区（第一个空行之前），去除首尾空白。
func extractHeaderField(data, name string) string {
	name = strings.ToLower(name) + ":"
	lines := strings.Split(data, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r")
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), name) {
			// 处理折叠首部（续行以空格/制表符开头）
			val := strings.TrimSpace(line[len(name):])
			for i+1 < len(lines) {
				next := strings.TrimRight(lines[i+1], "\r")
				if next == "" || (next[0] != ' ' && next[0] != '\t') {
					break
				}
				val += " " + strings.TrimSpace(next)
				i++
			}
			return val
		}
	}
	return ""
}

// ---- 连接处理 ----

func smtpHandle(ctx context.Context, service *services.Service) {
	baseOptions := service.BaseOptions
	address := fmt.Sprintf("%v:%v", baseOptions.Host, baseOptions.Port)
	listen, err := net.Listen("tcp4", address)
	if err != nil {
		logger.Log.Fatalln(err)
	}
	defer listen.Close()
	logger.Log.Info(baseOptions.Application, " listen on ", address)

	connChan := common.ForwardListenerToChan(listen)
	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", serviceName)
			return
		case conn := <-connChan:
			go Serve(conn, service, serviceName, true)
		}
	}
}

// Serve 运行一个 SMTP 会话。conn 为已建立的连接（明文或已 TLS）；
// prefix 为事件名前缀（"smtp"/"smtps"）；allowStartTLS 控制是否响应 STARTTLS。
func Serve(conn net.Conn, service *services.Service, prefix string, allowStartTLS bool) {
	defer conn.Close()
	id := xid.New()
	baseOptions := service.BaseOptions
	cfg := service.ServiceOptions.(TLSConfig)
	banner := cfg.Banner
	if banner == "" {
		banner = DefaultBanner
	}
	host := GreetingHost(banner)

	srcAddr, err := common.GetConnSrcIPAndSrcPort(&conn)
	if err != nil {
		logger.Log.Error(err)
	}
	dstAddr, err := common.GetConnDstIPAndDstPort(&conn)
	if err != nil {
		logger.Log.Error(err)
	}

	connectDetails := map[string]interface{}{
		"protocol":             baseOptions.Protocol,
		"application":          baseOptions.Application,
		prefix + ".session-id": id.String(),
	}
	event.EventPush(event.NewEvent(prefix, prefix+"-connect", srcAddr, dstAddr, connectDetails))

	pushClose := func() {
		event.EventPush(event.NewEvent(prefix, prefix+"-close", srcAddr, dstAddr, map[string]interface{}{
			"protocol":             baseOptions.Protocol,
			"application":          baseOptions.Application,
			prefix + ".session-id": id.String(),
		}))
	}

	send := func(s string) {
		if _, err := conn.Write([]byte(s)); err != nil {
			logger.Log.Debug(prefix, " write error:", err)
		}
	}

	reader := bufio.NewReader(conn)
	send("220 " + banner + "\r\n")

	// 会话级状态：MAIL FROM / RCPT TO 收集，供 DATA 事件使用
	var mailFrom string
	var rcptTo []string

	for {
		line, err := readLine(reader)
		if err != nil {
			if err != io.EOF {
				logger.Log.Debug(prefix, " read error:", err)
			}
			pushClose()
			return
		}
		if line == "" {
			continue
		}

		// 拆分命令与参数（命令大小写不敏感）
		cmd := line
		rest := ""
		if sp := strings.IndexByte(line, ' '); sp >= 0 {
			cmd = line[:sp]
			rest = strings.TrimSpace(line[sp+1:])
		}
		ucmd := strings.ToUpper(cmd)

		details := map[string]interface{}{
			"protocol":             baseOptions.Protocol,
			"application":          baseOptions.Application,
			prefix + ".session-id": id.String(),
			prefix + ".command":    ucmd,
			prefix + ".args":       line,
		}

		var reply string

		switch ucmd {
		case "EHLO", "HELO":
			if rest != "" {
				details[prefix+".helo_host"] = rest
			}
			if ucmd == "EHLO" {
				reply = ehloResponse(host)
			} else {
				reply = "250 " + host + "\r\n"
			}
		case "MAIL":
			mailFrom = parseAddr(rest)
			details[prefix+".mail_from"] = mailFrom
			reply = "250 2.1.0 Ok\r\n"
		case "RCPT":
			to := parseAddr(rest)
			rcptTo = append(rcptTo, to)
			details[prefix+".rcpt_to"] = to
			reply = "250 2.1.5 Ok\r\n"
		case "DATA":
			reply = "354 End data with <CR><LF>.<CR><LF>\r\n"
			send(reply)
			event.EventPush(event.NewEvent(prefix, prefix+"-command", srcAddr, dstAddr, details))
			body, rerr := readDataBlock(reader)
			if rerr != nil {
				pushClose()
				return
			}
			mailDetails := map[string]interface{}{
				"protocol":             baseOptions.Protocol,
				"application":          baseOptions.Application,
				prefix + ".session-id": id.String(),
				prefix + ".mail_from":  mailFrom,
				prefix + ".rcpt_to":    rcptTo,
				prefix + ".subject":    extractHeaderField(body, "Subject"),
				prefix + ".data":       body,
				prefix + ".data_size":  len(body),
			}
			event.EventPush(event.NewEvent(prefix, prefix+"-mail", srcAddr, dstAddr, mailDetails))
			send("250 2.0.0 Ok: queued as " + id.String() + "\r\n")
			// 重置事务状态
			mailFrom = ""
			rcptTo = nil
			continue
		case "AUTH":
			reply = handleAuth(reader, rest, send, details)
		case "RSET":
			mailFrom = ""
			rcptTo = nil
			reply = "250 2.0.0 Ok\r\n"
		case "NOOP":
			reply = "250 2.0.0 Ok\r\n"
		case "VRFY":
			reply = "252 2.0.0 " + rest + "\r\n"
		case "STARTTLS":
			if !allowStartTLS {
				reply = "502 5.5.1 Error: command not implemented\r\n"
				break
			}
			cert, cerr := common.LoadOrGenCert(cfg.CertFile, cfg.KeyFile, host)
			if cerr != nil {
				logger.Log.Error(prefix, " load cert error:", cerr)
				reply = "454 4.7.0 TLS not available due to temporary reason\r\n"
				break
			}
			send("220 2.0.0 Go ahead\r\n")
			event.EventPush(event.NewEvent(prefix, prefix+"-command", srcAddr, dstAddr, details))
			// 桥接 bufio 已预读的握手字节，避免 ClientHello 丢失
			bridge := &preReadConn{Conn: conn, buf: &bytes.Buffer{}}
			if reader.Buffered() > 0 {
				tmp := make([]byte, reader.Buffered())
				n, _ := reader.Read(tmp)
				bridge.buf.Write(tmp[:n])
			}
			tlsConn := tls.Server(bridge, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			if herr := tlsConn.Handshake(); herr != nil {
				logger.Log.Debug(prefix, " STARTTLS handshake error:", herr)
				pushClose()
				return
			}
			conn = tlsConn
			reader = bufio.NewReader(tlsConn)
			continue
		case "QUIT":
			send("221 2.0.0 Bye\r\n")
			event.EventPush(event.NewEvent(prefix, prefix+"-command", srcAddr, dstAddr, details))
			pushClose()
			return
		default:
			reply = "500 5.5.2 Error: command not recognized\r\n"
		}

		send(reply)
		event.EventPush(event.NewEvent(prefix, prefix+"-command", srcAddr, dstAddr, details))
	}
}

// preReadConn 在明文连接升级为 TLS 时作为桥梁：把 bufio 已预读进缓冲区的
// 后续字节（TLS ClientHello）先吐出，再读真正的底层连接，避免握手字节丢失。
type preReadConn struct {
	net.Conn
	buf *bytes.Buffer
}

func (p *preReadConn) Read(b []byte) (int, error) {
	if p.buf.Len() > 0 {
		return p.buf.Read(b)
	}
	return p.Conn.Read(b)
}

// readLine 读取到 \n 为止的一行，并去掉末尾的 \r\n。
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readDataBlock 读取 DATA 正文，直到出现仅含 "." 的行；还原 dot-stuffing（行首 "." 去掉一个）。
func readDataBlock(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		line, err := readLine(r)
		if err != nil {
			return "", err
		}
		if line == "." {
			break
		}
		if strings.HasPrefix(line, ".") {
			line = line[1:]
		}
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	return b.String(), nil
}

// handleAuth 处理 AUTH 交互，把口令相关字段写进 details，返回最终响应。
// 支持 LOGIN（可内联用户名或分步）/ PLAIN（内联或分步），其余方法回 504。
func handleAuth(reader *bufio.Reader, rest string, send func(string), details map[string]interface{}) string {
	parts := strings.Fields(rest)
	method := ""
	if len(parts) > 0 {
		method = strings.ToUpper(parts[0])
	}
	details["smtp.auth_method"] = method

	switch method {
	case "LOGIN":
		var user, pass string
		if len(parts) >= 2 {
			user = decodeB64Safe(parts[1])
		} else {
			send("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")) + "\r\n")
			if l, err := readLine(reader); err == nil {
				user = decodeB64Safe(strings.TrimSpace(l))
			}
		}
		send("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")) + "\r\n")
		if l, err := readLine(reader); err == nil {
			pass = decodeB64Safe(strings.TrimSpace(l))
		}
		details["smtp.username"] = user
		details["smtp.password"] = pass
		return "235 2.7.0 Authentication successful\r\n"
	case "PLAIN":
		var b64 string
		if len(parts) >= 2 {
			b64 = parts[1]
		} else {
			send("334 \r\n")
			if l, err := readLine(reader); err == nil {
				b64 = strings.TrimSpace(l)
			}
		}
		user, pass := authPlainCreds(b64)
		details["smtp.username"] = user
		details["smtp.password"] = pass
		return "235 2.7.0 Authentication successful\r\n"
	default:
		return "504 5.5.4 Unrecognized authentication type\r\n"
	}
}
