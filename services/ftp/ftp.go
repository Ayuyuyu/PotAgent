package ftp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"

	"github.com/rs/xid"
)

// 同时注册 "ftp" 与 "ftps" 两个协议键：二者共用同一套实现，
// 具体是明文 FTP、显式 FTPS（AUTH TLS）还是隐式 FTPS（连接即 TLS），
// 由 yaml 的 mode 字段决定。
var (
	_ = services.Register("ftp", FTPServiceInit)
	_ = services.Register("ftps", FTPServiceInit)
)

func FTPServiceInit() services.Service {
	return services.Service{
		WorkerHandle:   ftpHandle,
		ServiceOptions: ftpConfig{},
	}
}

type account struct {
	Username string `mapstructure:"username" yaml:"username"`
	Password string `mapstructure:"password" yaml:"password"`
}

type ftpConfig struct {
	// mode: ""/ftp = 明文 FTP；"ftps" = 显式 FTPS（AUTH TLS 升级）；"ftps-implicit" = 连接即 TLS（端口通常 990）
	Mode string `mapstructure:"mode" yaml:"mode"`
	// 欢迎横幅（连接后首行 220）
	Banner string `mapstructure:"banner" yaml:"banner"`
	// 出现在 SYST / FEAT 里的系统名
	Hostname string `mapstructure:"hostname" yaml:"hostname"`
	// 登录成功后给的提示
	Welcome string `mapstructure:"welcome" yaml:"welcome"`
	// 允许登录的账号；为空则接受任意账号口令（蜜罐默认行为，全部落日志）
	Accounts []account `mapstructure:"accounts"`
	// FTPS 证书；留空自动生成 2048 位自签 RSA
	CertFile string `mapstructure:"cert_file" yaml:"cert_file"`
	KeyFile  string `mapstructure:"key_file" yaml:"key_file"`
	// PASV 响应里回给客户端的 IP；留空则自动探测本机出口 IP（host=0.0.0.0 时很有用）
	PasvAddr string `mapstructure:"pasv_addr" yaml:"pasv_addr"`
	// 空闲超时（秒）
	IdleTimeoutSeconds int `mapstructure:"idle_timeout_seconds" yaml:"idle_timeout_seconds"`
	// 自定义 LIST 目录列表（留空用内置默认）；优先级高于 share_dir
	Listing string `mapstructure:"listing" yaml:"listing"`
	// 共享目录：配置后 LIST 读取本机该目录内容生成列表；留空则用内置默认列表。
	// 相对路径基于程序运行目录（CWD）解析。
	ShareDir string `mapstructure:"share_dir" yaml:"share_dir"`
}

func (c ftpConfig) isTLS() bool {
	return c.Mode == "ftps" || c.Mode == "ftps-implicit"
}
func (c ftpConfig) isImplicit() bool {
	return c.Mode == "ftps-implicit"
}

func ftpHandle(ctx context.Context, service *services.Service) {
	cfg := service.ServiceOptions.(ftpConfig)
	base := service.BaseOptions

	address := fmt.Sprintf("%v:%v", base.Host, base.Port)
	listen, err := net.Listen("tcp4", address)
	if err != nil {
		logger.Log.Fatalln(err)
	}
	defer listen.Close()
	logger.Log.Infof("%s listen on %s (mode=%s)", base.Application, address, modeName(cfg.Mode))

	connChan := common.ForwardListenerToChan(listen)
	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", base.Application)
			return
		case conn := <-connChan:
			go handleServiceConn(conn, service, cfg)
		}
	}
}

func modeName(m string) string {
	switch m {
	case "ftps":
		return "explicit FTPS"
	case "ftps-implicit":
		return "implicit FTPS"
	default:
		return "plain FTP"
	}
}

// preReadConn 在明文连接升级为 TLS 时作为桥梁：把 bufio 已经预读进缓冲区的
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

type ftpSession struct {
	service     *services.Service
	cfg         ftpConfig
	ctl         net.Conn // 当前控制连接（可能被 TLS 包裹）
	br          *bufio.Reader
	bw          *bufio.Writer
	tlsCfg      *tls.Config
	dataProtTLS bool // PROT P 时数据通道也走 TLS
	pasv        net.Listener
	portAddr    string // PORT/EPRT 给出的 host:port
	dataMode    string // "pasv" | "port"
	cat         string
	id          string
	srcAddr     common.Addr
	dstAddr     common.Addr
	user        string
	authed      bool
	cwd         string // 当前工作目录（相对于 share_dir 根，如 "t1" 或 "a/b"；根为 ""）
	rnfr        string // RNFR 暂存的源文件路径，供 RNTO 使用
}

func handleServiceConn(conn net.Conn, service *services.Service, cfg ftpConfig) {
	defer conn.Close()
	id := xid.New().String()
	cat := service.BaseOptions.Protocol

	srcAddr, _ := common.GetConnSrcIPAndSrcPort(&conn)
	dstAddr, _ := common.GetConnDstIPAndDstPort(&conn)

	event.EventPush(event.NewEvent(cat, "ftp-connect", srcAddr, dstAddr, map[string]interface{}{
		"protocol":    service.BaseOptions.Protocol,
		"application": service.BaseOptions.Application,
		"ftp.mode":    cfg.Mode,
		"ftp.session": id,
	}))

	s := &ftpSession{
		service: service,
		cfg:     cfg,
		ctl:     conn,
		br:      bufio.NewReader(conn),
		bw:      bufio.NewWriter(conn),
		cat:     cat,
		id:      id,
		srcAddr: srcAddr,
		dstAddr: dstAddr,
	}

	if cfg.isTLS() {
		pair, err := loadOrGenCert(cfg.CertFile, cfg.KeyFile, firstNonEmpty(cfg.Hostname, "PotAgent-FTP"))
		if err != nil {
			logger.Log.Errorf("%s 加载/生成 FTPS 证书失败: %v", cat, err)
			return
		}
		s.tlsCfg = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
		if cfg.isImplicit() {
			tlsConn := tls.Server(conn, s.tlsCfg)
			if err := tlsConn.Handshake(); err != nil {
				logger.Log.Debugf("%s 隐式 TLS 握手失败: %v", cat, err)
				return
			}
			s.ctl = tlsConn
			s.br = bufio.NewReader(s.ctl)
			s.bw = bufio.NewWriter(s.ctl)
		}
	}

	banner := cfg.Banner
	if banner == "" {
		banner = fmt.Sprintf("220 %s FTP Server ready.\r\n", firstNonEmpty(cfg.Hostname, "PotAgent"))
	} else {
		banner = "220 " + strings.TrimRight(banner, "\r\n") + "\r\n"
	}
	s.sendRaw(banner)

	if cfg.IdleTimeoutSeconds > 0 {
		conn.SetReadDeadline(time.Now().Add(time.Duration(cfg.IdleTimeoutSeconds) * time.Second))
	}

	for {
		line, err := s.br.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		cmd, arg := splitCmd(line)
		event.EventPush(event.NewEvent(cat, "ftp-command", srcAddr, dstAddr, map[string]interface{}{
			"protocol":    service.BaseOptions.Protocol,
			"application": service.BaseOptions.Application,
			"ftp.session": id,
			"ftp.command": line,
		}))
		if s.handle(cmd, arg) {
			break // 会话结束（QUIT 或致命错误）
		}
		if cfg.IdleTimeoutSeconds > 0 {
			conn.SetReadDeadline(time.Now().Add(time.Duration(cfg.IdleTimeoutSeconds) * time.Second))
		}
	}

	if s.pasv != nil {
		s.pasv.Close()
	}
	event.EventPush(event.NewEvent(cat, "ftp-close", srcAddr, dstAddr, map[string]interface{}{
		"protocol":    service.BaseOptions.Protocol,
		"application": service.BaseOptions.Application,
		"ftp.session": id,
	}))
}

// handle 返回 true 表示应当关闭会话。
func (s *ftpSession) handle(cmd, arg string) bool {
	switch cmd {
	case "USER":
		s.user = arg
		s.send("331 User name okay, need password.\r\n")
	case "PASS":
		ok := true
		if len(s.cfg.Accounts) > 0 {
			ok = false
			for _, a := range s.cfg.Accounts {
				if a.Username == "*" || (a.Username == s.user && a.Password == arg) {
					ok = true
					break
				}
			}
		}
		event.EventPush(event.NewEvent(s.cat, "ftp-login", s.srcAddr, s.dstAddr, map[string]interface{}{
			"protocol":     s.service.BaseOptions.Protocol,
			"application":  s.service.BaseOptions.Application,
			"ftp.session":  s.id,
			"ftp.username": s.user,
			"ftp.password": arg,
			"ftp.accepted": ok,
		}))
		if ok {
			s.authed = true
			msg := s.cfg.Welcome
			if msg == "" {
				msg = "User logged in."
			}
			s.send("230 %s\r\n", strings.TrimRight(msg, "\r\n"))
		} else {
			s.send("530 Login incorrect.\r\n")
		}
	case "ACCT":
		s.send("230 Account okay.\r\n")
	case "SYST":
		name := firstNonEmpty(s.cfg.Hostname, "UNIX")
		s.send("215 %s Type: L8\r\n", name)
	case "FEAT":
		s.feat()
	case "OPTS":
		s.send("200 OPTS command successful.\r\n")
	case "PWD", "XPWD":
		s.send("257 \"/%s\" is current directory.\r\n", strings.TrimPrefix(s.cwd, "/"))
	case "CWD", "XCWD":
		s.changeDir(arg)
	case "CDUP":
		s.changeDir("..")
	case "TYPE":
		s.send("200 Type set to %s.\r\n", firstNonEmpty(arg, "A"))
	case "NOOP":
		s.send("200 NOOP command successful.\r\n")
	case "PASV":
		s.openPasv()
	case "EPSV":
		s.openEpsv()
	case "PORT":
		s.setPort(arg)
	case "EPRT":
		s.setEprt(arg)
	case "LIST", "NLST":
		s.transferList(arg)
	case "RETR":
		s.transferRetr(arg)
	case "STOR", "APPE":
		s.transferStor(arg, cmd)
	case "SIZE":
		if path, ok := s.resolveSharePath(arg); ok {
			if fi, e := os.Stat(path); e == nil && !fi.IsDir() {
				s.send("213 %d\r\n", fi.Size())
				break
			}
		}
		s.send("213 %d\r\n", len(dummyFile()))
	case "REST":
		s.send("350 Restarting at %s. Ready to receive file.\r\n", arg)
	case "DELE":
		s.send("250 DELE command successful.\r\n")
		s.logData("delete", arg)
	case "MKD", "XMKD":
		s.send("257 \"%s\" created.\r\n", firstNonEmpty(arg, "/newdir"))
		s.logData("mkdir", arg)
	case "RMD", "XRMD":
		s.send("250 RMD command successful.\r\n")
		s.logData("rmdir", arg)
	case "RNFR":
		s.send("350 File exists, ready for destination.\r\n")
		s.rnfr = arg
	case "RNTO":
		from := s.rnfr
		s.rnfr = ""
		s.send("250 RNTO command successful.\r\n")
		s.logData("rename", from+" -> "+arg)
	case "AUTH":
		s.auth(arg)
	case "PBSZ":
		s.send("200 PBSZ command successful (buffer size 0).\r\n")
	case "PROT":
		if strings.EqualFold(arg, "P") {
			s.dataProtTLS = true
			s.send("200 PROT P successful.\r\n")
		} else {
			s.dataProtTLS = false
			s.send("200 PROT C successful.\r\n")
		}
	case "CCC":
		// 客户端要求把控制通道降级回明文（很少见）
		s.send("200 CCC accepted, control channel now clear.\r\n")
	case "QUIT":
		s.send("221 Goodbye.\r\n")
		return true
	default:
		s.send("500 Unknown command %q.\r\n", cmd)
	}
	return false
}

func (s *ftpSession) feat() {
	var b strings.Builder
	b.WriteString("211-Extensions supported:\r\n")
	b.WriteString(" AUTH TLS\r\n")
	b.WriteString(" AUTH SSL\r\n")
	b.WriteString(" PBSZ\r\n")
	b.WriteString(" PROT\r\n")
	b.WriteString(" EPSV\r\n")
	b.WriteString(" EPRT\r\n")
	b.WriteString(" UTF8\r\n")
	b.WriteString("211 End\r\n")
	s.sendRaw(b.String())
}

func (s *ftpSession) auth(arg string) {
	if !s.cfg.isTLS() {
		s.send("504 AUTH not supported on plain FTP.\r\n")
		return
	}
	if !strings.EqualFold(arg, "TLS") && !strings.EqualFold(arg, "SSL") {
		s.send("504 Unknown AUTH mechanism.\r\n")
		return
	}
	s.sendRaw("234 AUTH TLS OK. Initializing TLS.\r\n")
	if err := s.upgradeControlToTLS(); err != nil {
		logger.Log.Debugf("%s AUTH TLS 升级失败: %v", s.cat, err)
		// 升级失败直接结束会话
		s.ctl.Close()
	}
}

// upgradeControlToTLS 把当前明文控制连接升级为 TLS：把 bufio 已预读的握手字节
// 通过 preReadConn 桥接给 tls.Server，再替换 br/bw。
func (s *ftpSession) upgradeControlToTLS() error {
	bridge := &preReadConn{Conn: s.ctl, buf: &bytes.Buffer{}}
	if s.br.Buffered() > 0 {
		tmp := make([]byte, s.br.Buffered())
		n, _ := s.br.Read(tmp)
		bridge.buf.Write(tmp[:n])
	}
	tlsConn := tls.Server(bridge, s.tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	s.ctl = tlsConn
	s.br = bufio.NewReader(s.ctl)
	s.bw = bufio.NewWriter(s.ctl)
	return nil
}

// openPasv 开一个被动监听，回 227。
func (s *ftpSession) openPasv() {
	if s.pasv != nil {
		s.pasv.Close()
		s.pasv = nil
	}
	listen, err := net.Listen("tcp4", s.pasvHost()+":0")
	if err != nil {
		s.send("425 Can't open passive connection.\r\n")
		return
	}
	s.pasv = listen
	port := listen.Addr().(*net.TCPAddr).Port
	ip := s.pasvHost()
	s.dataMode = "pasv"
	s.sendRaw(pasvReply(ip, port))
}

func (s *ftpSession) openEpsv() {
	if s.pasv != nil {
		s.pasv.Close()
		s.pasv = nil
	}
	listen, err := net.Listen("tcp4", s.pasvHost()+":0")
	if err != nil {
		s.send("425 Can't open passive connection.\r\n")
		return
	}
	s.pasv = listen
	port := listen.Addr().(*net.TCPAddr).Port
	s.dataMode = "pasv"
	s.send("229 Entering Extended Passive Mode (|||%d|).\r\n", port)
}

// setPort 解析 PORT 命令：PORT h1,h2,h3,h4,p1,p2
func (s *ftpSession) setPort(arg string) {
	parts := strings.Split(arg, ",")
	if len(parts) != 6 {
		s.send("501 Syntax error in PORT argument.\r\n")
		return
	}
	ip := strings.Join(parts[:4], ".")
	p1, err1 := strconv.Atoi(parts[4])
	p2, err2 := strconv.Atoi(parts[5])
	if err1 != nil || err2 != nil {
		s.send("501 Syntax error in PORT argument.\r\n")
		return
	}
	s.portAddr = fmt.Sprintf("%s:%d", ip, p1*256+p2)
	s.dataMode = "port"
	s.send("200 PORT command successful.\r\n")
}

// setEprt 解析 EPRT 命令：EPRT |proto|addr|port|
func (s *ftpSession) setEprt(arg string) {
	parts := strings.Split(arg, "|")
	// 形如 |1|192.168.1.1|1025|
	if len(parts) < 4 {
		s.send("501 Syntax error in EPRT argument.\r\n")
		return
	}
	addr := parts[2]
	port, err := strconv.Atoi(parts[3])
	if err != nil {
		s.send("501 Syntax error in EPRT argument.\r\n")
		return
	}
	s.portAddr = fmt.Sprintf("%s:%d", addr, port)
	s.dataMode = "port"
	s.send("200 EPRT command successful.\r\n")
}

// openData 在传输命令触发时建立数据连接。
func (s *ftpSession) openData() (net.Conn, error) {
	switch s.dataMode {
	case "pasv":
		if s.pasv == nil {
			return nil, errors.New("no passive connection")
		}
		lc := s.pasv
		s.pasv = nil
		if tc, ok := lc.(*net.TCPListener); ok {
			tc.SetDeadline(time.Now().Add(30 * time.Second))
		}
		conn, err := lc.Accept()
		lc.Close()
		if err != nil {
			return nil, err
		}
		return s.wrapDataTLS(conn, false)
	case "port":
		if s.portAddr == "" {
			return nil, errors.New("no port address")
		}
		conn, err := net.DialTimeout("tcp4", s.portAddr, 10*time.Second)
		if err != nil {
			return nil, err
		}
		return s.wrapDataTLS(conn, true)
	default:
		return nil, errors.New("no data connection")
	}
}

func (s *ftpSession) wrapDataTLS(conn net.Conn, client bool) (net.Conn, error) {
	if !s.dataProtTLS {
		return conn, nil
	}
	var tlsConn *tls.Conn
	if client {
		tlsConn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	} else {
		tlsConn = tls.Server(conn, s.tlsCfg)
	}
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (s *ftpSession) transferList(arg string) {
	s.send("150 Opening data connection for directory listing.\r\n")
	conn, err := s.openData()
	if err != nil {
		s.send("425 Can't open data connection.\r\n")
		return
	}
	defer conn.Close()
	conn.Write([]byte(s.listing(arg)))
	s.send("226 Transfer complete.\r\n")
	s.logData("list", arg)
}

func (s *ftpSession) transferRetr(arg string) {
	s.send("150 Opening data connection for %s.\r\n", arg)
	conn, err := s.openData()
	if err != nil {
		s.send("425 Can't open data connection.\r\n")
		return
	}
	defer conn.Close()
	// share_dir 内存在该文件则回真实诱饵内容，否则回固定 dummy（兼容未配置 share_dir / 越界）。
	if path, ok := s.resolveSharePath(arg); ok {
		if data, e := os.ReadFile(path); e == nil {
			conn.Write(data)
			s.send("226 Transfer complete.\r\n")
			s.logData("retr", arg)
			return
		}
	}
	conn.Write(dummyFile())
	s.send("226 Transfer complete.\r\n")
	s.logData("retr", arg)
}

// shareRoot 返回 share_dir 的绝对根路径：绝对路径原样返回；相对路径基于进程 CWD（os.Getwd）解析。
func (s *ftpSession) shareRoot() string {
	dir := s.cfg.ShareDir
	if dir == "" {
		return ""
	}
	if filepath.IsAbs(dir) {
		return filepath.Clean(dir)
	}
	wd, err := os.Getwd()
	if err != nil {
		wd = "."
	}
	return filepath.Clean(filepath.Join(wd, dir))
}

// resolveUnderRoot 把 FTP 路径参数解析为 share_dir 内的绝对路径并做越界防护。
// 参数以 "/" 开头的绝对路径视为相对 share_dir 根（忽略当前目录）；否则相对当前目录 s.cwd 解析。
// 注意：绝对参数必须先去掉前导分隔符再拼接——path/filepath.Join 遇到绝对元素（如 "/"）会把结果
// 重置成该绝对路径，导致 filepath.Rel(root, "/") 变成一串 ".." 而误判越界；典型现象就是 `CWD /` 报 550。
// share_dir 未配置或越界返回 ("", false)。
func (s *ftpSession) resolveUnderRoot(arg string) (string, bool) {
	if s.cfg.ShareDir == "" {
		return "", false
	}
	root := s.shareRoot()
	var relpath string
	if filepath.IsAbs(arg) {
		relpath = strings.TrimLeft(arg, "/") // 相对根，忽略当前目录
	} else {
		relpath = filepath.Join(s.cwd, arg)
	}
	target := filepath.Clean(filepath.Join(root, relpath))
	rel, err := filepath.Rel(root, target)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", false
	}
	return target, true
}

// resolveSharePath 是 resolveUnderRoot 的别名，供 LIST/RETR/SIZE 复用。
func (s *ftpSession) resolveSharePath(arg string) (string, bool) {
	return s.resolveUnderRoot(arg)
}

func (s *ftpSession) transferStor(arg, cmd string) {
	s.send("150 Opening data connection for %s.\r\n", arg)
	conn, err := s.openData()
	if err != nil {
		s.send("425 Can't open data connection.\r\n")
		return
	}
	defer conn.Close()
	n, _ := io.Copy(io.Discard, conn)
	s.send("226 Transfer complete. %d bytes received.\r\n", n)
	s.logData("stor("+strings.ToLower(cmd)+")", arg)
}

func (s *ftpSession) logData(op, target string) {
	event.EventPush(event.NewEvent(s.cat, "ftp-data", s.srcAddr, s.dstAddr, map[string]interface{}{
		"protocol":    s.service.BaseOptions.Protocol,
		"application": s.service.BaseOptions.Application,
		"ftp.session": s.id,
		"ftp.op":      op,
		"ftp.target":  target,
	}))
}

func (s *ftpSession) listing(arg string) string {
	if s.cfg.Listing != "" {
		return s.cfg.Listing
	}
	if s.cfg.ShareDir != "" {
		return s.listingFromDir(arg)
	}
	return s.defaultListing(arg)
}

// defaultListing 内置的伪目录列表（未配置 share_dir / listing 时使用）。
func (s *ftpSession) defaultListing(arg string) string {
	dir := "/"
	if arg != "" {
		dir = arg
	}
	now := time.Now().Format("Jan 02 15:04")
	var b strings.Builder
	b.WriteString(fmt.Sprintf("drwxr-xr-x 1 user user     4096 %s .\r\n", now))
	b.WriteString(fmt.Sprintf("drwxr-xr-x 1 user user     4096 %s ..\r\n", now))
	b.WriteString(fmt.Sprintf("-rw-r--r-- 1 user user    12345 %s readme.txt\r\n", now))
	b.WriteString(fmt.Sprintf("-rw-r--r-- 1 user user   524288 %s backup.zip\r\n", now))
	b.WriteString(fmt.Sprintf("-rw-r--r-- 1 user user     4096 %s credentials.cfg\r\n", now))
	b.WriteString(fmt.Sprintf("drwxr-xr-x 1 user user     4096 %s documents\r\n", now))
	b.WriteString(fmt.Sprintf("drwxr-xr-x 1 user user     4096 %s %s\r\n", now, trimLeadingSlash(dir)))
	return b.String()
}

// defaultListingDirs 是默认伪目录树里可作为 CWD 目标的目录名（需与 defaultListing 保持一致）。
var defaultListingDirs = []string{"documents"}

// defaultCwdOk 在默认伪目录模式（share_dir 未配置）下判定 CWD 目标是否合法：
// 根（/、空、.、..）与伪列表里存在的目录接受，其余拒绝。
func (s *ftpSession) defaultCwdOk(arg string) (string, bool) {
	name := strings.TrimLeft(arg, "/")
	name = strings.Trim(name, "/")
	if name == "" || name == "." || name == ".." {
		return "", true // 根
	}
	for _, d := range defaultListingDirs {
		if name == d {
			return d, true
		}
	}
	return "", false
}

// changeDir 处理 CWD/XCWD/CDUP：把 arg 解析为 share_dir 内的新路径并保存。
//   - 以 "/" 开头的 arg 视为相对 share_dir 根（我们呈现为 "/"），忽略当前目录。
//   - 否则相对当前目录（s.cwd）解析。
// 越界（逃出 share_dir 根）拒绝；仅允许进入真实存在的目录；根目录的 ".." 保持在根。
func (s *ftpSession) changeDir(arg string) {
	target, ok := s.resolveUnderRoot(arg)
	if !ok {
		// share_dir 未配置（默认伪目录模式）：按伪目录树判定，避免 CWD / 也 550。
		if s.cfg.ShareDir == "" {
			if rel, okDir := s.defaultCwdOk(arg); okDir {
				s.cwd = rel
				s.send("250 CWD command successful.\r\n")
				return
			}
		}
		// 逃出 share_dir 根或路径非法：拒绝（避免泄露 share_dir 之外的真实文件）
		s.send("550 %s: No such file or directory.\r\n", arg)
		return
	}
	if fi, e := os.Stat(target); e != nil || !fi.IsDir() {
		s.send("550 %s: Not a directory.\r\n", arg)
		return
	}
	rel, _ := filepath.Rel(s.shareRoot(), target)
	if rel == "." {
		rel = "" // 回到根目录时记为 ""
	}
	s.cwd = rel
	s.send("250 CWD command successful.\r\n")
}

// listingFromDir 以 share_dir 为根生成 UNIX 风格目录列表：
//   - share_dir 根目录：读取本机真实条目作为诱饵（含其中的子目录条目）。
//   - 任何子目录（已进入其中再 LIST）：一律返回空目录（只有 . 与 ..），
//     不把子目录里的真实内容泄露给连接方。
func (s *ftpSession) listingFromDir(arg string) string {
	root := s.shareRoot()
	target, ok := s.resolveUnderRoot(arg)
	if !ok {
		target = root
	}
	// 进入子目录后只返回空目录
	if target != root {
		return emptyDirListing()
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		logger.Log.Debugf("%s 读取共享目录失败 %s: %v", s.cat, target, err)
		return ""
	}
	now := time.Now().Format("Jan 02 15:04")
	var b strings.Builder
	b.WriteString(fmt.Sprintf("drwxr-xr-x 1 user user     4096 %s .\r\n", now))
	b.WriteString(fmt.Sprintf("drwxr-xr-x 1 user user     4096 %s ..\r\n", now))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		mode := info.Mode()
		typ := "-"
		switch {
		case mode.IsDir():
			typ = "d"
		case mode&os.ModeSymlink != 0:
			typ = "l"
		}
		line := fmt.Sprintf("%s 1 user user %8d %s %s\r\n",
			typ+mode.Perm().String(),
			info.Size(),
			info.ModTime().Format("Jan 02 15:04"),
			e.Name())
		b.WriteString(line)
	}
	return b.String()
}

// emptyDirListing 返回一个空目录列表（仅 . 与 ..）。
func emptyDirListing() string {
	now := time.Now().Format("Jan 02 15:04")
	var b strings.Builder
	b.WriteString(fmt.Sprintf("drwxr-xr-x 1 user user     4096 %s .\r\n", now))
	b.WriteString(fmt.Sprintf("drwxr-xr-x 1 user user     4096 %s ..\r\n", now))
	return b.String()
}

// pasvHost 决定 PASV 响应里回的 IP。
func (s *ftpSession) pasvHost() string {
	if s.cfg.PasvAddr != "" {
		return s.cfg.PasvAddr
	}
	host := s.service.BaseOptions.Host
	if host != "" && host != "0.0.0.0" {
		return host
	}
	return localIP()
}

func (s *ftpSession) send(format string, args ...interface{}) {
	if s.bw == nil {
		return
	}
	s.bw.WriteString(fmt.Sprintf(format, args...))
	s.bw.Flush()
}

// sendRaw 直接发送已拼好的字符串（vet 不把它当 printf 风格，避免变量串告警）。
func (s *ftpSession) sendRaw(str string) {
	if s.bw == nil {
		return
	}
	s.bw.WriteString(str)
	s.bw.Flush()
}

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------

func splitCmd(line string) (string, string) {
	line = strings.TrimSpace(line)
	idx := strings.IndexByte(line, ' ')
	if idx < 0 {
		return strings.ToUpper(line), ""
	}
	return strings.ToUpper(line[:idx]), strings.TrimSpace(line[idx+1:])
}

func pasvReply(ip string, port int) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		parts = []string{"0", "0", "0", "0"}
	}
	p1 := port >> 8
	p2 := port & 0xff
	return fmt.Sprintf("227 Entering Passive Mode (%s,%s,%s,%s,%d,%d).\r\n",
		parts[0], parts[1], parts[2], parts[3], p1, p2)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func trimLeadingSlash(p string) string {
	return strings.TrimPrefix(p, "/")
}

func dummyFile() []byte {
	return []byte("This is a honeypot. There is no real file here.\r\n")
}

// localIP 探测本机出口 IP（用于 PASV 响应，host=0.0.0.0 时）。
func localIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "0.0.0.0"
	}
	defer conn.Close()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return "0.0.0.0"
}

// loadOrGenCert 加载或生成自签证书（仅含 CN + DNS SAN=hostname 的"标准"自签证书）。
func loadOrGenCert(certFile, keyFile, hostname string) (tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		if pair, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
			return pair, nil
		} else if !os.IsNotExist(err) {
			return tls.Certificate{}, err
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: hostname, Organization: []string{"PotAgent"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	pair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	pair.Leaf, _ = x509.ParseCertificate(der)
	return pair, nil
}
