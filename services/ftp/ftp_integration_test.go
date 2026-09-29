package ftp

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"potAgent/global"
	"potAgent/logger"
	"potAgent/services"
)

// pickFreePort 占一个空闲端口后归还，供 worker 复用，避免端口竞态。
func pickFreePort(t *testing.T) int {
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	return port
}

// startFTP 起一个 FTP/FTPS worker，返回控制地址与取消函数。
func startFTP(t *testing.T, cfg ftpConfig) (string, context.CancelFunc) {
	port := pickFreePort(t)
	svc := services.Service{
		WorkerHandle:   ftpHandle,
		ServiceOptions: cfg,
		BaseOptions: global.ServiceBaseConfig{
			Protocol:    "ftp",
			Application: "test",
			Enable:      true,
			Host:        "127.0.0.1",
			Port:        uint16(port),
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	go ftpHandle(ctx, &svc)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	var ctrl net.Conn
	var err error
	for i := 0; i < 50; i++ {
		ctrl, err = net.DialTimeout("tcp4", addr, time.Second)
		if err == nil {
			ctrl.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("dial control: %v", err)
	}
	return addr, cancel
}

// ctrlClient 是测试用的极简 FTP 控制通道封装。
type ctrlClient struct {
	t      *testing.T
	conn   net.Conn
	reader *bufio.Reader
}

func (c *ctrlClient) read() string {
	line, err := c.reader.ReadString('\n')
	if err != nil {
		c.t.Fatalf("read control: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

func (c *ctrlClient) expect(prefix string) {
	line := c.read()
	if !strings.HasPrefix(line, prefix) {
		c.t.Fatalf("期望 %q 开头，实际: %q", prefix, line)
	}
}

func (c *ctrlClient) write(s string) {
	if _, err := c.conn.Write([]byte(s + "\r\n")); err != nil {
		c.t.Fatalf("write control: %v", err)
	}
}

// TestFTPPasvIntegration 走一遍 USER/PASS -> PASV -> LIST -> QUIT，
// 验证明文控制通道与独立 PASV 数据通道都正常。
func TestFTPPasvIntegration(t *testing.T) {
	logger.InitLog("info")
	addr, cancel := startFTP(t, ftpConfig{})
	defer cancel()

	conn, err := net.DialTimeout("tcp4", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	c := &ctrlClient{t: t, conn: conn, reader: bufio.NewReader(conn)}

	c.expect("220 ")
	c.write("USER bob")
	c.expect("331 ")
	c.write("PASS secret")
	c.expect("230 ")

	c.write("PASV")
	pasvLine := c.read()
	if !strings.HasPrefix(pasvLine, "227 ") {
		t.Fatalf("bad PASV: %q", pasvLine)
	}
	dataPort := parsePasvPort(t, pasvLine)

	c.write("LIST")
	c.expect("150 ")
	dconn, err := net.DialTimeout("tcp4", "127.0.0.1:"+strconv.Itoa(dataPort), time.Second)
	if err != nil {
		t.Fatalf("dial data: %v", err)
	}
	buf := make([]byte, 4096)
	n, _ := dconn.Read(buf)
	dconn.Close()
	if n == 0 || !strings.Contains(string(buf[:n]), "readme.txt") {
		t.Fatalf("listing 异常: %q", string(buf[:n]))
	}
	c.expect("226 ")
	c.write("QUIT")
	c.expect("221 ")
}

// TestFTPSExplicitIntegration 验证显式 FTPS：AUTH TLS 把明文控制通道升级为 TLS
// （含 preRead 桥接，避免 bufio 已预读的握手字节丢失），再用 PROT P 加密 PASV 数据通道。
func TestFTPSExplicitIntegration(t *testing.T) {
	logger.InitLog("info")
	addr, cancel := startFTP(t, ftpConfig{Mode: "ftps"})
	defer cancel()

	conn, err := net.DialTimeout("tcp4", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	c := &ctrlClient{t: t, conn: conn, reader: bufio.NewReader(conn)}

	c.expect("220 ")
	c.write("AUTH TLS")
	c.expect("234 ")

	// 客户端侧把控制通道升级为 TLS
	tlsCtrl := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsCtrl.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	c.conn = tlsCtrl
	c.reader = bufio.NewReader(tlsCtrl)

	c.write("USER bob")
	c.expect("331 ")
	c.write("PASS secret")
	c.expect("230 ")
	c.write("PBSZ 0")
	c.expect("200 ")
	c.write("PROT P")
	c.expect("200 ")

	c.write("PASV")
	pasvLine := c.read()
	if !strings.HasPrefix(pasvLine, "227 ") {
		t.Fatalf("bad PASV: %q", pasvLine)
	}
	dataPort := parsePasvPort(t, pasvLine)

	c.write("LIST")
	c.expect("150 ")
	dconn, err := net.DialTimeout("tcp4", "127.0.0.1:"+strconv.Itoa(dataPort), time.Second)
	if err != nil {
		t.Fatalf("dial data: %v", err)
	}
	tdata := tls.Client(dconn, &tls.Config{InsecureSkipVerify: true})
	if err := tdata.Handshake(); err != nil {
		t.Fatalf("data tls handshake: %v", err)
	}
	buf := make([]byte, 4096)
	n, _ := tdata.Read(buf)
	tdata.Close()
	if n == 0 || !strings.Contains(string(buf[:n]), "readme.txt") {
		t.Fatalf("tls listing 异常: %q", string(buf[:n]))
	}
	c.expect("226 ")
	c.write("QUIT")
	c.expect("221 ")
}

// parsePasvPort 从 "227 ... (h,h,h,h,p1,p2)" 取出数据端口。
func parsePasvPort(t *testing.T, line string) int {
	open := strings.IndexByte(line, '(')
	close := strings.IndexByte(line, ')')
	if open < 0 || close < 0 {
		t.Fatalf("bad pasv line %q", line)
	}
	parts := strings.Split(line[open+1:close], ",")
	if len(parts) != 6 {
		t.Fatalf("bad pasv parts %q", line)
	}
	p1, _ := strconv.Atoi(parts[4])
	p2, _ := strconv.Atoi(parts[5])
	return p1*256 + p2
}
