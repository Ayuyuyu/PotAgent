package smtps

import (
	"bufio"
	"crypto/tls"
	"net"
	"strings"
	"testing"

	"potAgent/common"
	"potAgent/global"
	"potAgent/services"
	"potAgent/services/smtp"
)

// readReply 读取一个 SMTP 多行回复，直到出现 "NNN "（第 4 字节为空格）的终结行。
func readReply(r *bufio.Reader) (string, error) {
	var all strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return all.String(), err
		}
		all.WriteString(line)
		if len(line) >= 4 && line[3] == ' ' {
			return all.String(), nil
		}
	}
}

func TestImplicitTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		host := smtp.GreetingHost(smtp.DefaultBanner)
		cert, cerr := common.LoadOrGenCert("", "", host)
		if cerr != nil {
			t.Errorf("load cert: %v", cerr)
			c.Close()
			return
		}
		tlsConn := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if herr := tlsConn.Handshake(); herr != nil {
			t.Errorf("handshake: %v", herr)
			return
		}
		svc := &services.Service{
			BaseOptions:    global.ServiceBaseConfig{Protocol: "smtps", Application: "smtps"},
			ServiceOptions: smtpsConfig{},
		}
		smtp.Serve(tlsConn, svc, "smtps", false)
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// 客户端必须先 TLS 握手，再读 220 欢迎语
	tlsConn := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	r := bufio.NewReader(tlsConn)
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("banner: %q", line)
	}
	// 命令循环可用：EHLO 应得 250
	tlsConn.Write([]byte("EHLO client\r\n"))
	if reply, _ := readReply(r); !strings.Contains(reply, "250 ") {
		t.Fatalf("EHLO reply:\n%s", reply)
	}
}
