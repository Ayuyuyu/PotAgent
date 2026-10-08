package smtp

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"potAgent/global"
	"potAgent/services"
)

func mustB64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestEhloResponse(t *testing.T) {
	r := ehloResponse("mail")
	if !strings.Contains(r, "250-mail\r\n") ||
		!strings.Contains(r, "250-AUTH LOGIN PLAIN\r\n") ||
		!strings.Contains(r, "250-STARTTLS\r\n") ||
		!strings.HasSuffix(r, "250 OK\r\n") {
		t.Fatalf("ehlo response malformed: %q", r)
	}
}

func TestGreetingHost(t *testing.T) {
	if h := GreetingHost("mx.example.com ESMTP PotAgent"); h != "mx.example.com" {
		t.Fatalf("greetingHost: %q", h)
	}
	if h := GreetingHost(""); h != "mail" {
		t.Fatalf("greetingHost empty: %q", h)
	}
}

func TestParseAddr(t *testing.T) {
	cases := map[string]string{
		"FROM:<user@example.com>":  "user@example.com",
		"FROM: <user@example.com>": "user@example.com",
		"TO:user@example.com":      "user@example.com",
		"<a@b>":                    "a@b",
	}
	for in, want := range cases {
		if got := parseAddr(in); got != want {
			t.Fatalf("parseAddr(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAuthPlainCreds(t *testing.T) {
	// 无 authzid：\0user\0pass -> 3 段，user=段[1] pass=段[2]
	enc := mustB64("\x00alice\x00secret")
	u, p := authPlainCreds(enc)
	if u != "alice" || p != "secret" {
		t.Fatalf("authPlainCreds 3-seg: u=%q p=%q", u, p)
	}
	// 带 authzid：authz\0user\0pass -> 3 段，user=段[1] pass=段[2]
	encA := mustB64("authz\x00alice\x00secret")
	ua, pa := authPlainCreds(encA)
	if ua != "alice" || pa != "secret" {
		t.Fatalf("authPlainCreds with authzid: u=%q p=%q", ua, pa)
	}
	// 2 段退化：user\0pass
	enc2 := mustB64("bob\x00pw")
	u2, p2 := authPlainCreds(enc2)
	if u2 != "bob" || p2 != "pw" {
		t.Fatalf("authPlainCreds 2-seg: u=%q p=%q", u2, p2)
	}
}

func TestDecodeB64Safe(t *testing.T) {
	if decodeB64Safe("") != "" {
		t.Fatalf("empty should be empty")
	}
	if decodeB64Safe("not-base64!!") != "not-base64!!" {
		t.Fatalf("invalid should return original")
	}
}

func TestExtractHeaderField(t *testing.T) {
	msg := "Subject: Test Subject\r\nFrom: a@b\r\n\r\nbody line\r\n"
	if s := extractHeaderField(msg, "Subject"); s != "Test Subject" {
		t.Fatalf("subject=%q", s)
	}
	if s := extractHeaderField(msg, "subject"); s != "Test Subject" {
		t.Fatalf("case-insensitive subject=%q", s)
	}
	if s := extractHeaderField(msg, "X-Missing"); s != "" {
		t.Fatalf("missing header should be empty: %q", s)
	}
	// 折叠首部
	folded := "Received: from x\r\n by y\r\n\r\nbody\r\n"
	if s := extractHeaderField(folded, "Received"); s != "from x by y" {
		t.Fatalf("folded header=%q", s)
	}
}

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

func TestStarttlsUpgrade(t *testing.T) {
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
		svc := &services.Service{
			BaseOptions:    global.ServiceBaseConfig{Protocol: "smtp", Application: "smtp"},
			ServiceOptions: smtpConfig{},
		}
		Serve(c, svc, "smtp", true)
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)

	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("banner: %q", line)
	}
	// EHLO 应声明 STARTTLS
	c.Write([]byte("EHLO client\r\n"))
	ehlo, _ := readReply(r)
	if !strings.Contains(ehlo, "250-STARTTLS") {
		t.Fatalf("EHLO missing STARTTLS:\n%s", ehlo)
	}
	// STARTTLS 升级
	c.Write([]byte("STARTTLS\r\n"))
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("starttls reply: %q", line)
	}
	tlsConn := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	// 升级后命令循环继续：再发 EHLO 应得 250
	tlsConn.Write([]byte("EHLO client\r\n"))
	if reply, _ := readReply(bufio.NewReader(tlsConn)); !strings.Contains(reply, "250 ") {
		t.Fatalf("post-TLS EHLO reply:\n%s", reply)
	}
}

func TestStarttlsDisabled(t *testing.T) {
	// allowStartTLS=false（smtps 场景）时 STARTTLS 应回 502
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
		svc := &services.Service{
			BaseOptions:    global.ServiceBaseConfig{Protocol: "smtps", Application: "smtps"},
			ServiceOptions: smtpConfig{},
		}
		Serve(c, svc, "smtps", false)
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("banner: %q", line)
	}
	c.Write([]byte("STARTTLS\r\n"))
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "502 ") {
		t.Fatalf("starttls should be 502: %q", line)
	}
}
