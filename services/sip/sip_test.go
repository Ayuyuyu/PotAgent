package sip

import (
	"strings"
	"testing"
)

func TestParseSIPRequest(t *testing.T) {
	req := "REGISTER sip:192.168.1.1 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKabc\r\n" +
		"From: \"u\" <sip:alice@10.0.0.2>;tag=111\r\n" +
		"To: <sip:alice@192.168.1.1>\r\n" +
		"Call-ID: 123@10.0.0.2\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Contact: <sip:alice@10.0.0.2:5060>\r\n" +
		"User-Agent: SIPVicious\r\n"
	m, ok := parseSIPRequest(req)
	if !ok {
		t.Fatalf("parse failed")
	}
	if m.Method != "REGISTER" || m.URI != "sip:192.168.1.1" {
		t.Fatalf("method/uri: %q %q", m.Method, m.URI)
	}
	if m.header("call-id", "") != "123@10.0.0.2" {
		t.Fatalf("call-id: %q", m.header("call-id", ""))
	}
	if m.header("user-agent", "") != "SIPVicious" {
		t.Fatalf("ua: %q", m.header("user-agent", ""))
	}
}

func TestParseSIPRequestMalformed(t *testing.T) {
	if _, ok := parseSIPRequest("garbage line\r\nVia: x\r\n"); ok {
		t.Fatalf("malformed should fail")
	}
}

func TestExtractSipUser(t *testing.T) {
	cases := map[string]string{
		"<sip:alice@host>":               "alice",
		"sip:bob@host;transport=udp":     "bob",
		"\"Disp\" <sip:carol@host:5060>": "carol",
		"sip:dave@host?subject=x":        "dave",
	}
	for in, want := range cases {
		if got := extractSipUser(in); got != want {
			t.Fatalf("extractSipUser(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseAuthDigest(t *testing.T) {
	auth := `Digest username="alice", realm="PotAgent", nonce="abc123", uri="sip:1.2.3.4", response="deadbeef", algorithm=MD5`
	d := parseAuthDigest(auth)
	if d["username"] != "alice" || d["realm"] != "PotAgent" || d["nonce"] != "abc123" ||
		d["uri"] != "sip:1.2.3.4" || d["response"] != "deadbeef" || d["algorithm"] != "MD5" {
		t.Fatalf("parseAuthDigest: %v", d)
	}
	// 非 digest 应返回空
	if len(parseAuthDigest("Basic abcdef")) != 0 {
		t.Fatalf("non-digest should be empty")
	}
}

func TestBuildResponseChallenge(t *testing.T) {
	req := "REGISTER sip:1.2.3.4 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z\r\n" +
		"From: <sip:alice@10.0.0.2>;tag=1\r\n" +
		"To: <sip:alice@1.2.3.4>\r\n" +
		"Call-ID: c1\r\n" + "CSeq: 1 REGISTER\r\n"
	m, _ := parseSIPRequest(req)
	r := buildResponse(m, 401, "PotAgent")
	if !strings.Contains(r, "SIP/2.0 401 Unauthorized\r\n") ||
		!strings.Contains(r, "WWW-Authenticate: Digest realm=\"PotAgent\"") ||
		!strings.Contains(r, "algorithm=MD5") {
		t.Fatalf("401 response: %q", r)
	}
	// To 应被补上 tag
	if !strings.Contains(strings.ToLower(r), "tag=") {
		t.Fatalf("To missing tag: %q", r)
	}
	// 200 应带 Allow
	r2 := buildResponse(m, 200, "PotAgent")
	if !strings.Contains(r2, "SIP/2.0 200 OK\r\n") || !strings.Contains(r2, "Allow:") {
		t.Fatalf("200 response: %q", r2)
	}
}

func TestHeaderFold(t *testing.T) {
	// 折叠首部：Subject 跨行
	raw := "INVITE sip:x SIP/2.0\r\n" +
		"From: <sip:a@b>\r\n" +
		"Subject: hello\r\n world\r\n" +
		"To: <sip:c@d>\r\n"
	m, ok := parseSIPRequest(raw)
	if !ok {
		t.Fatalf("parse failed")
	}
	if !strings.Contains(m.header("subject", ""), "hello world") {
		t.Fatalf("folded subject: %q", m.header("subject", ""))
	}
}
