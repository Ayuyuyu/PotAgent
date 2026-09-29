package ldap

import (
	"bufio"
	"bytes"
	"net"
	"testing"

	"potAgent/global"
	"potAgent/services"
)

// ---- 测试构造器：手工拼 LDAP 请求报文 ----

func buildTestBind(msgID int, dn, pw string) []byte {
	req := encodeTLV(0x02, intBytes(3))               // version 3
	req = append(req, encodeTLV(0x04, []byte(dn))...) // name
	req = append(req, encodeTLV(0x80, []byte(pw))...) // simple auth
	op := encodeTLV(0x60, req)
	return encodeTLV(0x30, append(encodeTLV(0x02, intBytes(msgID)), op...))
}

func buildTestSaslBind(msgID int, dn, mech string) []byte {
	req := encodeTLV(0x02, intBytes(3))
	req = append(req, encodeTLV(0x04, []byte(dn))...)
	sasl := encodeTLV(0x04, []byte(mech)) // mechanism
	sasl = append(sasl, encodeTLV(0x04, []byte("cred"))...)
	req = append(req, encodeTLV(0xa3, sasl)...)
	op := encodeTLV(0x60, req)
	return encodeTLV(0x30, append(encodeTLV(0x02, intBytes(msgID)), op...))
}

func buildTestSearch(msgID int, base, filter string) []byte {
	req := encodeTLV(0x04, []byte(base))             // baseObject
	req = append(req, encodeTLV(0x0a, []byte{1})...) // scope=singleLevel
	req = append(req, encodeTLV(0x0a, []byte{0})...) // derefAliases
	req = append(req, encodeTLV(0x02, []byte{0})...) // sizeLimit
	req = append(req, encodeTLV(0x02, []byte{0})...) // timeLimit
	req = append(req, encodeTLV(0x01, []byte{0})...) // typesOnly
	// filter: (objectClass=*)
	eq := encodeTLV(0x04, []byte("objectClass"))
	eq = append(eq, encodeTLV(0x04, []byte("*"))...)
	req = append(req, encodeTLV(0xa3, eq)...)
	// attributes: SEQUENCE OF { "cn" }
	req = append(req, encodeTLV(0x30, encodeTLV(0x04, []byte("cn")))...)
	op := encodeTLV(0x63, req)
	return encodeTLV(0x30, append(encodeTLV(0x02, intBytes(msgID)), op...))
}

// ---- 单元测试：解析 ----

func TestParseBindRequest(t *testing.T) {
	msg := buildTestBind(1, "cn=admin,dc=example,dc=com", "secret123")
	m, ok := readTLVReader(bufio.NewReader(newByteReader(msg)))
	if !ok || m.tag != 0x30 {
		t.Fatal("帧化读取失败")
	}
	msgID, opTag, opVal, ok := parseLDAPMessage(m.val)
	if !ok || opTag != 0x60 {
		t.Fatalf("parseLDAPMessage 失败: opTag=%#x", opTag)
	}
	if msgID != 1 {
		t.Fatalf("msgID 期望 1, 实际 %d", msgID)
	}
	ver, dn, authType, pw, _ := parseBindRequest(opVal)
	if ver != 3 || dn != "cn=admin,dc=example,dc=com" || authType != "simple" || pw != "secret123" {
		t.Fatalf("parseBindRequest 异常: ver=%d dn=%q type=%q pw=%q", ver, dn, authType, pw)
	}
}

func TestParseSaslBind(t *testing.T) {
	msg := buildTestSaslBind(2, "cn=admin", "GSSAPI")
	m, _ := readTLVReader(bufio.NewReader(newByteReader(msg)))
	_, opTag, opVal, _ := parseLDAPMessage(m.val)
	_, dn, authType, _, mech := parseBindRequest(opVal)
	if opTag != 0x60 || dn != "cn=admin" || authType != "sasl" || mech != "GSSAPI" {
		t.Fatalf("parseSaslBind 异常: dn=%q type=%q mech=%q", dn, authType, mech)
	}
}

func TestParseSearchRequest(t *testing.T) {
	msg := buildTestSearch(3, "dc=example,dc=com", "(objectClass=*)")
	m, _ := readTLVReader(bufio.NewReader(newByteReader(msg)))
	_, opTag, opVal, _ := parseLDAPMessage(m.val)
	if opTag != 0x63 {
		t.Fatalf("opTag 期望 0x63, 实际 %#x", opTag)
	}
	base, scope, filter, _, attrs := parseSearchRequest(opVal)
	if base != "dc=example,dc=com" || scope != 1 || filter != "(objectClass=*)" {
		t.Fatalf("parseSearchRequest 异常: base=%q scope=%d filter=%q", base, scope, filter)
	}
	if len(attrs) != 1 || attrs[0] != "cn" {
		t.Fatalf("attributes 异常: %v", attrs)
	}
}

func TestDecodeFilter(t *testing.T) {
	// (&(objectClass=person)(cn=admin))
	and := encodeTLV(0x04, []byte("objectClass"))
	and = append(and, encodeTLV(0x04, []byte("person"))...)
	eq1 := encodeTLV(0xa3, and)
	cn := encodeTLV(0x04, []byte("cn"))
	cn = append(cn, encodeTLV(0x04, []byte("admin"))...)
	eq2 := encodeTLV(0xa3, cn)
	filter := encodeTLV(0xa0, append(eq1, eq2...))
	got := decodeFilterBytes(filter)
	want := "(&(objectClass=person)(cn=admin))"
	if got != want {
		t.Fatalf("decodeFilter 期望 %q, 实际 %q", want, got)
	}
}

func TestBuildResponses(t *testing.T) {
	// bindResponse 需是 0x30 { msgID, 0x61 { 0x0a 0(成功) ... } }
	b := buildBindResponse(7)
	m, ok := readTLVReader(bufio.NewReader(newByteReader(b)))
	if !ok || m.tag != 0x30 {
		t.Fatal("bindResponse 帧化失败")
	}
	_, opTag, opVal, ok := parseLDAPMessage(m.val)
	if !ok || opTag != 0x61 {
		t.Fatalf("bindResponse opTag 期望 0x61, 实际 %#x", opTag)
	}
	rc, ok := readTLV(opVal)
	if !ok || rc.tag != 0x0a || rc.val[0] != 0 {
		t.Fatalf("bindResponse resultCode 期望 success(0), 实际 %#x val=%v", rc.tag, rc.val)
	}

	// searchResultEntry + done
	e := buildSearchResultEntry(7, "cn=admin,dc=example,dc=com", buildFakeAttributes(nil))
	m2, _ := readTLVReader(bufio.NewReader(newByteReader(e)))
	if _, op, _, ok := parseLDAPMessage(m2.val); !ok || op != 0x64 {
		t.Fatalf("searchResultEntry opTag 期望 0x64, 实际 %#x", op)
	}
}

func TestBuildFakeAttributesFromConfig(t *testing.T) {
	cfg := ldapConfig{
		BaseDN: "dc=corp,dc=local",
		FakeEntry: []ldapAttr{
			{Type: "objectClass", Values: []string{"top", "person"}},
			{Type: "cn", Values: []string{"svc-ldap"}},
			{Type: "department", Values: []string{"IT"}},
		},
	}
	if got := entryDN(&cfg); got != "cn=svc-ldap,dc=corp,dc=local" {
		t.Fatalf("entryDN 期望 cn=svc-ldap,dc=corp,dc=local, 实际 %q", got)
	}
	attrs := buildFakeAttributes(cfg.FakeEntry)
	found := map[string]string{}
	b := attrs
	for len(b) > 0 {
		at, ok := readTLV(b)
		if !ok {
			break
		}
		tlvType, _ := readTLV(at.val)
		rest := at.val[tlvType.next:]
		setTLV, _ := readTLV(rest)
		valTLV, _ := readTLV(setTLV.val)
		found[string(tlvType.val)] = string(valTLV.val)
		b = b[at.next:]
	}
	if found["department"] != "IT" || found["cn"] != "svc-ldap" {
		t.Fatalf("配置属性未正确编入: %v", found)
	}
}

// ---- 集成测试：真实 TCP 往返 ----

func TestLDAPServiceRoundTrip(t *testing.T) {
	cfg := ldapConfig{BaseDN: "dc=example,dc=com"}
	svc := &services.Service{
		BaseOptions:    global.ServiceBaseConfig{Protocol: "ldap", Application: "ldap", Host: "127.0.0.1", Port: 0},
		ServiceOptions: cfg,
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go ldapHandleConn(c, svc, &cfg)
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)

	// 1) Bind(simple)
	conn.Write(buildTestBind(1, "cn=admin", "P@ssw0rd"))
	resp, ok := readTLVReader(br)
	if !ok {
		t.Fatal("未收到 bind 响应")
	}
	if _, op, _, ok := parseLDAPMessage(resp.val); !ok || op != 0x61 {
		t.Fatalf("bind 响应 opTag 期望 0x61, 实际 %#x", op)
	}

	// 2) Search -> 应收到 entry(0x64) 再 done(0x65)
	conn.Write(buildTestSearch(2, "", "(objectClass=*)"))
	e, ok := readTLVReader(br)
	if !ok {
		t.Fatal("未收到 searchResultEntry")
	}
	if _, op, _, ok := parseLDAPMessage(e.val); !ok || op != 0x64 {
		t.Fatalf("searchResultEntry opTag 期望 0x64, 实际 %#x", op)
	}
	d, ok := readTLVReader(br)
	if !ok {
		t.Fatal("未收到 searchResultDone")
	}
	if _, op, _, ok := parseLDAPMessage(d.val); !ok || op != 0x65 {
		t.Fatalf("searchResultDone opTag 期望 0x65, 实际 %#x", op)
	}

	// 3) Unbind -> 服务端应关闭连接
	conn.Write(buildTestUnbind(3))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("unbind 后连接应被服务端关闭")
	}
}

func buildTestUnbind(msgID int) []byte {
	op := encodeTLV(0x62, []byte{}) // unbindRequest NULL
	return encodeTLV(0x30, append(encodeTLV(0x02, intBytes(msgID)), op...))
}

// newByteReader 包装 []byte 为 io.Reader 供 bufio 使用
func newByteReader(b []byte) *bytes.Reader {
	return bytes.NewReader(b)
}
