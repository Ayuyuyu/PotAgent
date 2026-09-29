package snmp

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"potAgent/global"
	"potAgent/logger"
)

func TestOIDRoundTrip(t *testing.T) {
	cases := []string{
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.4.1.8072.3.2.10",
		"0.0",
		"2.25.128.1.2.3",
	}
	for _, oid := range cases {
		got := decodeOIDBody(encodeOIDBody(oid))
		if got != oid {
			t.Fatalf("OID 往返不一致: 输入 %q 得到 %q", oid, got)
		}
	}
}

// buildGetRequest 构造一个 GetRequest（0xA0）报文，供测试使用。
func buildGetRequest(community string, oids []string) []byte {
	var vbl []byte
	for _, oid := range oids {
		vbl = append(vbl, encodeTLV(0x30, append(encodeOID(oid), encodeTLV(0x05, nil)...))...)
	}
	pdu := append(append(encodeTLV(0x02, intBytes(12345)), encodeTLV(0x02, []byte{0})...), encodeTLV(0x02, []byte{0})...)
	pdu = append(pdu, encodeTLV(0x30, vbl)...)
	msg := append(encodeTLV(0x02, intBytes(1)), encodeTLV(0x04, []byte(community))...)
	msg = append(msg, encodeTLV(0xA0, pdu)...)
	return encodeTLV(0x30, msg)
}

func TestParseAndResponse(t *testing.T) {
	reqBytes := buildGetRequest("public", []string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"})
	req, ok := parseSNMP(reqBytes)
	if !ok {
		t.Fatal("解析 SNMP 请求失败")
	}
	if req.version != 1 || req.community != "public" || req.pduType != 0xA0 {
		t.Fatalf("请求字段异常: v=%d community=%q pdu=0x%02x", req.version, req.community, req.pduType)
	}
	if len(req.oids) != 2 || req.oids[0] != "1.3.6.1.2.1.1.1.0" {
		t.Fatalf("OID 解析异常: %v", req.oids)
	}

	cfg := snmpConfig{SysDescr: "PotAgent Network Device"}
	resp := buildSNMPResponse(req, &cfg)
	respMsg, ok := readTLV(resp)
	if !ok || respMsg.tag != 0x30 {
		t.Fatal("响应不是 SEQUENCE")
	}
	// 简单校验：响应含 GET-RESPONSE(0xA2) 与 sysDescr 字符串 "PotAgent Network Device"
	if !contains(resp, []byte("PotAgent Network Device")) {
		t.Fatalf("响应未包含默认 sysDescr")
	}
	if !contains(resp, []byte{0xA2}) {
		t.Fatalf("响应 PDU 类型不是 GET-RESPONSE(0xA2)")
	}
}

func TestSNMPServiceRoundTrip(t *testing.T) {
	logger.InitLog("info")
	port := freeUDPPort(t)
	svc := SNMPServiceInit()
	svc.BaseOptions = global.ServiceBaseConfig{
		Protocol: "snmp", Application: "snmp", Host: "127.0.0.1", Port: uint16(port),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go snmpHandle(ctx, &svc)

	client, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	req := buildGetRequest("public", []string{"1.3.6.1.2.1.1.1.0"})
	var resp []byte
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		client.SetDeadline(deadline)
		client.Write(req)
		buf := make([]byte, 4096)
		n, e := client.Read(buf)
		if e == nil && n > 0 {
			resp = buf[:n]
			break
		}
	}
	if resp == nil {
		t.Fatal("未收到 SNMP 响应")
	}
	// 解析响应，确认是 GET-RESPONSE 且回显了请求的 OID 与字符串值
	r, ok := parseSNMP(resp)
	if !ok {
		t.Fatal("响应解析失败")
	}
	if r.pduType != 0xA2 {
		t.Fatalf("响应 PDU 类型期望 0xA2(GET-RESPONSE), 实际 0x%02x", r.pduType)
	}
	if !contains(resp, []byte("PotAgent Network Device")) {
		t.Fatalf("响应未含 sysDescr 值")
	}
}

func contains(b []byte, sub []byte) bool {
	if len(sub) == 0 || len(sub) > len(b) {
		return false
	}
	for i := 0; i+len(sub) <= len(b); i++ {
		if string(b[i:i+len(sub)]) == string(sub) {
			return true
		}
	}
	return false
}

func freeUDPPort(t *testing.T) int {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}
