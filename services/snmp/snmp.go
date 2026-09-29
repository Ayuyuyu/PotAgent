package snmp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"
)

// SNMP 低交互蜜罐：监听 UDP 161，解析 SNMPv1/v2c 报文（ASN.1 BER），
// 对 GetRequest/GetNextRequest/SetRequest/GetBulk 回一份“像真设备”的 GET-RESPONSE，
// 并记录 community 字符串与请求 OID（扫描者常用 public/弱 community 枚举，属高价值情报）。
var _ = services.Register("snmp", SNMPServiceInit)

var startTime = time.Now()

func SNMPServiceInit() services.Service {
	return services.Service{
		WorkerHandle:   snmpHandle,
		ServiceOptions: snmpConfig{},
	}
}

type snmpConfig struct {
	SysDescr    string `mapstructure:"sys_descr"`    // 1.3.6.1.2.1.1.1.0 设备描述
	SysObjectID string `mapstructure:"sys_objectid"` // 1.3.6.1.2.1.1.2.0 厂商 OID
	SysContact  string `mapstructure:"sys_contact"`  // 1.3.6.1.2.1.1.4.0
	SysName     string `mapstructure:"sys_name"`     // 1.3.6.1.2.1.1.5.0
	SysLocation string `mapstructure:"sys_location"` // 1.3.6.1.2.1.1.6.0
}

func snmpHandle(ctx context.Context, service *services.Service) {
	cfg := service.ServiceOptions.(snmpConfig)
	if cfg.SysDescr == "" {
		cfg.SysDescr = "PotAgent Network Device"
	}
	if cfg.SysObjectID == "" {
		cfg.SysObjectID = "1.3.6.1.4.1.8072.3.2.10"
	}
	if cfg.SysContact == "" {
		cfg.SysContact = "admin@potagent.local"
	}
	if cfg.SysName == "" {
		cfg.SysName = "potagent"
	}
	if cfg.SysLocation == "" {
		cfg.SysLocation = "Default Location"
	}

	address := fmt.Sprintf("%v:%v", service.BaseOptions.Host, service.BaseOptions.Port)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(service.BaseOptions.Host), Port: int(service.BaseOptions.Port)})
	if err != nil {
		logger.Log.Fatalln(err)
		return
	}
	defer conn.Close()
	logger.Log.Infoln(service.BaseOptions.Application, "listen on", address)

	packetChan := common.ForwardUDPPacketToChan(conn)
	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", service.BaseOptions.Protocol)
			return
		case packet := <-packetChan:
			handleSNMP(packet, service, &cfg)
		}
	}
}

func handleSNMP(packet *common.DummyUDPConn, service *services.Service, cfg *snmpConfig) {
	req, ok := parseSNMP(packet.Data)
	src := common.Addr{IP: packet.UDPAddr.IP.String(), Port: uint16(packet.UDPAddr.Port)}
	dst := udpAddrToCommonAddr(localUDPAddr(packet))

	fields := map[string]interface{}{
		"ip_protocol": "udp",
		"protocol":    service.BaseOptions.Protocol,
		"application": service.BaseOptions.Application,
		"snmp.raw":    fmt.Sprintf("%x", packet.Data),
	}
	if ok {
		fields["snmp.version"] = req.version
		fields["snmp.community"] = req.community
		fields["snmp.pdu_type"] = int(req.pduType)
		fields["snmp.oids"] = req.oids
	}
	event.EventPush(event.NewEvent(service.BaseOptions.Protocol, "snmp-request", src, dst, fields))

	// 只对查询/写入类 PDU 回包；Trap/Inform(0xA4/0xA6/0xA7) 是 agent->manager，不回
	if ok && isQueryPDU(req.pduType) {
		resp := buildSNMPResponse(req, cfg)
		if _, err := packet.WriteToUDP(resp, packet.UDPAddr); err != nil {
			logger.Log.Debug("snmp: write response failed:", err)
		}
	}
}

// ---- SNMP 报文解析 ----

type snmpRequest struct {
	version   int
	community string
	pduType   byte
	requestID []byte // 原样回显，避免有符号/长度歧义
	oids      []string
}

func isQueryPDU(t byte) bool {
	switch t {
	case 0xA0, 0xA1, 0xA3, 0xA5: // GetRequest, GetNextRequest, SetRequest, GetBulkRequest
		return true
	}
	return false
}

func parseSNMP(data []byte) (snmpRequest, bool) {
	var req snmpRequest
	outer, ok := readTLV(data)
	if !ok || outer.tag != 0x30 {
		return req, false
	}
	b := outer.val
	v, ok := readTLV(b)
	if !ok || v.tag != 0x02 {
		return req, false
	}
	req.version = intFromBytes(v.val)
	b = b[v.next:]
	c, ok := readTLV(b)
	if !ok || c.tag != 0x04 {
		return req, false
	}
	req.community = string(c.val)
	b = b[c.next:]
	p, ok := readTLV(b)
	if !ok {
		return req, false
	}
	req.pduType = p.tag
	pb := p.val
	rid, ok := readTLV(pb)
	if !ok || rid.tag != 0x02 {
		return req, false
	}
	req.requestID = append([]byte(nil), rid.val...)
	pb = pb[rid.next:]
	// error-status
	es, ok := readTLV(pb)
	if !ok || es.tag != 0x02 {
		return req, false
	}
	pb = pb[es.next:]
	// error-index
	ei, ok := readTLV(pb)
	if !ok || ei.tag != 0x02 {
		return req, false
	}
	pb = pb[ei.next:]
	// varbind-list
	vbl, ok := readTLV(pb)
	if !ok || vbl.tag != 0x30 {
		return req, false
	}
	vb := vbl.val
	for len(vb) > 0 {
		ent, ok := readTLV(vb)
		if !ok || ent.tag != 0x30 {
			break
		}
		o, ok := readTLV(ent.val)
		if !ok || o.tag != 0x06 {
			break
		}
		req.oids = append(req.oids, decodeOIDBody(o.val))
		vb = vb[ent.next:]
	}
	return req, true
}

// ---- SNMP 报文构造 ----

func buildSNMPResponse(req snmpRequest, cfg *snmpConfig) []byte {
	var vbl []byte
	for _, oid := range req.oids {
		vbl = append(vbl, buildVarBind(oid, cfg)...)
	}
	pdu := append(append(encodeTLV(0x02, req.requestID), encodeTLV(0x02, []byte{0})...), encodeTLV(0x02, []byte{0})...)
	pdu = append(pdu, encodeTLV(0x30, vbl)...)
	msg := append(encodeTLV(0x02, intBytes(req.version)), encodeTLV(0x04, []byte(req.community))...)
	msg = append(msg, encodeTLV(0xA2, pdu)...) // GET-RESPONSE
	return encodeTLV(0x30, msg)
}

func buildVarBind(oid string, cfg *snmpConfig) []byte {
	tag, body := mibValue(oid, cfg)
	return encodeTLV(0x30, append(encodeOID(oid), encodeTLV(tag, body)...))
}

// mibValue 返回某 OID 的（ASN.1 标签, 值正文）；未知 OID 回一个通用字符串。
func mibValue(oid string, cfg *snmpConfig) (byte, []byte) {
	switch oid {
	case "1.3.6.1.2.1.1.1.0":
		return 0x04, []byte(cfg.SysDescr)
	case "1.3.6.1.2.1.1.2.0":
		return 0x06, encodeOIDBody(cfg.SysObjectID)
	case "1.3.6.1.2.1.1.3.0":
		return 0x43, uptimeBytes() // TimeTicks
	case "1.3.6.1.2.1.1.4.0":
		return 0x04, []byte(cfg.SysContact)
	case "1.3.6.1.2.1.1.5.0":
		return 0x04, []byte(cfg.SysName)
	case "1.3.6.1.2.1.1.6.0":
		return 0x04, []byte(cfg.SysLocation)
	case "1.3.6.1.2.1.1.7.0":
		return 0x02, intBytes(72) // sysServices
	default:
		return 0x04, []byte("PotAgent")
	}
}

func uptimeBytes() []byte {
	cs := int(time.Since(startTime) / (10 * time.Millisecond)) // TimeTicks = 1/100 秒
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(cs))
	return b
}

// ---- ASN.1 BER 基础编解码 ----

type tlv struct {
	tag  byte
	len  int
	val  []byte
	next int // 含头部在内的总字节数
}

func readTLV(b []byte) (tlv, bool) {
	if len(b) < 2 {
		return tlv{}, false
	}
	tag := b[0]
	idx := 1
	var l int
	if b[idx]&0x80 != 0 {
		n := int(b[idx] & 0x7f)
		idx++
		if len(b) < idx+n {
			return tlv{}, false
		}
		for i := 0; i < n; i++ {
			l = (l << 8) | int(b[idx])
			idx++
		}
	} else {
		l = int(b[idx])
		idx++
	}
	if len(b) < idx+l {
		return tlv{}, false
	}
	return tlv{tag: tag, len: l, val: b[idx : idx+l], next: idx + l}, true
}

func encodeTLV(tag byte, value []byte) []byte {
	return append([]byte{tag}, append(encodeLength(len(value)), value...)...)
}

func encodeLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(b))}, b...)
}

func intBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return b
}

func intFromBytes(b []byte) int {
	var n int
	for _, x := range b {
		n = (n << 8) | int(x)
	}
	return n
}

func encodeOID(oid string) []byte {
	return encodeTLV(0x06, encodeOIDBody(oid))
}

func encodeOIDBody(oid string) []byte {
	parts := strings.Split(oid, ".")
	sub := make([]int, 0, len(parts))
	for _, p := range parts {
		v, _ := strconv.Atoi(p)
		sub = append(sub, v)
	}
	var body []byte
	if len(sub) >= 2 {
		body = append(body, byte(40*sub[0]+sub[1]))
		sub = sub[2:]
	} else if len(sub) == 1 {
		body = append(body, byte(sub[0]))
	}
	for _, s := range sub {
		body = append(body, encodeSubID(s)...)
	}
	return body
}

func encodeSubID(n int) []byte {
	b := []byte{byte(n & 0x7f)}
	n >>= 7
	for n > 0 {
		b = append([]byte{byte(n&0x7f | 0x80)}, b...)
		n >>= 7
	}
	return b
}

func decodeOIDBody(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	first := int(b[0])
	parts := []string{strconv.Itoa(first / 40), strconv.Itoa(first % 40)}
	val := 0
	for i := 1; i < len(b); i++ {
		val = (val << 7) | int(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			parts = append(parts, strconv.Itoa(val))
			val = 0
		}
	}
	return strings.Join(parts, ".")
}

func localUDPAddr(packet *common.DummyUDPConn) *net.UDPAddr {
	la, _ := packet.UDPConn.LocalAddr().(*net.UDPAddr)
	if la == nil {
		return &net.UDPAddr{}
	}
	return la
}

func udpAddrToCommonAddr(a *net.UDPAddr) common.Addr {
	if a == nil {
		return common.Addr{}
	}
	return common.Addr{IP: a.IP.String(), Port: uint16(a.Port)}
}
