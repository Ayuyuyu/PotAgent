package ldap

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"

	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"
)

// LDAP 低交互蜜罐：监听 TCP 389，解析 ASN.1 BER 编码的 LDAPMessage，
// 对 Bind(Simple/SASL/匿名) 一律回 success、对 Search 回一份诱饵条目 + SearchResultDone，
// 并捕获 DN/口令/过滤器等凭据情报（扫描器常用弱口令或匿名绑定枚举目录）。
var _ = services.Register("ldap", LDAPServiceInit)

func LDAPServiceInit() services.Service {
	return services.Service{
		WorkerHandle:   ldapHandle,
		ServiceOptions: ldapConfig{},
	}
}

type ldapConfig struct {
	BaseDN    string     `mapstructure:"base_dn"`    // 伪目录基准 DN，Search 回应的条目据此构造诱饵属性
	FakeEntry []ldapAttr `mapstructure:"fake_entry"` // 可选：Search 回应的诱饵条目属性；空则用内置默认
}

// ldapAttr 单条属性（类型 + 一个或多个值），对应 LDAP PartialAttribute。
type ldapAttr struct {
	Type   string   `mapstructure:"type"`
	Values []string `mapstructure:"values"`
}

func ldapHandle(ctx context.Context, service *services.Service) {
	cfg := service.ServiceOptions.(ldapConfig)
	if cfg.BaseDN == "" {
		cfg.BaseDN = "dc=example,dc=com"
	}

	address := fmt.Sprintf("%v:%v", service.BaseOptions.Host, service.BaseOptions.Port)
	listen, err := net.Listen("tcp4", address)
	if err != nil {
		logger.Log.Fatalln(err)
		return
	}
	defer listen.Close()
	logger.Log.Infoln(service.BaseOptions.Application, "listen on", address)

	connChan := common.ForwardListenerToChan(listen)
	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", service.BaseOptions.Protocol)
			return
		case conn := <-connChan:
			go ldapHandleConn(conn, service, &cfg)
		}
	}
}

// ldapHandleConn 处理单条连接上的全部 LDAPMessage（连接级多请求，按 BER 长度帧切分）。
func ldapHandleConn(conn net.Conn, service *services.Service, cfg *ldapConfig) {
	defer conn.Close()
	src, _ := common.GetConnSrcIPAndSrcPort(&conn)
	dst, _ := common.GetConnDstIPAndDstPort(&conn)
	br := bufio.NewReader(conn)

	for {
		m, ok := readTLVReader(br)
		if !ok || m.tag != 0x30 {
			return
		}
		msgID, opTag, opVal, ok := parseLDAPMessage(m.val)
		if !ok {
			return
		}
		raw := hex.EncodeToString(append([]byte{m.tag}, append(encodeLength(m.len), m.val...)...))

		switch opTag {
		case 0x60: // bindRequest
			version, dn, authType, password, mech := parseBindRequest(opVal)
			extra := map[string]interface{}{
				"ldap.bind_version": version,
				"ldap.dn":           dn,
				"ldap.auth_type":    authType,
			}
			if authType == "simple" {
				extra["ldap.password"] = password
			}
			if authType == "sasl" {
				extra["ldap.sasl_mechanism"] = mech
			}
			pushLDAPEvent(service, "ldap-bind", msgID, opTag, raw, src, dst, extra)
			conn.Write(buildBindResponse(msgID))

		case 0x63: // searchRequest
			base, scope, filter, _, attrs := parseSearchRequest(opVal)
			extra := map[string]interface{}{
				"ldap.base":       base,
				"ldap.scope":      scope,
				"ldap.filter":     filter,
				"ldap.attributes": attrs,
			}
			pushLDAPEvent(service, "ldap-search", msgID, opTag, raw, src, dst, extra)
			conn.Write(buildSearchResultEntry(msgID, entryDN(cfg), buildFakeAttributes(cfg.FakeEntry)))
			conn.Write(buildSearchResultDone(msgID))

		case 0x62: // unbindRequest
			pushLDAPEvent(service, "ldap-unbind", msgID, opTag, raw, src, dst, nil)
			return

		case 0x70: // abandonRequest（无响应）
			pushLDAPEvent(service, "ldap-abandon", msgID, opTag, raw, src, dst, nil)
			return

		case 0x77: // extendedRequest（如 StartTLS 1.3.6.1.4.1.1466.20037）
			extra := map[string]interface{}{"ldap.oid": parseExtendedOID(opVal)}
			pushLDAPEvent(service, "ldap-extended", msgID, opTag, raw, src, dst, extra)
			conn.Write(buildResultResponse(msgID, 0x78))

		default:
			if respTag := opResponseTag(opTag); respTag != 0 {
				conn.Write(buildResultResponse(msgID, respTag))
			}
			pushLDAPEvent(service, "ldap-request", msgID, opTag, raw, src, dst, nil)
		}
	}
}

func pushLDAPEvent(service *services.Service, et string, msgID int, opTag byte, raw string, src, dst common.Addr, extra map[string]interface{}) {
	fields := map[string]interface{}{
		"ip_protocol":     "tcp",
		"protocol":        service.BaseOptions.Protocol,
		"application":     service.BaseOptions.Application,
		"ldap.message_id": msgID,
		"ldap.op":         opName(opTag),
		"ldap.raw":        raw,
	}
	for k, v := range extra {
		if v != nil {
			fields[k] = v
		}
	}
	event.EventPush(event.NewEvent(service.BaseOptions.Protocol, et, src, dst, fields))
}

// ---- LDAPMessage 解析 ----

func parseLDAPMessage(b []byte) (msgID int, opTag byte, opVal []byte, ok bool) {
	idTLV, ok := readTLV(b)
	if !ok || idTLV.tag != 0x02 {
		return 0, 0, nil, false
	}
	msgID = intFromBytes(idTLV.val)
	rest := b[idTLV.next:]
	opTLV, ok := readTLV(rest)
	if !ok {
		return 0, 0, nil, false
	}
	return msgID, opTLV.tag, opTLV.val, true
}

func parseBindRequest(b []byte) (version int, dn, authType, password, mech string) {
	ver, ok := readTLV(b)
	if !ok {
		return
	}
	version = intFromBytes(ver.val)
	rest := b[ver.next:]
	name, ok := readTLV(rest)
	if !ok {
		return
	}
	dn = string(name.val)
	rest = rest[name.next:]
	auth, ok := readTLV(rest)
	if !ok {
		return
	}
	switch auth.tag {
	case 0x80: // simple [0] OCTET STRING
		authType = "simple"
		password = string(auth.val)
	case 0xa3: // sasl [3] SEQUENCE { mechanism, credentials }
		authType = "sasl"
		mech = parseSaslMechanism(auth.val)
	default:
		authType = "unknown"
	}
	return
}

func parseSaslMechanism(b []byte) string {
	m, ok := readTLV(b)
	if !ok || m.tag != 0x04 {
		return ""
	}
	return string(m.val)
}

func parseSearchRequest(b []byte) (base string, scope int, filter, filterRaw string, attributes []string) {
	baseTLV, ok := readTLV(b)
	if !ok {
		return
	}
	base = string(baseTLV.val)
	rest := b[baseTLV.next:]
	scopeTLV, ok := readTLV(rest)
	if !ok {
		return
	}
	scope = intFromBytes(scopeTLV.val)
	rest = rest[scopeTLV.next:]
	// derefAliases ENUMERATED
	if deref, ok := readTLV(rest); ok {
		rest = rest[deref.next:]
	}
	// sizeLimit INTEGER
	if size, ok := readTLV(rest); ok {
		rest = rest[size.next:]
	}
	// timeLimit INTEGER
	if tim, ok := readTLV(rest); ok {
		rest = rest[tim.next:]
	}
	// typesOnly BOOLEAN
	if ty, ok := readTLV(rest); ok {
		rest = rest[ty.next:]
	}
	// filter
	filt, ok := readTLV(rest)
	if !ok {
		return
	}
	filter = decodeFilterBytes(encodeTLV(filt.tag, filt.val))
	rest = rest[filt.next:]
	// attributes SEQUENCE OF OCTET STRING
	attrs, ok := readTLV(rest)
	if !ok {
		return
	}
	a := attrs.val
	for len(a) > 0 {
		at, ok := readTLV(a)
		if !ok {
			break
		}
		attributes = append(attributes, string(at.val))
		a = a[at.next:]
	}
	return
}

func parseExtendedOID(b []byte) string {
	t, ok := readTLV(b)
	if !ok {
		return ""
	}
	return string(t.val)
}

func opResponseTag(op byte) byte {
	switch op {
	case 0x66:
		return 0x67 // modifyRequest -> modifyResponse
	case 0x68:
		return 0x69 // addRequest -> addResponse
	case 0x6a:
		return 0x6b // delRequest -> delResponse
	case 0x6c:
		return 0x6d // modDNRequest -> modDNResponse
	case 0x6e:
		return 0x6f // compareRequest -> compareResponse
	case 0x77:
		return 0x78 // extendedRequest -> extendedResponse
	}
	return 0
}

func opName(tag byte) string {
	names := map[byte]string{
		0x60: "bindRequest", 0x61: "bindResponse", 0x62: "unbindRequest",
		0x63: "searchRequest", 0x64: "searchResultEntry", 0x65: "searchResultDone",
		0x66: "modifyRequest", 0x67: "modifyResponse", 0x68: "addRequest", 0x69: "addResponse",
		0x6a: "delRequest", 0x6b: "delResponse", 0x6c: "modDNRequest", 0x6d: "modDNResponse",
		0x6e: "compareRequest", 0x6f: "compareResponse", 0x70: "abandonRequest",
		0x77: "extendedRequest", 0x78: "extendedResponse",
	}
	if n, ok := names[tag]; ok {
		return n
	}
	return fmt.Sprintf("0x%02x", tag)
}

// decodeFilterBytes 从完整过滤器 TLV 字节解码为可读字符串，便于事件落盘。
func decodeFilterBytes(b []byte) string {
	t, ok := readTLV(b)
	if !ok {
		return ""
	}
	return decodeFilter(t.tag, t.val)
}

// decodeFilter 解析单个过滤器 TLV（tag 为 CHOICE 标签，val 为其内容）。
func decodeFilter(tag byte, val []byte) string {
	switch tag {
	case 0xa0: // and
		return "(&" + joinFilters(val) + ")"
	case 0xa1: // or
		return "(|" + joinFilters(val) + ")"
	case 0xa2: // not（内含单个子过滤器）
		sub, ok := readTLV(val)
		if !ok {
			return "(! )"
		}
		return "(! " + decodeFilter(sub.tag, sub.val) + ")"
	case 0xa3: // equalityMatch
		return decodeAttrVal(val, "=")
	case 0xa4: // substrings
		return decodeAttrVal(val, "=") + "*"
	case 0xa5: // greaterOrEqual
		return decodeAttrVal(val, ">=")
	case 0xa6: // lessOrEqual
		return decodeAttrVal(val, "<=")
	case 0xa7: // present
		return "(" + string(val) + "=*)"
	case 0xa8: // approxMatch
		return decodeAttrVal(val, "~=")
	default:
		return fmt.Sprintf("(filter:0x%02x)", tag)
	}
}

func joinFilters(b []byte) string {
	var parts []string
	for len(b) > 0 {
		t, ok := readTLV(b)
		if !ok {
			break
		}
		parts = append(parts, decodeFilter(t.tag, t.val))
		b = b[t.next:]
	}
	return strings.Join(parts, "")
}

func decodeAttrVal(b []byte, op string) string {
	a, ok := readTLV(b)
	if !ok || a.tag != 0x04 {
		return ""
	}
	rest := b[a.next:]
	v, ok := readTLV(rest)
	if !ok {
		return "(" + string(a.val) + op + ")"
	}
	return "(" + string(a.val) + op + string(v.val) + ")"
}

// ---- LDAPMessage 构造 ----

func buildBindResponse(msgID int) []byte {
	op := encodeTLV(0x61, resultBytes())
	return encodeTLV(0x30, append(encodeTLV(0x02, intBytes(msgID)), op...))
}

func buildResultResponse(msgID int, respTag byte) []byte {
	op := encodeTLV(respTag, resultBytes())
	return encodeTLV(0x30, append(encodeTLV(0x02, intBytes(msgID)), op...))
}

func buildSearchResultDone(msgID int) []byte {
	return buildResultResponse(msgID, 0x65)
}

// resultBytes：resultCode(success=0) + matchedDN(空) + diagnosticMessage(空)
func resultBytes() []byte {
	var b []byte
	b = append(b, encodeTLV(0x0a, []byte{0})...) // ENUMERATED success
	b = append(b, encodeTLV(0x04, []byte{})...)  // matchedDN
	b = append(b, encodeTLV(0x04, []byte{})...)  // diagnosticMessage
	return b
}

func buildSearchResultEntry(msgID int, dn string, attrs []byte) []byte {
	entry := encodeTLV(0x04, []byte(dn))
	entry = append(entry, encodeTLV(0x30, attrs)...)
	op := encodeTLV(0x64, entry)
	return encodeTLV(0x30, append(encodeTLV(0x02, intBytes(msgID)), op...))
}

// buildFakeAttributes 构造一份像真实账户的 PartialAttributeList 诱饵。
// entries 为空时回落到 defaultFakeAttributes（保证不配 yaml 也有合理默认）。
func buildFakeAttributes(entries []ldapAttr) []byte {
	list := entries
	if len(list) == 0 {
		list = defaultFakeAttributes()
	}
	var out []byte
	for _, a := range list {
		var vals []byte
		for _, v := range a.Values {
			vals = append(vals, encodeTLV(0x04, []byte(v))...)
		}
		attr := encodeTLV(0x04, []byte(a.Type))
		attr = append(attr, encodeTLV(0x31, vals)...) // SET OF AttributeValue
		out = append(out, encodeTLV(0x30, attr)...)
	}
	return out
}

// defaultFakeAttributes 内置默认诱饵属性（与历史行为一致），yaml 未配 fake_entry 时使用。
func defaultFakeAttributes() []ldapAttr {
	return []ldapAttr{
		{"objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"}},
		{"cn", []string{"admin"}},
		{"sn", []string{"admin"}},
		{"uid", []string{"admin"}},
		{"mail", []string{"admin@example.com"}},
		{"userPassword", []string{"{SSHA}p0t4g3nt"}},
	}
}

// entryDN 计算 Search 回应的条目 DN：优先用 fake_entry 里的 cn 作 RDN，否则回落 cn=admin。
func entryDN(cfg *ldapConfig) string {
	for _, a := range cfg.FakeEntry {
		if a.Type == "cn" && len(a.Values) > 0 {
			return "cn=" + a.Values[0] + "," + cfg.BaseDN
		}
	}
	return "cn=admin," + cfg.BaseDN
}

// ---- ASN.1 BER 基础编解码 ----

type tlv struct {
	tag  byte
	len  int
	val  []byte
	next int // 含头部在内的总字节数（针对切片解析）
}

// readTLV 从切片解析一个 TLV（用于已帧化的消息内容）。
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

// readTLVReader 从 bufio.Reader 帧化读取一个完整 TLV，自动处理 TCP 分包。
func readTLVReader(br *bufio.Reader) (tlv, bool) {
	tag, err := br.ReadByte()
	if err != nil {
		return tlv{}, false
	}
	l, ok := readBERLengthReader(br)
	if !ok {
		return tlv{}, false
	}
	val := make([]byte, l)
	if _, err := io.ReadFull(br, val); err != nil {
		return tlv{}, false
	}
	header := []byte{tag}
	header = append(header, encodeLength(l)...)
	return tlv{tag: tag, len: l, val: val, next: len(header) + l}, true
}

func readBERLengthReader(br *bufio.Reader) (int, bool) {
	b, err := br.ReadByte()
	if err != nil {
		return 0, false
	}
	if b&0x80 == 0 {
		return int(b), true
	}
	n := int(b & 0x7f)
	length := 0
	for i := 0; i < n; i++ {
		x, err := br.ReadByte()
		if err != nil {
			return 0, false
		}
		length = (length << 8) | int(x)
	}
	return length, true
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
