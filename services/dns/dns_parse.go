package dns

import (
	"encoding/binary"
	"net"
	"strings"
)

// 常用查询类型
const (
	qtypeA    = 1
	qtypeAAAA = 28
)

// parseDNSQuery 解析事务 ID、查询名、查询类型，并返回问题段字节（用于回包时原样带上）。
func parseDNSQuery(buf []byte) (id uint16, qname string, qtype uint16, question []byte, ok bool) {
	if len(buf) < 12 {
		return 0, "", 0, nil, false
	}
	id = binary.BigEndian.Uint16(buf[0:2])
	qdcount := binary.BigEndian.Uint16(buf[4:6])
	if qdcount == 0 {
		return id, "", 0, nil, false
	}

	// 从 offset 12 起解析 qname 的标签形式
	off := 12
	var labels []string
	for off < len(buf) {
		l := int(buf[off])
		if l == 0 {
			off++
			break
		}
		if off+1+l > len(buf) {
			return id, strings.Join(labels, "."), 0, nil, false
		}
		labels = append(labels, string(buf[off+1:off+1+l]))
		off += 1 + l
	}
	// 之后 2 字节 qtype + 2 字节 qclass
	if off+4 > len(buf) {
		return id, strings.Join(labels, "."), 0, nil, false
	}
	qtype = binary.BigEndian.Uint16(buf[off : off+2])
	question = buf[12 : off+4]
	qname = strings.Join(labels, ".")
	return id, qname, qtype, question, true
}

// dnsRR 一条应答记录（名称用 0xC00C 压缩指针指回问题段，故这里只存类型与 RDATA）
type dnsRR struct {
	Type uint16
	Data []byte
}

// buildDNSResponse 用 12 字节头 + 原样问题段 + 应答记录拼出回包。
func buildDNSResponse(id uint16, question []byte, answers []dnsRR) []byte {
	resp := make([]byte, 0, 12+len(question)+256)
	// 头部
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	// QR=1 RD=1 RA=1 -> 0x8180
	binary.BigEndian.PutUint16(hdr[2:4], 0x8180)
	binary.BigEndian.PutUint16(hdr[4:6], 1)                    // QDCOUNT
	binary.BigEndian.PutUint16(hdr[6:8], uint16(len(answers))) // ANCOUNT
	resp = append(resp, hdr...)
	resp = append(resp, question...)
	for _, rr := range answers {
		resp = append(resp, encodeRR(rr)...)
	}
	return resp
}

// encodeRR 编码一条应答记录：RNAME(0xC00C) RTYPE RCLASS TTL RDLENGTH RDATA
func encodeRR(rr dnsRR) []byte {
	out := make([]byte, 0, 14+len(rr.Data))
	out = append(out, 0xC0, 0x0C)                       // 压缩指针，指向问题段里的 qname(offset 12)
	out = binaryAppendUint16(out, rr.Type)              // RTYPE
	out = binaryAppendUint16(out, 1)                    // RCLASS = IN
	out = binaryAppendUint32(out, 300)                  // TTL = 300s
	out = binaryAppendUint16(out, uint16(len(rr.Data))) // RDLENGTH
	out = append(out, rr.Data...)
	return out
}

func binaryAppendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func binaryAppendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// matchAnswers 先查配置里针对该 qname+qtype 的预置应答，未命中则按 qtype 用默认假记录。
func matchAnswers(qname string, qtype uint16, cfg *dnsConfig) []dnsRR {
	for _, a := range cfg.Answers {
		if !strings.EqualFold(a.Name, qname) {
			continue
		}
		t := dnsAnswerType(a.Type)
		if t == 0 || t != qtype {
			continue
		}
		if len(a.Values) == 0 {
			return nil
		}
		if rr := recordForValue(t, a.Values[0]); rr != nil {
			return []dnsRR{*rr}
		}
	}
	// 默认应答
	switch qtype {
	case qtypeA:
		if cfg.DefaultA != "" {
			if rr := recordForValue(qtypeA, cfg.DefaultA); rr != nil {
				return []dnsRR{*rr}
			}
		}
	case qtypeAAAA:
		if cfg.DefaultAAAA != "" {
			if rr := recordForValue(qtypeAAAA, cfg.DefaultAAAA); rr != nil {
				return []dnsRR{*rr}
			}
		}
	}
	return nil
}

// recordForValue 按类型把值编码成 RDATA；不支持/解析失败返回 nil。
func recordForValue(t uint16, value string) *dnsRR {
	switch t {
	case qtypeA:
		if ip := net.ParseIP(value).To4(); ip != nil {
			return &dnsRR{Type: qtypeA, Data: ip}
		}
	case qtypeAAAA:
		if ip := net.ParseIP(value); ip != nil {
			v16 := ip.To16()
			if v16 != nil {
				return &dnsRR{Type: qtypeAAAA, Data: v16}
			}
		}
	}
	return nil
}

func dnsAnswerType(s string) uint16 {
	switch strings.ToUpper(s) {
	case "A":
		return qtypeA
	case "AAAA":
		return qtypeAAAA
	}
	return 0
}

func qtypeToString(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	}
	return "TYPE" + itoa(t)
}

// 小整数转字符串，避免为此引入 strconv
func itoa(v uint16) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = digits[v%10]
		v /= 10
	}
	return string(b[i:])
}
