package ntp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"
)

// ntp 与 sntp 在线格式完全一致（SNTP 即 NTP 的简化子集，均用 UDP 123、同样的 48 字节报文），
// 故共用同一实现，仅由 yaml 的 protocol 决定事件分类（event_category = "ntp"/"sntp"）。
var (
	_ = services.Register("ntp", NTPServiceInit)
	_ = services.Register("sntp", NTPServiceInit)
)

// ntpEpochOffset 是 1900-01-01 与 1970-01-01 之间的秒数差：NTP 时间戳以 1900 为纪元。
const ntpEpochOffset = 2208988800

// ntpSize 是 NTP/SNTP 报文最小长度（不含扩展/认证字段）。
const ntpSize = 48

func NTPServiceInit() services.Service {
	return services.Service{
		WorkerHandle:   ntpHandle,
		ServiceOptions: ntpConfig{},
	}
}

type ntpConfig struct {
	// 响应中的 stratum：2=二级服务器（默认），1=一级/原子钟。
	Stratum int `mapstructure:"stratum"`
	// 4 字节参考标识（ASCII，不足补 0、超长截断），如上游服务器 IP 或 "LOCL"/"GPS"。
	RefID string `mapstructure:"ref_id"`
}

// NTP 低交互蜜罐：监听 UDP，解析请求并按规范构造一个“当前时间”的合法响应，
// 让连接方以为这是个正常的 NTP/SNTP 服务器；同时落 ntp-request/sntp-request 事件。
func ntpHandle(ctx context.Context, service *services.Service) {
	cfg := service.ServiceOptions.(ntpConfig)
	if cfg.Stratum == 0 {
		cfg.Stratum = 2
	}
	refU32 := refID4(cfg.RefID)

	proto := service.BaseOptions.Protocol
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
			logger.Log.Infof("%s service close", proto)
			return
		case packet := <-packetChan:
			handleNTP(packet, service, &cfg, refU32, proto)
		}
	}
}

func handleNTP(packet *common.DummyUDPConn, service *services.Service, cfg *ntpConfig, refU32 uint32, proto string) {
	req := packet.Data
	src := common.Addr{IP: packet.UDPAddr.IP.String(), Port: uint16(packet.UDPAddr.Port)}
	dst := udpAddrToCommonAddr(localUDPAddr(packet))

	var vn, mode uint8
	if len(req) > 0 {
		b0 := req[0]
		vn = (b0 >> 3) & 0x7
		mode = b0 & 0x7
	}

	event.EventPush(event.NewEvent(proto, proto+"-request", src, dst, map[string]interface{}{
		"ip_protocol":  "udp",
		"protocol":     service.BaseOptions.Protocol,
		"application":  service.BaseOptions.Application,
		"ntp.version":  vn,
		"ntp.mode":     mode,
		"ntp.raw":      fmt.Sprintf("%x", req),
	}))

	resp := buildNTPResponse(req, cfg, refU32, vn)
	if _, err := packet.WriteToUDP(resp, packet.UDPAddr); err != nil {
		logger.Log.Debug("ntp: write response failed:", err)
	}
}

// buildNTPResponse 按 RFC 5905/4330 构造 48 字节服务器响应：
//   - 首字节 LI=0、VN=客户端版本(缺省 4)、Mode=4(server)
//   - Originate Timestamp 回显客户端 Transmit Timestamp（请求 40-47 字节）
//   - Receive/Transmit Timestamp 与 Reference Timestamp 均填当前时间
//   - 请求不足 48 字节也照常回合法响应（低交互蜜罐尽量应答）
func buildNTPResponse(req []byte, cfg *ntpConfig, refU32 uint32, vn uint8) []byte {
	resp := make([]byte, ntpSize)
	if len(req) >= ntpSize {
		copy(resp, req[:ntpSize]) // 先整体拷贝，下面再覆盖需要重算的字段
	}
	if vn == 0 {
		vn = 4
	}
	sec, frac := ntpStamp(time.Now())
	stamp := uint64(sec)<<32 | uint64(frac)

	resp[0] = (0 << 6) | ((vn & 0x7) << 3) | 0x4 // LI=0, VN, Mode=4
	resp[1] = byte(cfg.Stratum)                  // stratum
	resp[2] = 10                                 // poll: log2(1024s)
	resp[3] = 0xEC                               // precision: -20 (~1us)
	// resp[4:12] root delay / root dispersion 保持 0
	binary.BigEndian.PutUint32(resp[12:16], refU32) // reference id
	binary.BigEndian.PutUint64(resp[16:24], stamp)  // reference timestamp
	// originate timestamp = 客户端的 transmit timestamp（请求 40-47 字节，RFC 5905）
	if len(req) >= ntpSize {
		copy(resp[24:32], req[40:48])
	}
	binary.BigEndian.PutUint64(resp[32:40], stamp) // receive timestamp
	binary.BigEndian.PutUint64(resp[40:48], stamp) // transmit timestamp
	return resp
}

// ntpStamp 将 time.Time 编码为 NTP 64 位定点时间戳（高 32 位秒、低 32 位 2^-32 秒）。
func ntpStamp(t time.Time) (uint32, uint32) {
	sec := uint32(t.Unix() + ntpEpochOffset)
	frac := uint32(float64(t.Nanosecond()) / 1e9 * (1 << 32))
	return sec, frac
}

// refID4 将至多 4 字符的 ASCII 参考标识编码为 uint32（默认 "LOCL"）。
func refID4(s string) uint32 {
	if s == "" {
		s = "LOCL"
	}
	b := []byte(s)
	var v uint32
	for i := 0; i < 4; i++ {
		c := byte(0)
		if i < len(b) {
			c = b[i]
		}
		v = (v << 8) | uint32(c)
	}
	return v
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
