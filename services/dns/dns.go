package dns

import (
	"context"
	"fmt"
	"net"
	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"
)

var (
	serviceName = "dns"
	_           = services.Register(serviceName, DNSServiceInit)
)

func DNSServiceInit() services.Service {
	s := services.Service{
		WorkerHandle:   dnsHandle,
		ServiceOptions: dnsConfig{},
	}
	return s
}

type dnsConfig struct {
	// 未命中 answers 时，对任意 A 查询返回的假 IPv4
	DefaultA string `mapstructure:"default_a"`
	// 未命中 answers 时，对任意 AAAA 查询返回的假 IPv6
	DefaultAAAA string `mapstructure:"default_aaaa"`
	// 针对特定查询名的预置应答
	Answers []dnsAnswer `mapstructure:"answers"`
}

type dnsAnswer struct {
	Name   string   `mapstructure:"name"`
	Type   string   `mapstructure:"type"` // A / AAAA
	Values []string `mapstructure:"values"`
}

// DNS 低交互蜜罐：监听 UDP，解析查询并记录事件，回一个尽量像样的应答。
func dnsHandle(ctx context.Context, service *services.Service) {
	var (
		serviceOptions = service.ServiceOptions.(dnsConfig)
		baseOptions    = service.BaseOptions
	)
	logger.Log.Debugln(serviceOptions, baseOptions)

	address := fmt.Sprintf("%v:%v", baseOptions.Host, baseOptions.Port)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(baseOptions.Host), Port: int(baseOptions.Port)})
	if err != nil {
		logger.Log.Fatalln(err)
	}
	defer conn.Close()
	logger.Log.Infoln(baseOptions.Application, "listen on ", address)

	// 读包 goroutine，在通道上喂包
	packetChan := common.ForwardUDPPacketToChan(conn)

	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", serviceName)
			return
		case packet := <-packetChan:
			handleUDPPacket(packet, service, &serviceOptions)
		}
	}
}

func handleUDPPacket(packet *common.DummyUDPConn, service *services.Service, cfg *dnsConfig) {
	id, qname, qtype, question, ok := parseDNSQuery(packet.Data)

	src := udpAddrToCommonAddr(packet.UDPAddr)
	dst := udpAddrToCommonAddr(localUDPAddr(packet))

	event.EventPush(event.NewEvent(serviceName, "dns-query", src, dst, map[string]interface{}{
		"protocol":     service.BaseOptions.Protocol,
		"application":  service.BaseOptions.Application,
		"ip_protocol":  "udp",
		"dns.query-id": id,
		"dns.qname":    qname,
		"dns.qtype":    qtypeToString(qtype),
		"dns.raw":      fmt.Sprintf("%x", packet.Data),
	}))

	if !ok {
		// 报文残缺，不回包（低交互）
		return
	}

	answers := matchAnswers(qname, qtype, cfg)
	resp := buildDNSResponse(id, question, answers)
	if _, err := packet.WriteToUDP(resp, packet.UDPAddr); err != nil {
		logger.Log.Debug("dns: write response failed:", err)
	}
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
