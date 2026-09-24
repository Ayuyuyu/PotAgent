// Package rdp 是一个低交互 RDP 蜜罐：按 MS-RDPBCGR 严格走完连接序列，
// 支持标准 RDP 安全 / TLS / NLA(CredSSP) 三种协商，能把一张 PNG 当桌面推给客户端，
// 并记录键鼠输入。
//
//   - RDP 必须按序走完 X.224 → MCS/GCC → 安全交换 → Client Info → Licensing →
//     Demand Active/Confirm Active → Synchronize/Control/Font Map 才能到达位图更新；
//     本包做到了同样的"静态桌面 + 键鼠记录"，代价是代码量高一个数量级。
//   - RDP 多出来的东西是凭据：标准 RDP 安全/TLS 下 Client Info 里的口令是用服务器
//     RSA 公钥加密的，我们持有私钥即可还原**明文口令**；NLA 下能拿到
//     **NetNTLMv2 响应**（hashcat -m 5600 或中继）。
package rdp

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"image"
	"net"
	"os"
	"path/filepath"
	"time"

	"potAgent/common"
	"potAgent/global"
	"potAgent/logger"
	"potAgent/services"
)

var (
	serviceName = "rdp"
	_           = services.Register(serviceName, RdpServiceInit)
)

// 协商模式
const (
	secModeNegotiate = "negotiate" // 按客户端请求挑最安全的一种
	secModeRDP       = "rdp"       // 强制标准 RDP 安全（RC4，能拿明文口令）
	secModeTLS       = "tls"       // 强制 TLS（能拿明文口令 + 能出画面）
	secModeHybrid    = "hybrid"    // 强制 NLA/CredSSP（只拿 NetNTLMv2）
)

const (
	// phaseTimeout 连接序列每个阶段的读超时
	phaseTimeout = 30 * time.Second
	// defaultIdleTimeout 会话建立后的空闲上限：蜜罐不能一直被闲置连接占着
	defaultIdleTimeout = 15 * time.Minute
	// typedBufferLimit 累计到这么多字符就把已输入内容落一次事件，避免事件过碎
	typedBufferLimit = 64
)

type rdpConfig struct {
	// Security 协商模式：negotiate / rdp / tls / hybrid
	Security string `mapstructure:"security"`
	// CertFile/KeyFile 为空时自动生成自签 RSA 证书（RDP 的 RSA 解密依赖私钥，必须是 RSA）
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
	KeyBits  int    `mapstructure:"key_bits"`
	// Hostname/Domain 会出现在服务器证书与 NLA 挑战（NetNTLMv2 的目标信息）里
	Hostname string `mapstructure:"hostname"`
	Domain   string `mapstructure:"domain"`
	// ImgPath 连接后展示的桌面图；Width/Height 为 0 时跟随客户端请求的分辨率
	ImgPath string `mapstructure:"img_path"`
	Width   int    `mapstructure:"width"`
	Height  int    `mapstructure:"height"`
	// LogPassword 是否把捕获到的明文口令写进事件
	LogPassword bool `mapstructure:"log_password"`
	// IdleTimeoutSeconds 空闲多久断开，0 用默认值
	IdleTimeoutSeconds int `mapstructure:"idle_timeout_seconds"`
}

func RdpServiceInit() services.Service {
	return services.Service{
		WorkerHandle:   rdpHandle,
		ServiceOptions: rdpConfig{},
	}
}

func rdpHandle(ctx context.Context, service *services.Service) {
	serviceOptions, ok := service.ServiceOptions.(rdpConfig)
	if !ok {
		logger.Log.Errorf("[rdp] 配置类型异常: %T", service.ServiceOptions)
		return
	}
	baseOptions := service.BaseOptions

	// 相对路径按 CWD 解析，语义与其它服务保持一致
	if pwd, err := filepath.Abs("."); err == nil && serviceOptions.ImgPath != "" &&
		!filepath.IsAbs(serviceOptions.ImgPath) {
		serviceOptions.ImgPath = filepath.Join(pwd, serviceOptions.ImgPath)
	}
	if serviceOptions.Domain == "" {
		serviceOptions.Domain = "WORKGROUP"
	}
	if serviceOptions.Hostname == "" {
		if hn, err := os.Hostname(); err == nil && hn != "" {
			serviceOptions.Hostname = hn
		} else {
			serviceOptions.Hostname = "WIN-SERVER"
		}
	}

	// 证书与密钥：
	//   tlsKey  —— TLS 握手用（也用于解 TLS 模式下 RSA 加密的口令字段），须是 RSA
	//   rdpKey  —— 标准 RDP 安全的专有证书密钥，协议历史约定为 512 位
	tlsKey, pair, err := loadOrGenRSAKey(serviceOptions.CertFile, serviceOptions.KeyFile, serviceOptions.KeyBits)
	if err != nil {
		logger.Log.Errorf("[rdp] 准备 TLS 证书失败: %v", err)
		return
	}
	rdpKey, err := generateRdpKey(512)
	if err != nil {
		logger.Log.Errorf("[rdp] 生成 RDP 专有证书密钥失败: %v", err)
		return
	}

	// 桌面图只解码一次，连接之间共享
	var desktop image.Image
	if serviceOptions.ImgPath != "" {
		img, err := loadPNG(serviceOptions.ImgPath)
		if err != nil {
			logger.Log.Errorf("[rdp] 无法加载桌面图 %s: %v", serviceOptions.ImgPath, err)
			return
		}
		desktop = img
	}

	address := fmt.Sprintf("%v:%v", baseOptions.Host, baseOptions.Port)
	listen, err := net.Listen("tcp4", address)
	if err != nil {
		logger.Log.Fatalln(err)
	}
	defer listen.Close()
	logger.Log.Infoln(baseOptions.Application, "listen on ", address,
		"(rdp/"+serviceOptions.Security+")")

	connChan := common.ForwardListenerToChan(listen)
	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", serviceName)
			return
		case conn := <-connChan:
			go handleServiceConn(conn, &serviceOptions, tlsKey, rdpKey, pair, desktop, baseOptions)
		}
	}
}

func handleServiceConn(conn net.Conn, cfg *rdpConfig, tlsKey *rsa.PrivateKey, rdpKey *rdpPrivateKey,
	pair tls.Certificate, desktop image.Image, base global.ServiceBaseConfig) {
	s := &rdpSession{
		cfg:     cfg,
		rdpKey:  rdpKey,
		tlsKey:  tlsKey,
		tlsPair: pair,
		srvImg:  desktop,
		name:    base.Application,
		conn:    conn,
	}
	defer func() {
		if r := recover(); r != nil {
			logger.Log.Debugf("[rdp] %s 连接处理异常: %v", s.srcIP(), r)
		}
		_ = conn.Close()
	}()

	if src, err := common.GetConnSrcIPAndSrcPort(&conn); err == nil {
		s.srcAddr = src
	}
	if dst, err := common.GetConnDstIPAndDstPort(&conn); err == nil {
		s.dstAddr = dst
	}
	s.push("rdp-connect", nil)

	// 任何 panic 都兜底成一条 rdp-error 事件，避免 mstsc 这类严格客户端触发
	// 的意外崩溃被静默吞掉（默认日志级看不到、event.log 也不会记录）。
	defer func() {
		if r := recover(); r != nil {
			logger.Log.Errorf("[rdp] %s 会话 panic: %v", s.srcIP(), r)
			s.push("rdp-error", map[string]interface{}{"stage": "panic", "reason": fmt.Sprintf("%v", r)})
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Hour)
	defer cancel()
	if err := s.run(ctx); err != nil {
		logger.Log.Warnf("[rdp] %s 会话结束: %v", s.srcIP(), err)
		// 把失败阶段记进 event.log（Info 级即可见），省去重编 Debug 版抓 stderr。
		s.push("rdp-error", map[string]interface{}{"stage": s.stage, "reason": err.Error(), "mcs_trace": s.mcsTrace})
	}
	s.flushTyping()
}
