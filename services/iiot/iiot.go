package iiot

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"
)

// serviceName 是全部 ICS/IIoT 协议事件的事件类别（event_category=iiot）。
var serviceName = "iiot"

// protocolKeys 是本包注册的协议 key，与 services_conf/<key>.yaml 里的 protocol 字段一一对应。
// 参考 services/http 用一个 InitFn 同时注册 http/https 的做法，这里也共用一个 InitFn。
var protocolKeys = []string{
	"modbus",
	"s7",
	"cip",
	"fins",
	"mitsubishi_a1e",
	"mitsubishi_qna3e",
	"bacnet",
	"mqtt",
	"mqtts",
}

func init() {
	for _, key := range protocolKeys {
		if err := services.Register(key, iiotServiceInit); err != nil {
			logger.Log.Error("iiot: register service failed: ", err)
		}
	}
}

// iiotServiceInit 被全部 IIoT 协议 key 共用，具体协议在 WorkerHandle 里按 protocol 分派。
func iiotServiceInit() services.Service {
	return services.Service{
		WorkerHandle:   iiotHandle,
		ServiceOptions: iiotConfig{},
	}
}

// iiotConfig 是各 ICS/IIoT 协议共用的服务配置（字段按协议取用，注释里标了适用范围）。
type iiotConfig struct {
	// 【全部】可选，对外声称的厂商/型号，仅写入事件 details 增加仿真度（如 "Siemens S7-300"）。
	Vendor string `mapstructure:"vendor"`
	// 【全部】可选十六进制串（如 "01020304"，容忍空格/逗号/短横线）：
	// “从未被写过的地址”读出来的数据（按需平铺/截断）；留空 = 全 0。
	DefaultValue string `mapstructure:"default_value"`
	// 【全部】true 时写请求只确认、不落数据（内存与 store_file 都不写），读到的永远是默认值。
	ReadOnly bool `mapstructure:"read_only"`
	// 【全部】可选：写数据持久化文件（JSON 快照，重启后还能读到写入的值）；留空 = 仅内存。
	StoreFile string `mapstructure:"store_file"`

	// 【modbus】站号过滤：配置后请求站号不一致不响应（0 = 不过滤，默认 1）。
	UnitID uint8 `mapstructure:"unit_id"`
	// 【fins】FINS/TCP 握手应答里的服务器节点编号（默认 1）。
	Node uint8 `mapstructure:"node"`
	// 【cip】预置标签值（初值），读的优先级：已写入数据 > 预置标签 > 默认值。
	Tags []cipTag `mapstructure:"tags"`
	// 【bacnet】设备实例号（I-Am 里的 device id，默认 1234）。
	DeviceID uint32 `mapstructure:"device_id"`
	// 【bacnet】厂商 ID（I-Am 里的 vendor id，默认 15）。
	VendorID uint16 `mapstructure:"vendor_id"`
	// 【bacnet】设备对象名（object-name 属性，默认 "PotAgent"）。
	DeviceName string `mapstructure:"device_name"`

	// 【mqtt】预置（保留消息初值）：客户端订阅命中时回给它，
	// 被 retain=1 的发布覆盖后以最新值为准。
	Topics []mqttTopic `mapstructure:"topics"`
	// 【mqtt】true 时把 retain=0 的发布也当作保留消息存下来（默认 false，按 MQTT 规范
	// 只有 retain=1 的消息才留给后续订阅者；retain=0 只实时转发给在线订阅者）。
	RetainAll bool `mapstructure:"retain_all"`
	// 【mqtt/mqtts】可选 TLS：配置 cert_file 后以 TLS 收连接；mqtts 必须配置。
	Tls tlsConfig `mapstructure:"tls"`
}

// cipTag 是 cip 的预置标签配置。
type cipTag struct {
	Name  string `mapstructure:"name"`
	Value string `mapstructure:"value"` // 十六进制串
}

// mqttTopic 是 mqtt 的预置消息配置。
type mqttTopic struct {
	Topic   string `mapstructure:"topic"`
	Payload string `mapstructure:"payload"`
	QoS     byte   `mapstructure:"qos"`
	Retain  bool   `mapstructure:"retain"`
}

// tlsConfig 可选的 TLS 配置（字段与 services/http 一致）。
type tlsConfig struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

// cipTagValue 按标签名取预置值；未配置或解析失败返回 nil。
func (c *iiotConfig) cipTagValue(name string) []byte {
	if c == nil {
		return nil
	}
	for _, tag := range c.Tags {
		if tag.Name != name {
			continue
		}
		if b, err := hexToBytes(tag.Value); err == nil && len(b) > 0 {
			return b
		}
		return nil
	}
	return nil
}

// storeMaxAreaBytes 是单个存储区的大小上限，防止异常报文把内存打爆。
const storeMaxAreaBytes = 1 << 20

// dataStore 保存写操作落下的数据：读请求优先取这里，没写过的地址回退 default_value/零值。
// 生命周期与某个服务实例（某个 yaml 配置）一致，多个连接共享，所以需要加锁。
type dataStore struct {
	mu    sync.Mutex
	cfg   *iiotConfig
	file  string
	areas map[string][]byte
}

func newDataStore(cfg *iiotConfig) *dataStore {
	s := &dataStore{cfg: cfg, areas: make(map[string][]byte)}
	if cfg != nil && cfg.StoreFile != "" {
		s.file = cfg.StoreFile
		s.load()
		logger.Log.Infoln("iiot: loaded store file ", s.file)
	}
	return s
}

// read 返回 [offset, offset+length)：写过的字节优先，没写过的用默认值/零补齐。
func (s *dataStore) read(area string, offset, length int) []byte {
	out := defaultBytes(s.cfg, length)
	if s == nil || length <= 0 {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data := s.areas[area]
	if offset < 0 || offset >= len(data) {
		return out
	}
	copy(out, data[offset:])
	return out
}

// get 取某个区已写入的全部数据（未写过返回 nil）。
func (s *dataStore) get(area string) []byte {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte{}, s.areas[area]...)
}

// write 覆盖写 [offset, offset+len(value))；read_only 或越界时返回 false。
func (s *dataStore) write(area string, offset int, value []byte) bool {
	if s == nil || len(value) == 0 {
		return false
	}
	if s.cfg != nil && s.cfg.ReadOnly {
		return false
	}
	if offset < 0 || offset+len(value) > storeMaxAreaBytes {
		logger.Log.Debug("iiot: store write out of range: ", area, " offset ", offset)
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data := s.areas[area]
	if end := offset + len(value); len(data) < end {
		grown := make([]byte, end)
		copy(grown, data)
		data = grown
	}
	copy(data[offset:], value)
	s.areas[area] = data
	s.save()
	return true
}

// set 写入某个区的完整内容（一般用于标签这类整体值）。
func (s *dataStore) set(area string, value []byte) bool {
	if s == nil || len(value) == 0 {
		return false
	}
	if s.cfg != nil && s.cfg.ReadOnly {
		return false
	}
	if len(value) > storeMaxAreaBytes {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.areas[area] = append([]byte{}, value...)
	s.save()
	return true
}

// del 删除某个区（例如 MQTT 收到空 payload 的保留消息 = 清除该主题）。
func (s *dataStore) del(area string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.areas, area)
	s.save()
}

// snapshot 取某个前缀下的全部区（区名去掉前缀作为 key），用于 MQTT 订阅时回放已发布主题。
func (s *dataStore) snapshot(prefix string) map[string][]byte {
	out := make(map[string][]byte)
	if s == nil {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.areas {
		if strings.HasPrefix(k, prefix) {
			out[strings.TrimPrefix(k, prefix)] = append([]byte{}, v...)
		}
	}
	return out
}

// setBit / getBit 用于按“位在字节里”寻址的协议（S7、三菱）。
// getBit 会用默认值兜底；setBit 基于当前值（含默认值）做读改写。
func (s *dataStore) getBit(area string, byteOffset int, bit uint) byte {
	return (s.read(area, byteOffset, 1)[0] >> bit) & 0x01
}

func (s *dataStore) setBit(area string, byteOffset int, bit uint, on bool) bool {
	if s == nil || byteOffset < 0 || byteOffset >= storeMaxAreaBytes {
		return false
	}
	if s.cfg != nil && s.cfg.ReadOnly {
		return false
	}
	cur := s.read(area, byteOffset, 1)[0]
	if on {
		cur |= 1 << bit
	} else {
		cur &^= 1 << bit
	}
	return s.write(area, byteOffset, []byte{cur})
}

// storeSnapshot 是 store_file 的 JSON 结构（区名 -> hex）。
type storeSnapshot struct {
	Areas map[string]string `json:"areas"`
}

// save 要求调用方已持有锁。
func (s *dataStore) save() {
	if s.file == "" {
		return
	}
	snap := storeSnapshot{Areas: make(map[string]string, len(s.areas))}
	for k, v := range s.areas {
		snap.Areas[k] = hex.EncodeToString(v)
	}
	if b, err := json.Marshal(snap); err == nil {
		if err := os.WriteFile(s.file, b, 0o600); err != nil {
			logger.Log.Error("iiot: save store file failed: ", err)
		}
	}
}

func (s *dataStore) load() {
	b, err := os.ReadFile(s.file)
	if err != nil {
		return
	}
	var snap storeSnapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		logger.Log.Error("iiot: load store file failed: ", err)
		return
	}
	for k, v := range snap.Areas {
		if data, err := hex.DecodeString(v); err == nil {
			s.areas[k] = data
		}
	}
}

// resolvePathRelativeToCwd 相对路径按当前工作目录解析（与 services/http 一致；
// 注意不能用 common.InsertDirIfNotAbsolutePath，它基于源文件位置而不是 CWD）。
func resolvePathRelativeToCwd(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	if pwd, err := os.Getwd(); err == nil {
		return filepath.Join(pwd, p)
	}
	return p
}

// loadTLSConfig 按配置加载证书；require=true（mqtts）时必须配置，否则报错退出。
func loadTLSConfig(cfg *iiotConfig, require bool) (*tls.Config, error) {
	if cfg == nil || cfg.Tls.CertFile == "" {
		if require {
			return nil, fmt.Errorf("iiot: 协议 mqtts 需要在 yaml 里配置 tls.cert_file / tls.key_file")
		}
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(
		resolvePathRelativeToCwd(cfg.Tls.CertFile),
		resolvePathRelativeToCwd(cfg.Tls.KeyFile),
	)
	if err != nil {
		return nil, fmt.Errorf("iiot: 加载 TLS 证书失败: %w", err)
	}
	logger.Log.Infoln("iiot: TLS enabled, cert =", cfg.Tls.CertFile)
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

// iiotHandle 按协议选择 TCP / UDP 收包方式，其余交给各协议处理函数。
func iiotHandle(ctx context.Context, service *services.Service) {
	base := service.BaseOptions
	cfg := service.ServiceOptions.(iiotConfig)
	// 存储与某个服务实例绑定：同配置的多个连接共享一份数据
	store := newDataStore(&cfg)
	// MQTT 的在线会话表（用于把发布实时转发给已订阅的客户端）
	broker := newMQTTBroker()

	if base.Protocol == "bacnet" {
		handleBacnet(ctx, service, &cfg, store)
		return
	}

	// 可选 TLS：目前只有 MQTT 用（IIoT 场景里 MQTT over TLS 很常见）
	tlsConf, err := loadTLSConfig(&cfg, base.Protocol == "mqtts")
	if err != nil {
		logger.Log.Fatalln(err)
	}

	address := fmt.Sprintf("%v:%v", base.Host, base.Port)
	listen, err := net.Listen("tcp4", address)
	if err != nil {
		logger.Log.Fatalln(err)
	}
	defer listen.Close()
	logger.Log.Infoln(base.Application, "listen on ", address)

	connChan := common.ForwardListenerToChan(listen)
	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", serviceName)
			return
		case conn := <-connChan:
			go handleTCPConn(conn, service, &cfg, store, broker, tlsConf)
		}
	}
}

// handleTCPConn 先记一次 <proto>-connect，然后按协议进入“读帧-应答”循环。
func handleTCPConn(conn net.Conn, service *services.Service, cfg *iiotConfig, store *dataStore,
	broker *mqttBroker, tlsConf *tls.Config) {
	// 用闭包在 TLS 包装后再取 Close，保证 TLS 连接被正确关闭
	defer func() { _ = conn.Close() }()
	protocol := service.BaseOptions.Protocol
	src, dst := connAddrs(conn)

	pushICS(protocol+"-connect", src, dst, service, cfg, nil)
	logger.Log.Debugf("iiot: %s connection from %s:%d", protocol, src.IP, src.Port)

	// MQTT 支持 TLS：mqtt 配了 tls 块即启用，mqtts 强制
	if tlsConf != nil && (protocol == "mqtt" || protocol == "mqtts") {
		tlsConn := tls.Server(conn, tlsConf)
		if err := tlsConn.Handshake(); err != nil {
			logger.Log.Warning("iiot: tls handshake failed: ", err)
			return
		}
		conn = tlsConn
	}

	switch protocol {
	case "mqtt", "mqtts":
		handleMQTT(conn, service, cfg, store, broker, src, dst)
	case "modbus":
		handleModbus(conn, service, cfg, store, src, dst)
	case "s7":
		handleSiemens(conn, service, cfg, store, src, dst)
	case "cip":
		handleCIP(conn, service, cfg, store, src, dst)
	case "fins":
		handleFins(conn, service, cfg, store, src, dst)
	case "mitsubishi_a1e":
		handleMitsubishiA1E(conn, service, cfg, store, src, dst)
	case "mitsubishi_qna3e":
		handleMitsubishiQna3E(conn, service, cfg, store, src, dst)
	default:
		logger.Log.Warn("iiot: unsupported protocol ", protocol)
	}
}

// pushICS 收敛各协议的事件字段：protocol/application/vendor + 协议自定义字段。
func pushICS(eventType string, src, dst common.Addr, service *services.Service, cfg *iiotConfig, details map[string]interface{}) {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["protocol"] = service.BaseOptions.Protocol
	details["application"] = service.BaseOptions.Application
	if cfg != nil && cfg.Vendor != "" {
		details["ics.vendor"] = cfg.Vendor
	}
	event.EventPush(event.NewEvent(serviceName, eventType, src, dst, details))
}

// connAddrs 取 TCP 连接的两端地址，失败时仅记日志（保持事件不中断）。
func connAddrs(conn net.Conn) (common.Addr, common.Addr) {
	src, err := common.GetConnSrcIPAndSrcPort(&conn)
	if err != nil {
		logger.Log.Error("iiot: parse src addr failed: ", err)
	}
	dst, err := common.GetConnDstIPAndDstPort(&conn)
	if err != nil {
		logger.Log.Error("iiot: parse dst addr failed: ", err)
	}
	return src, dst
}

// readFull 保证从流里读满 n 字节（TCP 一次 Read 未必到齐），上层据此按整帧解析。
// n 为 0 时返回空切片，便于调用方按“头 + 体”的写法统一处理。
func readFull(r io.Reader, n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("iiot: invalid frame length %d", n)
	}
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// hexToBytes 解析 default_value / 标签值，容忍空格、逗号、冒号、短横线与 0x 前缀等常见写法。
func hexToBytes(s string) ([]byte, error) {
	replacer := strings.NewReplacer(
		" ", "", "\t", "", ",", "", ":", "", "-", "", "_", "",
		"0x", "", "0X", "",
	)
	return hex.DecodeString(replacer.Replace(s))
}

// defaultBytes 按 default_value 平铺出 n 字节读数据；未配置或非法时返回 n 个 0。
func defaultBytes(cfg *iiotConfig, n int) []byte {
	out := make([]byte, n)
	if n <= 0 || cfg == nil || strings.TrimSpace(cfg.DefaultValue) == "" {
		return out
	}
	pattern, err := hexToBytes(cfg.DefaultValue)
	if err != nil || len(pattern) == 0 {
		logger.Log.Debug("iiot: invalid default_value, fallback to zero: ", err)
		return out
	}
	for i := range out {
		out[i] = pattern[i%len(pattern)]
	}
	return out
}

// rawHex 统一事件里 ics.raw 的格式。
func rawHex(b []byte) string {
	return hex.EncodeToString(b)
}
