package iiot

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"potAgent/common"
	"potAgent/logger"
	"potAgent/services"
)

const (
	// bacnetDefaultDeviceID 是未配置 device_id 时对外声称的设备实例号。
	bacnetDefaultDeviceID = 1234
	// bacnetDefaultVendorID / bacnetDefaultDeviceName 是 bacnet 的默认厂商 ID 与设备名。
	bacnetDefaultVendorID   = 0x000F
	bacnetDefaultDeviceName = "PotAgent"
	// bacnetObjectTypeDevice 是 BACnet 设备对象类型码。
	bacnetObjectTypeDevice = 8

	// BVLC 类型与功能码
	bvlcTypeIP            = 0x81
	bvlcOriginalUnicast   = 0x0A
	bvlcOriginalBroadcast = 0x0B

	// APDU 类型（高 4 位）
	bacnetAPDUConfirmed   = 0x00
	bacnetAPDUUnconfirmed = 0x10
	bacnetAPDUSimpleAck   = 0x20
	bacnetAPDUComplexAck  = 0x30
	bacnetAPDUError       = 0x50

	// 服务码
	bacnetServiceIAm           = 0x00
	bacnetServiceWhoIs         = 0x08
	bacnetServiceReadProperty  = 0x0C
	bacnetServiceWriteProperty = 0x05

	// 属性 ID
	bacnetPropObjectIdentifier = 75
	bacnetPropObjectName       = 77
	bacnetPropPresentValue     = 85

	// 错误类/错误码
	bacnetErrorClassObject          = 1
	bacnetErrorClassProperty        = 2
	bacnetErrorCodeUnknownProperty  = 32
	bacnetErrorCodeWriteAccessDenid = 34

	// context tag 0，长度 4：对象标识
	bacnetContextTagObjectID = 0x0C
)

// dataStore 区名
const (
	bacnetAreaPresentValue = "bacnet-present-value"
	bacnetAreaObjectName   = "bacnet-object-name"
)

// handleBacnet 监听 UDP，按 BACnet/IP 解析报文并回 I-Am / 读属性应答。
// 低交互取舍：只做 Who-Is、Read-Property(单属性) 与 Write-Property(PresentValue/Object-Name)，
// 不实现 COV 订阅那一套。写属性的值落 dataStore，之后读同一属性能读到。
func handleBacnet(ctx context.Context, service *services.Service, cfg *iiotConfig, store *dataStore) {
	base := service.BaseOptions
	address := fmt.Sprintf("%v:%v", base.Host, base.Port)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(base.Host), Port: int(base.Port)})
	if err != nil {
		logger.Log.Fatalln(err)
	}
	defer conn.Close()
	logger.Log.Infoln(base.Application, "listen on ", address)

	packetChan := common.ForwardUDPPacketToChan(conn)
	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", serviceName)
			return
		case packet := <-packetChan:
			handleBacnetPacket(packet, service, cfg, store)
		}
	}
}

func handleBacnetPacket(packet *common.DummyUDPConn, service *services.Service, cfg *iiotConfig, store *dataStore) {
	protocol := service.BaseOptions.Protocol
	src := udpAddrToCommonAddr(packet.UDPAddr)
	dst := udpAddrToCommonAddr(localUDPAddr(packet))
	details := map[string]interface{}{
		"ip_protocol": "udp",
		"ics.raw":     rawHex(packet.Data),
	}

	response := bacnetHandle(packet.Data, cfg, store, details)
	pushICS(protocol+"-request", src, dst, service, cfg, details)

	if len(response) == 0 {
		return
	}
	if _, err := packet.WriteToUDP(response, packet.UDPAddr); err != nil {
		logger.Log.Debug("iiot: bacnet write response failed: ", err)
	}
}

// bacnetHandle 解析一帧 BACnet/IP，返回需要回送的报文（nil 表示不回，只记事件）。
// details 会被就地补充 bacnet.* 字段。
func bacnetHandle(data []byte, cfg *iiotConfig, store *dataStore, details map[string]interface{}) []byte {
	if len(data) < 6 || data[0] != bvlcTypeIP {
		return nil
	}
	if data[1] != bvlcOriginalUnicast && data[1] != bvlcOriginalBroadcast {
		return nil
	}
	apdu := bacnetAPDU(data[4:])
	if len(apdu) < 2 {
		return nil
	}

	switch apdu[0] & 0xF0 {
	case bacnetAPDUUnconfirmed:
		if apdu[1] != bacnetServiceWhoIs {
			details["bacnet.service"] = fmt.Sprintf("unconfirmed-%#x", apdu[1])
			return nil
		}
		details["bacnet.service"] = "who-is"
		if !bacnetWhoIsMatch(apdu[2:], bacnetDeviceID(cfg)) {
			details["bacnet.match"] = false
			return nil
		}
		return bacnetIAm(cfg)

	case bacnetAPDUConfirmed:
		invokeID, service, params, ok := bacnetParseConfirmedRequest(apdu)
		if !ok {
			details["bacnet.service"] = "confirmed-unknown"
			return nil
		}
		switch service {
		case bacnetServiceReadProperty:
			return bacnetReadProperty(invokeID, params, cfg, store, details)
		case bacnetServiceWriteProperty:
			return bacnetWriteProperty(invokeID, params, cfg, store, details)
		}
	}
	return nil
}

// bacnetReadProperty 解析读属性请求并回 ComplexAck。
func bacnetReadProperty(invokeID byte, params []byte, cfg *iiotConfig, store *dataStore, details map[string]interface{}) []byte {
	objectID, property, arrayIndex, ok := bacnetParseReadProperty(params)
	if !ok {
		details["bacnet.service"] = "read-property-malformed"
		return nil
	}
	details["bacnet.service"] = "read-property"
	details["bacnet.instance"] = int(binary.BigEndian.Uint32(objectID) & 0x3FFFFF)
	details["bacnet.property"] = property

	value := bacnetPropertyValue(cfg, store, property, objectID)
	if value == nil {
		details["bacnet.status"] = "unknown-property"
		return bacnetErrorResponse(invokeID, bacnetServiceReadProperty, bacnetErrorClassProperty, bacnetErrorCodeUnknownProperty)
	}
	details["bacnet.value"] = rawHex(value)
	details["bacnet.status"] = "good"
	return bacnetReadPropertyAck(invokeID, objectID, property, arrayIndex, value)
}

// bacnetWriteProperty 解析写属性请求，把值落 dataStore 并回 SimpleAck。
func bacnetWriteProperty(invokeID byte, params []byte, cfg *iiotConfig, store *dataStore, details map[string]interface{}) []byte {
	objectID, property, value, ok := bacnetParseWriteProperty(params)
	if !ok {
		details["bacnet.service"] = "write-property-malformed"
		return nil
	}
	details["bacnet.service"] = "write-property"
	details["bacnet.instance"] = int(binary.BigEndian.Uint32(objectID) & 0x3FFFFF)
	details["bacnet.property"] = property
	details["bacnet.value"] = rawHex(value)

	if bacnetStoreWriteProperty(store, objectID, property, value) {
		details["bacnet.status"] = "stored"
		return bacnetSimpleAck(invokeID, bacnetServiceWriteProperty)
	}
	if cfg != nil && cfg.ReadOnly {
		details["bacnet.status"] = "read-only"
		return bacnetErrorResponse(invokeID, bacnetServiceWriteProperty, bacnetErrorClassObject, bacnetErrorCodeWriteAccessDenid)
	}
	// 值类型不在支持范围内：照常确认（低交互），只记事件
	details["bacnet.status"] = "unsupported-value"
	return bacnetSimpleAck(invokeID, bacnetServiceWriteProperty)
}

// bacnetDeviceID 取配置的设备实例号，未配置时用默认值。
func bacnetDeviceID(cfg *iiotConfig) uint32 {
	if cfg != nil && cfg.DeviceID != 0 {
		return cfg.DeviceID
	}
	return bacnetDefaultDeviceID
}

// bacnetVendor 取配置的厂商 ID，未配置时用默认值。
func bacnetVendor(cfg *iiotConfig) uint16 {
	if cfg != nil && cfg.VendorID != 0 {
		return cfg.VendorID
	}
	return bacnetDefaultVendorID
}

// bacnetDeviceName 取设备对象名：写过的值 > 配置值 > 默认值。
func bacnetDeviceName(cfg *iiotConfig, store *dataStore) string {
	if stored := store.get(bacnetAreaObjectName); len(stored) > 0 {
		return string(stored)
	}
	if cfg != nil && cfg.DeviceName != "" {
		return cfg.DeviceName
	}
	return bacnetDefaultDeviceName
}

// bacnetAPDU 定位 NPDU 里的 APDU。
// NPDU 头部长度取决于控制字节（目的/源地址可选），BACnet/IP 里 2 / 5 / 6 / 9 都很常见，
// 且不同实现对控制位的定义略有出入；这里按候选偏移逐个校验 APDU 头部特征，取第一个合法位置。
func bacnetAPDU(npdu []byte) []byte {
	if len(npdu) < 2 || npdu[0] != 0x01 { // 版本号必须为 1
		return nil
	}
	for pos := 2; pos <= len(npdu) && pos <= 12; pos++ {
		if apdu := npdu[pos:]; bacnetLooksLikeAPDU(apdu) {
			return apdu
		}
	}
	return nil
}

// bacnetLooksLikeAPDU 用“PDU 类型 + 已知服务码”判断这段字节是否像 APDU。
// 低交互只关心 Who-Is / I-Am / Read-Property / Write-Property，其余一律不回。
func bacnetLooksLikeAPDU(apdu []byte) bool {
	if len(apdu) < 2 {
		return false
	}
	switch apdu[0] & 0xF0 {
	case bacnetAPDUUnconfirmed:
		return apdu[1] == bacnetServiceWhoIs || apdu[1] == bacnetServiceIAm
	case bacnetAPDUConfirmed:
		return isBacnetPropertyService(apdu[2]) ||
			(len(apdu) > 3 && isBacnetPropertyService(apdu[3]))
	default:
		return false
	}
}

func isBacnetPropertyService(service byte) bool {
	return service == bacnetServiceReadProperty || service == bacnetServiceWriteProperty
}

// bacnetParseConfirmedRequest 解析确认请求的 invoke-id / 服务码 / 参数。
// 各实现对 invoke-id 与服务码的偏移略有差异，这里用“参数必以 context tag 0 +
// 长度 4（对象标识）开头”这一特征做校验后取偏移。
func bacnetParseConfirmedRequest(apdu []byte) (invokeID byte, service byte, params []byte, ok bool) {
	if len(apdu) >= 6 && isBacnetPropertyService(apdu[2]) && apdu[3] == bacnetContextTagObjectID {
		return apdu[1], apdu[2], apdu[3:], true
	}
	if len(apdu) >= 7 && isBacnetPropertyService(apdu[3]) && apdu[4] == bacnetContextTagObjectID {
		return apdu[2], apdu[3], apdu[4:], true
	}
	return 0, 0, nil, false
}

// bacnetParseReadProperty 从 ReadProperty 参数里取对象标识、属性 ID 与可选数组下标。
func bacnetParseReadProperty(params []byte) (objectID []byte, property byte, arrayIndex int, ok bool) {
	if len(params) < 7 || params[0] != bacnetContextTagObjectID {
		return nil, 0, -1, false
	}
	objectID = params[1:5]

	// 属性 ID：context tag 1，长度 1
	tag := params[5]
	if tag>>4 != 1 || tag&0x08 == 0 || tag&0x07 != 1 {
		return nil, 0, -1, false
	}
	property = params[6]

	// 可选数组下标：context tag 2，长度 1
	arrayIndex = -1
	if len(params) >= 9 && params[7]>>4 == 2 && params[7]&0x08 != 0 && params[7]&0x07 == 1 {
		arrayIndex = int(params[8])
	}
	return objectID, property, arrayIndex, true
}

// bacnetParseWriteProperty 从 WriteProperty 参数里取对象标识、属性 ID 与属性值
// （值在打开/关闭标签 3 之间）。
func bacnetParseWriteProperty(params []byte) (objectID []byte, property byte, value []byte, ok bool) {
	if len(params) < 9 || params[0] != bacnetContextTagObjectID {
		return nil, 0, nil, false
	}
	objectID = params[1:5]

	tag := params[5]
	if tag>>4 != 1 || tag&0x08 == 0 || tag&0x07 != 1 {
		return nil, 0, nil, false
	}
	property = params[6]

	pos := 7
	// 可选数组下标：context tag 2
	if pos < len(params) && params[pos]>>4 == 2 && params[pos]&0x08 != 0 {
		pos += 1 + int(params[pos]&0x07)
	}
	// 打开标签 3 之后是一个应用标签（如 0x44 实数、0x75 字符串），按标签长度取值，
	// 最后必须紧跟关闭标签 3 —— 不能朴素地找 0x3F，否则实数值里的 0x3F 字节会被误判
	if pos >= len(params) || params[pos] != 0x3E {
		return nil, 0, nil, false
	}
	if pos+1 >= len(params) || params[pos+1]&0x08 != 0 { // 必须是应用标签
		return nil, 0, nil, false
	}
	tagByte := params[pos+1]
	length := int(tagByte & 0x07)
	vStart := pos + 2
	if length == 5 { // 扩展长度：后跟 1 字节长度
		if vStart >= len(params) {
			return nil, 0, nil, false
		}
		length = int(params[vStart])
		vStart++
	}
	vEnd := vStart + length
	if length <= 0 || vEnd >= len(params) || params[vEnd] != 0x3F {
		return nil, 0, nil, false
	}
	// 返回“应用标签 + 数据”，方便调用方按标签类型处理
	return objectID, property, params[pos+1 : vEnd], true
}

// bacnetWhoIsMatch 判断本设备实例号是否落在 Who-Is 的实例号区间内（未携带区间则一律应答）。
func bacnetWhoIsMatch(params []byte, deviceID uint32) bool {
	reader := bacnetTagReader{data: params}
	low, high := uint32(0), uint32(0x3FFFFF)
	hasLow, hasHigh := false, false
	if tag, payload, ok := reader.next(); ok && tag == 0 {
		low, hasLow = bacnetUnsigned(payload), true
	}
	if tag, payload, ok := reader.next(); ok && tag == 1 {
		high, hasHigh = bacnetUnsigned(payload), true
	}
	if hasLow && deviceID < low {
		return false
	}
	if hasHigh && deviceID > high {
		return false
	}
	return true
}

// bacnetPropertyValue 取读属性的值；属性不在支持列表内时返回 nil。
func bacnetPropertyValue(cfg *iiotConfig, store *dataStore, property byte, objectID []byte) []byte {
	instance := int(binary.BigEndian.Uint32(objectID) & 0x3FFFFF)
	switch property {
	case bacnetPropObjectName:
		name := []byte(bacnetDeviceName(cfg, store))
		// 字符型：tag 7 + 长度（1 字节字符集 + 字符串）+ 字符集 0(UTF-8) + 内容
		out := []byte{0x75, byte(len(name) + 1), 0x00}
		return append(out, name...)
	case bacnetPropObjectIdentifier:
		return append([]byte{0xC4}, objectID...)
	case bacnetPropPresentValue:
		// 实数（Real，4 字节）：写过的值优先，没写过回默认值/0.0
		return append([]byte{0x44}, store.read(bacnetAreaPresentValue, instance*4, 4)...)
	default:
		return nil
	}
}

// bacnetStoreWriteProperty 把写属性请求里的值落 dataStore；不支持的值类型返回 false。
func bacnetStoreWriteProperty(store *dataStore, objectID []byte, property byte, value []byte) bool {
	instance := int(binary.BigEndian.Uint32(objectID) & 0x3FFFFF)
	switch {
	case property == bacnetPropPresentValue && len(value) == 5 && value[0] == 0x44:
		// 实数（Real，4 字节）
		return store.write(bacnetAreaPresentValue, instance*4, value[1:5])
	case property == bacnetPropObjectName && len(value) >= 3 && value[0] == 0x75:
		// 字符串（tag 0x75：长度 + 字符集 + 内容），去掉长度与字符集字节，只存内容
		return store.set(bacnetAreaObjectName, value[3:])
	}
	return false
}

// bacnetIAm 构造 I-Am 报文（未确认请求，服务码 0x00）。
func bacnetIAm(cfg *iiotConfig) []byte {
	vendor := bacnetVendor(cfg)
	apdu := make([]byte, 0, 20)
	apdu = append(apdu, bacnetAPDUUnconfirmed, bacnetServiceIAm)
	apdu = append(apdu, 0x0C) // context tag 0，长度 4：设备对象标识
	apdu = append(apdu, bacnetObjectIdentifier(bacnetObjectTypeDevice, bacnetDeviceID(cfg))...)
	apdu = append(apdu, 0x19, 0x05)                          // context tag 1，长度 1：最大 APDU 长度 1476
	apdu = append(apdu, 0x29, 0x03)                          // context tag 2，长度 1：支持分段
	apdu = append(apdu, 0x3A, byte(vendor>>8), byte(vendor)) // context tag 3，长度 2：厂商 ID
	return bacnetBVLC(bvlcOriginalUnicast, append([]byte{0x01, 0x00}, apdu...))
}

// bacnetReadPropertyAck 构造读属性的 ComplexAck 应答。
func bacnetReadPropertyAck(invokeID byte, objectIDRaw []byte, property byte, arrayIndex int, value []byte) []byte {
	apdu := make([]byte, 0, 32)
	apdu = append(apdu, bacnetAPDUComplexAck, invokeID, bacnetServiceReadProperty)
	apdu = append(apdu, bacnetContextTagObjectID)
	apdu = append(apdu, objectIDRaw...)
	apdu = append(apdu, 0x19, property)
	if arrayIndex >= 0 {
		apdu = append(apdu, 0x29, byte(arrayIndex))
	}
	apdu = append(apdu, 0x3E) // 打开标签 3：property-value
	apdu = append(apdu, value...)
	apdu = append(apdu, 0x3F) // 关闭标签 3
	return bacnetBVLC(bvlcOriginalUnicast, append([]byte{0x01, 0x00}, apdu...))
}

// bacnetSimpleAck 构造确认应答（如写属性成功）。
func bacnetSimpleAck(invokeID, service byte) []byte {
	apdu := []byte{bacnetAPDUSimpleAck, invokeID, service}
	return bacnetBVLC(bvlcOriginalUnicast, append([]byte{0x01, 0x00}, apdu...))
}

// bacnetErrorResponse 构造错误应答（如未知属性、只读拒绝写入）。
func bacnetErrorResponse(invokeID, service, errClass, errCode byte) []byte {
	apdu := []byte{
		bacnetAPDUError, invokeID, service,
		0x09, errClass, // context tag 0，长度 1：错误类
		0x19, errCode, // context tag 1，长度 1：错误码
	}
	return bacnetBVLC(bvlcOriginalUnicast, append([]byte{0x01, 0x00}, apdu...))
}

// bacnetBVLC 给 NPDU 套上 BVLC 头（type/function/length）。
func bacnetBVLC(function byte, npdu []byte) []byte {
	frame := make([]byte, 4+len(npdu))
	frame[0] = bvlcTypeIP
	frame[1] = function
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	copy(frame[4:], npdu)
	return frame
}

// bacnetObjectIdentifier 编码 BACnet 对象标识（高 10 位类型 + 低 22 位实例号）。
func bacnetObjectIdentifier(objectType uint16, instance uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(objectType)<<22|(instance&0x3FFFFF))
	return out
}

// bacnetTagReader 顺序读取 APDU 里的短上下文标签（长度 ≤ 4）。
type bacnetTagReader struct {
	data []byte
	pos  int
}

// next 返回下一个上下文标签的 (tag 号, 负载)；不足或非上下文标签时 ok=false。
func (r *bacnetTagReader) next() (tag byte, payload []byte, ok bool) {
	if r.pos >= len(r.data) {
		return 0, nil, false
	}
	b := r.data[r.pos]
	if b&0x08 == 0 { // 非上下文标签
		return 0, nil, false
	}
	length := int(b & 0x07)
	if length > 4 {
		return 0, nil, false
	}
	r.pos++
	if r.pos+length > len(r.data) {
		return 0, nil, false
	}
	payload = r.data[r.pos : r.pos+length]
	r.pos += length
	return b >> 4, payload, true
}

// bacnetUnsigned 把 1~4 字节的大端无符号数转成 uint32。
func bacnetUnsigned(b []byte) uint32 {
	var out uint32
	for _, v := range b {
		out = out<<8 | uint32(v)
	}
	return out
}

// udpAddrToCommonAddr 与 common.Addr 互转（BACnet 事件用）。
func udpAddrToCommonAddr(a *net.UDPAddr) common.Addr {
	if a == nil {
		return common.Addr{}
	}
	return common.Addr{IP: a.IP.String(), Port: uint16(a.Port)}
}

// localUDPAddr 取本端 UDP 地址。
func localUDPAddr(packet *common.DummyUDPConn) *net.UDPAddr {
	la, _ := packet.UDPConn.LocalAddr().(*net.UDPAddr)
	if la == nil {
		return &net.UDPAddr{}
	}
	return la
}
