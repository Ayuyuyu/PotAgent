package iiot

import (
	"fmt"
	"net"

	"potAgent/common"
	"potAgent/logger"
	"potAgent/services"
)

const (
	// cipHeaderLen 是 EtherNet/IP 封装头长度；cipTailLen 是参考实现继续读的 12 字节。
	cipHeaderLen = 28
	cipTailLen   = 12
	// cipMaxPayload 是 CIP 指令长度的防呆上限。
	cipMaxPayload = 2048
	// cipMaxData 是读响应/写值数据段的防呆上限。
	cipMaxData = 1024
	// cipDataOffset 是读响应里数据段的起始偏移（与参考实现一致）。
	cipDataOffset = 46
	// cipReadService / cipWriteService 是 CIP 读/写标签的服务码。
	cipReadService  = 0x4C
	cipWriteService = 0x4D
)

// cipConnectResponse 是 EtherNet/IP 注册/连接握手响应（28 字节，字面量取自 AllenBradleyServer.cs）。
var cipConnectResponse = []byte{
	0x65, 0x00, 0x04, 0x00, // 命令 + 命令数据长度
	0x57, 0x01, 0x56, 0x00, // 会话句柄
	0x00, 0x00, 0x00, 0x00, // 状态
	0x00, 0x00, 0x00, 0x00, // 发送方上下文
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, // 选项
	0x01, 0x00, 0x00, 0x00, // 协议版本 + 选项标记
}

// cipReadResponse 是 CIP 读标签响应（50 字节字面量，数据段从 [46] 起被实际值覆盖）。
var cipReadResponse = []byte{
	0x66, 0x00, 0x1A, 0x00, // 命令 + 长度（随数据段长度改写）
	0x10, 0x00, 0x00, 0x00, // 会话句柄
	0x00, 0x00, 0x00, 0x00, // 状态
	0x00, 0x00, 0x00, 0x00, // 发送方上下文
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, // 选项
	0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x02, 0x00, // 接口句柄 + 超时 + 项数
	0x00, 0x00, 0x00, 0x00, // 空地址项
	0xB2, 0x00, 0x0A, 0x00, // 未连接数据项 + 指令长度（随数据段长度改写）
	0xCC, 0x00, 0x00, 0x00, // 服务码(0xCC 读标签应答) + 状态 + 附加状态长度
	0x00, 0x00, //  数据类型
	0x7B, 0x00, 0x00, 0x00, // 数据（被覆盖）
}

// cipWriteResponse 是 CIP 写标签响应（46 字节字面量）。
var cipWriteResponse = []byte{
	0x66, 0x00, 0x16, 0x00,
	0x10, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x02, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0xB2, 0x00, 0x06, 0x00,
	0xCD, 0x00, 0x00, 0x00,
	0x00, 0x00,
}

// handleCIP 处理 EtherNet/IP + CIP（罗克韦尔/AllenBradley）。
// 帧布局参照 IoTServer/Servers/PLC/AllenBradleyServer.cs：
// 先读 28 字节封装头（[0]=0x65,[2]=0x04,[24]=0x01 即注册命令），
// 否则再读 12 字节取指令长度，最后读 CIP 指令体。
// 读优先级：预置标签（tags） > 已写入数据 > 默认值；写操作按标签名落数据存储。
func handleCIP(conn net.Conn, service *services.Service, cfg *iiotConfig, store *dataStore, src, dst common.Addr) {
	protocol := service.BaseOptions.Protocol
	for {
		head, err := readFull(conn, cipHeaderLen)
		if err != nil {
			return
		}
		details := map[string]interface{}{
			"ics.raw": rawHex(head),
		}

		// 注册会话（连接握手）
		if head[0] == 0x65 && head[2] == 0x04 && head[24] == 0x01 {
			details["ics.operation"] = "register-session"
			pushICS(protocol+"-request", src, dst, service, cfg, details)
			if _, err := conn.Write(cipConnectResponse); err != nil {
				logger.Log.Debug("iiot: cip write connect response failed: ", err)
				return
			}
			continue
		}

		tail, err := readFull(conn, cipTailLen)
		if err != nil {
			return
		}
		payloadLen := int(tail[11])<<8 | int(tail[10])
		if payloadLen < 0 || payloadLen > cipMaxPayload {
			return
		}
		payload, err := readFull(conn, payloadLen)
		if err != nil {
			return
		}
		request := append(append(head, tail...), payload...)
		details["ics.raw"] = rawHex(request)

		if len(request) < 54+2 {
			details["ics.operation"] = "short-frame"
			pushICS(protocol+"-request", src, dst, service, cfg, details)
			continue
		}

		// 地址长度 / 起始偏移与参考实现一致：address_ASCII_Length = [51]*2-2，地址从 [54] 起
		addressLen := int(request[51])*2 - 2
		if addressLen < 0 || 54+addressLen+1 >= len(request) {
			details["ics.operation"] = "bad-address"
			pushICS(protocol+"-request", src, dst, service, cfg, details)
			continue
		}
		address := string(request[54 : 54+addressLen])
		details["cip.address"] = address

		var response []byte
		switch request[50] {
		case cipReadService: // 读标签
			details["ics.operation"] = "read"
			data := cipTagData(cfg, store, address, request, addressLen)
			details["cip.data"] = rawHex(data)
			response = cipReadReply(data)
		case cipWriteService: // 写标签：按标签名落数据存储
			details["ics.operation"] = "write"
			value := cipWriteValue(request, addressLen)
			if len(value) == 0 {
				details["cip.status"] = "malformed"
			} else {
				details["cip.value"] = rawHex(value)
				details["cip.stored"] = store.set("cip-tag-"+address, value)
			}
			response = cipWriteResponse
		default:
			details["ics.operation"] = fmt.Sprintf("service-%#x", request[50])
		}

		pushICS(protocol+"-request", src, dst, service, cfg, details)
		if len(response) == 0 {
			continue
		}
		if _, err := conn.Write(response); err != nil {
			logger.Log.Debug("iiot: cip write response failed: ", err)
			return
		}
	}
}

// cipTagData 取读标签的数据：已写入数据 > 预置标签（初值） > 默认值。
func cipTagData(cfg *iiotConfig, store *dataStore, address string, request []byte, addressLen int) []byte {
	if stored := store.get("cip-tag-" + address); len(stored) > 0 {
		return stored
	}
	if preset := cfg.cipTagValue(address); preset != nil {
		return preset
	}
	// 请求里的元素个数（ little-endian），超出防呆上限按 4 字节处理
	dataLen := int(request[54+addressLen]) | int(request[55+addressLen])<<8
	if dataLen <= 0 || dataLen > cipMaxData {
		dataLen = 4
	}
	return defaultBytes(cfg, dataLen)
}

// cipReadReply 用读标签响应字面量 + 实际数据拼应答（同步修正封装头与 CIP 长度字段）。
func cipReadReply(data []byte) []byte {
	response := make([]byte, cipDataOffset+len(data))
	copy(response, cipReadResponse)
	total := len(response) - 24
	response[2] = byte(total % 256)
	response[3] = byte(total / 256)
	cipLen := len(data) + 6
	response[38] = byte(cipLen % 256)
	response[39] = byte(cipLen / 256)
	copy(response[cipDataOffset:], data)
	return response
}

// cipWriteValue 取写标签请求里的数据段（58+地址长度 起，末尾 4 字节是 01 00 01 slot）。
func cipWriteValue(request []byte, addressLen int) []byte {
	start := 58 + addressLen
	end := len(request) - 4
	if start >= end || end > len(request) {
		return nil
	}
	value := request[start:end]
	if len(value) > cipMaxData {
		value = value[:cipMaxData]
	}
	return append([]byte{}, value...)
}
