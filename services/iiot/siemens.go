package iiot

import (
	"fmt"
	"net"

	"potAgent/common"
	"potAgent/logger"
	"potAgent/services"
)

const (
	// S7-200Smart 的两条连接初始化指令长度（参见 SiemensConstant.cs 的 Command1/2_200Smart）。
	// 服务器只需按长度识别并原样回显。
	s7COTPCommand1Len = 22
	s7COTPCommand2Len = 25
	// s7MaxFrame 是 COTP 长度字段的防呆上限。
	s7MaxFrame = 4096
	// s7MaxItems 是单次读/写请求最多允许的数据块个数。
	s7MaxItems = 20
)

// s7ReadResponseHead 是 S7 读响应的固定 21 字节头，之后接数据项。
var s7ReadResponseHead = []byte{
	0x03, 0x00, 0x00, 0x1A, // TPKT: 版本 + 长度（应答时改写）
	0x02, 0xF0, 0x80, 0x32, // COTP / 协议 ID
	0x03, 0x00, 0x00, 0x00, // 服务器回复命令
	0x01, 0x00, 0x02, 0x00, // PDU 参考 + 参数长度 + 数据长度
	0x00, 0x00, 0x00, 0x04, // 数据长度 + 返回码
	0x01, // 数据块个数
}

// s7WriteResponse 是 S7 写响应的固定 22 字节。
var s7WriteResponse = []byte{
	0x03, 0x00, 0x00, 0x16,
	0x02, 0xF0, 0x80, 0x32,
	0x03, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x02, 0x00,
	0x01, 0x00, 0x00, 0x05,
	0x01, 0xFF,
}

// s7AreaName 把 S7 区域类型码映射成存储区名（0x81=I、0x82=Q、0x83=M、0x84=DB…）。
func s7AreaName(typeCode byte) string {
	return fmt.Sprintf("s7-area-%#x", typeCode)
}

// handleSiemens 处理 S7comm（TPKT + COTP + S7 PDU）。
// 帧布局参照 IoTServer/Servers/PLC/SiemensServer.cs：4 字节 TPKT 头，
// 两阶段握手原样回显，其余按 request[17] 区分读(4)/写(5)；写操作落数据存储。
func handleSiemens(conn net.Conn, service *services.Service, cfg *iiotConfig, store *dataStore, src, dst common.Addr) {
	protocol := service.BaseOptions.Protocol
	for {
		head, err := readFull(conn, 4)
		if err != nil {
			return
		}
		total := int(head[2])<<8 | int(head[3])
		if total < 4 || total > s7MaxFrame {
			return
		}
		body, err := readFull(conn, total-4)
		if err != nil {
			return
		}
		request := append(head, body...)

		details := map[string]interface{}{
			"ics.raw": rawHex(request),
		}

		// 连接握手阶段的两条初始化指令：原样回显
		if total == s7COTPCommand1Len || total == s7COTPCommand2Len {
			details["ics.operation"] = "cotp-connect"
			pushICS(protocol+"-request", src, dst, service, cfg, details)
			if _, err := conn.Write(request); err != nil {
				logger.Log.Debug("iiot: s7 write cotp echo failed: ", err)
				return
			}
			continue
		}

		if len(request) < 19 {
			details["ics.operation"] = "short-frame"
			pushICS(protocol+"-request", src, dst, service, cfg, details)
			continue
		}

		var response []byte
		switch request[17] {
		case 4: // 读变量
			details["ics.operation"] = "read"
			response = s7ReadResponse(request, cfg, store)
		case 5: // 写变量：解析数据项并落数据存储
			details["ics.operation"] = "write"
			if s7WriteRequest(request, store, details) {
				response = s7WriteResponse
			} else {
				details["s7.parse"] = "failed"
			}
		default:
			details["ics.operation"] = fmt.Sprintf("function-%d", request[17])
		}

		pushICS(protocol+"-request", src, dst, service, cfg, details)
		if len(response) == 0 {
			continue
		}
		if _, err := conn.Write(response); err != nil {
			logger.Log.Debug("iiot: s7 write response failed: ", err)
			return
		}
	}
}

// s7ReadResponse 按参考实现的偏移解析数据块请求，拼出“固定头 + 数据项”读响应。
// 数据来源：dataStore（写过的地址），没写过的地址回退 default_value/零。
func s7ReadResponse(request []byte, cfg *iiotConfig, store *dataStore) []byte {
	itemCount := int(request[18])
	if itemCount <= 0 || itemCount > s7MaxItems || len(request) < 19+itemCount*12 {
		return nil
	}

	dataContent := make([]byte, 0, 4*itemCount)
	for i := 0; i < itemCount; i++ {
		// 访问数据的个数（以 byte 为单位）；非最后一个 bit/byte 需要补全
		byteLength := int(request[23+i*12])<<8 | int(request[24+i*12])
		if byteLength == 1 && i < itemCount-1 {
			byteLength++
		}
		if byteLength <= 0 || byteLength > s7MaxFrame {
			return nil
		}
		isBit := request[22+i*12] == 0x01
		// S7 地址是位地址，字节偏移要 /8
		beginAddress := int(request[28+i*12])<<16 | int(request[29+i*12])<<8 | int(request[30+i*12])
		byteOffset := beginAddress / 8
		area := s7AreaName(request[27+i*12])

		item := make([]byte, 4+byteLength)
		item[0] = 0xFF // 返回码
		if isBit {
			item[1] = 0x03 // 03 位
			item[4] = store.getBit(area, byteOffset, uint(beginAddress%8))
		} else {
			item[1] = 0x04 // 04 字节
			copy(item[4:], store.read(area, byteOffset, byteLength))
		}
		item[2] = byte(byteLength / 256)
		item[3] = byte(byteLength % 256)
		dataContent = append(dataContent, item...)
	}

	response := make([]byte, 21+len(dataContent))
	copy(response, s7ReadResponseHead)
	response[2] = byte(len(response) / 256) // TPKT 长度
	response[3] = byte(len(response) % 256)
	response[8] = 0x03 // 服务器回复命令
	response[15] = byte(len(request) / 256)
	response[16] = byte(len(request) % 256)
	response[20] = request[18] // 数据块个数
	copy(response[21:], dataContent)
	return response
}

// s7WriteRequest 解析写请求的数据项并写入 dataStore，成功返回 true。
// 解析逻辑（含非最后一个 bit 项的补位）与参考实现一致。
func s7WriteRequest(request []byte, store *dataStore, details map[string]interface{}) bool {
	itemCount := int(request[18])
	if itemCount <= 0 || itemCount > s7MaxItems || len(request) < 19+itemCount*12 {
		return false
	}
	// Data 段从 18 + 数据块个数 * 12 开始，每个数据项前有 4 字节头
	dataBeforeIndex := 18 + itemCount*12
	cursor := 0
	stored := 0

	for i := 0; i < itemCount; i++ {
		beginAddress := int(request[28+i*12])<<16 | int(request[29+i*12])<<8 | int(request[30+i*12])
		area := s7AreaName(request[27+i*12])

		idx := dataBeforeIndex + 4*(i+1) + cursor
		if idx-2 < 0 || idx >= len(request) {
			return false
		}
		isBit := request[idx-2] == 0x03 // 03 位 / 04 字节
		coefficient := 8
		if isBit {
			coefficient = 1
		}
		writeLen := int(request[idx]) / coefficient
		reqBegin := idx + 1
		if reqBegin+writeLen > len(request) {
			return false
		}
		value := request[reqBegin : reqBegin+writeLen]

		// 非最后一个 bit 项需要补位
		if writeLen == 1 && i < itemCount-1 {
			cursor++
		}
		cursor += writeLen

		if writeLen <= 0 {
			continue
		}
		if isBit {
			if store.setBit(area, beginAddress/8, uint(beginAddress%8), value[0] == 0x01) {
				stored++
			}
		} else if store.write(area, beginAddress/8, value) {
			stored++
		}
	}

	details["s7.items"] = itemCount
	details["s7.stored"] = stored
	return true
}
