package iiot

import (
	"fmt"
	"net"

	"potAgent/common"
	"potAgent/logger"
	"potAgent/services"
)

const (
	// 三菱 MC 请求头长度：A-1E 12 字节、Qna-3E 21 字节。
	mitsubishiA1EHeaderLen   = 12
	mitsubishiQna3EHeaderLen = 21
	// mitsubishiMaxPoints 是单次读写点数防呆上限。
	mitsubishiMaxPoints = 2048
	// A-1E 命令码
	a1eReadBit   = 0x00
	a1eReadWord  = 0x01
	a1eWriteBit  = 0x02
	a1eWriteWord = 0x03
	// Qna-3E 命令码
	qna3ERead  = 0x04
	qna3EWrite = 0x14
)

// handleMitsubishiA1E 处理三菱 MC A-1E 帧（12 字节头 + 可选数据体）。
// 帧布局参照 IoTServer/Servers/PLC/MitsubishiA1EServer.cs：
// [0] 命令码（00 读位 / 01 读字 / 02 写位 / 03 写字），
// [4..5] 起始地址、[8..9] 软元件码、[10..11] 点数。
// 位区 1 字节存 2 个点位（bit4/bit0），字区 2 字节 1 个字；写操作落数据存储。
func handleMitsubishiA1E(conn net.Conn, service *services.Service, cfg *iiotConfig, store *dataStore, src, dst common.Addr) {
	protocol := service.BaseOptions.Protocol
	for {
		head, err := readFull(conn, mitsubishiA1EHeaderLen)
		if err != nil {
			return
		}
		points := int(head[10]) + int(head[11])*256
		if points < 0 || points > mitsubishiMaxPoints {
			return
		}

		// 写位：数据字节数 = [11]*256 + [10]；写字：字节数 = 点数 * 2
		var body []byte
		switch head[0] {
		case a1eWriteBit:
			body, err = readFull(conn, points)
		case a1eWriteWord:
			body, err = readFull(conn, points*2)
		}
		if err != nil {
			return
		}
		request := append(head, body...)

		area := fmt.Sprintf("a1e-%02x%02x", request[8], request[9])
		beginAddress := int(request[5])*256 + int(request[4])

		details := map[string]interface{}{
			"ics.raw":           rawHex(request),
			"ics.address":       fmt.Sprintf("%02x%02x-%d", request[8], request[9], beginAddress),
			"mitsubishi.points": points,
		}

		var response []byte
		switch request[0] {
		case a1eReadBit:
			details["ics.operation"] = "read-bit"
			dataLen := (points + 1) / 2
			response = make([]byte, 2+dataLen)
			copy(response, []byte{0x80, 0x00})
			if points == 1 {
				// 一个字节存两个点位：读出对应位的呈现值（0x10/0x00）
				mask := byte(0x01)
				if beginAddress%2 == 0 {
					mask = 0x10
				}
				if store.read(area, beginAddress/2, 1)[0]&mask != 0 {
					response[2] = 0x10
				}
			} else {
				copy(response[2:], store.read(area, beginAddress/2, dataLen))
			}
		case a1eReadWord:
			details["ics.operation"] = "read-word"
			data := store.read(area, beginAddress*2, points*2)
			response = make([]byte, 2+len(data))
			copy(response, []byte{0x81, 0x00})
			copy(response[2:], data)
		case a1eWriteBit:
			details["ics.operation"] = "write-bit"
			bit := uint(0)
			if beginAddress%2 == 0 {
				bit = 4
			}
			details["mitsubishi.stored"] = store.setBit(area, beginAddress/2, bit, len(body) > 0 && body[0] == 0x10)
			response = []byte{0x82, 0x00}
		case a1eWriteWord:
			details["ics.operation"] = "write-word"
			details["mitsubishi.value"] = rawHex(body)
			details["mitsubishi.stored"] = store.write(area, beginAddress*2, body)
			response = []byte{0x83, 0x00}
		default:
			details["ics.operation"] = fmt.Sprintf("command-%#x", request[0])
		}

		pushICS(protocol+"-request", src, dst, service, cfg, details)
		if len(response) == 0 {
			continue
		}
		if _, err := conn.Write(response); err != nil {
			logger.Log.Debug("iiot: mitsubishi a1e write response failed: ", err)
			return
		}
	}
}

// handleMitsubishiQna3E 处理三菱 MC Qna-3E 帧（21 字节头 + 可选数据体）。
// 帧布局参照 IoTServer/Servers/PLC/MitsubishiQna3EServer.cs：
// [12] 命令码（0x04 读 / 0x14 写）、[13] 子命令（0x01 位）、[15..17] 起始地址、
// [18] 软元件码、[19..20] 点数。位区 1 字节存 2 个点位，字区 2 字节 1 个字。
func handleMitsubishiQna3E(conn net.Conn, service *services.Service, cfg *iiotConfig, store *dataStore, src, dst common.Addr) {
	protocol := service.BaseOptions.Protocol
	for {
		head, err := readFull(conn, mitsubishiQna3EHeaderLen)
		if err != nil {
			return
		}
		points := int(head[19]) + int(head[20])*256
		if points < 0 || points > mitsubishiMaxPoints {
			return
		}
		isBit := head[13] == 0x01

		// 写请求：数据字节数 = 点数 * 2，按位时固定 1 字节
		var body []byte
		if head[12] == qna3EWrite {
			dataLen := points * 2
			if isBit {
				dataLen = 1
			}
			body, err = readFull(conn, dataLen)
			if err != nil {
				return
			}
			head = append(head, body...)
		}
		request := head

		area := fmt.Sprintf("qna3e-%02x", request[18])
		beginAddress := int(request[17])*65536 + int(request[16])*256 + int(request[15])

		details := map[string]interface{}{
			"ics.raw":           rawHex(request),
			"ics.address":       fmt.Sprintf("%02x-%d", request[18], beginAddress),
			"mitsubishi.points": points,
			"mitsubishi.bit":    isBit,
		}

		var response []byte
		switch request[12] {
		case qna3ERead:
			details["ics.operation"] = "read"
			dataLen := points * 2
			offset := beginAddress * 2
			if isBit {
				dataLen = (points + 1) / 2
				offset = beginAddress / 2
			}
			data := store.read(area, offset, dataLen)
			response = make([]byte, 11+len(data))
			copy(response, []byte{0xD0, 0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00})
			// [7..8] 是“其后还有多少长度”（小端）
			responseLen := 2 + len(data)
			response[7] = byte(responseLen % 256)
			response[8] = byte(responseLen / 256)
			copy(response[11:], data)
			if isBit && points == 1 {
				// 单点位读：返回呈现值 0x10/0x00
				mask := byte(0x01)
				if beginAddress%2 == 0 {
					mask = 0x10
				}
				if data[0]&mask != 0 {
					response[11] = 0x10
				}
			}
		case qna3EWrite:
			details["ics.operation"] = "write"
			if isBit {
				bit := uint(0)
				if beginAddress%2 == 0 {
					bit = 4
				}
				details["mitsubishi.stored"] = store.setBit(area, beginAddress/2, bit, len(body) > 0 && body[0] == 0x10)
			} else {
				details["mitsubishi.value"] = rawHex(body)
				details["mitsubishi.stored"] = store.write(area, beginAddress*2, body)
			}
			response = []byte{0xD0, 0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00}
		default:
			details["ics.operation"] = fmt.Sprintf("command-%#x", request[12])
		}

		pushICS(protocol+"-request", src, dst, service, cfg, details)
		if len(response) == 0 {
			continue
		}
		if _, err := conn.Write(response); err != nil {
			logger.Log.Debug("iiot: mitsubishi qna3e write response failed: ", err)
			return
		}
	}
}
