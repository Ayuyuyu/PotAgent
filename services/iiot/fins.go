package iiot

import (
	"bytes"
	"fmt"
	"net"

	"potAgent/common"
	"potAgent/logger"
	"potAgent/services"
)

const (
	// finsHeaderLen 是 FINS/TCP 头部长度；握手后还要再读 14 字节。
	finsHeaderLen = 20
	finsTailLen   = 14
	// finsMaxLength 是单次读写的数量防呆上限。
	finsMaxLength = 1024
	// FINS 命令码：0x01 读、0x02 写。
	finsCommandRead  = 0x01
	finsCommandWrite = 0x02
)

// finsBasicCommand 是握手指令特征。参考实现只比较前 16 字节，这里保持一致。
var finsBasicCommand = []byte{
	0x46, 0x49, 0x4E, 0x53, // "FINS"
	0x00, 0x00, 0x00, 0x0C, // length
	0x00, 0x00, 0x00, 0x00, // command
	0x00, 0x00, 0x00, 0x00, // error code
}

// finsHandshakeResponse 是 FINS/TCP 握手响应（24 字节字面量，[20] 为服务器节点编号）。
var finsHandshakeResponse = []byte{
	0x46, 0x49, 0x4E, 0x53,
	0x00, 0x00, 0x00, 0x10,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x01,
}

// finsResponseHead 是 FINS 读响应的固定 30 字节头（[4..7] 长度字段应答时改写），
// 写响应复用同一头、只把长度改成 22。
var finsResponseHead = []byte{
	0x46, 0x49, 0x4E, 0x53, // "FINS"
	0x00, 0x00, 0x00, 0x1A, // length
	0x00, 0x00, 0x00, 0x00, // command
	0x00, 0x00, 0x00, 0x00, // error code
	0x00, 0x00, 0x00, 0x00, // client node address
	0x00, 0x00, 0x00, 0x00, // server node address
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,
}

// isFinsBitArea 判断数据区码是否按位访问（DM/CIO/WR/HR/AR 区的位码）。
func isFinsBitArea(dataAreaCode byte) bool {
	switch dataAreaCode {
	case 0x02, 0x30, 0x31, 0x32, 0x33:
		return true
	default:
		return false
	}
}

// handleFins 处理欧姆龙 FINS/TCP。
// 帧布局参照 IoTServer/Servers/PLC/OmronFinsServer.cs：20 字节头，
// 中间 14 字节取命令/长度/数据区，写请求继续读数据体并落数据存储（位区 1 字节 1 个位，
// 字区 2 字节 1 个字），之后读同一地址能读到写入的值。
func handleFins(conn net.Conn, service *services.Service, cfg *iiotConfig, store *dataStore, src, dst common.Addr) {
	protocol := service.BaseOptions.Protocol
	for {
		head, err := readFull(conn, finsHeaderLen)
		if err != nil {
			return
		}
		details := map[string]interface{}{
			"ics.raw": rawHex(head),
		}

		// 连接握手
		if bytes.Equal(head[:len(finsBasicCommand)], finsBasicCommand) {
			details["ics.operation"] = "handshake"
			pushICS(protocol+"-request", src, dst, service, cfg, details)
			if _, err := conn.Write(finsHandshakeWithNode(cfg)); err != nil {
				logger.Log.Debug("iiot: fins write handshake response failed: ", err)
				return
			}
			continue
		}

		tail, err := readFull(conn, finsTailLen)
		if err != nil {
			return
		}
		request := append(head, tail...)

		commandCode := request[27]
		readWriteLength := int(request[32])<<8 | int(request[33])
		dataAreaCode := request[28]
		isBit := isFinsBitArea(dataAreaCode)
		addressLength := 2
		if isBit {
			addressLength = 1
		}
		if readWriteLength < 0 || readWriteLength > finsMaxLength {
			return
		}

		if commandCode == finsCommandWrite {
			// 写请求：数据体在 34 字节之后
			value, err := readFull(conn, readWriteLength*addressLength)
			if err != nil {
				return
			}
			request = append(request, value...)
		}

		area := fmt.Sprintf("fins-area-%#x", dataAreaCode)
		// 字区按 2 字节 1 个字，位区按 1 字节 1 个位（位地址 = 字地址*16 + 位号）
		address := int(request[30]) + int(request[29])*256
		offset := address * 2
		if isBit {
			offset = address*16 + int(request[31])
		}

		details["ics.raw"] = rawHex(request)
		details["fins.command"] = commandCode
		details["fins.data-area"] = dataAreaCode
		details["fins.address"] = address
		details["fins.length"] = readWriteLength

		var response []byte
		switch commandCode {
		case finsCommandRead:
			details["ics.operation"] = "read"
			data := store.read(area, offset, readWriteLength*addressLength)
			response = make([]byte, len(finsResponseHead)+len(data))
			copy(response, finsResponseHead)
			setBigEndianLength(response, 22+len(data))
			copy(response[len(finsResponseHead):], data)
		case finsCommandWrite:
			details["ics.operation"] = "write"
			if len(request) > 34 {
				details["fins.value"] = rawHex(request[34:])
				details["fins.stored"] = store.write(area, offset, request[34:])
			}
			response = make([]byte, len(finsResponseHead))
			copy(response, finsResponseHead)
			setBigEndianLength(response, 22)
		default:
			details["ics.operation"] = fmt.Sprintf("command-%d", commandCode)
		}

		pushICS(protocol+"-request", src, dst, service, cfg, details)
		if len(response) == 0 {
			continue
		}
		if _, err := conn.Write(response); err != nil {
			logger.Log.Debug("iiot: fins write response failed: ", err)
			return
		}
	}
}

// finsHandshakeWithNode 按配置的服务器节点编号（node，默认 1）拼握手响应。
func finsHandshakeWithNode(cfg *iiotConfig) []byte {
	response := append([]byte{}, finsHandshakeResponse...)
	node := byte(1)
	if cfg != nil && cfg.Node != 0 {
		node = cfg.Node
	}
	response[20] = node
	return response
}

// setBigEndianLength 把 FINS 长度字段写到 [4..7]（大端）。
func setBigEndianLength(frame []byte, length int) {
	frame[4] = byte(length >> 24)
	frame[5] = byte(length >> 16)
	frame[6] = byte(length >> 8)
	frame[7] = byte(length)
}
