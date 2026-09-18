package iiot

import (
	"fmt"
	"net"

	"potAgent/common"
	"potAgent/logger"
	"potAgent/services"
)

const (
	// modbusMaxFrame 是 MBAP length 字段的防呆上限（正常请求远小于此）。
	modbusMaxFrame = 260
	// modbusMaxRegisters / modbusMaxBits 是单次读写的合法数量上限，超出回异常码。
	modbusMaxRegisters = 125
	modbusMaxBits      = 2000
)

// Modbus 异常码（响应功能码 = 请求功能码 | 0x80）。
const (
	modbusExIllegalFunction    = 0x01 // 非法功能
	modbusExIllegalDataAddress = 0x02 // 非法数据地址
	modbusExIllegalDataValue   = 0x03 // 非法数据值
	modbusExServerFailure      = 0x04 // 从站设备故障（如写入被拒绝）
)

// dataStore 的区名：线圈/离散量按位存（1 字节 1 个点位），寄存器按字存（2 字节 1 个寄存器）。
const (
	modbusAreaCoils    = "modbus-coils"
	modbusAreaDiscrete = "modbus-discrete"
	modbusAreaHolding  = "modbus-holding"
	modbusAreaInput    = "modbus-input"
)

// handleModbus 处理 Modbus/TCP（MBAP 头 7 字节 + PDU）。
// 支持功能码 1/2/3/4（读）与 5/6/15/16（写）：写操作落数据存储，之后读同一地址就能读到；
// 站号不一致不响应（可配 unit_id=0 关闭过滤），非法功能/参数回标准异常码。
func handleModbus(conn net.Conn, service *services.Service, cfg *iiotConfig, store *dataStore, src, dst common.Addr) {
	protocol := service.BaseOptions.Protocol
	for {
		head, err := readFull(conn, 8)
		if err != nil {
			return
		}
		// MBAP 的 length 字段表示其后（uid + PDU）的字节数，这里已读到 [4][5]
		bodyLen := int(head[5]) - 2
		if bodyLen < 0 || bodyLen > modbusMaxFrame {
			return
		}
		body, err := readFull(conn, bodyLen)
		if err != nil {
			return
		}
		request := append(head, body...)

		details := map[string]interface{}{
			"ics.raw": rawHex(request),
		}
		if len(request) < 12 {
			details["ics.operation"] = "short-frame"
			pushICS(protocol+"-request", src, dst, service, cfg, details)
			continue
		}

		unitID := request[6]
		funcCode := request[7]
		address := int(request[8])<<8 | int(request[9])
		quantity := int(request[10])<<8 | int(request[11])
		details["modbus.unit-id"] = unitID
		details["modbus.function"] = funcCode
		details["modbus.address"] = address
		details["modbus.quantity"] = quantity

		// 站号过滤：像真实总线设备一样，不响应别的站号（unit_id=0 表示不过滤）
		if cfg.UnitID != 0 && unitID != cfg.UnitID {
			details["ics.operation"] = "unit-mismatch"
			details["modbus.unit-mismatch"] = true
			pushICS(protocol+"-request", src, dst, service, cfg, details)
			continue
		}

		pdu := modbusHandlePDU(request, funcCode, address, quantity, cfg, store, details)
		pushICS(protocol+"-request", src, dst, service, cfg, details)

		if len(pdu) == 0 {
			continue
		}
		if _, err := conn.Write(modbusWrap(request, pdu)); err != nil {
			logger.Log.Debug("iiot: modbus write response failed: ", err)
			return
		}
	}
}

// modbusHandlePDU 按功能码处理一帧 PDU，返回应答 PDU（空表示不响应）。
func modbusHandlePDU(request []byte, funcCode byte, address, quantity int, cfg *iiotConfig, store *dataStore, details map[string]interface{}) []byte {
	switch funcCode {
	case 1, 2: // 读线圈 / 读离散输入
		area, op := modbusAreaCoils, "read-coils"
		if funcCode == 2 {
			area, op = modbusAreaDiscrete, "read-discrete-inputs"
		}
		details["ics.operation"] = op
		if quantity <= 0 || quantity > modbusMaxBits || address+quantity > 65536 {
			return modbusException(funcCode, modbusExIllegalDataValue)
		}
		if address+quantity > 65536 {
			return modbusException(funcCode, modbusExIllegalDataAddress)
		}
		bits := store.read(area, address, quantity)
		byteCount := (quantity + 7) / 8
		packed := make([]byte, byteCount)
		for i, v := range bits {
			if v != 0 {
				packed[i/8] |= 1 << (i % 8)
			}
		}
		return append([]byte{funcCode, byte(byteCount)}, packed...)

	case 3, 4: // 读保持寄存器 / 读输入寄存器
		area, op := modbusAreaHolding, "read-holding-registers"
		if funcCode == 4 {
			area, op = modbusAreaInput, "read-input-registers"
		}
		details["ics.operation"] = op
		if quantity <= 0 || quantity > modbusMaxRegisters {
			return modbusException(funcCode, modbusExIllegalDataValue)
		}
		if address+quantity > 65536 {
			return modbusException(funcCode, modbusExIllegalDataAddress)
		}
		data := store.read(area, address*2, quantity*2)
		return append([]byte{funcCode, byte(len(data))}, data...)

	case 5: // 写单个线圈
		details["ics.operation"] = "write-single-coil"
		value := int(request[10])<<8 | int(request[11])
		details["modbus.value"] = value
		if value != 0x0000 && value != 0xFF00 {
			return modbusException(funcCode, modbusExIllegalDataValue)
		}
		coil := byte(0)
		if value == 0xFF00 {
			coil = 0x01
		}
		if !store.write(modbusAreaCoils, address, []byte{coil}) {
			return modbusException(funcCode, modbusExServerFailure)
		}
		return request[7:12]

	case 6: // 写单个寄存器
		details["ics.operation"] = "write-single-register"
		details["modbus.value"] = int(request[10])<<8 | int(request[11])
		if !store.write(modbusAreaHolding, address*2, request[10:12]) {
			return modbusException(funcCode, modbusExServerFailure)
		}
		return request[7:12]

	case 15: // 写多个线圈
		details["ics.operation"] = "write-multiple-coils"
		if len(request) < 14 {
			return modbusException(funcCode, modbusExIllegalDataValue)
		}
		byteCount := int(request[12])
		if quantity <= 0 || quantity > modbusMaxBits || byteCount != (quantity+7)/8 ||
			len(request) < 13+byteCount || address+quantity > 65536 {
			return modbusException(funcCode, modbusExIllegalDataValue)
		}
		values := make([]byte, quantity)
		for i := 0; i < quantity; i++ {
			if request[13+i/8]>>(i%8)&0x01 != 0 {
				values[i] = 0x01
			}
		}
		if !store.write(modbusAreaCoils, address, values) {
			return modbusException(funcCode, modbusExServerFailure)
		}
		return request[7:12]

	case 16: // 写多个寄存器
		details["ics.operation"] = "write-multiple-registers"
		if len(request) < 14 {
			return modbusException(funcCode, modbusExIllegalDataValue)
		}
		byteCount := int(request[12])
		if quantity <= 0 || quantity > modbusMaxRegisters || byteCount != quantity*2 ||
			len(request) < 13+byteCount || address+quantity > 65536 {
			return modbusException(funcCode, modbusExIllegalDataValue)
		}
		if !store.write(modbusAreaHolding, address*2, request[13:13+byteCount]) {
			return modbusException(funcCode, modbusExServerFailure)
		}
		return request[7:12]

	default:
		details["ics.operation"] = fmt.Sprintf("function-%d", funcCode)
		return modbusException(funcCode, modbusExIllegalFunction)
	}
}

// modbusWrap 给 PDU 套上 MBAP 头（事务/协议 ID 与站号原样回显，长度字段重算）。
func modbusWrap(request []byte, pdu []byte) []byte {
	resp := make([]byte, 0, 7+len(pdu))
	resp = append(resp, request[:6]...)
	resp[4] = byte((1 + len(pdu)) >> 8)
	resp[5] = byte(1 + len(pdu))
	resp = append(resp, request[6])
	return append(resp, pdu...)
}

// modbusException 构造异常应答 PDU（功能码 | 0x80 + 异常码）。
func modbusException(funcCode, code byte) []byte {
	return []byte{funcCode | 0x80, code}
}
