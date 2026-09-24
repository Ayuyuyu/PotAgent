package rdp

import "encoding/binary"

// 本文件组装连接序列后半段的 PDU（MS-RDPBCGR 2.2.1.6~2.2.1.20）。
//
// 关键约定：TS_SHARECONTROLHEADER.pduType 的**低 4 位**是 PDU 类型，高 4 位是版本
// （标准 RDP 安全为 0，TLS/NLA 为 1）。这里统一发 1：真实服务器在两种模式下都发 1，
// 而且这样"按低位掩码解析"和"整值比较"的两类客户端都能对上。

const (
	pduTypeDemandActive  = 0x01
	pduTypeConfirmActive = 0x03
	pduTypeDeactivateAll = 0x06
	pduTypeData          = 0x07

	pduType2Update          = 0x02
	pduType2Control         = 0x14
	pduType2Pointer         = 0x1B
	pduType2Input           = 0x1C
	pduType2Synchronize     = 0x1F
	pduType2SuppressOutput  = 0x23
	pduType2FontList        = 0x27
	pduType2FontMap         = 0x28
	pduType2SaveSessionInfo = 0x26

	ctrlActionRequestControl = 0x0001
	ctrlActionGrantedControl = 0x0002
	ctrlActionCooperate      = 0x0004

	shareCtrlVersion = 0x1

	// 能力集类型（MS-RDPBCGR 2.2.7.1.1，数值与 FreeRDP CAPSET_TYPE_* 一致）
	capsGeneral             uint16 = 0x0001
	capsBitmap              uint16 = 0x0002
	capsOrder               uint16 = 0x0003
	capsBitmapCache         uint16 = 0x0004
	capsBitmapCacheV3Codec  uint16 = 0x0006
	capsPointer             uint16 = 0x0008
	capsShare               uint16 = 0x0009
	capsColorCache          uint16 = 0x000A
	capsInput               uint16 = 0x000D
	capsFont                uint16 = 0x000E
	capsVirtualChannel      uint16 = 0x0014
	capsMultiFragmentUpdate uint16 = 0x001A
	capsLargePointer        uint16 = 0x001B
	capsSurfaceCommands     uint16 = 0x001C
	capsBitmapCodecs        uint16 = 0x001D
	capsFrameAcknowledge    uint16 = 0x001E
	// 通用能力集的 extraFlags
	generalFastPathOutput  uint16 = 0x0001
	generalLongCreds       uint16 = 0x0004
	generalNoBitmapCompHdr uint16 = 0x0400
)

// buildShareControl 组装 TS_SHARECONTROLHEADER + body
func buildShareControl(pduType uint16, userID uint16, body []byte) []byte {
	out := make([]byte, 6, 6+len(body))
	binary.LittleEndian.PutUint16(out[0:], uint16(6+len(body)))
	binary.LittleEndian.PutUint16(out[2:], (shareCtrlVersion<<4)|pduType)
	binary.LittleEndian.PutUint16(out[4:], userID)
	return append(out, body...)
}

// buildDataPDU 组装共享数据 PDU（Synchronize / Control / Font Map / 位图更新等）
func buildDataPDU(shareID uint32, userID uint16, pduType2 uint8, data []byte) []byte {
	body := make([]byte, 0, 12+len(data))
	body = appendLE32(body, shareID)
	body = append(body, 0x00) // pad1
	body = append(body, 0x01) // streamId = STREAM_LOW
	// uncompressedLength：按 MS 真实服务器转储（MS-RDPBCGR 4.3.1，总长 624 的 SSI PDU 里
	// 该字段 = 0x270 = 624），它等于**整个共享 PDU 的长度**（totalLength），即
	// 6(ShareControlHeader) + 12(ShareDataHeader) + len(data) = len(data) + 18。
	// 之前写 data+4 比真实服务器小 14，属于与真实服务器的系统性偏差（xfreerdp 不校验、
	// mstsc 会校验）。
	ul := uint16(18 + len(data))
	body = append(body, byte(ul), byte(ul>>8))
	body = append(body, pduType2)
	body = append(body, 0x00)       // compressedType
	body = append(body, 0x00, 0x00) // compressedLength
	body = append(body, data...)
	return buildShareControl(pduTypeData, userID, body)
}

func buildSynchronizePDU(shareID uint32, userID, targetUser uint16) []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint16(data[0:], 1) // messageType = SYNCMSGTYPE_SYNC
	binary.LittleEndian.PutUint16(data[2:], targetUser)
	return buildDataPDU(shareID, userID, pduType2Synchronize, data)
}

func buildControlPDU(shareID uint32, userID uint16, action uint16) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint16(data[0:], action)
	binary.LittleEndian.PutUint16(data[2:], 0) // grantId
	binary.LittleEndian.PutUint32(data[4:], 0) // controlId
	return buildDataPDU(shareID, userID, pduType2Control, data)
}

// buildFontMapPDU 空字体映射：客户端发来 Font List 后必须回一个，否则部分客户端认为连接没就绪
func buildFontMapPDU(shareID uint32, userID uint16) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint16(data[0:], 0) // numberEntries
	binary.LittleEndian.PutUint16(data[2:], 0) // totalNumEntries
	binary.LittleEndian.PutUint16(data[4:], 0x0003)
	binary.LittleEndian.PutUint16(data[6:], 0x0004)
	return buildDataPDU(shareID, userID, pduType2FontMap, data)
}

// buildPointerPDU 发送指针（光标）更新——慢路径共享数据 PDU。
// TS_POINTER_PDU 先是 messageType(2) + pad2Octets(2)，随后才是
// TS_POINTERATTRIBUTE（MS-RDPBCGR 2.2.9.1.1.4/2.2.9.1.1.4.5）：
//
//	messageType=TS_PTRMSGTYPE_POINTER(2) + pad(2) + xorBpp(2) + cacheIndex(2)
//	+ hotSpotX(2) + hotSpotY(2) + width(2) + height(2)
//	+ lengthAndMask(2) + lengthXorMask(2) + xorMaskData + andMaskData
//
// xorBpp=1 表示掩码为 1bpp、行按 2 字节对齐。xor=1 且 and=0 的像素被绘制（白），
// and=1 的像素透明。真实 Windows 服务器在会话建立后必定会发指针更新；缺了它客户端
// 一直处于"没有任何光标"的状态，而它仍在持续上报鼠标/键盘输入 —— mstsc 会因此
// 判为协议异常（0x2904，现象是黑屏后报错）。
func buildPointerPDU(shareID uint32, userID uint16, pduType2 uint8) []byte {
	const w, h = 32, 32
	rowBytes := ((w + 15) / 16) * 2 // 1bpp，行按 2 字节对齐
	xorMask := make([]byte, rowBytes*h)
	andMask := make([]byte, rowBytes*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			// 简易箭头（左上角为热点）：斜边三角 + 尾部竖条
			inside := (x*2 <= 30-y && y < 16) || (y >= 6 && y < 26 && x >= 10 && x <= 14)
			if inside {
				xorMask[y*rowBytes+x/8] |= 1 << uint(7-x%8)
			} else {
				andMask[y*rowBytes+x/8] |= 1 << uint(7-x%8)
			}
		}
	}
	le16 := func(b []byte, v uint16) []byte { return append(b, byte(v), byte(v>>8)) }
	data := make([]byte, 0, 20+len(xorMask)+len(andMask))
	data = le16(data, 0x0008)       // messageType = TS_PTRMSGTYPE_POINTER (New Pointer Update)
	data = le16(data, 0)            // pad2Octets
	data = append(data, 0x01, 0x00) // xorBpp = 1（1bpp 掩码）
	data = le16(data, 0)            // cacheIndex
	data = le16(data, 0)            // hotSpotX
	data = le16(data, 0)            // hotSpotY
	data = le16(data, w)            // width
	data = le16(data, h)            // height
	data = le16(data, uint16(len(andMask)))
	data = le16(data, uint16(len(xorMask)))
	data = append(data, xorMask...)
	data = append(data, andMask...)
	return buildDataPDU(shareID, userID, pduType2, data)
}

// buildSaveSessionInfoPDU 组装 Save Session Info PDU（MS-RDPBCGR 2.2.10.1.1，LogonInfoV1）。
// 服务端在连接完成阶段发它来收尾；mstsc 缺了它会认为会话没就绪而中断。
//
// TS_LOGON_INFO（2.2.10.1.1.1）结构为：
//
//	infoType(4) + cbDomain(4) + cbUserName(4) + pad2Octets(558) + Domain(UTF-16LE) + UserName(UTF-16LE)
//
// 其中 cbXxx 是各自的字节数（含终止 NUL）。客户端会做长度校验，
// 少了它直接判协议错误并掐断连接（xfreerdp 报 "SaveSessionInfo error: infoType: Logon Info V1 (0)"，
func buildSaveSessionInfoPDU(shareID uint32, userID uint16, domain, user string) []byte {
	d := append(utf16leEncode(domain), 0, 0) // UTF-16LE + 终止 NUL
	u := append(utf16leEncode(user), 0, 0)
	info := make([]byte, 0, 4+2+4+4+4+4+558+len(d)+len(u))
	info = appendLE32(info, 1)                // infoType = INFOTYPE_LOGON_LONG（LogonInfo V2）
	info = append(info, 0x01, 0x00)           // Version = 1
	info = appendLE32(info, 18)               // Size = 定长标量头部长度（2+4+4+4+4）
	info = appendLE32(info, 0)                // SessionId
	info = appendLE32(info, uint32(len(d)))   // cbDomain（字节数，含终止 NUL）
	info = appendLE32(info, uint32(len(u)))   // cbUserName
	info = append(info, make([]byte, 558)...) // Pad（558 字节，必须为 0）
	info = append(info, d...)
	info = append(info, u...)
	return buildDataPDU(shareID, userID, pduType2SaveSessionInfo, info)
}

// ---------------------------------------------------------------------------
// 能力集
// ---------------------------------------------------------------------------

func capSet(typ uint16, body []byte) []byte {
	out := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint16(out[0:], typ)
	binary.LittleEndian.PutUint16(out[2:], uint16(4+len(body)))
	copy(out[4:], body)
	return out
}

func capGeneral() []byte {
	body := make([]byte, 20)
	binary.LittleEndian.PutUint16(body[0:], 0x0001) // osMajorType = WINDOWS
	binary.LittleEndian.PutUint16(body[2:], 0x0003) // osMinorType = WINDOWS_NT
	binary.LittleEndian.PutUint16(body[4:], 0x0200) // protocolVersion
	//   NO_BITMAP_COMPRESSION_HDR(0x0400) | ENC_SALTED_CHECKSUM(0x0010) |
	//   AUTORECONNECT_SUPPORTED(0x0008) | LONG_CREDENTIALS_SUPPORTED(0x0004) |
	//   FASTPATH_OUTPUT_SUPPORTED(0x0001)
	binary.LittleEndian.PutUint16(body[10:], 0x041d)
	body[18] = 0x01 // refreshRectSupport
	body[19] = 0x01 // suppressOutputSupport
	return capSet(capsGeneral, body)
}

func capBitmap(core *clientCore, bpp int) []byte {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:], uint16(bpp)) // preferredBitsPerPixel
	binary.LittleEndian.PutUint16(body[2:], 1)           // receive1BitPerPixel
	binary.LittleEndian.PutUint16(body[4:], 1)           // receive4BitsPerPixel
	binary.LittleEndian.PutUint16(body[6:], 1)           // receive8BitsPerPixel
	binary.LittleEndian.PutUint16(body[8:], core.desktopWidth)
	binary.LittleEndian.PutUint16(body[10:], core.desktopHeight)
	// pad2octets(12) 保持 0；desktopResizeFlag(14) 置 1（与真实服务器一致）
	binary.LittleEndian.PutUint16(body[14:], 0x0001)
	binary.LittleEndian.PutUint16(body[16:], 0x0001) // bitmapCompressionFlag（发送时仍只走未压缩位图）
	binary.LittleEndian.PutUint16(body[20:], 1)      // multipleRectangleSupport
	return capSet(capsBitmap, body)
}

// capOrder 数据体 84 字节（含 4 字节头共 0x58）。
// orderSupport 必须声明基础订单（DstBlt/PatBlt/ScrBlt/MemBlt/LineTo/OpaqueRect/
// MultiOpaqueRect/GlyphIndex），数值对齐真实服务器/xrdp；全 0 会被 mstsc 判为能力非法。
func capOrder() []byte {
	body := make([]byte, 84)
	copy(body[0:16], []byte("RDP"))                  // terminalDescriptor
	binary.LittleEndian.PutUint16(body[20:], 1)      // desktopSaveXGranularity
	binary.LittleEndian.PutUint16(body[22:], 20)     // desktopSaveYGranularity
	binary.LittleEndian.PutUint16(body[26:], 1)      // maximumOrderLevel
	binary.LittleEndian.PutUint16(body[28:], 0)      // numberFonts（真实服务器为 0）
	binary.LittleEndian.PutUint16(body[30:], 0x0022) // orderFlags
	os := body[32:64]                                // orderSupport(32)
	os[0] = 1                                        // DstBlt
	os[1] = 1                                        // PatBlt
	os[2] = 1                                        // ScrBlt
	os[3] = 1                                        // MemBlt
	os[8] = 1                                        // LineTo
	os[10] = 1                                       // OpaqueRect
	os[18] = 1                                       // MultiOpaqueRect
	os[27] = 1                                       // GlyphIndex
	binary.LittleEndian.PutUint16(body[64:], 0x6a1)  // textFlags
	// orderSupportExFlags 必须为 0：真实服务器为 0。之前声明 CACHE_BITMAP_REV3_SUPPORT(0x0008)
	// 却从不发 Rev3 缓存指令，属于"声明了却不实现"（同 FrameAcknowledge 的坑）。
	binary.LittleEndian.PutUint16(body[66:], 0x0000)
	binary.LittleEndian.PutUint32(body[72:], 0x0f4240)
	return capSet(capsOrder, body)
}

func capPointer() []byte {
	body := make([]byte, 6)
	binary.LittleEndian.PutUint16(body[0:], 0x0001) // colorPointerFlag
	binary.LittleEndian.PutUint16(body[2:], 0x19)   // colorPointerCacheSize
	binary.LittleEndian.PutUint16(body[4:], 0x19)   // pointerCacheSize（仅服务器发送）
	return capSet(capsPointer, body)
}

// capInput 数据体 84 字节（含 4 字节头共 88），即 TS_INPUT_CAPABILITY_SET 的规范长度；
// 多出来的尾巴会让 FreeRDP 报 "incorrect offset" 并对能力集解析产生噪声。
func capInput(core *clientCore) []byte {
	body := make([]byte, 84)
	// SCANCODES | MOUSEX | UNICODE | FASTPATH_INPUT | FASTPATH_INPUT2 | MOUSE_HWHEEL
	binary.LittleEndian.PutUint16(body[0:], 0x0001|0x0004|0x0010|0x0002|0x0008|0x0020)
	binary.LittleEndian.PutUint32(body[4:], core.kbdLayout)
	binary.LittleEndian.PutUint32(body[8:], core.keyboardType)
	binary.LittleEndian.PutUint32(body[12:], core.keyboardSubType)
	binary.LittleEndian.PutUint32(body[16:], core.keyboardFnKeys)
	return capSet(capsInput, body)
}

func capFont() []byte {
	body := make([]byte, 4)
	binary.LittleEndian.PutUint16(body[0:], 0x0001) // supportFlags = FONTSUPPORT_FONTLIST
	return capSet(capsFont, body)
}

func capShare(channelID uint16) []byte {
	body := make([]byte, 4)
	binary.LittleEndian.PutUint16(body[0:], channelID) // nodeId
	binary.LittleEndian.PutUint16(body[2:], 0xb5e2)    // pad2octets
	return capSet(capsShare, body)
}

// ----- 以下为真实服务器/xrdp 会带、mstsc 期望存在的补充能力集 -----

func capBitmapCacheV3CodecID() []byte {
	return capSet(capsBitmapCacheV3Codec, make([]byte, 1))
}

func capMultiFragmentUpdate(maxSize uint32) []byte {
	body := make([]byte, 4)
	binary.LittleEndian.PutUint32(body[0:], maxSize)
	return capSet(capsMultiFragmentUpdate, body)
}

func capLargePointer() []byte {
	body := make([]byte, 2)
	binary.LittleEndian.PutUint16(body[0:], 0x0001) // LARGE_POINTER_FLAG_96x96
	return capSet(capsLargePointer, body)
}

func capFrameAcknowledge() []byte {
	body := make([]byte, 4)
	binary.LittleEndian.PutUint32(body[0:], 2) // maxUnacknowledgedFrameCount
	return capSet(capsFrameAcknowledge, body)
}

func capColorCache() []byte {
	body := make([]byte, 4)
	binary.LittleEndian.PutUint16(body[0:], 6) // cacheSize
	return capSet(capsColorCache, body)
}

func capVirtualChannel() []byte {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[4:], 1600) // VCChunkSize
	return capSet(capsVirtualChannel, body)
}

// capBitmapCacheHostSupport 位图缓存宿主支持能力集（CAPSTYPE_BITMAPCACHE_HOSTSUPPORT = 18）。
// 真实 Windows 服务器的 Demand Active 里必带这一项（MS-RDPBCGR 4.1.12 转储：type=18、length=8），
// 我们此前漏了它——客户端会据此判断服务器是否具备位图缓存宿主能力（影响它对位图更新的处理）。
func capBitmapCacheHostSupport() []byte {
	body := make([]byte, 4)
	body[0] = 0x01 // CacheVersion = 1（对应 rev.2 能力，MS 4.1.12 转储实测值为 1）
	return capSet(0x0012, body)
}

// buildDemandActive 组装服务器端 Demand Active（MS-RDPBCGR 2.2.1.6.1）
func buildDemandActive(shareID uint32, userID uint16, core *clientCore, bpp int) []byte {
	caps := [][]byte{
		capShare(userID), capGeneral(), capBitmap(core, bpp), capFont(), capOrder(),
		capColorCache(), capPointer(), capInput(core), capVirtualChannel(),
		capBitmapCacheHostSupport(),
	}
	combined := 4 // numberCapabilities + pad2Octets
	for _, c := range caps {
		combined += len(c)
	}
	body := make([]byte, 0, 32+combined)
	body = appendLE32(body, shareID)
	body = append(body, 3, 0) // lengthSourceDescriptor
	combined16 := uint16(combined)
	body = append(body, byte(combined16), byte(combined16>>8))
	body = append(body, "RDP"...)
	body = append(body, byte(len(caps)), 0) // numberCapabilities
	body = append(body, 0x00, 0x00)         // pad2Octets
	for _, c := range caps {
		body = append(body, c...)
	}
	body = appendLE32(body, 0) // sessionId
	return buildShareControl(pduTypeDemandActive, userID, body)
}

// ---------------------------------------------------------------------------
// 客户端 Confirm Active（我们只需要从中取 SHA/能力，用于后续数据 PDU）
// ---------------------------------------------------------------------------

type clientCaps struct {
	shareID        uint32
	originatorID   uint16
	generalFlags   uint16
	fastPathOut    bool
	preferredBPP   int
	desktopWidth   uint16
	desktopHeight  uint16
	suppressOutput bool
}

func parseConfirmActive(b []byte) *clientCaps {
	ca := &clientCaps{}
	r := newPktReader(b)
	var err error
	if ca.shareID, err = r.u32le(); err != nil {
		return ca
	}
	if ca.originatorID, err = r.u16le(); err != nil {
		return ca
	}
	srcLen, err := r.u16le()
	if err != nil {
		return ca
	}
	if _, err = r.u16le(); err != nil { // lengthCombinedCapabilities
		return ca
	}
	if err = r.skip(int(srcLen)); err != nil {
		return ca
	}
	n, err := r.u16le()
	if err != nil {
		return ca
	}
	if err = r.skip(2); err != nil { // pad2Octets
		return ca
	}
	for i := 0; i < int(n); i++ {
		typ, err := r.u16le()
		if err != nil {
			return ca
		}
		l, err := r.u16le()
		if err != nil || l < 4 {
			return ca
		}
		data, err := r.bytes(int(l) - 4)
		if err != nil {
			return ca
		}
		switch typ {
		case capsGeneral:
			if len(data) >= 14 {
				ca.generalFlags = binary.LittleEndian.Uint16(data[10:])
				ca.fastPathOut = ca.generalFlags&generalFastPathOutput != 0
			}
		case capsBitmap:
			if len(data) >= 12 {
				ca.preferredBPP = int(binary.LittleEndian.Uint16(data[0:]))
				if w := binary.LittleEndian.Uint16(data[8:]); w > 0 {
					ca.desktopWidth = w
				}
				if h := binary.LittleEndian.Uint16(data[10:]); h > 0 {
					ca.desktopHeight = h
				}
			}
		}
	}
	return ca
}
