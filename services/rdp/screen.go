package rdp

import (
	"encoding/binary"
	"image"
	"image/png"
	"os"
)

// 本文件是"画面 + 输入"：
//   - 把配置里的 PNG 缩放成客户端请求的分辨率，编码成 TS_BITMAP_DATA（无压缩、自底向上、
//     每行 4 字节对齐）；
//   - 解析慢路径/快速路径输入事件，把扫描码翻译成可读按键，得到攻击者在登录界面敲了什么。

// ---------------------------------------------------------------------------
// 图像
// ---------------------------------------------------------------------------

func loadPNG(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return png.Decode(f)
}

// scaleNearest 最近邻缩放，输出 *image.RGBA（后续编码走直接取 Pix 的快路径）
func scaleNearest(src image.Image, w, h int) *image.RGBA {
	if w <= 0 || h <= 0 {
		b := src.Bounds()
		w, h = b.Dx(), b.Dy()
	}
	sb := src.Bounds()
	sw, sh := sb.Dx(), sb.Dy()
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	if sw == 0 || sh == 0 {
		return dst
	}
	for y := 0; y < h; y++ {
		sy := sb.Min.Y + y*sh/h
		for x := 0; x < w; x++ {
			sx := sb.Min.X + x*sw/w
			r, g, b, a := src.At(sx, sy).RGBA()
			i := y*dst.Stride + x*4
			dst.Pix[i] = byte(r >> 8)
			dst.Pix[i+1] = byte(g >> 8)
			dst.Pix[i+2] = byte(b >> 8)
			dst.Pix[i+3] = byte(a >> 8)
		}
	}
	return dst
}

// pickBPP 选择位图更新用的色深：优先跟客户端会话色深一致，避免颜色错乱
func pickBPP(core *clientCore) int {
	switch {
	// 优先跟随客户端宣告的 highColorDepth（24）。32bpp 下 mstsc 对位图更新更挑，
	// 曾触发协议错误 0xd06（颜色深度不兼容），故不主动升到 32。
	case core.highColorDepth == 24:
		return 24
	case core.highColorDepth == 15:
		return 15
	case core.highColorDepth == 16:
		return 16
	case core.supportedColorDepths&0x0008 != 0: // 32bpp
		return 32
	case core.supportedColorDepths&0x0002 != 0: // 16bpp
		return 16
	default:
		return 16
	}
}

// maxStripBytes 单个位图矩形的字节上限。
// TS_BITMAP_DATA.bitmapLength 是 16 位（≤64KB），所以整屏必须切成若干小矩形分别发送。
const maxStripBytes = 28 * 1024

// maxFastPathStripBytes 快速路径（fast-path）位图条带的像素数据上限。
// 快速路径 PDU 的长度字段只有 14 位（规范：总长 SHOULD ≤ 16383），远超上限会被
// mstsc 判为协议错误(0x1204)并中断会话；扣除外壳+TS_BITMAP_DATA 头（约 28 字节）后留余量。
const maxFastPathStripBytes = 16*1024 - 512

// bitmapStrips 把整屏按行切成若干个矩形（每个 ≤ maxBytes），返回各自的 TS_BITMAP_DATA
func bitmapStrips(img *image.RGBA, bpp, maxBytes int) [][]byte {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	rowLen := ((w*bpp + 31) / 32) * 4
	rows := maxBytes / rowLen
	if rows < 1 {
		rows = 1
	}
	out := make([][]byte, 0, h/rows+1)
	for y := 0; y < h; y += rows {
		y1 := y + rows
		if y1 > h {
			y1 = h
		}
		out = append(out, encodeStrip(img, y, y1, bpp))
	}
	return out
}

// encodeStrip 编码 img 的 [y0,y1) 行为一段 TS_BITMAP_DATA（MS-RDPBCGR 2.2.9.1.1.3.1.2.2）：
// 无压缩、矩形内部自底向上、每行 4 字节对齐
func encodeStrip(img *image.RGBA, y0, y1, bpp int) []byte {
	w := img.Bounds().Dx()
	h := y1 - y0
	rowLen := ((w*bpp + 31) / 32) * 4
	pix := make([]byte, rowLen*h)

	putPixel := func(off int, r, g, bl uint8) {
		switch bpp {
		case 32:
			pix[off] = bl
			pix[off+1] = g
			pix[off+2] = r
			pix[off+3] = 0xff
		case 24:
			pix[off] = bl
			pix[off+1] = g
			pix[off+2] = r
		case 16: // RGB565
			v := uint16(r>>3)<<11 | uint16(g>>2)<<5 | uint16(bl>>3)
			binary.LittleEndian.PutUint16(pix[off:], v)
		default: // 15bpp RGB555
			v := uint16(r>>3)<<10 | uint16(g>>3)<<5 | uint16(bl>>3)
			binary.LittleEndian.PutUint16(pix[off:], v)
		}
	}
	for i := 0; i < h; i++ {
		srcRow := y1 - 1 - i // 矩形内自底向上
		off := i * rowLen
		for x := 0; x < w; x++ {
			j := srcRow*img.Stride + x*4
			putPixel(off+x*bpp/8, img.Pix[j], img.Pix[j+1], img.Pix[j+2])
		}
	}

	out := make([]byte, 0, 18+len(pix))
	appendU16 := func(v uint16) { out = append(out, byte(v), byte(v>>8)) }
	appendU16(0)             // destLeft
	appendU16(uint16(y0))    // destTop
	appendU16(uint16(w - 1)) // destRight（含端点）
	appendU16(uint16(y1 - 1))
	appendU16(uint16(w)) // width
	appendU16(uint16(h))
	appendU16(uint16(bpp)) // bitsPerPixel
	appendU16(0x0000)      // flags：无压缩
	appendU16(uint16(len(pix)))
	return append(out, pix...)
}

// buildFastPathDefaultPointer 发送"使用系统默认指针"的快速路径更新（MS-RDPBCGR 2.2.9.1.2.1.4）。
//
// 真实服务器在会话建立后一定会发指针更新：缺了它客户端会一直处于"没有任何光标"的状态，
// 而它仍在不断上报鼠标/键盘输入——mstsc 在这种状态下会判定协议异常（0x2904）。
//
// 布局：fpOutputHeader(1) + length1|length2(2) + updateHeader(1) + size(2, 大端) + xorBpp(2)
func buildFastPathDefaultPointer() []byte {
	updateData := []byte{0x00, 0x00} // xorBpp：空/默认指针无掩码数据
	update := make([]byte, 0, 3+len(updateData))
	// updateHeader：updateCode 占低 4 位，FASTPATH_UPDATETYPE_PTR_DEFAULT = 0x6
	update = append(update, 0x06)
	update = append(update, byte(len(updateData)>>8), byte(len(updateData))) // size（大端）
	update = append(update, updateData...)

	total := 3 + len(update)
	out := make([]byte, 0, total)
	out = append(out, 0x00)                             // fpOutputHeader：快路径、未加密
	out = append(out, byte(total>>8)|0x80, byte(total)) // 长格式总长
	return append(out, update...)
}

// 目前置 false：我们的 fast-path 封装会让 mstsc 收下第一帧位图即报协议错误 0xd06
// （同一帧载荷走慢路径时 mstsc 要求的封装细节不同，尚未完全对齐，见 buildFastPathBitmapUpdate）。
// 两条路径的 TS_BITMAP_DATA 载荷格式完全相同（MS-RDPBCGR 2.2.9.1.2.1.2：
// "Both slow-path and fast-path utilize the same data format"），客户端渲染结果一致。
var fastPathBitmapEnabled = false

// useFastPathBitmap 是否用快速路径推送画面：需开关开启、客户端声明支持、且非标准 RDP 安全。
func (s *rdpSession) useFastPathBitmap() bool {
	return fastPathBitmapEnabled && !s.standardSec && s.fastPathOut
}

// buildFastPathBitmapUpdate 快速路径输出外壳（MS-RDPBCGR 2.2.9.1.2），画面帧走这条。
//
//	布局：fpOutputHeader(1) + length1 [length2] + TS_FP_UPDATE{
//	        updateHeader(1) + [compressionFlags] + size(2, 大端) + updateData }
//
// updateHeader 位域（MS-RDPBCGR 2.2.9.1.2.1）：updateCode 占低 4 位，fragmentation 占 bit4-5，
// compression 占 bit6-7。BITMAP 的 updateCode=0x1、SINGLE=0、未压缩=0 → 字节 0x01。
// （曾写成 0x10，等于把 updateCode 塞进高 4 位；mstsc 会按 ORDERS 解析 → 协议错误 0xd06。）
func buildFastPathBitmapUpdate(bitmapData []byte) []byte {
	updateData := make([]byte, 0, 4+len(bitmapData))
	updateData = append(updateData, 0x01, 0x00) // updateType = UPDATETYPE_BITMAP
	updateData = append(updateData, 0x01, 0x00) // numberRectangles = 1
	updateData = append(updateData, bitmapData...)

	update := make([]byte, 0, 3+len(updateData))
	update = append(update, 0x01)                                            // updateHeader：updateCode=BITMAP(1) 在低 4 位 | SINGLE(0) | 未压缩(0)
	update = append(update, byte(len(updateData)>>8), byte(len(updateData))) // size（大端）
	update = append(update, updateData...)

	out := make([]byte, 0, 3+len(update))
	out = append(out, 0x00)                             // fpOutputHeader：FASTPATH 输出、未加密
	total := 3 + len(update)                            // fpOutputHeader(1) + length(2) + update
	out = append(out, byte(total>>8)|0x80, byte(total)) // 长格式：总长 = (length1&0x7F)<<8 | length2
	return append(out, update...)
}

// buildSlowPathBitmapUpdate 慢路径（共享数据 PDU）形式的位图更新
func buildSlowPathBitmapUpdate(shareID uint32, userID uint16, bitmapData []byte) []byte {
	update := make([]byte, 0, 4+len(bitmapData))
	update = append(update, 0x01, 0x00) // UPDATETYPE_BITMAP
	update = append(update, 0x01, 0x00) // numberRectangles
	update = append(update, bitmapData...)
	return buildDataPDU(shareID, userID, pduType2Update, update)
}

// ---------------------------------------------------------------------------
// 输入事件
// ---------------------------------------------------------------------------

const (
	inputEventSync     uint16 = 0x0000
	inputEventScanCode uint16 = 0x0004
	inputEventUnicode  uint16 = 0x0005
	inputEventMouse    uint16 = 0x8001

	kbdFlagsExtended uint16 = 0x0100
	kbdFlagsRelease  uint16 = 0x8000

	ptrFlagsMove  uint16 = 0x0800
	ptrFlagsDown  uint16 = 0x8000
	ptrFlagsWheel uint16 = 0x0200
)

type inputEvent struct {
	messageType uint16
	keyCode     uint16
	flags       uint16
	unicode     uint16
	x, y        uint16
}

// parseSlowPathInput 解析 Client Input Event PDU 的事件数组
// （事件不定长：长度由 messageType 决定，见 MS-RDPBCGR 2.2.1.16.1.1）
func parseSlowPathInput(b []byte) []inputEvent {
	r := newPktReader(b)
	n, err := r.u16le()
	if err != nil {
		return nil
	}
	if err = r.skip(2); err != nil { // pad2Octets
		return nil
	}
	events := make([]inputEvent, 0, n)
	for i := 0; i < int(n) && r.remaining() > 0; i++ {
		if err = r.skip(4); err != nil { // eventTime
			break
		}
		mt, err := r.u16le()
		if err != nil {
			break
		}
		ev := inputEvent{messageType: mt}
		switch mt {
		case inputEventSync:
			_ = r.skip(2 + 4)
		case inputEventScanCode:
			if ev.flags, err = r.u16le(); err != nil {
				return events
			}
			if ev.keyCode, err = r.u16le(); err != nil {
				return events
			}
			// 部分客户端在扫描码事件后多补 2 字节
			if r.remaining() >= 2 && int(n) == 1 {
				_ = r.skip(2)
			}
		case inputEventUnicode:
			if ev.flags, err = r.u16le(); err != nil {
				return events
			}
			if ev.unicode, err = r.u16le(); err != nil {
				return events
			}
			_ = r.skip(2)
		case inputEventMouse:
			if ev.flags, err = r.u16le(); err != nil {
				return events
			}
			if ev.x, err = r.u16le(); err != nil {
				return events
			}
			if ev.y, err = r.u16le(); err != nil {
				return events
			}
		default:
			return events
		}
		events = append(events, ev)
	}
	return events
}

// parseFastPathInput 解析快速路径输入（会话建立后大部分客户端都走这条）
func parseFastPathInput(b []byte) []inputEvent {
	r := newPktReader(b)
	var events []inputEvent
	for r.remaining() > 0 {
		head, err := r.u8()
		if err != nil {
			break
		}
		code := head & 0x1f
		flags := head >> 5
		switch code {
		case 0x00: // scancode
			kc, err := r.u8()
			if err != nil {
				return events
			}
			kf, err := r.u8()
			if err != nil {
				return events
			}
			ev := inputEvent{messageType: inputEventScanCode, keyCode: uint16(kc)}
			if kf&0x01 != 0 {
				ev.flags |= kbdFlagsRelease
			}
			if kf&0x02 != 0 {
				ev.flags |= kbdFlagsExtended
			}
			if flags&0x01 != 0 { // 快速路径自己的 release 位
				ev.flags |= kbdFlagsRelease
			}
			events = append(events, ev)
		case 0x01, 0x02: // mouse / mousex
			ev := inputEvent{messageType: inputEventMouse}
			if ev.flags, err = r.u16le(); err != nil {
				return events
			}
			if ev.x, err = r.u16le(); err != nil {
				return events
			}
			if ev.y, err = r.u16le(); err != nil {
				return events
			}
			events = append(events, ev)
		case 0x03: // sync
			_ = r.skip(6)
		case 0x04: // unicode
			u, err := r.u16le()
			if err != nil {
				return events
			}
			kf, _ := r.u16le()
			ev := inputEvent{messageType: inputEventUnicode, unicode: u}
			if kf&0x01 != 0 {
				ev.flags |= kbdFlagsRelease
			}
			events = append(events, ev)
		default:
			return events
		}
	}
	return events
}

// ---------------------------------------------------------------------------
// 扫描码 → 可读按键（US 布局）
// ---------------------------------------------------------------------------

type keyStroke struct {
	text    string // 可直接连成"输入串"的文本
	special string // <ENTER> 这类特殊键
	isKey   bool
}

var scanTable = map[uint8][2]string{
	0x02: {"1", "!"}, 0x03: {"2", "@"}, 0x04: {"3", "#"}, 0x05: {"4", "$"}, 0x06: {"5", "%"},
	0x07: {"6", "^"}, 0x08: {"7", "&"}, 0x09: {"8", "*"}, 0x0A: {"9", "("}, 0x0B: {"0", ")"},
	0x0C: {"-", "_"}, 0x0D: {"=", "+"},
	0x10: {"q", "Q"}, 0x11: {"w", "W"}, 0x12: {"e", "E"}, 0x13: {"r", "R"}, 0x14: {"t", "T"},
	0x15: {"y", "Y"}, 0x16: {"u", "U"}, 0x17: {"i", "I"}, 0x18: {"o", "O"}, 0x19: {"p", "P"},
	0x1A: {"[", "{"}, 0x1B: {"]", "}"},
	0x1E: {"a", "A"}, 0x1F: {"s", "S"}, 0x20: {"d", "D"}, 0x21: {"f", "F"}, 0x22: {"g", "G"},
	0x23: {"h", "H"}, 0x24: {"j", "J"}, 0x25: {"k", "K"}, 0x26: {"l", "L"},
	0x27: {";", ":"}, 0x28: {"'", "\""}, 0x29: {"`", "~"},
	0x2B: {"\\", "|"},
	0x2C: {"z", "Z"}, 0x2D: {"x", "X"}, 0x2E: {"c", "C"}, 0x2F: {"v", "V"}, 0x30: {"b", "B"},
	0x31: {"n", "N"}, 0x32: {"m", "M"}, 0x33: {",", "<"}, 0x34: {".", ">"}, 0x35: {"/", "?"},
	0x37: {"*", "*"}, 0x39: {" ", " "},
	0x4A: {"-", "-"}, 0x4E: {"+", "+"},
}

var specialKeys = map[uint8]string{
	0x01: "<ESC>", 0x0E: "<BS>", 0x0F: "<TAB>", 0x1C: "<ENTER>", 0x0D: "<ENTER>",
	0x48: "<UP>", 0x50: "<DOWN>", 0x4B: "<LEFT>", 0x4D: "<RIGHT>",
	0x47: "<HOME>", 0x4F: "<END>", 0x49: "<PGUP>", 0x51: "<PGDN>", 0x52: "<INS>", 0x53: "<DEL>",
	0x3B: "<F1>", 0x3C: "<F2>", 0x3D: "<F3>", 0x3E: "<F4>", 0x3F: "<F5>", 0x40: "<F6>",
	0x41: "<F7>", 0x42: "<F8>", 0x43: "<F9>", 0x44: "<F10>", 0x57: "<F11>", 0x58: "<F12>",
	0x1D: "", 0x2A: "", 0x36: "", 0x38: "", 0x3A: "", // 修饰键不单独成字符
}

// keyTracker 维护修饰键状态并翻译按键，用于还原"攻击者敲了什么"
type keyTracker struct {
	shift bool
	ctrl  bool
	alt   bool
	caps  bool
	line  []rune
}

func (k *keyTracker) typed() string { return string(k.line) }

func (k *keyTracker) feed(sc uint8, release, extended bool) keyStroke {
	switch sc {
	case 0x2A, 0x36:
		k.shift = !release
		return keyStroke{}
	case 0x1D:
		k.ctrl = !release
		if extended {
			k.ctrl = true
		}
		return keyStroke{}
	case 0x38:
		k.alt = !release
		return keyStroke{}
	case 0x3A:
		if !release {
			k.caps = !k.caps
		}
		return keyStroke{}
	}
	if release {
		return keyStroke{}
	}
	if sp, ok := specialKeys[sc]; ok {
		if sp == "" {
			return keyStroke{}
		}
		switch sp {
		case "<BS>":
			if n := len(k.line); n > 0 {
				k.line = k.line[:n-1]
			}
		case "<ENTER>":
			k.line = append(k.line, '\n')
		case "<TAB>":
			k.line = append(k.line, '\t')
		}
		return keyStroke{special: sp, isKey: true}
	}
	pair, ok := scanTable[sc]
	if !ok {
		return keyStroke{isKey: true}
	}
	if extended && k.alt {
		return keyStroke{isKey: true} // Alt+方向键之类的组合不产出字符
	}
	ch := pair[0]
	switch {
	case ch >= "a" && ch <= "z": // 字母：Shift 与 CapsLock 异或
		if k.shift != k.caps {
			ch = pair[1]
		}
	case k.shift && pair[1] != "": // 符号：只看 Shift
		ch = pair[1]
	}
	k.line = append(k.line, []rune(ch)...)
	return keyStroke{text: ch, isKey: true}
}
