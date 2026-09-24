package rdp

import (
	"bytes"
	"encoding/binary"
	"image"
	"math/big"
	"testing"
)

// 这里固化几处实现时踩过的字节级约定，防止后续改动悄悄破坏兼容性：
//  1. client random 的 RSA 字节序（反转一次 vs 两次）
//  2. T.125 ConferenceCreate 的 PER 前缀（FreeRDP 对 PER 长度有校验）
//  3. 专有证书必须以 dwVersion 开头、签名字段为 72 字节（FreeRDP 硬性要求）
//  4. Client Info 两种字段长度写法（协议规定 vs grdp 等客户端的实际写法）
//  5. 快速路径位图更新的分帧长度计算

// TestDecryptClientRandom 校验客户端随机数恢复：按 grdp/FreeRDP 的加密写法构造密文，
// 服务端解出的必须等于原始随机数。
func TestDecryptClientRandom(t *testing.T) {
	k, err := generateRdpKey(512)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	cr := randomBytes(32)

	// 客户端侧：证书里的模数是小端存放，客户端按小端解释后得到的整数就是服务端的 n
	//（两次反转相互抵消）；d = int_be(reverse(cr))，r = d^e mod n，
	// enc = reverse(pad_be(r, modLen))
	d := new(big.Int).SetBytes(reverseBytes(cr))
	r := new(big.Int).Exp(d, big.NewInt(int64(k.e)), k.n)
	enc := reverseBytes(padTo(r.Bytes(), k.modulusLen()))

	s := &rdpSession{rdpKey: k}
	if got := s.decryptClientRandom(enc); !bytes.Equal(got, cr) {
		t.Fatalf("client random 恢复错误\n got  %x\n want %x", got, cr)
	}
}

// TestConferenceCreateRoundTrip 校验服务器 GCC 容器的 PER 编码能被剥离逻辑还原，
// 且块数据逐字节一致。
func TestConferenceCreateRoundTrip(t *testing.T) {
	blocks := bytes.Join([][]byte{
		gccBlock(csCore, make([]byte, 12)),
		gccBlock(csNet, make([]byte, 12)),
	}, nil)

	if got := splitConferenceCreate(buildConferenceCreateResponse(blocks), h221KeyServer); !bytes.Equal(got, blocks) {
		t.Fatalf("ConferenceCreateResponse 剥离后块不一致\n got  %x\n want %x", got, blocks)
	}
	if got := splitConferenceCreate(buildConferenceCreateRequest(blocks), h221KeyClient); !bytes.Equal(got, blocks) {
		t.Fatalf("ConferenceCreateRequest 剥离后块不一致\n got  %x\n want %x", got, blocks)
	}
}

// TestProprietaryCertLayout 校验专有证书以 dwVersion 开头、签名字段为 72 字节
// （FreeRDP 硬性要求），且公钥模数与密钥一致。
func TestProprietaryCertLayout(t *testing.T) {
	k, err := generateRdpKey(512)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	cert := buildProprietaryCert(k)

	if binary.LittleEndian.Uint32(cert[0:]) != 0x00000001 {
		t.Fatalf("缺少 dwVersion: %x", cert[0:4])
	}
	if binary.LittleEndian.Uint32(cert[4:]) != 1 || binary.LittleEndian.Uint32(cert[8:]) != 1 {
		t.Fatalf("SigAlg/KeyAlg 不是 RSA: %x", cert[4:12])
	}
	if binary.LittleEndian.Uint16(cert[12:]) != 0x0006 {
		t.Fatalf("publicKeyBlobType 应为 BB_RSA_KEY_BLOB")
	}
	pubLen := int(binary.LittleEndian.Uint16(cert[14:]))
	if pubLen != 92 { // 20 字节 RSA 头 + 64 字节模数 + 8 字节 padding
		t.Fatalf("publicKeyBlobLen = %d, 期望 92", pubLen)
	}
	sigOff := 16 + pubLen
	if binary.LittleEndian.Uint16(cert[sigOff:]) != 0x0008 {
		t.Fatalf("signatureBlobType 应为 BB_RSA_SIGNATURE_BLOB")
	}
	if got := binary.LittleEndian.Uint16(cert[sigOff+2:]); got != 72 {
		t.Fatalf("signatureBlobLen = %d, FreeRDP 要求 72", got)
	}
	mod := cert[16+20 : sigOff-8]
	if !bytes.Equal(mod, reverseBytes(k.n.Bytes())) {
		t.Fatalf("证书模数与密钥不一致")
	}
}

// buildClientInfoPayload 构造 Client Info 载荷：extra=0 为协议规定的写法
// （cbXxx 含结尾 NUL），extra=2 为 grdp 等客户端的实际写法（cbXxx 不含 NUL）。
func buildClientInfoPayload(t *testing.T, extra int) []byte {
	t.Helper()
	str := func(s string) []byte { return append(utf16leEncode(s), 0, 0) }
	fields := [][]byte{str("CORP"), str("alice"), str("pwd123"), str(""), str("")}

	out := make([]byte, 0, 128)
	out = appendLE32(out, 0)           // codePage
	out = appendLE32(out, infoUnicode) // flags
	for _, f := range fields {
		cb := len(f) - extra
		out = append(out, byte(cb), byte(cb>>8)) // cbXxx
	}
	for _, f := range fields {
		out = append(out, f...)
	}
	out = append(out, 0x02, 0x00) // 扩展信息块起始：AF_INET
	out = append(out, make([]byte, 8)...)
	return out
}

// TestParseClientInfoLayouts 两种字段长度写法都必须能解出同样的凭据
func TestParseClientInfoLayouts(t *testing.T) {
	k, err := generateRdpKey(512)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	s := &rdpSession{rdpKey: k, tlsKey: nil, cfg: &rdpConfig{LogPassword: true}}

	for _, extra := range []int{0, 2} {
		ci := s.parseClientInfo(buildClientInfoPayload(t, extra))
		if ci.domain != "CORP" || ci.user != "alice" {
			t.Fatalf("extra=%d 解析错误: domain=%q user=%q", extra, ci.domain, ci.user)
		}
		if ci.password != "pwd123" {
			t.Fatalf("extra=%d 口令解析错误: %q (%s)", extra, ci.password, ci.decodedBy)
		}
	}
}

// TestFastPathBitmapFraming 校验快速路径位图分帧：PER 长度字段应等于整个报文长度，
// size 字段应等于位图更新数据长度。
func TestFastPathBitmapFraming(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 64, 32))
	strips := bitmapStrips(img, 16, maxStripBytes)
	if len(strips) != 1 {
		t.Fatalf("64x32 应只切出一个条带，实际 %d", len(strips))
	}
	pkt := buildFastPathBitmapUpdate(strips[0])

	total := int(pkt[1]&0x7f)<<8 | int(pkt[2])
	if total != len(pkt) {
		t.Fatalf("快速路径长度字段=%d, 实际报文=%d", total, len(pkt))
	}
	// updateHeader 位域（MS-RDPBCGR 2.2.9.1.2.1）：updateCode 占低 4 位（BITMAP=0x1），
	// fragmentation 占 bit4-5（SINGLE=0），compression 占 bit6-7（未压缩=0）→ 0x01。
	// 曾写成 0x10（updateCode 被放进高 4 位），mstsc 会按 ORDERS 解析并报协议错误 0xd06。
	if pkt[3] != 0x01 {
		t.Fatalf("updateHeader = %#x", pkt[3])
	}
	size := int(binary.BigEndian.Uint16(pkt[4:])) // size 字段为**大端**
	if size != len(pkt)-6 {
		t.Fatalf("size 字段=%d, 剩余数据=%d", size, len(pkt)-6)
	}
	if binary.LittleEndian.Uint16(pkt[6:]) != 0x0001 { // updateType
		t.Fatalf("updateType = %x", pkt[6:8])
	}
	if got := binary.LittleEndian.Uint16(pkt[8:]); got != 1 {
		t.Fatalf("numberRectangles = %d", got)
	}
}

// TestPointerPDUHasMessageType 锁定慢路径指针 PDU 的 TS_POINTER_PDU 外壳。
func TestPointerPDUHasMessageType(t *testing.T) {
	pdu := buildPointerPDU(defaultShareID, 1002, pduType2Pointer)
	if got := pdu[14]; got != pduType2Pointer {
		t.Fatalf("pduType2 = %#x, want %#x", got, pduType2Pointer)
	}
	data := pdu[18:]
	if got := binary.LittleEndian.Uint16(data[0:]); got != 0x0008 {
		t.Fatalf("pointer messageType = %#x, want TS_PTRMSGTYPE_POINTER", got)
	}
	if got := binary.LittleEndian.Uint16(data[2:]); got != 0 {
		t.Fatalf("pointer pad = %#x, want 0", got)
	}
	if got := binary.LittleEndian.Uint16(data[4:]); got != 1 {
		t.Fatalf("pointer xorBpp = %d, want 1", got)
	}
}
