package rdp

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"os"
	"strings"
	"time"
	"unicode/utf16"
)

// 本文件负责"安全层"：
//   - 标准 RDP 安全（MS-RDPBCGR 5.3）：RSA 交换 client random → RC4 会话密钥 + MAC；
//   - TLS / CredSSP：证书准备（自签或复用已有 PEM）；
//   - Client Info PDU 的解析：**口令字段的解密**是 RDP 蜜罐最有价值的产出。
//
// RDP 在标准安全/TLS 下口令是用服务器公钥加密的，我们持有私钥就能还原成明文。

// ---------------------------------------------------------------------------
// 摘要与 UTF-16 小工具
// ---------------------------------------------------------------------------

func md5Sum(b []byte) []byte {
	d := md5.Sum(b)
	return d[:]
}

func sha1Sum(b []byte) []byte {
	d := sha1.Sum(b)
	return d[:]
}

// utf16leDecode 解 UTF-16LE（容忍奇数长度与截断的代理项）
func utf16leDecode(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	n := len(b) / 2
	u := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		u = append(u, binary.LittleEndian.Uint16(b[2*i:]))
	}
	return string(utf16.Decode(u))
}

func utf16leEncode(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(u))
	for i, v := range u {
		binary.LittleEndian.PutUint16(out[2*i:], v)
	}
	return out
}

// utf16leTrim 去掉 UTF-16LE 里的尾部 NUL（客户端名字段是定长填充）
func utf16leTrim(b []byte) string {
	s := utf16leDecode(b)
	return strings.TrimRight(s, "\x00")
}

func printableScore(s string) int {
	if s == "" {
		return 0
	}
	ok := 0
	for _, r := range s {
		switch {
		case r == '\x00':
		case r == '\t', r == '\r', r == '\n':
			ok++
		case r >= 0x20 && r != 0xFFFD && r < 0x3000:
			ok++
		default:
			return -1
		}
	}
	return ok
}

// ---------------------------------------------------------------------------
// 标准 RDP 安全的密钥派生（MS-RDPBCGR 5.3.5）
// ---------------------------------------------------------------------------

type rdpCrypto struct {
	macKey     []byte
	encryptKey []byte // 服务器 → 客户端
	decryptKey []byte // 客户端 → 服务器
	encryptRC4 *rc4.Cipher
	decryptRC4 *rc4.Cipher
	packets    int
}

func saltedHash(input, salt, random1, random2 []byte) []byte {
	h := sha1.New()
	h.Write(input)
	h.Write(salt[:48])
	h.Write(random1)
	h.Write(random2)
	sig := h.Sum(nil)
	sum := md5.New()
	sum.Write(salt[:48])
	sum.Write(sig)
	return sum.Sum(nil)[:16]
}

func secretBlob(prefixes [3]string, secret, random1, random2 []byte) []byte {
	out := []byte{}
	for _, p := range prefixes {
		out = append(out, saltedHash([]byte(p), secret, random1, random2)...)
	}
	return out
}

// deriveStandardKeys 复刻 MS-RDPBCGR 5.3.5：preMasterSecret = clientRandom[0:24] + serverRandom[0:24]，
// 再加盐哈希出 macKey 与两个方向的 RC4 初始密钥。
func deriveStandardKeys(clientRandom, serverRandom []byte) (macKey, serverToClient, clientToServer []byte) {
	if len(clientRandom) < 24 || len(serverRandom) < 24 {
		return nil, nil, nil
	}
	preMaster := append(append([]byte{}, clientRandom[:24]...), serverRandom[:24]...)
	master := secretBlob([3]string{"A", "BB", "CCC"}, preMaster, clientRandom, serverRandom)
	session := secretBlob([3]string{"X", "YY", "ZZZ"}, master, clientRandom, serverRandom)
	final := func(seed []byte) []byte {
		h := md5.New()
		h.Write(seed)
		h.Write(clientRandom)
		h.Write(serverRandom)
		return h.Sum(nil)
	}
	macKey = session[:16]
	serverToClient = final(session[16:32])
	clientToServer = final(session[32:48])
	return
}

// macData 计算 TS_SECURITY_HEADER 后那 8 字节签名（MS-RDPBCGR 5.3.6.1.1）
func macData(macKey, data []byte) []byte {
	h := sha1.New()
	h.Write(macKey)
	h.Write([]byte(strings.Repeat("\x36", 40)))
	var l [4]byte
	binary.LittleEndian.PutUint32(l[:], uint32(len(data)))
	h.Write(l[:])
	h.Write(data)
	sig := h.Sum(nil)

	sum := md5.New()
	sum.Write(macKey)
	sum.Write([]byte(strings.Repeat("\x5c", 48)))
	sum.Write(sig)
	return sum.Sum(nil)
}

// decryptPDU 处理带 TS_SECURITY_HEADER 的载荷，返回 (flags, 明文)
func (c *rdpCrypto) decryptPDU(b []byte) (uint16, []byte) {
	if len(b) < 4 {
		return 0, nil
	}
	flags := binary.LittleEndian.Uint16(b)
	data := b[4:]
	if flags&secEncrypt == 0 {
		return flags, data
	}
	if len(data) < 8 {
		return flags, nil
	}
	data = data[8:] // 跳过签名（蜜罐不校验，避免被伪造签名打成拒绝服务）
	if c.decryptRC4 == nil {
		c.decryptRC4, _ = rc4.NewCipher(c.decryptKey)
	}
	out := make([]byte, len(data))
	c.decryptRC4.XORKeyStream(out, data)
	return flags, out
}

// encryptPDU 组装带 TS_SECURITY_HEADER 的载荷（标准安全下所有出站 PDU 都要这样包）
func (c *rdpCrypto) encryptPDU(flags uint16, data []byte) []byte {
	out := make([]byte, 0, len(data)+12)
	out = append(out, byte(flags), byte(flags>>8), 0x00, 0x00)
	if flags&secEncrypt == 0 {
		return append(out, data...)
	}
	if c.encryptRC4 == nil {
		c.encryptRC4, _ = rc4.NewCipher(c.encryptKey)
	}
	sig := macData(c.macKey, data)[:8]
	enc := make([]byte, len(data))
	c.encryptRC4.XORKeyStream(enc, data)
	return append(append(out, sig...), enc...)
}

const (
	secExchangePkt uint16 = 0x0001
	secEncrypt     uint16 = 0x0008
	secInfoPkt     uint16 = 0x0040
	secLicensePkt  uint16 = 0x0080
)

// ---------------------------------------------------------------------------
// RSA：client random 与口令字段
//
// 这套协议在模幂前后各做一次字节序反转（"RDP 的 RSA 从来不是标准 PKCS#1"），
// 所以下面既不调用 crypto/rsa 的填充逻辑，也不假设标准字节序，而是两种都试、
// 用"解出来像不像 UTF-16 文本"来选。
// ---------------------------------------------------------------------------

// rdpPrivateKey 标准 RDP 安全用的"小"RSA 密钥。协议历史约定是 512 位
// （FreeRDP 甚至硬性要求专有证书里的签名字段为 72 字节），而 Go 1.24 的 crypto/rsa
// 拒绝生成 1024 位以下的密钥；我们的私钥运算只用到模幂，所以直接用 math/big 生成。
type rdpPrivateKey struct {
	n *big.Int
	e int
	d *big.Int
}

func generateRdpKey(bits int) (*rdpPrivateKey, error) {
	if bits < 512 {
		bits = 512
	}
	half := bits / 2
	one := big.NewInt(1)
	six := big.NewInt(65537)
	for tries := 0; tries < 100; tries++ {
		p, err := rand.Prime(rand.Reader, half)
		if err != nil {
			return nil, err
		}
		q, err := rand.Prime(rand.Reader, half)
		if err != nil {
			return nil, err
		}
		if p.Cmp(q) == 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		if n.BitLen() != bits {
			continue
		}
		phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
		if new(big.Int).GCD(nil, nil, six, phi).Cmp(one) != 0 {
			continue
		}
		d := new(big.Int).ModInverse(six, phi)
		if d == nil {
			continue
		}
		return &rdpPrivateKey{n: n, e: 65537, d: d}, nil
	}
	return nil, errors.New("rdp: 生成 RDP 密钥失败")
}

// fromRSA 把 TLS 证书的 RSA 私钥套进同一接口（TLS 模式下口令用它解）
func rdpKeyFromRSA(k *rsa.PrivateKey) *rdpPrivateKey {
	if k == nil {
		return nil
	}
	return &rdpPrivateKey{n: k.N, e: k.E, d: k.D}
}

func (k *rdpPrivateKey) modulusLen() int { return (k.n.BitLen() + 7) / 8 }

// decrypt 原始模幂；reverse 对应 RDP 的字节序怪癖
func (k *rdpPrivateKey) decrypt(in []byte, reverse bool) []byte {
	c := in
	if reverse {
		c = reverseBytes(in)
	}
	m := new(big.Int).SetBytes(c)
	m.Exp(m, k.d, k.n)
	out := padTo(m.Bytes(), k.modulusLen())
	if reverse {
		out = reverseBytes(out)
	}
	return out
}

// decryptClientRandom 解出 32 字节 client random。
// 客户端做的是 int_be(reverse(random)) 的模幂再整体反转，所以解出来后
// "反转 + 左补零"的结果前 32 字节恰好就是原始 random，不能再反转一次。
func (s *rdpSession) decryptClientRandom(enc []byte) []byte {
	raw := s.rdpKey.decrypt(enc, true)
	if len(raw) > 32 {
		raw = raw[:32]
	}
	return padTo(raw, 32)
}

// decryptPassword 还原 Client Info 里的口令字段：依次尝试给定的私钥（标准安全的
// 专有证书密钥、TLS 证书密钥），最后退化为按明文 UTF-16 解释。
func (s *rdpSession) decryptPassword(field []byte, keys ...*rdpPrivateKey) (string, string) {
	if len(field) == 0 {
		return "", "empty"
	}
	for _, k := range keys {
		if k == nil {
			continue
		}
		modLen := k.modulusLen()
		if modLen <= 0 || len(field)%modLen != 0 || len(field) > 4096 {
			continue
		}
		for _, reverse := range []bool{true, false} {
			plain := []byte{}
			for off := 0; off+modLen <= len(field); off += modLen {
				plain = append(plain, k.decrypt(field[off:off+modLen], reverse)...)
			}
			txt := utf16leDecode(trimUTF16NUL(plain))
			if printableScore(txt) > 0 {
				if reverse {
					return txt, "rsa"
				}
				return txt, "rsa-be"
			}
		}
	}
	txt := utf16leDecode(trimUTF16NUL(field))
	if printableScore(txt) >= 0 {
		return txt, "plain"
	}
	return "", "unknown"
}

func trimUTF16NUL(b []byte) []byte {
	end := len(b)
	for end >= 2 && b[end-1] == 0 && b[end-2] == 0 {
		end -= 2
	}
	return b[:end]
}

// ---------------------------------------------------------------------------
// Client Info PDU（MS-RDPBCGR 2.2.1.11.1.1）
// ---------------------------------------------------------------------------

type clientInfo struct {
	codePage    uint32
	flags       uint32
	domain      string
	user        string
	password    string
	decodedBy   string
	hasPassword bool
	clientName  string
}

const (
	infoUnicode uint32 = 0x00000010 // INFO_UNICODE：字符串是 UTF-16LE
)

// parseClientInfo 解析 TS_INFO_PACKET。
//
// 注意一个真实存在的兼容坑：协议规定 cbXxx 包含结尾的 NUL（即字符串占 cbXxx 字节），
// 但部分客户端（如 grdp）写的是"不含 NUL 的长度 + 长度为 cbXxx+2 的字节"。
// 两种写法字符串的**实际字节数**一致，差别只在后续字段的偏移。这里用"哪套偏移能对上
// 扩展信息块起始标记（AF_INET/AF_INET6）"来判定，外加可打印性做二次校验。
func (s *rdpSession) parseClientInfo(b []byte) *clientInfo {
	info := &clientInfo{}
	r := newPktReader(b)
	var err error
	if info.codePage, err = r.u32le(); err != nil {
		return info
	}
	if info.flags, err = r.u32le(); err != nil {
		return info
	}
	const headerLen = 18
	lens := make([]uint16, 5)
	for i := range lens {
		if lens[i], err = r.u16le(); err != nil {
			return info
		}
	}

	// tryLayout 按“声明长度是否含结尾 NUL”这一差异切出五个字段，并返回结束偏移
	tryLayout := func(extra int) ([][]byte, int) {
		rr := newPktReader(b[headerLen:])
		out := make([][]byte, 0, 5)
		for _, l := range lens {
			n := int(l) + extra
			if n < 0 {
				return nil, -1
			}
			raw, err := rr.bytes(n)
			if err != nil {
				return nil, -1
			}
			out = append(out, raw)
		}
		return out, headerLen + rr.off
	}

	// 两种偏移各自打分。最强信号是"每个字段都以 UTF-16 NUL 结尾"——切错布局时
	// 字段会整体错位 2 字节，结尾就不是 NUL 了；其次看剩余字节是否对上扩展信息块。
	var fields [][]byte
	bestScore := -1
	for i, extra := range []int{0, 2} {
		strs, consumed := tryLayout(extra)
		if strs == nil {
			continue
		}
		score := 0
		for _, f := range strs {
			if len(f) >= 2 && binary.LittleEndian.Uint16(f[len(f)-2:]) == 0x0000 {
				score += 2 // 字段以 NUL 结尾
			}
			if printableScore(utf16leDecode(trimUTF16NUL(f))) >= 0 {
				score++
			}
		}
		tail := b[consumed:]
		if len(tail) == 0 {
			score += 3 // 恰好结束（说明没有扩展信息块）
		} else if len(tail) >= 2 && (binary.LittleEndian.Uint16(tail) == 0x0002 ||
			binary.LittleEndian.Uint16(tail) == 0x0017) {
			score += 3 // 正好落在扩展信息块开头
		}
		if i == 0 {
			score++ // 协议规定写法优先
		}
		if score > bestScore {
			bestScore, fields = score, strs
		}
	}
	if fields == nil {
		return info
	}
	for i := range fields {
		fields[i] = trimUTF16NUL(fields[i])
	}

	if info.flags&infoUnicode != 0 {
		info.domain = utf16leDecode(fields[0])
		info.user = utf16leDecode(fields[1])
	} else {
		info.domain = string(fields[0])
		info.user = string(fields[1])
	}

	// 口令：要么是 RSA 密文（标准 RDP 安全 / 部分客户端的 TLS 路径），要么就是明文 UTF-16
	if len(fields[2]) > 0 {
		pwd, how := s.decryptPassword(fields[2], s.rdpKey, rdpKeyFromRSA(s.tlsKey))
		if pwd == "" && how == "unknown" {
			// 兜底：当明文处理，至少把原始字节记下来，便于人工分析
			pwd = strings.Map(func(r rune) rune {
				if r >= 0x20 && r < 0x7f {
					return r
				}
				return '.'
			}, string(fields[2]))
			how = "raw"
		}
		info.password = pwd
		info.decodedBy = how
		info.hasPassword = len(fields[2]) > 0
	}
	info.clientName = s.clientName
	return info
}

// ---------------------------------------------------------------------------
// TLS：证书准备
// ---------------------------------------------------------------------------

type securityData struct {
	encryptionMethod uint32
	encryptionLevel  uint32
	serverRandom     []byte
	certificate      []byte
}

func loadOrGenRSAKey(certFile, keyFile string, bits int) (*rsa.PrivateKey, tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err == nil {
			if key, ok := pair.PrivateKey.(*rsa.PrivateKey); ok {
				return key, pair, nil
			}
			// 非 RSA 私钥（例如 ECDSA）无法做 RDP 的 RSA 解密，退化为自签 RSA
		} else if !os.IsNotExist(err) {
			return nil, tls.Certificate{}, err
		}
	}
	if bits < 1024 {
		bits = 2048
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "RDP", Organization: []string{"Microsoft Corporation"}},
		NotBefore:             time.Now().Add(-time.Hour * 24),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 5),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	pair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	pair.Leaf, _ = x509.ParseCertificate(der)
	return key, pair, nil
}

func tlsServerConfig(pair tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		// 老客户端（Win7/老 FreeRDP）只谈到 TLS1.0/1.1
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
}
