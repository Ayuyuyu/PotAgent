package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"time"
)

// LoadOrGenCert 加载或生成自签证书（仅含 CN + DNS SAN=hostname 的"标准"自签证书）。
// certFile/keyFile 同时非空时优先从文件加载；文件不存在则回退生成自签 RSA2048。
// 相对路径按进程当前工作目录解析（与 services/http、iiot 约定一致）。
func LoadOrGenCert(certFile, keyFile, hostname string) (tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		if pair, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
			return pair, nil
		} else if !os.IsNotExist(err) {
			return tls.Certificate{}, err
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: hostname, Organization: []string{"PotAgent"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	pair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	pair.Leaf, _ = x509.ParseCertificate(der)
	return pair, nil
}
