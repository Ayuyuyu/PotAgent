package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

func makePrivateKey(data []byte) *privateKey {
	privblk := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   data,
	}

	privateBytes := pem.EncodeToMemory(&privblk)

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil
	}

	return &privateKey{private}
}

type privateKey struct {
	ssh.Signer
}

func generateKey() ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	if cerr := priv.Validate(); cerr != nil {
		return nil, cerr
	}

	data := x509.MarshalPKCS1PrivateKey(priv)
	// log.Log.Infoln("generate key: ", string(data))

	// key := makePrivateKey(data)
	return data, nil
}
