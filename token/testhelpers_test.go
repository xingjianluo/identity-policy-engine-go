package token

import (
	"crypto/rsa"
	"crypto/x509"
)

// x509PublicKeyBytes 返回公钥的 DER 编码字节（模拟对外公开的验签材料）。
func x509PublicKeyBytes(pub *rsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}
