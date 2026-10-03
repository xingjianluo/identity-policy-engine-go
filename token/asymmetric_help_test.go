package token

import (
	"crypto/x509"
)

// publicKeyDER 以 PKIX 形式编码公钥，供攻击测试模拟“拿公钥字节当 HMAC 密钥”。
func publicKeyDER(pub any) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}
