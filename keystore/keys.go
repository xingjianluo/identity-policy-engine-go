package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	"github.com/xingjianluo/identity-policy-engine-go/token"
)

// validKeyMaterial 校验密钥类型是否与声明算法匹配。
func validKeyMaterial(alg token.Algorithm, signing, verify interface{}) bool {
	switch alg {
	case token.HS256:
		_, sk := signing.([]byte)
		_, vk := verify.([]byte)
		return sk && vk
	case token.RS256:
		_, sk := signing.(*rsa.PrivateKey)
		_, vk := verify.(*rsa.PublicKey)
		return sk && vk
	case token.ES256:
		priv, sk := signing.(*ecdsa.PrivateKey)
		_, vk := verify.(*ecdsa.PublicKey)
		return sk && vk && priv.Curve.Params().Name == "P-256"
	default:
		return false
	}
}

// GenerateHMACKey 生成本地随机 HS256 对称密钥。
func GenerateHMACKey() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateRSAKey 生成本地 RS256 私钥（2048 位）。
func GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// GenerateECDSAKey 生成本地 ES256（P-256）私钥。
func GenerateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
