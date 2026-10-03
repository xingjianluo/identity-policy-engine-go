package engine

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/xingjianluo/identity-policy-engine-go/token"
)

// signLocally 仅供攻击测试：用任意字节当 HMAC 密钥伪造签名。
func signLocally(alg token.Algorithm, secret, input []byte) ([]byte, error) {
	if alg != token.AlgHS256 {
		return nil, nil
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(input)
	return mac.Sum(nil), nil
}
