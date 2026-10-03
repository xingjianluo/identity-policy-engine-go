package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"math/big"
)

// 内部哨兵错误：只在本包内翻译成对外 *Error，绝不直接透出。
var (
	errKeyTypeMismatch   = errors.New("key material type does not match algorithm")
	errSignatureMismatch = errors.New("signature does not match")
)

// hashFor 返回算法对应的哈希构造函数；未知算法返回 nil。
func hashFor(a Algorithm) func() hash.Hash {
	switch a {
	case AlgHS256, AlgRS256, AlgES256:
		return sha256.New
	case AlgHS384, AlgRS384, AlgES384:
		return sha512.New384
	case AlgHS512, AlgRS512, AlgES512:
		return sha512.New
	default:
		return nil
	}
}

// cryptoHashFor 返回算法对应的 crypto.Hash（用于 RSA/PSS 无关的 PKCS1v15 接口）。
func cryptoHashFor(a Algorithm) crypto.Hash {
	switch a {
	case AlgHS256, AlgRS256, AlgES256:
		return crypto.SHA256
	case AlgHS384, AlgRS384, AlgES384:
		return crypto.SHA384
	case AlgHS512, AlgRS512, AlgES512:
		return crypto.SHA512
	default:
		return 0
	}
}

// sign 用注册算法对应的密钥材料对 input 计算签名。
func sign(alg Algorithm, key any, input []byte) ([]byte, error) {
	hf := hashFor(alg)
	if hf == nil {
		return nil, errKeyTypeMismatch
	}
	switch familyFor(alg) {
	case FamilyHMAC:
		secret, ok := key.([]byte)
		if !ok {
			return nil, errKeyTypeMismatch
		}
		mac := hmac.New(hf, secret)
		mac.Write(input)
		return mac.Sum(nil), nil
	case FamilyRSA:
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errKeyTypeMismatch
		}
		h := hf()
		h.Write(input)
		return rsa.SignPKCS1v15(rand.Reader, priv, cryptoHashFor(alg), h.Sum(nil))
	case FamilyECDSA:
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errKeyTypeMismatch
		}
		h := hf()
		h.Write(input)
		r, s, err := ecdsa.Sign(rand.Reader, priv, h.Sum(nil))
		if err != nil {
			return nil, err
		}
		return marshalECDSASignature(alg, r, s)
	default:
		return nil, errKeyTypeMismatch
	}
}

// verifySignature 校验 sig 是否为 input 在 alg/key 下的合法签名。
func verifySignature(alg Algorithm, key any, input, sig []byte) error {
	hf := hashFor(alg)
	if hf == nil {
		return errKeyTypeMismatch
	}
	switch familyFor(alg) {
	case FamilyHMAC:
		secret, ok := key.([]byte)
		if !ok {
			return errKeyTypeMismatch
		}
		mac := hmac.New(hf, secret)
		mac.Write(input)
		if !hmac.Equal(sig, mac.Sum(nil)) {
			return errSignatureMismatch
		}
		return nil
	case FamilyRSA:
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return errKeyTypeMismatch
		}
		h := hf()
		h.Write(input)
		if err := rsa.VerifyPKCS1v15(pub, cryptoHashFor(alg), h.Sum(nil), sig); err != nil {
			// 任何密码库层面的失败都收敛成“签名确实不匹配”，不透出原始报错。
			return errSignatureMismatch
		}
		return nil
	case FamilyECDSA:
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errKeyTypeMismatch
		}
		h := hf()
		h.Write(input)
		r, s, ok := parseECDSASignature(alg, pub, sig)
		if !ok || !ecdsa.Verify(pub, h.Sum(nil), r, s) {
			return errSignatureMismatch
		}
		return nil
	default:
		return errKeyTypeMismatch
	}
}

// ecdsaCoordBytes 返回某 ECDSA 算法签名坐标 r/s 的定长字节数。
func ecdsaCoordBytes(alg Algorithm) int {
	switch alg {
	case AlgES256:
		return 32
	case AlgES384:
		return 48
	case AlgES512:
		return 66
	default:
		return 0
	}
}

// marshalECDSASignature 将 (r,s) 按算法曲线长度编码为定长拼接串（IEEE P1363 风格）。
func marshalECDSASignature(alg Algorithm, r, s *big.Int) ([]byte, error) {
	n := ecdsaCoordBytes(alg)
	if n == 0 {
		return nil, errKeyTypeMismatch
	}
	out := make([]byte, 2*n)
	rb := r.Bytes()
	sb := s.Bytes()
	if len(rb) > n || len(sb) > n {
		return nil, errSignatureMismatch
	}
	copy(out[n-len(rb):n], rb)
	copy(out[2*n-len(sb):], sb)
	return out, nil
}

// parseECDSASignature 将定长拼接串还原为 (r,s)，长度非法直接判失败。
func parseECDSASignature(alg Algorithm, _ *ecdsa.PublicKey, sig []byte) (*big.Int, *big.Int, bool) {
	n := ecdsaCoordBytes(alg)
	if n == 0 || len(sig) != 2*n {
		return nil, nil, false
	}
	r := new(big.Int).SetBytes(sig[:n])
	s := new(big.Int).SetBytes(sig[n:])
	return r, s, true
}
