package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"
)

// ResolvedKey 是密钥库解析出的密钥句柄：既包含注册时声明的算法，
// 也包含具体的密钥材料。签发方与校验方都以此为准选择密码学操作，
// 绝不仅凭令牌头里的 alg 决定如何使用密钥。
//
// 各算法族对应的材料形态：
//   - HMAC ：[]byte（共享密钥）
//   - RSA  ：*rsa.PrivateKey（签发）或 *rsa.PublicKey（仅校验）
//   - ECDSA：*ecdsa.PrivateKey（签发）或 *ecdsa.PublicKey（仅校验）
type ResolvedKey struct {
	KeyID    string
	Alg      Algorithm
	Material any
}

// KeyResolver 按密钥 ID 与时刻查找已注册的密钥句柄。
type KeyResolver interface {
	Resolve(kid string, at time.Time) (ResolvedKey, bool)
}

// GenerateRSAKey 生成本地 RSA 私钥（bits 为模数位数，如 2048）。
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	return k, nil
}

// GenerateECDSAKey 按算法（ES256/ES384/ES512）生成本地 ECDSA 私钥。
func GenerateECDSAKey(alg Algorithm) (*ecdsa.PrivateKey, error) {
	var curve elliptic.Curve
	switch alg {
	case AlgES256:
		curve = elliptic.P256()
	case AlgES384:
		curve = elliptic.P384()
	case AlgES512:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("alg %q is not an ECDSA algorithm", alg)
	}
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ecdsa key: %w", err)
	}
	return k, nil
}

// PublicMaterial 从私钥/公钥材料中提取可用于校验的公钥材料；
// HMAC 共享密钥原样返回。传入无法识别的类型时返回错误。
func PublicMaterial(material any) (any, error) {
	switch k := material.(type) {
	case []byte:
		return k, nil
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *rsa.PublicKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PublicKey:
		return k, nil
	default:
		return nil, fmt.Errorf("%w: unsupported key material %T", errKeyTypeMismatch, material)
	}
}
