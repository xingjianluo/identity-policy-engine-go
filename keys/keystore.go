// Package keys 提供签名密钥的生命周期管理与跨算法族轮换。
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/token"
)

// Key 表示一个带生效窗口的签名密钥，并绑定具体签名算法。
// 算法绑定信息随密钥一起存储，是防止令牌头部「换算法」伪造的依据：
// 校验时令牌头部算法必须与密钥绑定算法同族（同族内还要求精确一致）。
type Key struct {
	ID        string
	Alg       token.Algorithm  // 该密钥绑定的算法
	Material  []byte           // HMAC 密钥材料（非对称密钥留空）
	Signer    crypto.Signer    // 非对称私钥（签发侧）
	Public    crypto.PublicKey // 非对称公钥（校验侧可只放它）
	NotBefore time.Time
	NotAfter  time.Time
	Retired   bool // 被吊销后不再可用
}

// ErrInvalidKey 表示密钥与声明的算法族不匹配。
var ErrInvalidKey = errors.New("invalid key material for algorithm")

// HMACKey 构造一个对称密钥。
func HMACKey(id string, alg token.Algorithm, secret []byte, notBefore, notAfter time.Time) Key {
	return Key{ID: id, Alg: alg, Material: secret, NotBefore: notBefore, NotAfter: notAfter}
}

// AsymmetricKey 用已有私钥/公钥构造一个非对称密钥，并校验算法族是否匹配。
// signer 为私钥（签发侧）；publicKey 可单独提供给只验签的一侧。
func AsymmetricKey(id string, alg token.Algorithm, signer crypto.Signer, publicKey crypto.PublicKey, notBefore, notAfter time.Time) (Key, error) {
	var candidate crypto.PublicKey
	if signer != nil {
		candidate = signer.Public()
	} else {
		candidate = publicKey
	}
	if err := checkKeyAlg(alg, candidate); err != nil {
		return Key{}, err
	}
	return Key{ID: id, Alg: alg, Signer: signer, Public: publicKey,
		NotBefore: notBefore, NotAfter: notAfter}, nil
}

// GenerateKey 在本地生成一把与算法匹配的密钥（不依赖外部服务或证书）。
// 对称算法生成 32/48/64 字节随机密钥；非对称算法生成 RSA-2048 或对应 P 曲线私钥。
func GenerateKey(id string, alg token.Algorithm, notBefore, notAfter time.Time) (Key, error) {
	switch token.FamilyOf(alg) {
	case token.FamilyHMAC:
		n := 0
		switch alg {
		case token.AlgHS256:
			n = 32
		case token.AlgHS384:
			n = 48
		case token.AlgHS512:
			n = 64
		}
		secret := make([]byte, n)
		if _, err := rand.Read(secret); err != nil {
			return Key{}, fmt.Errorf("generate hmac key: %w", err)
		}
		return HMACKey(id, alg, secret, notBefore, notAfter), nil
	case token.FamilyRSA:
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return Key{}, fmt.Errorf("generate rsa key: %w", err)
		}
		return AsymmetricKey(id, alg, priv, priv.Public(), notBefore, notAfter)
	case token.FamilyECDSA:
		var curve elliptic.Curve
		switch alg {
		case token.AlgES256:
			curve = elliptic.P256()
		case token.AlgES384:
			curve = elliptic.P384()
		case token.AlgES512:
			curve = elliptic.P521()
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return Key{}, fmt.Errorf("generate ecdsa key: %w", err)
		}
		return AsymmetricKey(id, alg, priv, priv.Public(), notBefore, notAfter)
	default:
		return Key{}, fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidKey, alg)
	}
}

// checkKeyAlg 校验公钥类型/曲线是否与算法匹配。
func checkKeyAlg(alg token.Algorithm, pub crypto.PublicKey) error {
	if pub == nil {
		return fmt.Errorf("%w: %s requires a key", ErrInvalidKey, alg)
	}
	switch token.FamilyOf(alg) {
	case token.FamilyRSA:
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return fmt.Errorf("%w: %s requires an RSA key", ErrInvalidKey, alg)
		}
	case token.FamilyECDSA:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: %s requires an ECDSA key", ErrInvalidKey, alg)
		}
		wantCurve := map[token.Algorithm]elliptic.Curve{
			token.AlgES256: elliptic.P256(),
			token.AlgES384: elliptic.P384(),
			token.AlgES512: elliptic.P521(),
		}[alg]
		if wantCurve == nil || ecPub.Curve != wantCurve {
			return fmt.Errorf("%w: %s key curve does not match algorithm", ErrInvalidKey, alg)
		}
	default:
		return fmt.Errorf("%w: %s is not an asymmetric algorithm", ErrInvalidKey, alg)
	}
	return nil
}

// Active 判断密钥在 at 时刻是否可用（处于生效窗口且未被吊销）。
func (k *Key) Active(at time.Time) bool {
	if k.Retired {
		return false
	}
	if at.Before(k.NotBefore) {
		return false
	}
	if !k.NotAfter.IsZero() && at.After(k.NotAfter) {
		return false
	}
	return true
}

// resolved 转成 token 包的解析结果。
func (k *Key) resolved() token.ResolvedKey {
	return token.ResolvedKey{
		Algorithm: k.Alg,
		Family:    token.FamilyOf(k.Alg),
		HMAC:      k.Material,
		Signer:    k.Signer,
		Public:    k.Public,
	}
}

// Store 是并发安全的内存密钥库，支持轮换期间新旧密钥并行可用，
// 且新旧密钥允许属于不同算法族。
type Store struct {
	mu   sync.RWMutex
	keys map[string]*Key
}

func NewStore() *Store { return &Store{keys: make(map[string]*Key)} }

// Add 注册一个密钥。HMAC 材料会被拷贝，避免外部修改。
func (s *Store) Add(k Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(k.Material) > 0 {
		mat := make([]byte, len(k.Material))
		copy(mat, k.Material)
		k.Material = mat
	}
	s.keys[k.ID] = &k
}

// Retire 吊销指定密钥，吊销立即对后续 Resolve 可见。
func (s *Store) Retire(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return false
	}
	k.Retired = true
	return true
}

// Resolve 实现 token.KeyResolver：返回 at 时刻处于生效窗口且未吊销的密钥
// （含算法族绑定）。HMAC 材料是拷贝，调用方无法篡改库内状态。
func (s *Store) Resolve(kid string, at time.Time) (token.ResolvedKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[kid]
	if !ok || !k.Active(at) {
		return token.ResolvedKey{}, false
	}
	rk := k.resolved()
	if len(k.Material) > 0 {
		rk.HMAC = make([]byte, len(k.Material))
		copy(rk.HMAC, k.Material)
	}
	return rk, true
}

// Current 返回 at 时刻可用于签发的最新密钥（NotBefore 最晚且处于激活态；
// NotBefore 相同时按 ID 取序，保证选择稳定）。
func (s *Store) Current(at time.Time) (Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *Key
	for _, k := range s.keys {
		if !k.Active(at) {
			continue
		}
		if best == nil || k.NotBefore.After(best.NotBefore) ||
			(k.NotBefore.Equal(best.NotBefore) && k.ID > best.ID) {
			best = k
		}
	}
	if best == nil {
		return Key{}, false
	}
	out := *best
	if len(best.Material) > 0 {
		out.Material = make([]byte, len(best.Material))
		copy(out.Material, best.Material)
	}
	return out, true
}

// IssuerForCurrent 返回基于当前最新密钥的令牌签发器。
func (s *Store) IssuerForCurrent(at time.Time) (*token.Issuer, Key, bool) {
	k, ok := s.Current(at)
	if !ok {
		return nil, Key{}, false
	}
	rk, ok := s.Resolve(k.ID, at)
	if !ok {
		return nil, Key{}, false
	}
	return token.NewIssuer(rk).WithKID(k.ID), k, true
}
