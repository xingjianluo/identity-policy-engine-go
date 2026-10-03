// Package keys 提供签名密钥的生命周期管理与跨算法族轮换。
package keys

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/token"
)

// Key 表示一个带生效窗口、且绑定了确定签名算法的密钥。
//
// 跨算法族轮换时，新旧 Key 可分属不同算法族（如旧 HS256、新 RS256），
// 每条密钥自带 Alg，校验时以它为信任锚，防止令牌头改算法的伪造。
//
// Material 支持：
//   - []byte（HMAC 共享密钥）
//   - *rsa.PrivateKey / *rsa.PublicKey
//   - *ecdsa.PrivateKey / *ecdsa.PublicKey
type Key struct {
	ID        string
	Alg       token.Algorithm
	Material  any
	NotBefore time.Time
	NotAfter  time.Time
	Retired   bool // 被吊销后不再可用
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

// Store 是并发安全的内存密钥库，支持轮换期间新旧密钥（可跨算法族）并行可用。
type Store struct {
	mu   sync.RWMutex
	keys map[string]*Key
}

func NewStore() *Store { return &Store{keys: make(map[string]*Key)} }

// Add 注册一个密钥。密钥材料会被深拷贝，避免外部后续修改影响库内状态。
// 材料形态必须与其 Alg 所在算法族匹配，否则返回错误且不会入库。
func (s *Store) Add(k Key) error {
	if k.ID == "" {
		return errors.New("key id must not be empty")
	}
	mat, err := cloneMaterial(k.Alg, k.Material)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k.Material = mat
	s.keys[k.ID] = &k
	return nil
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

// Resolve 实现 token.KeyResolver：返回 at 时刻处于生效窗口且未吊销的密钥句柄。
// 非对称密钥返回其公钥材料（仅够验签），对称密钥返回共享密钥拷贝；
// 返回材料始终是独立拷贝，调用方无法篡改库内状态。
func (s *Store) Resolve(kid string, at time.Time) (token.ResolvedKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[kid]
	if !ok || !k.Active(at) {
		return token.ResolvedKey{}, false
	}
	pub, err := token.PublicMaterial(k.Material)
	if err != nil {
		return token.ResolvedKey{}, false
	}
	out, err := cloneMaterial(k.Alg, pub)
	if err != nil {
		return token.ResolvedKey{}, false
	}
	return token.ResolvedKey{KeyID: k.ID, Alg: k.Alg, Material: out}, true
}

// Current 返回 at 时刻可用于签发的最新密钥（NotBefore 最晚且处于激活态）。
// 返回的材料是库内私钥/共享密钥的深拷贝，调用方无法篡改库内状态。
func (s *Store) Current(at time.Time) (Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *Key
	for _, k := range s.keys {
		if !k.Active(at) {
			continue
		}
		if best == nil || k.NotBefore.After(best.NotBefore) {
			best = k
		}
	}
	if best == nil {
		return Key{}, false
	}
	mat, err := cloneMaterial(best.Alg, best.Material)
	if err != nil {
		return Key{}, false
	}
	out := *best
	out.Material = mat
	return out, true
}

// cloneMaterial 校验材料与算法族匹配，并返回一份独立深拷贝。
func cloneMaterial(alg token.Algorithm, material any) (any, error) {
	fam := token.FamilyFor(alg)
	if fam == "" {
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}

	switch fam {
	case token.FamilyHMAC:
		secret, ok := material.([]byte)
		if !ok {
			return nil, fmt.Errorf("alg %q requires []byte secret, got %T", alg, material)
		}
		if len(secret) == 0 {
			return nil, fmt.Errorf("hmac secret for %q must not be empty", alg)
		}
		cp := make([]byte, len(secret))
		copy(cp, secret)
		return cp, nil
	case token.FamilyRSA:
		switch k := material.(type) {
		case *rsa.PrivateKey:
			return cloneRSAPrivate(k)
		case *rsa.PublicKey:
			return cloneRSAPublic(k)
		default:
			return nil, fmt.Errorf("alg %q requires RSA key, got %T", alg, material)
		}
	case token.FamilyECDSA:
		switch k := material.(type) {
		case *ecdsa.PrivateKey:
			return cloneECDSAPrivate(k)
		case *ecdsa.PublicKey:
			return cloneECDSAPublic(k)
		default:
			return nil, fmt.Errorf("alg %q requires ECDSA key, got %T", alg, material)
		}
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

func cloneRSAPrivate(k *rsa.PrivateKey) (*rsa.PrivateKey, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("clone rsa private key: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("clone rsa private key: %w", err)
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("cloned key is not RSA")
	}
	return priv, nil
}

func cloneRSAPublic(k *rsa.PublicKey) (*rsa.PublicKey, error) {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, fmt.Errorf("clone rsa public key: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("clone rsa public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cloned key is not RSA public")
	}
	return pub, nil
}

func cloneECDSAPrivate(k *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("clone ecdsa private key: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("clone ecdsa private key: %w", err)
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("cloned key is not ECDSA")
	}
	return priv, nil
}

func cloneECDSAPublic(k *ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, fmt.Errorf("clone ecdsa public key: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("clone ecdsa public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cloned key is not ECDSA public")
	}
	return pub, nil
}
