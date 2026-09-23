// Package keystore 管理本地签名/验签密钥的生命周期：
// 每个密钥带有生效窗口（not_before / expires_at），支持轮换期新旧密钥并行可用。
//
// 并发模型：所有读取均在 RLock 内完成取值与结构拷贝（快照），
// 吊销/登记使用写锁；验签密钥查找与时间窗口判定在同一把读锁内原子完成，
// 因此并发校验中不会出现旧密钥在窗口外被误用、或吊销后仍被短暂放行的情况。
package keystore

import (
	"errors"
	"sync"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/token"
)

// SigningKey 一把带生命周期的本地密钥。
type SigningKey struct {
	ID         string
	Algorithm  token.Algorithm
	SigningKey interface{} // 对称密钥 []byte，或 *rsa.PrivateKey / *ecdsa.PrivateKey
	VerifyKey  interface{} // 对称密钥 []byte，或 *rsa.PublicKey / *ecdsa.PublicKey
	NotBefore  time.Time
	ExpiresAt  time.Time
	Revoked    bool
}

// Store 线程安全的密钥仓库。
type Store struct {
	mu   sync.RWMutex
	keys map[string]*SigningKey
}

// NewStore 创建空密钥仓库。
func NewStore() *Store {
	return &Store{keys: make(map[string]*SigningKey)}
}

var (
	errDuplicateKey = errors.New("key id already exists")
	errInvalidKey   = errors.New("invalid signing key definition")
)

// Add 登记一把密钥（ID 不可重复，窗口必须合法，密钥类型须与算法匹配）。
func (s *Store) Add(k SigningKey) error {
	if k.ID == "" || k.ExpiresAt.IsZero() || !k.NotBefore.Before(k.ExpiresAt) {
		return errInvalidKey
	}
	if !validKeyMaterial(k.Algorithm, k.SigningKey, k.VerifyKey) {
		return errInvalidKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.keys[k.ID]; exists {
		return errDuplicateKey
	}
	cp := k
	s.keys[k.ID] = &cp
	return nil
}

// Revoke 立即吊销指定密钥；不存在时为空操作。吊销对所有后续及在途校验即时可见。
func (s *Store) Revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.keys[id]; ok {
		k.Revoked = true
	}
}

// Get 返回密钥当前状态的快照副本；调用方对返回值的修改不会影响仓库内部状态。
func (s *Store) Get(id string) (*SigningKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[id]
	if !ok {
		return nil, false
	}
	cp := *k
	return &cp, true
}

// ActiveSigningKey 返回 now 时刻处于生效窗口内且未吊销的、
// 最近轮换（NotBefore 最晚）的可签发密钥；无可用密钥时返回 nil。
func (s *Store) ActiveSigningKey(now time.Time) *SigningKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *SigningKey
	for _, k := range s.keys {
		if k.Revoked || !inWindow(k, now) {
			continue
		}
		if best == nil || k.NotBefore.After(best.NotBefore) {
			cp := *k
			best = &cp
		}
	}
	return best
}

// VerifyKey 提供给令牌校验使用的快照式密钥查找：
// 仅返回 now 时刻在生效窗口内且未吊销的验签密钥；
// 不存在、已吊销或已过期一律返回 token.VerifyError(key_not_found)，
// 不向调用方泄漏仓库内部状态与底层错误。
func (s *Store) VerifyKey(kid string, alg token.Algorithm, now time.Time) (interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[kid]
	if !ok {
		return nil, &token.VerifyError{Reason: token.ReasonKeyNotFound, Detail: "unknown key id"}
	}
	if k.Revoked || !inWindow(k, now) {
		return nil, &token.VerifyError{Reason: token.ReasonKeyNotFound, Detail: "key not active"}
	}
	if k.Algorithm != alg {
		return nil, &token.VerifyError{Reason: token.ReasonKeyNotFound, Detail: "key algorithm mismatch"}
	}
	return k.VerifyKey, nil
}

func inWindow(k *SigningKey, now time.Time) bool {
	return (k.NotBefore.IsZero() || !now.Before(k.NotBefore)) && now.Before(k.ExpiresAt)
}
