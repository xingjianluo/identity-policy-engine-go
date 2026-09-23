// Package keys 提供签名密钥的生命周期管理与轮换。
package keys

import (
	"sync"
	"time"
)

// Key 表示一个带生效窗口的签名密钥。
type Key struct {
	ID        string
	Material  []byte
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

// Store 是并发安全的内存密钥库，支持轮换期间新旧密钥并行可用。
type Store struct {
	mu   sync.RWMutex
	keys map[string]*Key
}

func NewStore() *Store { return &Store{keys: make(map[string]*Key)} }

// Add 注册一个密钥。密钥材料会被拷贝，避免外部修改。
func (s *Store) Add(k Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mat := make([]byte, len(k.Material))
	copy(mat, k.Material)
	k.Material = mat
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

// Resolve 实现 token.KeyResolver：返回 at 时刻处于生效窗口且未吊销的密钥。
// 返回的材料是拷贝，调用方无法篡改库内状态。
func (s *Store) Resolve(kid string, at time.Time) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[kid]
	if !ok || !k.Active(at) {
		return nil, false
	}
	mat := make([]byte, len(k.Material))
	copy(mat, k.Material)
	return mat, true
}

// Current 返回 at 时刻可用于签发的最新密钥（NotBefore 最晚且处于激活态）。
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
	mat := make([]byte, len(best.Material))
	copy(mat, best.Material)
	out := *best
	out.Material = mat
	return out, true
}
