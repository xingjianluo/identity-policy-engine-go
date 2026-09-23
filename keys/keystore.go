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

// Active 判断密钥在 at 时刻是否可用。
func (k *Key) Active(at time.Time) bool { return false }

// Store 是并发安全的内存密钥库，支持轮换期间新旧密钥并行可用。
type Store struct {
	mu   sync.RWMutex
	keys map[string]*Key
}

func NewStore() *Store { return &Store{keys: make(map[string]*Key)} }

// Add 注册一个密钥。
func (s *Store) Add(k Key) {}

// Retire 吊销指定密钥。
func (s *Store) Retire(id string) bool { return false }

// Resolve 实现 token.KeyResolver：返回 at 时刻处于生效窗口且未吊销的密钥。
func (s *Store) Resolve(kid string, at time.Time) ([]byte, bool) { return nil, false }

// Current 返回 at 时刻可用于签发的最新密钥。
func (s *Store) Current(at time.Time) (Key, bool) { return Key{}, false }
