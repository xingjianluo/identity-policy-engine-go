// Package session 提供内存会话生命周期管理。
package session

import (
	"sync"
	"time"
)

// Session 表示一条登录会话。
type Session struct {
	ID        string
	Subject   string
	ExpiresAt time.Time
	Revoked   bool
}

// Store 是并发安全的会话存储。
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	now      func() time.Time
}

func NewStore() *Store {
	return &Store{sessions: make(map[string]*Session), now: time.Now}
}

// Create 创建会话。
func (s *Store) Create(sess Session) {}

// Revoke 吊销会话，吊销立即对后续校验可见。
func (s *Store) Revoke(id string) bool { return false }

// Valid 判断会话是否存在、未吊销且未过期。
func (s *Store) Valid(id string) bool { return false }
