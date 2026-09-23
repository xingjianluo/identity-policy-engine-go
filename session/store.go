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
// 所有校验都在读锁内完成，吊销在写锁内完成，
// 因此并发校验下不会出现已吊销会话被短暂放行的窗口。
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	now      func() time.Time
}

func NewStore() *Store {
	return &Store{sessions: make(map[string]*Session), now: time.Now}
}

// Create 创建（或替换）会话。
func (s *Store) Create(sess Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = &sess
}

// Revoke 吊销会话，吊销立即对后续校验可见。
func (s *Store) Revoke(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return false
	}
	sess.Revoked = true
	return true
}

// Valid 判断会话是否存在、未吊销且未过期。
func (s *Store) Valid(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok || sess.Revoked {
		return false
	}
	return s.now().Before(sess.ExpiresAt)
}
