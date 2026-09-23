// Package session 管理令牌签发后对应的内存会话状态，
// 支持吊销、过期与并发一致的校验。
//
// 并发模型与 keystore 一致：Check 在单次 RLock 临界区内完成
// 全部状态与时间窗口判断并返回快照副本，吊销使用写锁即时生效，
// 因此并发校验中不会出现已吊销会话被短暂放行的窗口。
package session

import (
	"errors"
	"sync"
	"time"
)

// Session 一条内存会话。
type Session struct {
	ID        string
	Subject   string
	NotBefore time.Time
	ExpiresAt time.Time
	Roles     []string
	Attrs     map[string]string
	Revoked   bool
	CreatedAt time.Time
}

// Status 会话校验结论。
type Status string

const (
	StatusValid      Status = "valid"
	StatusNotFound   Status = "not_found"
	StatusRevoked    Status = "revoked"
	StatusExpired    Status = "expired"
	StatusNotStarted Status = "not_started"
)

// Store 线程安全的会话仓库。
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

var errDuplicateSession = errors.New("session id already exists")

// NewStore 创建空会话仓库。
func NewStore() *Store {
	return &Store{sessions: make(map[string]*Session)}
}

func cloneStringSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneAttrs(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (s Session) clone() Session {
	s.Roles = cloneStringSlice(s.Roles)
	s.Attrs = cloneAttrs(s.Attrs)
	return s
}

// Create 写入一条新会话；ID 重复返回错误。
func (s *Store) Create(sess Session) error {
	if sess.ID == "" {
		return errors.New("session id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[sess.ID]; exists {
		return errDuplicateSession
	}
	cp := sess.clone()
	s.sessions[sess.ID] = &cp
	return nil
}

// Revoke 立即吊销会话，对后续及并发中的校验立即生效；不存在时为空操作。
func (s *Store) Revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		sess.Revoked = true
	}
}

// Get 快照式读取会话当前状态。
func (s *Store) Get(id string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	cp := sess.clone()
	return &cp, true
}

// Check 返回会话在 now 时刻的状态结论与会话快照。
// 判定顺序：不存在 -> 已吊销 -> 未到生效时间 -> 已过期 -> 有效。
func (s *Store) Check(id string, now time.Time) (*Session, Status) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, StatusNotFound
	}
	if sess.Revoked {
		cp := sess.clone()
		return &cp, StatusRevoked
	}
	if !sess.NotBefore.IsZero() && now.Before(sess.NotBefore) {
		cp := sess.clone()
		return &cp, StatusNotStarted
	}
	if !sess.ExpiresAt.IsZero() && !now.Before(sess.ExpiresAt) {
		cp := sess.clone()
		return &cp, StatusExpired
	}
	cp := sess.clone()
	return &cp, StatusValid
}
