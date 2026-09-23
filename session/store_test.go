package session

import (
	"sync"
	"testing"
	"time"
)

func TestRevokedSessionRejected(t *testing.T) {
	s := NewStore()
	s.Create(Session{ID: "s1", Subject: "alice", ExpiresAt: time.Now().Add(time.Hour)})
	if !s.Valid("s1") {
		t.Fatal("fresh session should be valid")
	}
	s.Revoke("s1")
	if s.Valid("s1") {
		t.Fatal("revoked session must be rejected")
	}
	t.Logf("session s1: valid -> revoked -> rejected")
}

func TestExpiredSessionRejected(t *testing.T) {
	s := NewStore()
	s.Create(Session{ID: "s2", Subject: "bob", ExpiresAt: time.Now().Add(-time.Second)})
	if s.Valid("s2") {
		t.Fatal("expired session must be rejected")
	}
	t.Logf("session s2 expired -> rejected")
}

func TestUnknownSessionRejected(t *testing.T) {
	s := NewStore()
	if s.Valid("ghost") {
		t.Fatal("unknown session must be rejected")
	}
}

func TestConcurrentRevokeNoStaleReads(t *testing.T) {
	// 吊销完成后，任何后续并发校验都不得再放行该会话。
	s := NewStore()
	s.Create(Session{ID: "s1", Subject: "alice", ExpiresAt: time.Now().Add(time.Hour)})
	s.Revoke("s1")

	const workers = 32
	const rounds = 500
	var wg sync.WaitGroup
	leaks := make(chan struct{}, workers*rounds)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if s.Valid("s1") {
					leaks <- struct{}{}
				}
			}
		}()
	}
	wg.Wait()
	close(leaks)
	if n := len(leaks); n > 0 {
		t.Fatalf("revoked session was allowed %d times after revoke", n)
	}
	t.Logf("%d workers x %d rounds: revoked session never allowed after revoke", workers, rounds)
}

func TestConcurrentMixedValidAndRevoked(t *testing.T) {
	s := NewStore()
	s.Create(Session{ID: "live", Subject: "alice", ExpiresAt: time.Now().Add(time.Hour)})
	s.Create(Session{ID: "dead", Subject: "bob", ExpiresAt: time.Now().Add(time.Hour)})
	s.Revoke("dead")

	var wg sync.WaitGroup
	bad := make(chan string, 1024)
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				if !s.Valid("live") {
					bad <- "live session rejected"
				}
				if s.Valid("dead") {
					bad <- "revoked session allowed"
				}
			}
		}()
	}
	wg.Wait()
	close(bad)
	for msg := range bad {
		t.Fatal(msg)
	}
	t.Logf("concurrent check: live session always valid, revoked session always rejected")
}
