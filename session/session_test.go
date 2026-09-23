package session

import (
	"sync"
	"testing"
	"time"
)

var s0 = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

func sampleSession(id string) Session {
	return Session{
		ID:        id,
		Subject:   "alice",
		NotBefore: s0.Add(-time.Minute),
		ExpiresAt: s0.Add(time.Hour),
		Roles:     []string{"reader"},
		Attrs:     map[string]string{"dept": "platform"},
		CreatedAt: s0,
	}
}

func TestStatusesAreDistinguishable(t *testing.T) {
	s := NewStore()
	if err := s.Create(sampleSession("s1")); err != nil {
		t.Fatal(err)
	}
	expired := sampleSession("s2")
	expired.ExpiresAt = s0.Add(-time.Minute)
	if err := s.Create(expired); err != nil {
		t.Fatal(err)
	}
	future := sampleSession("s3")
	future.NotBefore = s0.Add(time.Hour)
	if err := s.Create(future); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		id   string
		want Status
	}{
		{"s1", StatusValid},
		{"s2", StatusExpired},
		{"s3", StatusNotStarted},
		{"missing", StatusNotFound},
	}
	for _, tc := range cases {
		_, got := s.Check(tc.id, s0)
		t.Logf("input session=%s now=12:00 | decision: status=%s", tc.id, got)
		if got != tc.want {
			t.Fatalf("session=%s status=%s want=%s", tc.id, got, tc.want)
		}
	}

	s.Revoke("s1")
	_, got := s.Check("s1", s0)
	t.Logf("input session=s1 after revoke | decision: status=%s", got)
	if got != StatusRevoked {
		t.Fatalf("revoked status=%s want=%s", got, StatusRevoked)
	}
}

func TestCreateDuplicateAndInvalid(t *testing.T) {
	s := NewStore()
	if err := s.Create(sampleSession("s1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(sampleSession("s1")); err == nil {
		t.Fatal("duplicate session must fail")
	}
	bad := sampleSession("s2")
	bad.ID = ""
	if err := s.Create(bad); err == nil {
		t.Fatal("empty id must fail")
	}
}

func TestCheckReturnsSnapshot(t *testing.T) {
	s := NewStore()
	if err := s.Create(sampleSession("s1")); err != nil {
		t.Fatal(err)
	}
	sess, _ := s.Check("s1", s0)
	sess.Roles[0] = "admin"
	sess.Attrs["dept"] = "root"
	again, _ := s.Check("s1", s0)
	if again.Roles[0] != "reader" || again.Attrs["dept"] != "platform" {
		t.Fatal("Check result must be an isolated snapshot")
	}
}

func TestConcurrentCheckAcrossRevocation(t *testing.T) {
	s := NewStore()
	if err := s.Create(sampleSession("s1")); err != nil {
		t.Fatal(err)
	}

	const goroutines = 64
	const preIter = 100
	const postIter = 200
	var wg sync.WaitGroup
	start := make(chan struct{})
	ready := make(chan struct{}, goroutines) // worker 完成吊销前批次
	proceed := make(chan struct{})           // 主线程吊销后放行
	var acceptedAfter, rejectedAfter int64
	var mu sync.Mutex

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < preIter; i++ {
				if _, st := s.Check("s1", s0); st != StatusValid {
					t.Errorf("pre-revocation check got %s", st)
					return
				}
			}
			ready <- struct{}{}
			<-proceed // 屏障：关闭此通道严格发生在 Revoke 完成之后
			for i := 0; i < postIter; i++ {
				_, st := s.Check("s1", s0)
				mu.Lock()
				if st == StatusValid {
					acceptedAfter++
				} else if st == StatusRevoked {
					rejectedAfter++
				}
				mu.Unlock()
			}
		}()
	}
	close(start)
	for g := 0; g < goroutines; g++ {
		<-ready
	}
	s.Revoke("s1")
	close(proceed)
	wg.Wait()

	t.Logf("input concurrent Check: pre=%d all valid | post=%d rejected, accepted=%d",
		goroutines*preIter, rejectedAfter, acceptedAfter)
	if acceptedAfter != 0 {
		t.Fatalf("revoked session accepted %d times (no transient allow window allowed)", acceptedAfter)
	}
	if rejectedAfter != int64(goroutines*postIter) {
		t.Fatalf("post-revocation rejected=%d want=%d", rejectedAfter, goroutines*postIter)
	}
}
