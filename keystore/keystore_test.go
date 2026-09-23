package keystore

import (
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/token"
)

var t0 = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

func hmacKeys(t *testing.T, oldID, newID string) ([]byte, []byte) {
	t.Helper()
	old, err := GenerateHMACKey()
	if err != nil {
		t.Fatal(err)
	}
	new, err := GenerateHMACKey()
	if err != nil {
		t.Fatal(err)
	}
	return old, new
}

func addHMAC(t *testing.T, s *Store, id string, secret []byte, nb, exp time.Time) {
	t.Helper()
	if err := s.Add(SigningKey{
		ID: id, Algorithm: token.HS256, SigningKey: secret, VerifyKey: secret,
		NotBefore: nb, ExpiresAt: exp,
	}); err != nil {
		t.Fatalf("add %s: %v", id, err)
	}
}

func verifyErrReason(t *testing.T, err error) token.Reason {
	t.Helper()
	ve, ok := err.(*token.VerifyError)
	if !ok {
		t.Fatalf("err type %T want *token.VerifyError", err)
	}
	return ve.Reason
}

func TestRotationOverlapBothKeysUsable(t *testing.T) {
	s := NewStore()
	old, new := hmacKeys(t, "k1", "k2")
	// 旧密钥 [t0-2h, t0+1h)，新密钥 [t0-30m, t0+24h) => t0 处并行可用。
	addHMAC(t, s, "k1", old, t0.Add(-2*time.Hour), t0.Add(time.Hour))
	addHMAC(t, s, "k2", new, t0.Add(-30*time.Minute), t0.Add(24*time.Hour))

	for _, kid := range []string{"k1", "k2"} {
		k, err := s.VerifyKey(kid, token.HS256, t0)
		if err != nil {
			t.Fatalf("kid=%s at overlap: %v", kid, err)
		}
		t.Logf("input now=t0 kid=%s | decision: key available %T", kid, k)
	}
	if active := s.ActiveSigningKey(t0); active.ID != "k2" {
		t.Fatalf("active signing key = %q, want k2 (latest rotation)", active.ID)
	}
}

func TestOldKeyExpiredNewKeyUsable(t *testing.T) {
	s := NewStore()
	old, new := hmacKeys(t, "k1", "k2")
	addHMAC(t, s, "k1", old, t0.Add(-2*time.Hour), t0.Add(time.Hour))
	addHMAC(t, s, "k2", new, t0.Add(-30*time.Minute), t0.Add(24*time.Hour))

	at := t0.Add(2 * time.Hour)
	if _, err := s.VerifyKey("k1", token.HS256, at); err == nil {
		t.Fatal("old key must be unusable after expiry")
	} else {
		t.Logf("input now=t0+2h kid=k1 | decision: rejected reason=%s", verifyErrReason(t, err))
	}
	if _, err := s.VerifyKey("k2", token.HS256, at); err != nil {
		t.Fatalf("new key must be usable after old expiry: %v", err)
	}
	t.Logf("input now=t0+2h kid=k2 | decision: key available")
	if active := s.ActiveSigningKey(at); active.ID != "k2" {
		t.Fatalf("active = %q want k2", active.ID)
	}
}

func TestRevocationImmediate(t *testing.T) {
	s := NewStore()
	old, _ := hmacKeys(t, "k1", "k2")
	addHMAC(t, s, "k1", old, t0.Add(-time.Hour), t0.Add(time.Hour))

	if _, err := s.VerifyKey("k1", token.HS256, t0); err != nil {
		t.Fatal(err)
	}
	s.Revoke("k1")
	_, err := s.VerifyKey("k1", token.HS256, t0)
	if err == nil {
		t.Fatal("revoked key must be rejected")
	}
	t.Logf("input kid=k1 after revoke | decision: rejected reason=%s", verifyErrReason(t, err))
	if got, _ := s.Get("k1"); !got.Revoked {
		t.Fatal("Get snapshot must reflect revoked flag")
	}
}

func TestKeyBeforeNotBeforeUnusable(t *testing.T) {
	s := NewStore()
	secret, _ := hmacKeys(t, "future", "")
	addHMAC(t, s, "future", secret, t0.Add(time.Hour), t0.Add(2*time.Hour))
	_, err := s.VerifyKey("future", token.HS256, t0)
	if err == nil {
		t.Fatal("future key must not verify before not_before")
	}
	t.Logf("input kid=future now<not_before | decision: rejected reason=%s", verifyErrReason(t, err))
}

func TestAlgorithmMismatch(t *testing.T) {
	s := NewStore()
	secret, _ := hmacKeys(t, "k1", "")
	addHMAC(t, s, "k1", secret, t0.Add(-time.Hour), t0.Add(time.Hour))
	if _, err := s.VerifyKey("k1", token.RS256, t0); err == nil {
		t.Fatal("HMAC key must not be served for RS256")
	} else {
		t.Logf("input kid=k1 alg=RS256 | decision: rejected reason=%s", verifyErrReason(t, err))
	}
}

func TestAddValidation(t *testing.T) {
	s := NewStore()
	if err := s.Add(SigningKey{ID: "", Algorithm: token.HS256}); err == nil {
		t.Fatal("empty id must fail")
	}
	if err := s.Add(SigningKey{ID: "x", Algorithm: token.HS256, NotBefore: t0, ExpiresAt: t0}); err == nil {
		t.Fatal("zero/invalid window must fail")
	}
	secret, _ := hmacKeys(t, "k1", "")
	addHMAC(t, s, "k1", secret, t0.Add(-time.Hour), t0.Add(time.Hour))
	if err := s.Add(SigningKey{ID: "k1", Algorithm: token.HS256, SigningKey: secret, VerifyKey: secret,
		NotBefore: t0.Add(-time.Hour), ExpiresAt: t0.Add(time.Hour)}); err == nil {
		t.Fatal("duplicate id must fail")
	}
}

func TestConcurrentVerifyAcrossRevocation(t *testing.T) {
	s := NewStore()
	secret, _ := hmacKeys(t, "k1", "")
	addHMAC(t, s, "k1", secret, t0.Add(-time.Hour), t0.Add(time.Hour))

	const goroutines = 64
	const preIter = 100
	const postIter = 200
	var wg sync.WaitGroup
	start := make(chan struct{})
	ready := make(chan struct{}, goroutines)
	proceed := make(chan struct{})
	var acceptedAfter, rejectedAfter int64
	var mu sync.Mutex

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < preIter; i++ {
				if _, err := s.VerifyKey("k1", token.HS256, t0); err != nil {
					t.Errorf("pre-revocation verify failed: %v", err)
					return
				}
			}
			ready <- struct{}{}
			<-proceed
			for i := 0; i < postIter; i++ {
				_, err := s.VerifyKey("k1", token.HS256, t0)
				mu.Lock()
				if err == nil {
					acceptedAfter++
				} else {
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
	s.Revoke("k1")
	close(proceed)
	wg.Wait()

	t.Logf("input concurrent VerifyKey: pre=%d all available | post=%d rejected, accepted=%d",
		goroutines*preIter, rejectedAfter, acceptedAfter)
	if acceptedAfter != 0 {
		t.Fatalf("revoked key accepted %d times after revocation", acceptedAfter)
	}
	if rejectedAfter != int64(goroutines*postIter) {
		t.Fatalf("post-revocation rejected=%d want=%d", rejectedAfter, goroutines*postIter)
	}
}
