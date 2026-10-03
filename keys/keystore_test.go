package keys

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/token"
)

func mustAdd(t *testing.T, s *Store, k Key) {
	t.Helper()
	if err := s.Add(k); err != nil {
		t.Fatalf("Add(%s): %v", k.ID, err)
	}
}

func TestRotationOverlapWindow(t *testing.T) {
	now := time.Now()
	old := Key{ID: "old", Alg: token.AlgHS256, Material: []byte("old-secret"),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * time.Minute)}
	newK := Key{ID: "new", Alg: token.AlgHS512, Material: []byte("new-secret"),
		NotBefore: now} // 新密钥已生效，旧密钥仍在宽限窗口内

	s := NewStore()
	mustAdd(t, s, old)
	mustAdd(t, s, newK)

	// 轮换窗口内：新旧密钥并行可用
	if rk, ok := s.Resolve("old", now); !ok || rk.Alg != token.AlgHS256 {
		t.Fatal("old key should be resolvable during overlap window")
	}
	if rk, ok := s.Resolve("new", now); !ok || rk.Alg != token.AlgHS512 {
		t.Fatal("new key should be resolvable during overlap window")
	}
	t.Logf("overlap window: old(HS256) and new(HS512) keys both resolvable at %s", now)

	// 窗口结束后：旧密钥不可用，新密钥仍可用
	after := now.Add(11 * time.Minute)
	if _, ok := s.Resolve("old", after); ok {
		t.Fatal("old key must not be resolvable after its window ends")
	}
	if _, ok := s.Resolve("new", after); !ok {
		t.Fatal("new key should still be resolvable")
	}
	t.Logf("after window: old rejected, new accepted at %s", after)

	// 新签发必须选用新密钥
	cur, ok := s.Current(now)
	if !ok || cur.ID != "new" {
		t.Fatalf("Current = %v, want new key", cur.ID)
	}
	t.Logf("current signing key = %s alg=%s", cur.ID, cur.Alg)
}

func TestRetiredKeyRejected(t *testing.T) {
	now := time.Now()
	s := NewStore()
	mustAdd(t, s, Key{ID: "k1", Alg: token.AlgHS256, Material: []byte("x"), NotBefore: now.Add(-time.Hour)})

	if !s.Retire("k1") {
		t.Fatal("Retire should report success")
	}
	if _, ok := s.Resolve("k1", now); ok {
		t.Fatal("retired key must not resolve even inside its window")
	}
	t.Logf("retired key k1 rejected at %s despite valid window", now)
}

func TestKeyMaterialIsCopied(t *testing.T) {
	now := time.Now()
	mat := []byte("original")
	s := NewStore()
	mustAdd(t, s, Key{ID: "k1", Alg: token.AlgHS256, Material: mat, NotBefore: now.Add(-time.Hour)})
	mat[0] = 'X' // 外部修改不应影响库内密钥

	got, ok := s.Resolve("k1", now)
	if !ok || string(got.Material.([]byte)) != "original" {
		t.Fatalf("key material mutated: %q", got.Material)
	}
	got.Material.([]byte)[0] = 'Y' // 调用方修改返回值不应影响库内密钥
	again, _ := s.Resolve("k1", now)
	if string(again.Material.([]byte)) != "original" {
		t.Fatalf("returned key material is shared with store: %q", again.Material)
	}
	t.Logf("key material isolation verified")
}

func TestConcurrentResolveDuringRotation(t *testing.T) {
	now := time.Now()
	s := NewStore()
	mustAdd(t, s, Key{ID: "old", Alg: token.AlgHS256, Material: []byte("old"), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	rsaKey, err := token.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, s, Key{ID: "new", Alg: token.AlgRS256, Material: rsaKey, NotBefore: now})

	const workers = 32
	const rounds = 500
	var wg sync.WaitGroup
	errs := make(chan error, workers*rounds)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				// 轮换窗口内，两个密钥（分属 HMAC/RSA 族）都必须稳定可解析
				if rk, ok := s.Resolve("old", now); !ok || token.FamilyFor(rk.Alg) != token.FamilyHMAC {
					errs <- fmt.Errorf("worker %d: old key vanished during window", w)
				}
				if rk, ok := s.Resolve("new", now); !ok || token.FamilyFor(rk.Alg) != token.FamilyRSA {
					errs <- fmt.Errorf("worker %d: new key vanished during window", w)
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	t.Logf("%d workers x %d rounds: cross-family rotation window resolution stable", workers, rounds)
}

// TestAddRejectsFamilyMaterialMismatch 注册时材料与算法族不一致必须拒绝入库。
func TestAddRejectsFamilyMaterialMismatch(t *testing.T) {
	now := time.Now()
	rsaKey, err := token.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := token.GenerateECDSAKey(token.AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	s := NewStore()

	cases := []struct {
		name string
		k    Key
	}{
		{"rsa-alg-with-hmac-secret", Key{ID: "bad1", Alg: token.AlgRS256, Material: []byte("secret")}},
		{"hmac-alg-with-rsa-key", Key{ID: "bad2", Alg: token.AlgHS256, Material: rsaKey}},
		{"ecdsa-alg-with-rsa-key", Key{ID: "bad3", Alg: token.AlgES256, Material: rsaKey}},
		{"rsa-alg-with-ecdsa-key", Key{ID: "bad4", Alg: token.AlgRS256, Material: ecKey}},
		{"unknown-alg", Key{ID: "bad5", Alg: token.Algorithm("XX999"), Material: []byte("secret")}},
		{"empty-hmac-secret", Key{ID: "bad6", Alg: token.AlgHS256, Material: []byte{}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.k.NotBefore = now.Add(-time.Hour)
			if err := s.Add(c.k); err == nil {
				t.Fatalf("Add(%s) must reject mismatched material", c.name)
			} else {
				t.Logf("Add(%s) rejected: %v", c.name, err)
			}
			if _, ok := s.Resolve(c.k.ID, now); ok {
				t.Fatalf("rejected key %s must not be resolvable", c.k.ID)
			}
		})
	}
}
