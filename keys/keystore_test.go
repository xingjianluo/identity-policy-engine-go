package keys

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/token"
)

func TestRotationOverlapWindow(t *testing.T) {
	now := time.Now()
	old := Key{ID: "old", Alg: token.AlgHS256, Material: []byte("old-secret"),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * time.Minute)}
	newK := Key{ID: "new", Alg: token.AlgHS256, Material: []byte("new-secret"),
		NotBefore: now} // 新密钥已生效，旧密钥仍在宽限窗口内

	s := NewStore()
	s.Add(old)
	s.Add(newK)

	// 轮换窗口内：新旧密钥并行可用
	if _, ok := s.Resolve("old", now); !ok {
		t.Fatal("old key should be resolvable during overlap window")
	}
	if _, ok := s.Resolve("new", now); !ok {
		t.Fatal("new key should be resolvable during overlap window")
	}
	t.Logf("overlap window: old and new keys both resolvable at %s", now)

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
	t.Logf("current signing key = %s", cur.ID)
}

func TestRetiredKeyRejected(t *testing.T) {
	now := time.Now()
	s := NewStore()
	s.Add(Key{ID: "k1", Alg: token.AlgHS256, Material: []byte("x"), NotBefore: now.Add(-time.Hour)})

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
	s.Add(Key{ID: "k1", Alg: token.AlgHS256, Material: mat, NotBefore: now.Add(-time.Hour)})
	mat[0] = 'X' // 外部修改不应影响库内密钥

	got, ok := s.Resolve("k1", now)
	if !ok || string(got.HMAC) != "original" {
		t.Fatalf("key material mutated: %q", got.HMAC)
	}
	got.HMAC[0] = 'Y' // 调用方修改返回值不应影响库内密钥
	again, _ := s.Resolve("k1", now)
	if string(again.HMAC) != "original" {
		t.Fatalf("returned key material is shared with store: %q", again.HMAC)
	}
	t.Logf("key material isolation verified")
}

func TestConcurrentResolveDuringRotation(t *testing.T) {
	now := time.Now()
	s := NewStore()
	s.Add(Key{ID: "old", Alg: token.AlgHS256, Material: []byte("old"), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	s.Add(Key{ID: "new", Alg: token.AlgHS256, Material: []byte("new"), NotBefore: now})

	const workers = 32
	const rounds = 500
	var wg sync.WaitGroup
	errs := make(chan error, workers*rounds)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				// 轮换窗口内，两个密钥都必须稳定可解析
				if _, ok := s.Resolve("old", now); !ok {
					errs <- fmt.Errorf("worker %d: old key vanished during window", w)
				}
				if _, ok := s.Resolve("new", now); !ok {
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
	t.Logf("%d workers x %d rounds: rotation window resolution stable", workers, rounds)
}
