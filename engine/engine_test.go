package engine

import (
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/keys"
	"github.com/xingjianluo/identity-policy-engine-go/policy"
	"github.com/xingjianluo/identity-policy-engine-go/session"
	"github.com/xingjianluo/identity-policy-engine-go/token"
)

type fixture struct {
	engine   *Engine
	keys     *keys.Store
	sessions *session.Store
	policies *policy.Engine
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ks := keys.NewStore()
	now := time.Now()
	if err := ks.Add(keys.Key{ID: "k1", Alg: token.AlgHS256, Material: []byte("secret-1"),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	ss := session.NewStore()
	ss.Create(session.Session{ID: "sess-1", Subject: "alice", ExpiresAt: now.Add(time.Hour)})

	pe := policy.NewEngine()
	pe.SetPolicies([]policy.Policy{
		{ID: "allow-read", Effect: policy.EffectPermit, Roles: []string{"reader"},
			Actions: []string{"read"}, Resources: []string{"doc/1"}},
	})

	v := token.NewVerifier(ks, 30*time.Second, token.AlgHS256)
	return &fixture{engine: New(v, ss, pe), keys: ks, sessions: ss, policies: pe}
}

func (f *fixture) issueToken(t *testing.T, kid string, secret string) string {
	t.Helper()
	iss := token.NewIssuer(token.AlgHS256, kid, []byte(secret))
	tok, err := iss.Issue(token.Claims{
		Subject: "alice", SessionID: "sess-1", Roles: []string{"reader"},
	}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestEndToEndAllow(t *testing.T) {
	f := newFixture(t)
	tok := f.issueToken(t, "k1", "secret-1")
	res := f.engine.Authorize(tok, "read", "doc/1")
	t.Logf("input=(valid token, read, doc/1) result=%+v trace=%s", res, res.Trace)
	if !res.Allowed {
		t.Fatalf("expected allow, got %+v (%s)", res, res.Trace)
	}
}

func TestEndToEndStagesDistinct(t *testing.T) {
	f := newFixture(t)

	// 阶段一：令牌被篡改 -> TOKEN / SIGNATURE_MISMATCH
	tampered := f.issueToken(t, "k1", "wrong-secret")
	res := f.engine.Authorize(tampered, "read", "doc/1")
	t.Logf("tampered token: stage=%s reason=%s", res.Stage, res.Reason)
	if res.Allowed || res.Stage != StageToken || res.Reason != token.ReasonSignatureMismatch {
		t.Fatalf("tampered token: got %+v", res)
	}

	// 阶段二：会话被吊销 -> SESSION
	tok := f.issueToken(t, "k1", "secret-1")
	f.sessions.Revoke("sess-1")
	res = f.engine.Authorize(tok, "read", "doc/1")
	t.Logf("revoked session: stage=%s", res.Stage)
	if res.Allowed || res.Stage != StageSession {
		t.Fatalf("revoked session: got %+v", res)
	}

	// 阶段三：策略无匹配 -> POLICY / NO_MATCH
	f2 := newFixture(t)
	tok2 := f2.issueToken(t, "k1", "secret-1")
	res = f2.engine.Authorize(tok2, "write", "doc/1")
	t.Logf("no matching policy: stage=%s trace=%s", res.Stage, res.Trace)
	if res.Allowed || res.Stage != StagePolicy || res.Trace.Decision != policy.DecisionNoMatch {
		t.Fatalf("no matching policy: got %+v", res)
	}
}

func TestKeyRotationEndToEnd(t *testing.T) {
	f := newFixture(t)
	now := time.Now()

	// 旧密钥签发的令牌
	oldTok := f.issueToken(t, "k1", "secret-1")

	// 轮换：加入新密钥，旧密钥保留宽限窗口
	if err := f.keys.Add(keys.Key{ID: "k2", Alg: token.AlgHS256, Material: []byte("secret-2"),
		NotBefore: now, NotAfter: now.Add(2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}

	// 旧令牌在窗口内仍可通过
	if res := f.engine.Authorize(oldTok, "read", "doc/1"); !res.Allowed {
		t.Fatalf("old-key token must remain valid during overlap: %+v", res)
	}
	// 新密钥签发的令牌也可通过
	newTok := f.issueToken(t, "k2", "secret-2")
	if res := f.engine.Authorize(newTok, "read", "doc/1"); !res.Allowed {
		t.Fatalf("new-key token must be valid: %+v", res)
	}
	t.Logf("rotation overlap: old-key and new-key tokens both accepted")

	// 吊销旧密钥后，旧令牌必须被拒绝且原因可区分
	f.keys.Retire("k1")
	res := f.engine.Authorize(oldTok, "read", "doc/1")
	t.Logf("after retiring k1: stage=%s reason=%s", res.Stage, res.Reason)
	if res.Allowed || res.Reason != token.ReasonUnknownKey {
		t.Fatalf("retired key token must be rejected with UNKNOWN_KEY, got %+v", res)
	}
	// 新令牌不受影响
	if res := f.engine.Authorize(newTok, "read", "doc/1"); !res.Allowed {
		t.Fatalf("new-key token must survive old key retirement: %+v", res)
	}
}

func TestConcurrentAuthorizeStable(t *testing.T) {
	f := newFixture(t)
	good := f.issueToken(t, "k1", "secret-1")
	bad := f.issueToken(t, "k1", "wrong-secret")

	const workers = 32
	const rounds = 300
	var wg sync.WaitGroup
	badResults := make(chan string, workers*rounds)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if res := f.engine.Authorize(good, "read", "doc/1"); !res.Allowed {
					badResults <- "valid token rejected: " + string(res.Stage)
				}
				if res := f.engine.Authorize(bad, "read", "doc/1"); res.Allowed {
					badResults <- "tampered token allowed"
				}
			}
		}()
	}
	wg.Wait()
	close(badResults)
	for msg := range badResults {
		t.Fatal(msg)
	}
	t.Logf("%d workers x %d rounds: concurrent authorize results stable", workers, rounds)
}
