package engine

import (
	"errors"
	"reflect"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/policy"
	"github.com/xingjianluo/identity-policy-engine-go/token"
)

// issueTokenWithTTL 用指定有效期签发 alice/reader 令牌（ttl 可为负，模拟已过期）。
func (f *fixture) issueTokenWithTTL(t *testing.T, ttl time.Duration) string {
	t.Helper()
	iss := token.NewIssuer(token.HMACKey(token.AlgHS256, "k1", []byte("secret-1"))).WithKID("k1")
	tok, err := iss.Issue(token.Claims{
		Subject: "alice", SessionID: "sess-1", Roles: []string{"reader"},
	}, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestReplayAfterTokenExpiry 当初判定过后令牌已过期：
// 线上 Authorize 在令牌阶段失败，但 Replay 必须原样还原当初的策略结论与依据。
func TestReplayAfterTokenExpiry(t *testing.T) {
	f := newFixture(t)

	// 当初：令牌有效，判定通过，记下结论与版本。
	validTok := f.issueTokenWithTTL(t, 10*time.Minute)
	original := f.engine.Authorize(validTok, "read", "doc/1")
	if !original.Allowed || original.Stage != StagePolicy {
		t.Fatalf("baseline authorize must pass, got %+v", original)
	}
	t.Logf("original: version=%d trace=%s", original.PolicyVersion, original.Trace)

	// 隔了很久：同一主体同一声明的令牌已经过期（exp 在过去）。
	expiredTok := f.issueTokenWithTTL(t, -time.Hour)
	res := f.engine.Authorize(expiredTok, "read", "doc/1")
	t.Logf("expired token authorize: stage=%s reason=%s", res.Stage, res.Reason)
	if res.Allowed || res.Stage != StageToken || res.Reason != token.ReasonExpired {
		t.Fatalf("expired token must fail at TOKEN/EXPIRED, got %+v", res)
	}

	// 回放：不受令牌时效影响，结论、命中策略与依据与当初逐字段一致。
	replayed, err := f.engine.Replay(expiredTok, "read", "doc/1", original.PolicyVersion)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("replay v%d with expired token: stage=%s trace=%s",
		replayed.PolicyVersion, replayed.Stage, replayed.Trace)
	if replayed.Stage != StagePolicy || !replayed.Allowed {
		t.Fatalf("replay must reproduce the policy decision, got %+v", replayed)
	}
	if !reflect.DeepEqual(replayed.Trace, original.Trace) {
		t.Fatalf("replay trace differs from original:\n original=%s\n replayed=%s",
			original.Trace, replayed.Trace)
	}
}

// TestReplayAfterSessionAndKeyGone 会话被吊销、密钥被吊销之后，
// 回放依然还原当初的策略结论，而不是变成会话/令牌阶段失败。
func TestReplayAfterSessionAndKeyGone(t *testing.T) {
	f := newFixture(t)
	tok := f.issueTokenWithTTL(t, 10*time.Minute)
	original := f.engine.Authorize(tok, "read", "doc/1")
	if !original.Allowed {
		t.Fatalf("baseline authorize must pass, got %+v", original)
	}
	t.Logf("original: version=%d trace=%s", original.PolicyVersion, original.Trace)

	// 会话吊销 + 密钥吊销：线上判定分别倒在 SESSION / TOKEN 阶段。
	f.sessions.Revoke("sess-1")
	if res := f.engine.Authorize(tok, "read", "doc/1"); res.Stage != StageSession {
		t.Fatalf("revoked session must fail at SESSION, got %+v", res)
	}
	f.keys.Retire("k1")
	if res := f.engine.Authorize(tok, "read", "doc/1"); res.Stage != StageToken {
		t.Fatalf("retired key must fail at TOKEN, got %+v", res)
	}

	replayed, err := f.engine.Replay(tok, "read", "doc/1", original.PolicyVersion)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("replay v%d after session revoked & key retired: trace=%s",
		replayed.PolicyVersion, replayed.Trace)
	if replayed.Stage != StagePolicy || !reflect.DeepEqual(replayed.Trace, original.Trace) {
		t.Fatalf("replay must ignore current token/session state:\n original=%s\n replayed=%+v",
			original.Trace, replayed)
	}
}

// TestReplayUnknownVersion 版本号不存在时必须返回可识别的错误，
// 且不能返回任何看似结论的结果。
func TestReplayUnknownVersion(t *testing.T) {
	f := newFixture(t)
	tok := f.issueTokenWithTTL(t, 10*time.Minute)

	for _, v := range []int64{0, -1, 99} {
		res, err := f.engine.Replay(tok, "read", "doc/1", v)
		t.Logf("replay v%d: err=%v", v, err)
		if !errors.Is(err, policy.ErrUnknownVersion) {
			t.Fatalf("replay v%d: want ErrUnknownVersion, got err=%v", v, err)
		}
		if !reflect.DeepEqual(res, Result{}) {
			t.Fatalf("replay v%d: result must be zero value on unknown version, got %+v", v, res)
		}
	}
}

// TestConcurrentPublishAuthorizeReplay 并发发布与并发判定/回放混在一起时，
// 每条判定的依据链必须完整来自同一个版本（版本号与命中策略自洽）。
func TestConcurrentPublishAuthorizeReplay(t *testing.T) {
	f := newFixture(t)
	tok := f.issueTokenWithTTL(t, 10*time.Minute)

	const publishers = 6
	const workers = 12
	const rounds = 200

	var wg sync.WaitGroup
	bad := make(chan string, (publishers+workers)*rounds)

	for p := 0; p < publishers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				eff := policy.EffectPermit
				if (p+r)%2 == 1 {
					eff = policy.EffectDeny
				}
				f.policies.Publish([]policy.Policy{{
					ID: fmt.Sprintf("pub-%d-%d", p, r), Effect: eff,
					Roles: []string{"reader"}, Actions: []string{"read"}, Resources: []string{"doc/1"},
				}})
			}
		}(p)
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				res := f.engine.Authorize(tok, "read", "doc/1")
				if res.Stage != StagePolicy {
					bad <- fmt.Sprintf("worker %d: unexpected stage %s", w, res.Stage)
					continue
				}
				tr := res.Trace
				// 每个版本只有一条策略：结论与证据必须自洽且来自同一版本。
				if tr.Version != res.PolicyVersion || tr.Version < 1 ||
					tr.Version > f.policies.LatestVersion() {
					bad <- fmt.Sprintf("worker %d: incoherent version res=%d trace=%d",
						w, res.PolicyVersion, tr.Version)
					continue
				}
				switch tr.Decision {
				case policy.DecisionPermit:
					if !res.Allowed || len(tr.MatchedPermits) != 1 || len(tr.MatchedDenies) != 0 {
						bad <- fmt.Sprintf("worker %d: mixed evidence v%d: %s", w, tr.Version, tr)
					}
				case policy.DecisionDeny:
					if res.Allowed || len(tr.MatchedDenies) != 1 || len(tr.MatchedPermits) != 0 {
						bad <- fmt.Sprintf("worker %d: mixed evidence v%d: %s", w, tr.Version, tr)
					}
				default:
					bad <- fmt.Sprintf("worker %d: unexpected decision %s v%d", w, tr.Decision, tr.Version)
				}
				// 用刚拿到的版本号回放同一输入，必须逐字段复现。
				replayed, err := f.engine.Replay(tok, "read", "doc/1", tr.Version)
				if err != nil {
					bad <- fmt.Sprintf("worker %d: replay v%d: %v", w, tr.Version, err)
					continue
				}
				if !reflect.DeepEqual(replayed.Trace, tr) {
					bad <- fmt.Sprintf("worker %d: replay v%d mismatch:\n live=%s\n replay=%s",
						w, tr.Version, tr, replayed.Trace)
				}
			}
		}(w)
	}
	wg.Wait()
	close(bad)
	for msg := range bad {
		t.Fatal(msg)
	}
	t.Logf("%d publishers + %d workers x %d rounds: every decision's evidence chain came from a single version, replay reproduced each one",
		publishers, workers, rounds)
}
