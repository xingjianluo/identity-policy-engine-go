package engine

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/keys"
	"github.com/xingjianluo/identity-policy-engine-go/policy"
	"github.com/xingjianluo/identity-policy-engine-go/session"
	"github.com/xingjianluo/identity-policy-engine-go/token"
)

// newReplayFixture 构造零时间容差、会话长期有效的回放测试环境，
// 便于精确制造「令牌过期 / 会话吊销 / 密钥吊销」三种失效态。
func newReplayFixture(t *testing.T) (*Engine, *keys.Store, *session.Store, *policy.Engine) {
	t.Helper()
	now := time.Now()
	ks := keys.NewStore()
	ks.Add(keys.Key{ID: "k1", Alg: token.AlgHS256, Material: []byte("secret-1"),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	ss := session.NewStore()
	ss.Create(session.Session{ID: "sess-1", Subject: "alice", ExpiresAt: now.Add(24 * time.Hour)})
	pe := policy.NewEngine()
	pe.Publish([]policy.Policy{{ID: "allow-read", Effect: policy.EffectPermit,
		Roles: []string{"reader"}, Actions: []string{"read"}, Resources: []string{"doc/1"}}})
	v := token.NewVerifier(ks, 0, token.AlgHS256) // 零 leeway，过期即拒
	return New(v, ss, pe), ks, ss, pe
}

// TestReplayAfterTokenExpiredAndSessionRevoked 隔一段时间后令牌已过期、
// 会话已吊销，实时授权早已失败，但历史回放必须还原出当初那条策略结论与依据，
// 而不是退化成 TOKEN/SESSION 阶段失败。
func TestReplayAfterTokenExpiredAndSessionRevoked(t *testing.T) {
	eng, ks, ss, pe := newReplayFixture(t)

	// 签发一枚极短 TTL 的令牌（1 秒），在其有效时完成原始判定
	iss := token.NewIssuer(token.HMACKey(token.AlgHS256, "k1", []byte("secret-1"))).
		WithKID("k1")
	tok, err := iss.Issue(token.Claims{
		Subject: "alice", SessionID: "sess-1",
		Roles: []string{"reader"}, Attrs: map[string]string{"dept": "eng"},
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	original := eng.Authorize(tok, "read", "doc/1")
	if !original.Allowed || original.Stage != StagePolicy || original.PolicyVersion != 1 {
		t.Fatalf("original authorize: %+v", original)
	}
	t.Logf("input=(fresh token, read, doc/1) version=%d ORIGINAL trace=%s",
		original.PolicyVersion, original.Trace)

	// 失效态一：令牌过期（零 leeway）。实时授权停在 TOKEN/EXPIRED。
	time.Sleep(1100 * time.Millisecond)
	if r := eng.Authorize(tok, "read", "doc/1"); r.Allowed ||
		r.Stage != StageToken || r.Reason != token.ReasonExpired {
		t.Fatalf("expired token must fail LIVE at TOKEN/EXPIRED, got %+v", r)
	}
	t.Logf("after token expiry, LIVE authorize: stage=TOKEN reason=EXPIRED")

	// 失效态二：再吊销会话。令牌仍过期，停在 TOKEN（会话吊销对实时同样致命）。
	ss.Revoke("sess-1")
	if r := eng.Authorize(tok, "read", "doc/1"); r.Allowed || r.Stage != StageToken {
		t.Fatalf("revoked session must keep LIVE failing, got %+v", r)
	}
	t.Logf("after session revocation too, LIVE authorize still denied")

	// 失效态三：再吊销签名密钥（模拟轮换后旧密钥退役），实时连密钥都解析不到。
	ks.Retire("k1")
	if r := eng.Authorize(tok, "read", "doc/1"); r.Allowed ||
		r.Stage != StageToken {
		t.Fatalf("retired key must keep LIVE failing, got %+v", r)
	}
	t.Logf("after key retirement too, LIVE authorize: stage=TOKEN (expired+revoked+retired)")

	// 发布新版本把同一输入改为 DENY，确认回放不会被最新版本带偏。
	n2 := pe.Publish([]policy.Policy{{
		ID: "deny-read", Effect: policy.EffectDeny, Roles: []string{"reader"},
		Actions: []string{"read"}, Resources: []string{"doc/1"},
	}})
	if r := eng.Authorize(tok, "read", "doc/1"); r.Stage != StageToken {
		t.Fatalf("sanity: live still token-failed, got %+v", r)
	}

	// 关键断言：用当初的输入 + 版本号 1 回放，结论与依据原样还原，
	// 不受当前时间、令牌时效、会话状态与密钥状态影响。
	replayed, err := eng.Replay(tok, "read", "doc/1", 1)
	if err != nil {
		t.Fatalf("replay must not depend on current token/session/key validity: %v", err)
	}
	t.Logf("REPLAY version=1 (token expired, session revoked, key retired, live=v%d) trace=%s",
		n2, replayed.Trace)
	if !replayed.Allowed || replayed.Stage != StagePolicy || replayed.PolicyVersion != 1 {
		t.Fatalf("replay must reproduce original PERMIT@v1, got %+v", replayed)
	}
	if replayed.Trace.Decision != original.Trace.Decision ||
		replayed.Trace.Explanation != original.Trace.Explanation ||
		len(replayed.Trace.MatchedPermits) != 1 ||
		replayed.Trace.MatchedPermits[0] != original.Trace.MatchedPermits[0] {
		t.Fatalf("replay evidence differs from original:\n replay=%s\n origin=%s",
			replayed.Trace, original.Trace)
	}

	// 用留存的请求回放，结果一致（不依赖令牌这一载体）
	direct, err := eng.ReplayRequest(policy.Request{
		Subject: "alice", Roles: []string{"reader"}, Action: "read",
		Resource: "doc/1", Attrs: map[string]string{"dept": "eng"},
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if direct.Trace.Decision != replayed.Trace.Decision ||
		direct.Trace.MatchedPermits[0] != replayed.Trace.MatchedPermits[0] {
		t.Fatalf("ReplayRequest must match token-based replay: %s vs %s",
			direct.Trace, replayed.Trace)
	}
	t.Logf("ReplayRequest with recorded input yields identical evidence: %s", direct.Trace)
}

// TestReplayUnknownVersionAndBadToken 错误输入必须得到可识别的错误，
// 绝不能返回一条像模像样的判定结论。
func TestReplayUnknownVersionAndBadToken(t *testing.T) {
	f := newFixture(t)
	tok := f.issueToken(t, "k1", "secret-1")

	// 未知版本
	if _, err := f.engine.Replay(tok, "read", "doc/1", 42); !errors.Is(err, policy.ErrUnknownVersion) {
		t.Fatalf("unknown version must wrap policy.ErrUnknownVersion, got %v", err)
	}
	t.Logf("replay version=42 -> recognizable error (ErrUnknownVersion)")

	// 版本号非法（0 / 负数）
	for _, bad := range []int64{0, -1} {
		if _, err := f.engine.Replay(tok, "read", "doc/1", bad); !errors.Is(err, policy.ErrUnknownVersion) {
			t.Fatalf("version %d must yield ErrUnknownVersion, got %v", bad, err)
		}
	}

	// 结构损坏的令牌：即便版本有效也不能伪装成结论
	if _, err := f.engine.Replay("not-a-token", "read", "doc/1", 1); err == nil {
		t.Fatal("malformed token must error, not produce a verdict")
	} else if te, ok := err.(*token.Error); !ok || te.Reason != token.ReasonMalformed {
		t.Fatalf("malformed token must yield *token.Error/MALFORMED, got %v", err)
	} else {
		t.Logf("malformed token -> recognizable error (%s)", te.Reason)
	}

	// 载荷 base64 损坏
	if _, err := f.engine.Replay("a.b.c", "read", "doc/1", 1); err == nil ||
		!strings.Contains(err.Error(), string(token.ReasonMalformed)) {
		t.Fatalf("garbage segments must yield MALFORMED, got %v", err)
	}
}

// TestConcurrentPublishAuthorizeAndReplay 并发发布、并发实时判定、并发历史回放
// 混在一起时：
//   - 每条实时判定的 Trace 必须完整来自某一个自洽版本（结论与命中策略 ID 同源）；
//   - 对任意已发布版本号回放，得到的依据必须等于该版本冻结策略独立重算的结果，
//     不会被正在发生的发布带到新版本；
//   - 整个过程令牌始终有效，但我们同时对同一令牌做 Replay，验证回放路径在
//     高并发下依旧版本自洽。
func TestConcurrentPublishAuthorizeAndReplay(t *testing.T) {
	eng, _, _, pe := newReplayFixture(t)

	iss := token.NewIssuer(token.HMACKey(token.AlgHS256, "k1", []byte("secret-1"))).
		WithKID("k1")
	tok, err := iss.Issue(token.Claims{
		Subject: "alice", SessionID: "sess-1", Roles: []string{"reader"},
		Attrs: map[string]string{"dept": "eng"},
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	req := policy.Request{Subject: "alice", Roles: []string{"reader"},
		Action: "read", Resource: "doc/1", Attrs: map[string]string{"dept": "eng"}}

	const publishers = 8
	const workers = 16
	const rounds = 200

	var wg sync.WaitGroup
	bad := make(chan string, publishers*rounds+workers*rounds*2)

	// 发布者：交替发布 PERMIT/DENY 单策略版本，ID 带版本特征。
	for p := 0; p < publishers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				eff := policy.EffectPermit
				id := "permit-policy"
				if (p+r)%2 == 1 {
					eff = policy.EffectDeny
					id = "deny-policy"
				}
				n := pe.Publish([]policy.Policy{{ID: id, Effect: eff,
					Roles: []string{"reader"}, Actions: []string{"read"},
					Resources: []string{"doc/1"}}})
				// 记录该版本的期望依据，供回放比对（用独立引擎视角读取冻结版本）。
				want, err := pe.Replay(n, req)
				if err != nil {
					bad <- "publisher: cannot replay just-published version"
					continue
				}
				_ = want
			}
		}(p)
	}

	// 工作者：实时判定 + 随机历史版本回放，各自检查版本自洽。
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				// 实时判定：Trace 的版本号必须与命中依据自洽。
				live := eng.Authorize(tok, "read", "doc/1")
				if live.Stage != StagePolicy {
					bad <- "live authorize unexpectedly not at policy stage"
					continue
				}
				if !coherent(live.Trace) {
					bad <- "live trace mixes evidence across versions/policies: " + live.Trace.String()
				}

				// 历史回放：任选一个已发布版本，依据必须与该版本独立重算一致。
				latest := pe.LatestVersion()
				if latest < 1 {
					continue
				}
				vn := int64((w*rounds+r)%int(latest)) + 1
				got, err := eng.Replay(tok, "read", "doc/1", vn)
				if err != nil {
					bad <- "replay of published version errored: " + err.Error()
					continue
				}
				want, err := pe.Replay(vn, req)
				if err != nil {
					bad <- "policy replay of published version errored"
					continue
				}
				if got.PolicyVersion != vn || !sameTrace(got.Trace, want) {
					bad <- "replay evidence drifted from frozen version " +
						"got=" + got.Trace.String() + " want=" + want.String()
				}
			}
		}(w)
	}

	wg.Wait()
	close(bad)
	for msg := range bad {
		t.Fatal(msg)
	}
	t.Logf("%d publishers + %d workers x %d rounds: every live/replay trace came from a single coherent version",
		publishers, workers, rounds)
}

// coherent 校验一条 Trace 的依据链自洽：每个发布内只有一条单策略，
// 因此 PERMIT 只能带一个 permit 依据、DENY 只能带一个 deny 依据，
// 不允许出现跨版本/跨策略把两边依据串在一起的情况。
func coherent(tr policy.Trace) bool {
	switch tr.Decision {
	case policy.DecisionPermit:
		return len(tr.MatchedPermits) == 1 && len(tr.MatchedDenies) == 0
	case policy.DecisionDeny:
		return len(tr.MatchedDenies) == 1 && len(tr.MatchedPermits) == 0
	default:
		return false // 本测试策略必然匹配
	}
}

func sameTrace(a, b policy.Trace) bool {
	if a.Version != b.Version || a.Decision != b.Decision || a.Explanation != b.Explanation {
		return false
	}
	return equalSlice(a.MatchedPermits, b.MatchedPermits) &&
		equalSlice(a.MatchedDenies, b.MatchedDenies) &&
		equalSlice(a.ConditionFails, b.ConditionFails)
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
