package engine

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/keys"
	"github.com/xingjianluo/identity-policy-engine-go/policy"
	"github.com/xingjianluo/identity-policy-engine-go/session"
	"github.com/xingjianluo/identity-policy-engine-go/token"
)

type asymmetricFixture struct {
	engine   *Engine
	keys     *keys.Store
	sessions *session.Store
	policies *policy.Engine
	now      time.Time
}

func newAsymmetricFixture(t *testing.T) *asymmetricFixture {
	t.Helper()
	now := time.Now()
	ks := keys.NewStore()

	// 存量 HMAC 密钥（老签发方），与新 RSA 密钥并存于重叠窗口
	ks.Add(keys.HMACKey("k-hmac", token.AlgHS256, []byte("legacy-secret"),
		now.Add(-24*time.Hour), now.Add(time.Hour)))
	rsaKey, err := keys.GenerateKey("k-rsa", token.AlgRS256, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ks.Add(rsaKey)

	ss := session.NewStore()
	ss.Create(session.Session{ID: "sess-1", Subject: "alice", ExpiresAt: now.Add(time.Hour)})

	pe := policy.NewEngine()
	pe.Publish([]policy.Policy{
		{ID: "allow-read", Effect: policy.EffectPermit, Roles: []string{"reader"},
			Actions: []string{"read"}, Resources: []string{"doc/1"}},
	})

	// 校验方同时放行 HMAC 与 RSA 两个算法族
	v := token.NewVerifier(ks, 30*time.Second, token.AlgHS256, token.AlgRS256)
	return &asymmetricFixture{engine: New(v, ss, pe), keys: ks, sessions: ss,
		policies: pe, now: now}
}

func claimsFor(subject string) token.Claims {
	return token.Claims{Subject: subject, SessionID: "sess-1", Roles: []string{"reader"},
		Attrs: map[string]string{"dept": "eng"}}
}

func issueLegacyHMAC(t *testing.T) string {
	t.Helper()
	iss := token.NewIssuer(token.HMACKey(token.AlgHS256, "k-hmac", []byte("legacy-secret"))).
		WithKID("k-hmac")
	tok, err := iss.Issue(claimsFor("alice"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestCrossFamilyRotationEndToEnd 完整链路：老 HMAC 令牌继续放行，
// 新 RSA 令牌经 Current 自动签发并放行；过期后老令牌以 UNKNOWN_KEY 拒绝。
func TestCrossFamilyRotationEndToEnd(t *testing.T) {
	f := newAsymmetricFixture(t)

	legacy := issueLegacyHMAC(t)
	res := f.engine.Authorize(legacy, "read", "doc/1")
	t.Logf("step=legacy HMAC token result allowed=%v stage=%s reason=%s trace=%s",
		res.Allowed, res.Stage, res.Reason, res.Trace)
	if !res.Allowed {
		t.Fatalf("legacy HMAC token must pass during overlap: %+v", res)
	}

	// 新签发自动走最新（RSA）密钥
	iss, k, ok := f.keys.IssuerForCurrent(f.now)
	if !ok || k.ID != "k-rsa" {
		t.Fatalf("current issuer must be k-rsa, got %q ok=%v", k.ID, ok)
	}
	rsaTok, err := iss.Issue(claimsFor("alice"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	res = f.engine.Authorize(rsaTok, "read", "doc/1")
	t.Logf("step=fresh RSA token via Current key=%s result allowed=%v policyVersion=%d trace=%s",
		k.ID, res.Allowed, res.PolicyVersion, res.Trace)
	if !res.Allowed || res.Stage != StagePolicy {
		t.Fatalf("fresh RSA token must pass policy stage: %+v", res)
	}

	// 老密钥窗口结束：存量 HMAC 令牌被拒，RSA 令牌不受影响
	f.keys.Retire("k-hmac")
	if res := f.engine.Authorize(legacy, "read", "doc/1"); res.Allowed ||
		res.Stage != StageToken || res.Reason != token.ReasonUnknownKey {
		t.Fatalf("retired HMAC key -> TOKEN/UNKNOWN_KEY, got %+v", res)
	}
	if res := f.engine.Authorize(rsaTok, "read", "doc/1"); !res.Allowed {
		t.Fatalf("RSA token must survive HMAC retirement: %+v", res)
	}
	t.Logf("step=after retirement: legacy rejected UNKNOWN_KEY, RSA still allowed")
}

// TestAlgorithmSubstitutionEndToEnd 攻击：拿到 RSA 公钥后改 alg=HS256，
// 并以公钥 DER 字节作为 HMAC 密钥伪造签名。引擎必须以 ALG_SUBSTITUTION 拒绝。
func TestAlgorithmSubstitutionEndToEnd(t *testing.T) {
	f := newAsymmetricFixture(t)

	// 先用新 RSA 密钥签一条合法令牌
	iss, k, ok := f.keys.IssuerForCurrent(f.now)
	if !ok {
		t.Fatal("no current key")
	}
	good, err := iss.Issue(claimsFor("alice"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	rk, _ := f.keys.Resolve(k.ID, f.now)
	rsaPub, ok := rk.Public.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("k-rsa public key type = %T", rk.Public)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(rsaPub)
	if err != nil {
		t.Fatal(err)
	}

	// 攻击者改写头部 alg 为 HS256（kid 仍指向 RSA 密钥）
	parts := strings.Split(good, ".")
	hb, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT", "kid": k.ID})
	parts[0] = base64.RawURLEncoding.EncodeToString(hb)
	forgedSig, err := signLocally(token.AlgHS256, pubDER, []byte(parts[0]+"."+parts[1]))
	if err != nil {
		t.Fatal(err)
	}
	parts[2] = base64.RawURLEncoding.EncodeToString(forgedSig)
	forged := strings.Join(parts, ".")

	res := f.engine.Authorize(forged, "read", "doc/1")
	t.Logf("attack=RSA->HMAC substitution with public-key bytes stage=%s reason=%s",
		res.Stage, res.Reason)
	if res.Allowed || res.Stage != StageToken || res.Reason != token.ReasonAlgSubstitution {
		t.Fatalf("substitution attack must yield TOKEN/ALG_SUBSTITUTION, got %+v", res)
	}

	// 对照组一：算法不在白名单 -> ALG_NOT_ALLOWED（ES256 未放行）
	esParts := strings.Split(good, ".")
	ehb, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": k.ID})
	esParts[0] = base64.RawURLEncoding.EncodeToString(ehb)
	res = f.engine.Authorize(strings.Join(esParts, "."), "read", "doc/1")
	t.Logf("control=ES256 not in allowlist stage=%s reason=%s", res.Stage, res.Reason)
	if res.Reason != token.ReasonAlgNotAllowed {
		t.Fatalf("control want ALG_NOT_ALLOWED, got %s", res.Reason)
	}

	// 对照组二：密钥类型对不上（把 RSA 令牌的 kid 指向 HMAC 密钥且保留 RS256）
	rsaParts := strings.Split(good, ".")
	rhb, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k-hmac"})
	rsaParts[0] = base64.RawURLEncoding.EncodeToString(rhb)
	res = f.engine.Authorize(strings.Join(rsaParts, "."), "read", "doc/1")
	t.Logf("control=RS256 header on HMAC key stage=%s reason=%s", res.Stage, res.Reason)
	if res.Reason != token.ReasonAlgSubstitution {
		t.Fatalf("HMAC key with RS256 header is also substitution, got %s", res.Reason)
	}
}

// TestPolicyReplayEndToEnd 线上策略升级后，历史判定仍可按当时版本号完整回放。
func TestPolicyReplayEndToEnd(t *testing.T) {
	f := newAsymmetricFixture(t)
	iss, _, ok := f.keys.IssuerForCurrent(f.now)
	if !ok {
		t.Fatal("no current key")
	}
	tok, err := iss.Issue(claimsFor("alice"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// 记录 v1 的判定
	original := f.engine.Authorize(tok, "read", "doc/1")
	if !original.Allowed || original.PolicyVersion != 1 {
		t.Fatalf("v1 decision: %+v", original)
	}
	t.Logf("step=original authorize v%d allowed=%v trace=%s",
		original.PolicyVersion, original.Allowed, original.Trace)

	// 发布 v2：同一输入改为拒绝
	n2 := f.policies.Publish([]policy.Policy{
		{ID: "deny-read", Effect: policy.EffectDeny, Roles: []string{"reader"},
			Actions: []string{"read"}, Resources: []string{"doc/1"}},
	})
	live := f.engine.Authorize(tok, "read", "doc/1")
	t.Logf("step=after v%d publish live allowed=%v trace=%s", n2, live.Allowed, live.Trace)
	if live.Allowed || live.PolicyVersion != 2 {
		t.Fatalf("live must follow v2 DENY, got %+v", live)
	}

	// 用当初的输入 + 版本号 1 回放：结论与依据必须和当初完全一致
	replayed, err := f.engine.Replay(tok, "read", "doc/1", 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("step=replay v1 allowed=%v version=%d trace=%s",
		replayed.Allowed, replayed.PolicyVersion, replayed.Trace)
	if !replayed.Allowed || replayed.PolicyVersion != 1 {
		t.Fatalf("replay v1 must reproduce PERMIT on version 1, got %+v", replayed)
	}
	if replayed.Trace.Decision != original.Trace.Decision ||
		replayed.Trace.Explanation != original.Trace.Explanation ||
		len(replayed.Trace.MatchedPermits) != len(original.Trace.MatchedPermits) ||
		replayed.Trace.MatchedPermits[0] != original.Trace.MatchedPermits[0] {
		t.Fatalf("replay evidence differs: %s vs %s", replayed.Trace, original.Trace)
	}

	if _, err := f.engine.Replay(tok, "read", "doc/1", 42); err == nil {
		t.Fatal("replay of nonexistent version must error")
	}
	t.Logf("step=replay v42 correctly errored")
}

// TestConcurrentAuthorizeAcrossRotation 跨算法族轮换 + 并发判定下结果稳定。
func TestConcurrentAuthorizeAcrossRotation(t *testing.T) {
	f := newAsymmetricFixture(t)
	legacy := issueLegacyHMAC(t)
	iss, _, _ := f.keys.IssuerForCurrent(f.now)
	rsaTok, err := iss.Issue(claimsFor("alice"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 24
	const rounds = 200
	var wg sync.WaitGroup
	bad := make(chan string, workers*rounds*2)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if r := f.engine.Authorize(legacy, "read", "doc/1"); !r.Allowed {
					bad <- "legacy token rejected during overlap"
				}
				if r := f.engine.Authorize(rsaTok, "read", "doc/1"); !r.Allowed {
					bad <- "RSA token rejected: " + string(r.Stage)
				}
			}
		}()
	}
	wg.Wait()
	close(bad)
	for msg := range bad {
		t.Fatal(msg)
	}
	t.Logf("%d workers x %d rounds: HMAC+RSA tokens stable across families", workers, rounds)
}
