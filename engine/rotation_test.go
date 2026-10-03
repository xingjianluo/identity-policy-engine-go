package engine

import (
	"testing"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/keys"
	"github.com/xingjianluo/identity-policy-engine-go/token"
)

// issueWithCurrent 用密钥库中“当前最新密钥”签发令牌，模拟新签发自动走新密钥。
func issueWithCurrent(t *testing.T, ks *keys.Store) string {
	t.Helper()
	k, ok := ks.Current(time.Now())
	if !ok {
		t.Fatal("no current signing key")
	}
	iss := token.NewIssuerForKey(k.Alg, k.ID, k.Material)
	tok, err := iss.Issue(token.Claims{
		Subject: "alice", SessionID: "sess-1", Roles: []string{"reader"},
	}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestCrossFamilyRotationEndToEnd 老 HS256 令牌在 HMAC->RSA 轮换窗口内继续放行；
// 新签发自动走 RS256；换算法伪造在组合引擎入口被 ALG_SUBSTITUTION 拒绝。
func TestCrossFamilyRotationEndToEnd(t *testing.T) {
	f := newFixture(t)
	now := time.Now()

	// 存量：HS256 对称密钥签发的令牌（k1 窗口仍开放）
	legacy := f.issueToken(t, "k1", "secret-1")

	// 轮换到 RSA 族：加入 RS256 新密钥（NotBefore 最新），k1 保留宽限窗口
	rsaKey, err := token.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.keys.Add(keys.Key{ID: "rsa-1", Alg: token.AlgRS256, Material: rsaKey,
		NotBefore: now, NotAfter: now.Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}

	// 校验器需要同时放行 HMAC 与 RSA 两个族（既有夹具只放行 HS256，重建引擎）
	v := token.NewVerifier(f.keys, 30*time.Second,
		token.AlgorithmsOfFamilies(token.FamilyHMAC, token.FamilyRSA)...)
	f.engine = New(v, f.sessions, f.policies)

	// 1) 老令牌继续能验过，且策略判定通过
	if res := f.engine.Authorize(legacy, "read", "doc/1"); !res.Allowed {
		t.Fatalf("legacy HMAC token must survive cross-family rotation: %+v %s", res, res.Trace)
	}
	t.Logf("legacy HS256 token still accepted after RSA key added")

	// 2) 新签发自动选 RS256 密钥
	newTok := issueWithCurrent(t, f.keys)
	k, _ := f.keys.Current(now)
	if k.Alg != token.AlgRS256 || k.ID != "rsa-1" {
		t.Fatalf("current key = %s/%s, want rsa-1/RS256", k.ID, k.Alg)
	}
	if res := f.engine.Authorize(newTok, "read", "doc/1"); !res.Allowed {
		t.Fatalf("new RSA token must pass: %+v %s", res, res.Trace)
	}
	t.Logf("new issuance auto-selected %s/%s and passed", k.ID, k.Alg)

	// 3) 换算法伪造：把 RSA 令牌头 alg 改成 HS256（kid 仍指向 rsa-1）
	forged := forgeAlgHeader(t, newTok, "HS256")
	res := f.engine.Authorize(forged, "read", "doc/1")
	t.Logf("alg-substitution token at engine entry: stage=%s reason=%s", res.Stage, res.Reason)
	if res.Allowed || res.Stage != StageToken || res.Reason != token.ReasonAlgSubstitution {
		t.Fatalf("cross-family forged token must be ALG_SUBSTITUTION, got %+v", res)
	}

	// 4) 旧密钥到期/吊销后，老令牌以 UNKNOWN_KEY 拒绝；新 RSA 令牌不受影响
	f.keys.Retire("k1")
	if res := f.engine.Authorize(legacy, "read", "doc/1"); res.Allowed || res.Reason != token.ReasonUnknownKey {
		t.Fatalf("legacy token after k1 retired must be UNKNOWN_KEY, got %+v", res)
	}
	if res := f.engine.Authorize(newTok, "read", "doc/1"); !res.Allowed {
		t.Fatalf("RSA token must remain valid after old HMAC key retired: %+v", res)
	}
	t.Logf("after retiring HMAC key: legacy rejected UNKNOWN_KEY, RSA token still allowed")
}
