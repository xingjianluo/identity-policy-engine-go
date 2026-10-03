package keys

import (
	"testing"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/token"
)

func TestGenerateKeyForAllFamilies(t *testing.T) {
	now := time.Now()
	algs := []token.Algorithm{
		token.AlgHS256, token.AlgHS384, token.AlgHS512,
		token.AlgRS256, token.AlgRS384, token.AlgRS512,
		token.AlgES256, token.AlgES384, token.AlgES512,
	}
	for _, alg := range algs {
		k, err := GenerateKey(string(alg), alg, now.Add(-time.Hour), now.Add(time.Hour))
		if err != nil {
			t.Fatalf("generate %s: %v", alg, err)
		}
		switch token.FamilyOf(alg) {
		case token.FamilyHMAC:
			if len(k.Material) == 0 || k.Signer != nil {
				t.Fatalf("%s: expected HMAC material", alg)
			}
		case token.FamilyRSA, token.FamilyECDSA:
			if k.Signer == nil || k.Public == nil || k.Material != nil {
				t.Fatalf("%s: expected asymmetric key pair", alg)
			}
		}
		if !k.Active(now) {
			t.Fatalf("%s key should be active right after generation", alg)
		}
		t.Logf("generated local key id=%s alg=%s family=%s active=true", k.ID, alg, token.FamilyOf(alg))
	}
}

func TestAsymmetricKeyRejectsWrongFamily(t *testing.T) {
	now := time.Now()
	rsaK, err := GenerateKey("rsa", token.AlgRS256, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// RSA 私钥冒充 ES256 / HS256 注册都必须失败
	if _, badErr := AsymmetricKey("bad-ec", token.AlgES256, rsaK.Signer, rsaK.Public, now, now.Add(time.Hour)); badErr == nil {
		t.Fatal("RSA key must not register as ES256")
	} else {
		t.Logf("register RSA key under ES256 -> rejected: %v", badErr)
	}
}

// TestCrossFamilyRotation 是本轮重点：HMAC 旧密钥与 RSA 新密钥属于不同算法族，
// 重叠窗口内两者都可解析；Current 自动选新族密钥；旧令牌验签不受影响。
func TestCrossFamilyRotation(t *testing.T) {
	now := time.Now()
	s := NewStore()

	old := HMACKey("k-hmac", token.AlgHS256, []byte("legacy-secret"),
		now.Add(-24*time.Hour), now.Add(time.Hour))
	rsaKey, err := GenerateKey("k-rsa", token.AlgRS256, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s.Add(old)
	s.Add(rsaKey)

	// 重叠窗口：两个算法族的密钥都可解析
	oldRK, ok := s.Resolve("k-hmac", now)
	if !ok || oldRK.Family != token.FamilyHMAC {
		t.Fatalf("legacy HMAC key must remain resolvable, got ok=%v family=%s", ok, oldRK.Family)
	}
	newRK, ok := s.Resolve("k-rsa", now)
	if !ok || newRK.Family != token.FamilyRSA {
		t.Fatalf("new RSA key must be resolvable, got ok=%v family=%s", ok, newRK.Family)
	}
	t.Logf("overlap window: legacy %s key and new %s key both active", oldRK.Family, newRK.Family)

	// 新签发自动走新密钥（NotBefore 更晚）
	cur, ok := s.Current(now)
	if !ok {
		t.Fatal("Current key missing")
	}
	t.Logf("current signing key id=%s alg=%s family=%s", cur.ID, cur.Alg, token.FamilyOf(cur.Alg))
	if cur.ID != "k-rsa" || token.FamilyOf(cur.Alg) != token.FamilyRSA {
		t.Fatalf("Current must select the new RSA key, got %s/%s", cur.ID, cur.Alg)
	}

	// IssuerForCurrent 应直接产出基于 RSA 的签发器
	iss, k, ok := s.IssuerForCurrent(now)
	if !ok || k.ID != "k-rsa" || iss == nil {
		t.Fatal("IssuerForCurrent must bind to the RSA key")
	}
	tok, err := iss.Issue(token.Claims{Subject: "alice", SessionID: "s1"}, time.Hour)
	if err != nil {
		t.Fatalf("issue with current RSA key: %v", err)
	}
	// 用库里的公钥能验过（同源 resolver）
	verifier := token.NewVerifier(s, time.Minute, token.AlgHS256, token.AlgRS256)
	if _, err := verifier.Verify(tok); err != nil {
		t.Fatalf("RSA token issued from Current must verify: %v", err)
	}

	// 老 HMAC 令牌仍然能验过（存量兼容）
	legacyTok, err := token.NewIssuer(token.HMACKey(token.AlgHS256, "k-hmac", []byte("legacy-secret"))).
		WithKID("k-hmac").Issue(token.Claims{Subject: "bob", SessionID: "s2"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(legacyTok); err != nil {
		t.Fatalf("legacy HMAC token must verify during overlap: %v", err)
	}
	t.Logf("cross-family rotation: legacy HMAC token and fresh RSA token both verified")

	// 窗口结束后旧 HMAC 密钥不可解析，新 RSA 密钥照常
	after := now.Add(2 * time.Hour)
	if _, ok := s.Resolve("k-hmac", after); ok {
		t.Fatal("expired HMAC key must no longer resolve")
	}
	if _, ok := s.Resolve("k-rsa", after); !ok {
		t.Fatal("RSA key should still be active")
	}
	t.Logf("after overlap: HMAC key gone, RSA key still active")
}
