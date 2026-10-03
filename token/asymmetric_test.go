package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// 生成测试用 RSA / ECDSA 私钥。
func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// verifyWith 用指定算法白名单与密钥表校验，返回拒绝原因或空串。
func verifyWith(t *testing.T, tok string, keys map[string]ResolvedKey, allowed ...Algorithm) (Claims, Reason) {
	t.Helper()
	claims, err := NewVerifier(staticResolver{keys: keys}, time.Minute, allowed...).Verify(tok)
	if err == nil {
		return claims, ReasonNone
	}
	te := err.(*Error)
	return Claims{}, te.Reason
}

func TestAsymmetricRoundTripRSA(t *testing.T) {
	priv := testRSAKey(t)
	for _, alg := range []Algorithm{AlgRS256, AlgRS384, AlgRS512} {
		rk := ResolvedKey{Algorithm: alg, Family: FamilyRSA, Signer: priv}
		iss := NewIssuer(rk).WithKID("rsa-1")
		tok, err := iss.Issue(Claims{Subject: "alice", SessionID: "s1",
			Roles: []string{"reader"}, Attrs: map[string]string{"dept": "eng"}}, time.Hour)
		if err != nil {
			t.Fatalf("%s issue: %v", alg, err)
		}
		// 校验方只持有公钥（模拟公开的验签材料）
		pubRK := ResolvedKey{Algorithm: alg, Family: FamilyRSA, Public: priv.Public().(*rsa.PublicKey)}
		claims, reason := verifyWith(t, tok, map[string]ResolvedKey{"rsa-1": pubRK}, alg)
		t.Logf("input=RSA token alg=%s reason=%q claims.sub=%s", alg, reason, claims.Subject)
		if reason != ReasonNone {
			t.Fatalf("%s verify failed: %s", alg, reason)
		}
		if claims.Subject != "alice" {
			t.Fatalf("%s unexpected claims: %+v", alg, claims)
		}
	}
}

func TestAsymmetricRoundTripECDSA(t *testing.T) {
	cases := []struct {
		alg   Algorithm
		curve elliptic.Curve
	}{
		{AlgES256, elliptic.P256()},
		{AlgES384, elliptic.P384()},
		{AlgES512, elliptic.P521()},
	}
	for _, c := range cases {
		priv := testECKey(t, c.curve)
		rk := ResolvedKey{Algorithm: c.alg, Family: FamilyECDSA, Signer: priv}
		tok, err := NewIssuer(rk).WithKID("ec-1").Issue(
			Claims{Subject: "bob", SessionID: "s2"}, time.Hour)
		if err != nil {
			t.Fatalf("%s issue: %v", c.alg, err)
		}
		pubRK := ResolvedKey{Algorithm: c.alg, Family: FamilyECDSA, Public: priv.Public().(*ecdsa.PublicKey)}
		claims, reason := verifyWith(t, tok, map[string]ResolvedKey{"ec-1": pubRK}, c.alg)
		t.Logf("input=ECDSA token alg=%s reason=%q claims.sub=%s", c.alg, reason, claims.Subject)
		if reason != ReasonNone {
			t.Fatalf("%s verify failed: %s", c.alg, reason)
		}
	}
}

func TestAsymmetricTamperedPayload(t *testing.T) {
	priv := testRSAKey(t)
	tok, err := NewIssuer(ResolvedKey{Algorithm: AlgRS256, Family: FamilyRSA, Signer: priv}).
		WithKID("rsa-1").Issue(Claims{Subject: "alice", SessionID: "s1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	m["sub"] = "mallory" // 改 payload 但保留原 RSA 签名
	raw, _ := json.Marshal(m)
	parts[1] = base64.RawURLEncoding.EncodeToString(raw)

	pubRK := ResolvedKey{Algorithm: AlgRS256, Family: FamilyRSA, Public: priv.Public().(*rsa.PublicKey)}
	_, reason := verifyWith(t, strings.Join(parts, "."),
		map[string]ResolvedKey{"rsa-1": pubRK}, AlgRS256)
	t.Logf("input=RSA token with tampered payload reason=%s", reason)
	if reason != ReasonSignatureMismatch {
		t.Fatalf("tampered RSA payload: reason=%s, want SIGNATURE_MISMATCH", reason)
	}
}

// 构造一条头部被改写的令牌（不重新签名）。
func rewriteHeader(t *testing.T, tok, alg string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	h := headerJSON{Alg: alg, Typ: "JWT", KID: "k-rsa"}
	hb, _ := json.Marshal(h)
	parts[0] = base64.RawURLEncoding.EncodeToString(hb)
	return strings.Join(parts, ".")
}

// TestAlgSubstitutionAttack 是本轮核心安全用例：
// 攻击者只拿到公钥（验签材料），把头部算法从 RS256 改成 HS256，
// 并把公钥字节当作 HMAC 密钥重新签名。必须被拒绝为 ALG_SUBSTITUTION，
// 且区别于 ALG_NOT_ALLOWED / KEY_ALG_MISMATCH / SIGNATURE_MISMATCH。
func TestAlgSubstitutionAttack(t *testing.T) {
	priv := testRSAKey(t)
	pub := priv.Public().(*rsa.PublicKey)

	// 原始合法 RS256 令牌
	original, err := NewIssuer(ResolvedKey{Algorithm: AlgRS256, Family: FamilyRSA, Signer: priv}).
		WithKID("k-rsa").Issue(Claims{Subject: "alice", SessionID: "s1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// 攻击一：只改头部 alg=HS256，保留 RSA 签名
	tamperedHeader := rewriteHeader(t, original, "HS256")
	pubRK := ResolvedKey{Algorithm: AlgRS256, Family: FamilyRSA, Public: pub}
	_, reason := verifyWith(t, tamperedHeader,
		map[string]ResolvedKey{"k-rsa": pubRK}, AlgRS256, AlgHS256)
	t.Logf("attack=header-only RS256->HS256 reason=%s", reason)
	if reason != ReasonAlgSubstitution {
		t.Fatalf("header-only substitution: reason=%s, want ALG_SUBSTITUTION", reason)
	}

	// 攻击二：改头部并按 DER 公钥字节当 HMAC 密钥重新伪造签名
	parts := strings.Split(tamperedHeader, ".")
	pubBytes, err := x509PublicKeyBytes(pub)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := sign(AlgHS256, HMACKey(AlgHS256, "k-rsa", pubBytes), []byte(parts[0]+"."+parts[1]))
	if err != nil {
		t.Fatal(err)
	}
	forgedTok := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(forged)
	_, reason = verifyWith(t, forgedTok,
		map[string]ResolvedKey{"k-rsa": pubRK}, AlgRS256, AlgHS256)
	t.Logf("attack=forged HMAC with RSA public-key bytes reason=%s", reason)
	if reason != ReasonAlgSubstitution {
		t.Fatalf("forged HMAC using public key: reason=%s, want ALG_SUBSTITUTION", reason)
	}

	// 反方向：HMAC 密钥被改写成 RS256，同样属于换算法伪造
	hmacTok := issueHS256(t) // kid=k1 的 HS256 令牌
	hmacParts := strings.Split(hmacTok, ".")
	hh := headerJSON{Alg: "RS256", Typ: "JWT", KID: "k1"}
	hb, _ := json.Marshal(hh)
	hmacParts[0] = base64.RawURLEncoding.EncodeToString(hb)
	_, reason = verifyWith(t, strings.Join(hmacParts, "."),
		map[string]ResolvedKey{"k1": HMACKey(AlgHS256, "k1", []byte("secret-1"))},
		AlgHS256, AlgRS256)
	t.Logf("attack=header-only HS256->RS256 reason=%s", reason)
	if reason != ReasonAlgSubstitution {
		t.Fatalf("HMAC->RSA substitution: reason=%s, want ALG_SUBSTITUTION", reason)
	}
}

// TestKeyAlgorithmMismatch 同族内算法/密钥类型对不上（但不是族间替换）：
// 必须以 KEY_ALG_MISMATCH 拒绝，区别于换算法伪造与签名不匹配。
func TestKeyAlgorithmMismatch(t *testing.T) {
	priv256 := testRSAKey(t)
	tok, err := NewIssuer(ResolvedKey{Algorithm: AlgRS256, Family: FamilyRSA, Signer: priv256}).
		WithKID("k-rsa").Issue(Claims{Subject: "a", SessionID: "s"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv256.Public().(*rsa.PublicKey)

	// 密钥库里这把钥匙绑定成 RS512，但令牌头写 RS256：同族不同算法
	wrongBound := ResolvedKey{Algorithm: AlgRS512, Family: FamilyRSA, Public: pub}
	_, reason := verifyWith(t, tok, map[string]ResolvedKey{"k-rsa": wrongBound}, AlgRS256, AlgRS512)
	t.Logf("input=RS256 token, key bound RS512 reason=%s", reason)
	if reason != ReasonKeyAlgMismatch {
		t.Fatalf("same-family alg mismatch: reason=%s, want KEY_ALG_MISMATCH", reason)
	}

	// 曲线对不上：ES256 头部 + P-384 密钥
	ec384 := testECKey(t, elliptic.P384())
	ecTok, err := NewIssuer(ResolvedKey{Algorithm: AlgES256, Family: FamilyECDSA,
		Signer: testECKey(t, elliptic.P256())}).WithKID("k-ec").
		Issue(Claims{Subject: "a", SessionID: "s"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ecPub := ResolvedKey{Algorithm: AlgES384, Family: FamilyECDSA,
		Public: ec384.Public().(*ecdsa.PublicKey)}
	_, reason = verifyWith(t, ecTok, map[string]ResolvedKey{"k-ec": ecPub}, AlgES256, AlgES384)
	t.Logf("input=ES256 token, P-384 key reason=%s", reason)
	if reason != ReasonKeyAlgMismatch {
		t.Fatalf("curve mismatch: reason=%s, want KEY_ALG_MISMATCH", reason)
	}
}

// TestAsymmetricAlgNotAllowed 白名单不放行非对称算法时，以 ALG_NOT_ALLOWED 拒绝。
func TestAsymmetricAlgNotAllowed(t *testing.T) {
	priv := testRSAKey(t)
	tok, err := NewIssuer(ResolvedKey{Algorithm: AlgRS256, Family: FamilyRSA, Signer: priv}).
		WithKID("k-rsa").Issue(Claims{Subject: "a", SessionID: "s"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// 只放行 HS 家族，且库中根本没有非对称密钥：应在白名单处即拒绝
	_, reason := verifyWith(t, tok, map[string]ResolvedKey{}, AlgHS256)
	t.Logf("input=RS256 token, verifier HS256-only reason=%s", reason)
	if reason != ReasonAlgNotAllowed {
		t.Fatalf("reason=%s, want ALG_NOT_ALLOWED", reason)
	}
}

// TestWrongPublicKeySignatureMismatch 算法族、密钥类型都对，但签名确实不是这把公钥签的。
func TestWrongPublicKeySignatureMismatch(t *testing.T) {
	signer := testRSAKey(t)
	other := testRSAKey(t)
	tok, err := NewIssuer(ResolvedKey{Algorithm: AlgRS256, Family: FamilyRSA, Signer: signer}).
		WithKID("k-rsa").Issue(Claims{Subject: "a", SessionID: "s"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	otherPub := ResolvedKey{Algorithm: AlgRS256, Family: FamilyRSA,
		Public: other.Public().(*rsa.PublicKey)}
	_, reason := verifyWith(t, tok, map[string]ResolvedKey{"k-rsa": otherPub}, AlgRS256)
	t.Logf("input=valid RS256 token verified with another public key reason=%s", reason)
	if reason != ReasonSignatureMismatch {
		t.Fatalf("wrong public key: reason=%s, want SIGNATURE_MISMATCH", reason)
	}
}

// TestRejectReasonsDistinguishable 四种拒绝结论必须彼此不同，且对外错误不透明。
func TestRejectReasonsDistinguishable(t *testing.T) {
	reasons := []Reason{ReasonAlgNotAllowed, ReasonAlgSubstitution,
		ReasonKeyAlgMismatch, ReasonSignatureMismatch}
	seen := map[Reason]bool{}
	for _, r := range reasons {
		if seen[r] {
			t.Fatalf("duplicate reason %q", r)
		}
		seen[r] = true
	}
	t.Logf("distinguishable rejections: %v", reasons)
}

// TestLegacyHMACStillVerifies 存量 HMAC 令牌在新增非对称支持后照常校验通过。
func TestLegacyHMACStillVerifies(t *testing.T) {
	tok := issueHS256(t)
	v := NewVerifier(staticResolver{keys: map[string]ResolvedKey{
		"k1": HMACKey(AlgHS256, "k1", []byte("secret-1")),
	}}, 30*time.Second, AlgHS256, AlgRS256, AlgES256) // 同时放行三个族
	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("legacy HMAC token must still verify: %v", err)
	}
	t.Logf("input=legacy HS256 token under mixed-family allowlist claims=%+v", claims)
}
