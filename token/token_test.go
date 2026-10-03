package token

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type staticResolver struct{ keys map[string]ResolvedKey }

func (r staticResolver) Resolve(kid string, _ time.Time) (ResolvedKey, bool) {
	k, ok := r.keys[kid]
	return k, ok
}

func hmacKey(kid string, alg Algorithm, secret string) ResolvedKey {
	return ResolvedKey{KeyID: kid, Alg: alg, Material: []byte(secret)}
}

func newTestVerifier() *Verifier {
	return NewVerifier(
		staticResolver{keys: map[string]ResolvedKey{
			"k1": hmacKey("k1", AlgHS256, "secret-1"),
		}},
		30*time.Second, AlgHS256, AlgHS384, AlgHS512)
}

func issueHS256(t *testing.T) string {
	t.Helper()
	iss := NewIssuer(AlgHS256, "k1", []byte("secret-1"))
	tok, err := iss.Issue(Claims{Subject: "alice", SessionID: "s1", Roles: []string{"admin"}}, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tok
}

func expectReason(t *testing.T, tok string, want Reason) {
	t.Helper()
	_, err := newTestVerifier().Verify(tok)
	if err == nil {
		t.Fatalf("expected rejection %s, got success", want)
	}
	te, ok := err.(*Error)
	if !ok {
		t.Fatalf("error type = %T, want *Error (底层错误不得直接透出)", err)
	}
	t.Logf("input=%.40s... reason=%s msg=%s", tok, te.Reason, te.Message)
	if te.Reason != want {
		t.Fatalf("reason = %s, want %s", te.Reason, want)
	}
}

func TestVerifyValidToken(t *testing.T) {
	tok := issueHS256(t)
	claims, err := newTestVerifier().Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Logf("input=valid token claims=%+v", claims)
	if claims.Subject != "alice" || claims.SessionID != "s1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestVerifyTamperedPayload(t *testing.T) {
	tok := issueHS256(t)
	parts := strings.Split(tok, ".")
	// 篡改 payload：把 subject 改成 mallory，但保留原签名
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	m["sub"] = "mallory"
	raw, _ := json.Marshal(m)
	parts[1] = base64.RawURLEncoding.EncodeToString(raw)
	expectReason(t, strings.Join(parts, "."), ReasonSignatureMismatch)
}

func TestVerifyTamperedSignature(t *testing.T) {
	tok := issueHS256(t)
	parts := strings.Split(tok, ".")
	parts[2] = base64.RawURLEncoding.EncodeToString([]byte("forged-signature"))
	expectReason(t, strings.Join(parts, "."), ReasonSignatureMismatch)
}

func TestVerifyMalformed(t *testing.T) {
	expectReason(t, "not-a-token", ReasonMalformed)
	expectReason(t, "a.b.c.d", ReasonMalformed)
	expectReason(t, "!!!.yyy.zzz", ReasonMalformed)
}

func TestVerifyAlgNotAllowed(t *testing.T) {
	// 构造 alg=none 的令牌
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"a","sid":"s","iat":1,"exp":9999999999}`))
	expectReason(t, header+"."+payload+".sig", ReasonAlgNotAllowed)

	// 只允许 HS256 的校验器拒绝 HS384 令牌
	iss := NewIssuer(AlgHS384, "k1", []byte("secret-1"))
	tok, err := iss.Issue(Claims{Subject: "a", SessionID: "s"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(staticResolver{keys: map[string]ResolvedKey{
		"k1": hmacKey("k1", AlgHS384, "secret-1"),
	}}, 0, AlgHS256)
	_, err = v.Verify(tok)
	te := err.(*Error)
	t.Logf("input=HS384 token, verifier allows HS256 only, reason=%s", te.Reason)
	if te.Reason != ReasonAlgNotAllowed {
		t.Fatalf("reason = %s, want %s", te.Reason, ReasonAlgNotAllowed)
	}
}

func TestVerifyUnknownKey(t *testing.T) {
	iss := NewIssuer(AlgHS256, "no-such-key", []byte("x"))
	tok, err := iss.Issue(Claims{Subject: "a", SessionID: "s"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	expectReason(t, tok, ReasonUnknownKey)
}

func TestVerifyExpired(t *testing.T) {
	iss := NewIssuer(AlgHS256, "k1", []byte("secret-1"))
	iss.now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	tok, err := iss.Issue(Claims{Subject: "a", SessionID: "s"}, time.Hour) // 1 小时前已过期
	if err != nil {
		t.Fatal(err)
	}
	expectReason(t, tok, ReasonExpired)
}

func TestVerifyExpiredWithinLeeway(t *testing.T) {
	iss := NewIssuer(AlgHS256, "k1", []byte("secret-1"))
	iss.now = func() time.Time { return time.Now().Add(-10 * time.Second) }
	tok, err := iss.Issue(Claims{Subject: "a", SessionID: "s"}, 5*time.Second) // 过期 5 秒，容差 30 秒
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newTestVerifier().Verify(tok); err != nil {
		t.Fatalf("token within leeway should pass: %v", err)
	}
	t.Logf("input=token expired 5s ago, leeway=30s, result=accepted")
}

func TestVerifyNotYetValid(t *testing.T) {
	iss := NewIssuer(AlgHS256, "k1", []byte("secret-1"))
	tok, err := iss.Issue(Claims{
		Subject: "a", SessionID: "s",
		NotBefore: time.Now().Add(time.Hour),
	}, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	expectReason(t, tok, ReasonNotYetValid)
}

func TestVerifyMissingClaim(t *testing.T) {
	// 手工构造缺少 sid 的令牌并用正确密钥签名
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"k1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"sub":"a","iat":1000,"exp":9999999999}`))
	input := header + "." + payload
	sig, err := sign(AlgHS256, []byte("secret-1"), []byte(input))
	if err != nil {
		t.Fatal(err)
	}
	tok := input + "." + base64.RawURLEncoding.EncodeToString(sig)
	expectReason(t, tok, ReasonMissingClaim)
}

func TestReasonsAreDistinct(t *testing.T) {
	reasons := []Reason{ReasonMalformed, ReasonAlgNotAllowed, ReasonUnknownKey,
		ReasonSignatureMismatch, ReasonExpired, ReasonNotYetValid, ReasonMissingClaim}
	seen := map[Reason]bool{}
	for _, r := range reasons {
		if seen[r] {
			t.Fatalf("duplicate reason %q", r)
		}
		seen[r] = true
	}
	t.Logf("distinct rejection reasons: %v", reasons)
}
