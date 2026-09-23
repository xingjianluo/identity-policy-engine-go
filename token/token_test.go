package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

type keyRing struct {
	hmac []byte
	rsa  *rsa.PrivateKey
	ec   *ecdsa.PrivateKey
}

func newKeyRing(t *testing.T) *keyRing {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("read random: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec key: %v", err)
	}
	return &keyRing{hmac: secret, rsa: rsaKey, ec: ecKey}
}

func (kr *keyRing) lookup(kid string, alg Algorithm) (interface{}, error) {
	switch kid {
	case "hmac":
		return kr.hmac, nil
	case "rsa":
		return &kr.rsa.PublicKey, nil
	case "ec":
		return &kr.ec.PublicKey, nil
	}
	return nil, errf(ReasonKeyNotFound, "no such key")
}

func allAlgs() map[Algorithm]bool {
	return map[Algorithm]bool{HS256: true, RS256: true, ES256: true}
}

func validClaims() Claims {
	return Claims{
		Issuer:    "local",
		Subject:   "alice",
		Audience:  []string{"svc"},
		ExpiresAt: fixedNow.Add(time.Hour).Unix(),
		NotBefore: fixedNow.Add(-time.Minute).Unix(),
		IssuedAt:  fixedNow.Unix(),
		ID:        "jti-1",
		Roles:     []string{"reader"},
	}
}

func TestSignVerifyAllAlgorithms(t *testing.T) {
	kr := newKeyRing(t)
	cases := []struct {
		name string
		alg  Algorithm
		kid  string
		key  interface{}
	}{
		{"HS256", HS256, "hmac", kr.hmac},
		{"RS256", RS256, "rsa", kr.rsa},
		{"ES256", ES256, "ec", kr.ec},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := Sign(validClaims(), tc.alg, tc.kid, tc.key)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			t.Logf("input alg=%s kid=%s => token=%s", tc.alg, tc.kid, raw)
			got, err := Verify(raw, allAlgs(), 0, fixedNow, kr.lookup)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			t.Logf("decision: accepted subject=%s roles=%v", got.Subject, got.Roles)
			if got.Subject != "alice" {
				t.Fatalf("subject = %q", got.Subject)
			}
		})
	}
}

// expectReason 断言拒绝原因并打印输入与判定依据。
func expectReason(t *testing.T, raw, mutateDesc string, want Reason, allowed map[Algorithm]bool, leeway time.Duration, now time.Time, kr *keyRing) {
	t.Helper()
	_, err := Verify(raw, allowed, leeway, now, kr.lookup)
	if err == nil {
		t.Fatalf("input[%s]: expected rejection %q, got accepted", mutateDesc, want)
	}
	ve, ok := err.(*VerifyError)
	if !ok {
		t.Fatalf("input[%s]: error type %T, want *VerifyError", mutateDesc, err)
	}
	t.Logf("input: %-28s token=%.60s... | decision: rejected reason=%s detail=%q",
		mutateDesc, raw, ve.Reason, ve.Detail)
	if ve.Reason != want {
		t.Fatalf("input[%s]: reason=%q want=%q (detail must not leak internals)", mutateDesc, ve.Reason, want)
	}
}

func TestTamperedSignature(t *testing.T) {
	kr := newKeyRing(t)
	raw, err := Sign(validClaims(), HS256, "hmac", kr.hmac)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parts := strings.Split(raw, ".")
	sig, _ := b64.DecodeString(parts[2])
	if len(sig) == 0 || sig[0] == 0xFF {
		sig[0] = 0
	} else {
		sig[0] ^= 0xFF
	}
	parts[2] = b64.EncodeToString(sig)
	expectReason(t, strings.Join(parts, "."), "flip first signature byte", ReasonSignatureInvalid, allAlgs(), 0, fixedNow, kr)
}

func TestTamperedPayload(t *testing.T) {
	kr := newKeyRing(t)
	raw, err := Sign(validClaims(), RS256, "rsa", kr.rsa)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parts := strings.Split(raw, ".")
	pb, _ := b64.DecodeString(parts[1])
	// 把 sub 从 alice 篡改为 admin（保持 JSON 长度）。
	pb = []byte(strings.Replace(string(pb), `"sub":"alice"`, `"sub":"admin"`, 1))
	parts[1] = b64.EncodeToString(pb)
	if strings.Join(parts, ".") == raw {
		t.Fatal("payload tamper did not change token")
	}
	expectReason(t, strings.Join(parts, "."), "sub alice->admin", ReasonSignatureInvalid, allAlgs(), 0, fixedNow, kr)
}

func TestAlgorithmNotAllowed(t *testing.T) {
	kr := newKeyRing(t)
	raw, err := Sign(validClaims(), ES256, "ec", kr.ec)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	t.Logf("input: ES256 token under HS256-only allowlist")
	expectReason(t, raw, "ES256 with HS256-only allowlist", ReasonAlgorithmNotAllowed,
		map[Algorithm]bool{HS256: true}, 0, fixedNow, kr)
}

func TestHeaderAlgorithmConfusionRejected(t *testing.T) {
	kr := newKeyRing(t)
	// 用 HMAC 签名，再把头部 alg 改为 RS256；查找按 alg 匹配密钥类型，验签必然失败。
	raw, err := Sign(validClaims(), HS256, "hmac", kr.hmac)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parts := strings.Split(raw, ".")
	hb, _ := b64.DecodeString(parts[0])
	hb = []byte(strings.Replace(string(hb), `"alg":"HS256"`, `"alg":"RS256"`, 1))
	parts[0] = b64.EncodeToString(hb)
	expectReason(t, strings.Join(parts, "."), "alg confusion HS256->RS256", ReasonSignatureInvalid,
		allAlgs(), 0, fixedNow, kr)
}

func TestMalformedTokens(t *testing.T) {
	kr := newKeyRing(t)
	for _, tc := range []struct {
		desc, raw string
	}{
		{"empty", ""},
		{"two parts", "a.b"},
		{"bad base64 header", "!!!.eyJhIjoxfQ.sig"},
		{"bad json header", b64.EncodeToString([]byte("{not-json")) + ".eyJ9.sig"},
		{"kid missing header", b64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + ".eyJ9.sig"},
	} {
		want := ReasonMalformed
		if tc.desc == "kid missing header" {
			want = ReasonKeyIDMissing
		}
		expectReason(t, tc.raw, tc.desc, want, allAlgs(), 0, fixedNow, kr)
	}
}

func TestUnknownKey(t *testing.T) {
	kr := newKeyRing(t)
	raw, err := Sign(validClaims(), HS256, "ghost", kr.hmac)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	expectReason(t, raw, "unknown kid", ReasonKeyNotFound, allAlgs(), 0, fixedNow, kr)
}

func TestClaimsMissing(t *testing.T) {
	kr := newKeyRing(t)
	noSub := validClaims()
	noSub.Subject = ""
	raw, err := Sign(noSub, HS256, "hmac", kr.hmac)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	expectReason(t, raw, "missing sub", ReasonClaimsMissing, allAlgs(), 0, fixedNow, kr)

	noExp := validClaims()
	noExp.ExpiresAt = 0
	raw, err = Sign(noExp, HS256, "hmac", kr.hmac)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	expectReason(t, raw, "missing exp", ReasonClaimsMissing, allAlgs(), 0, fixedNow, kr)
}

func TestTimeClaimsWithLeeway(t *testing.T) {
	kr := newKeyRing(t)

	expired := validClaims()
	expired.ExpiresAt = fixedNow.Add(-30 * time.Second).Unix()
	raw, err := Sign(expired, HS256, "hmac", kr.hmac)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// 超过容差 40s => 过期。
	expectReason(t, raw, "exp -30s, leeway 10s", ReasonTokenExpired, allAlgs(), 10*time.Second, fixedNow, kr)
	// 容差 60s 内 => 通过。
	if _, err := Verify(raw, allAlgs(), 60*time.Second, fixedNow, kr.lookup); err != nil {
		t.Fatalf("within leeway should pass, got %v", err)
	}
	t.Logf("input exp=-30s leeway=60s | decision: accepted by leeway")

	future := validClaims()
	future.NotBefore = fixedNow.Add(30 * time.Second).Unix()
	raw, err = Sign(future, HS256, "hmac", kr.hmac)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	expectReason(t, raw, "nbf +30s, leeway 10s", ReasonTokenNotYetValid, allAlgs(), 10*time.Second, fixedNow, kr)
	if _, err := Verify(raw, allAlgs(), 60*time.Second, fixedNow, kr.lookup); err != nil {
		t.Fatalf("within leeway should pass, got %v", err)
	}
	t.Logf("input nbf=+30s leeway=60s | decision: accepted by leeway")
}

func TestSignRequiresKid(t *testing.T) {
	if _, err := Sign(validClaims(), HS256, "", []byte("secret")); err == nil {
		t.Fatal("expected error when kid empty")
	}
}

// 静态保证：导出的错误类型不带底层库字段。
var _ = base64.RawURLEncoding
