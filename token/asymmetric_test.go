package token

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// resolverWith 返回包含多把不同算法族密钥的解析器（注册值即验签公钥材料）。
func resolverWith(entries ...ResolvedKey) staticResolver {
	r := staticResolver{keys: map[string]ResolvedKey{}}
	for _, e := range entries {
		r.keys[e.KeyID] = e
	}
	return r
}

func asymmetricClaims() Claims {
	return Claims{Subject: "bob", SessionID: "s-rsa", Roles: []string{"reader"},
		Attrs: map[string]string{"dept": "eng"}}
}

func TestAsymmetricRoundTripAllAlgorithms(t *testing.T) {
	rsaKey, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	ec256, err := GenerateECDSAKey(AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	ec384, err := GenerateECDSAKey(AlgES384)
	if err != nil {
		t.Fatal(err)
	}
	ec521, err := GenerateECDSAKey(AlgES512)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		kid string
		alg Algorithm
		key any
		pub any
	}{
		{"rsa256", AlgRS256, rsaKey, &rsaKey.PublicKey},
		{"rsa384", AlgRS384, rsaKey, &rsaKey.PublicKey},
		{"rsa512", AlgRS512, rsaKey, &rsaKey.PublicKey},
		{"es256", AlgES256, ec256, &ec256.PublicKey},
		{"es384", AlgES384, ec384, &ec384.PublicKey},
		{"es512", AlgES512, ec521, &ec521.PublicKey},
	}
	for _, c := range cases {
		t.Run(string(c.alg), func(t *testing.T) {
			iss := NewIssuerForKey(c.alg, c.kid, c.key)
			tok, err := iss.Issue(asymmetricClaims(), time.Hour)
			if err != nil {
				t.Fatalf("issue %s: %v", c.alg, err)
			}
			v := NewVerifier(
				resolverWith(ResolvedKey{KeyID: c.kid, Alg: c.alg, Material: c.pub}),
				0, AllAlgorithms()...)
			claims, err := v.Verify(tok)
			if err != nil {
				t.Fatalf("verify %s: %v", c.alg, err)
			}
			t.Logf("alg=%s input=(asymmetric token) claims.sub=%s claims.kid=%s",
				c.alg, claims.Subject, claims.KeyID)
			if claims.Subject != "bob" || claims.KeyID != c.kid {
				t.Fatalf("unexpected claims for %s: %+v", c.alg, claims)
			}
		})
	}
}

// TestAlgSubstitutionRSAToHMAC 防住经典换算法攻击：攻击者拿到 RSA 公钥后，
// 把头部 alg 从 RS256 改成 HS256，并拿公钥字节当 HMAC 共享密钥伪造签名。
func TestAlgSubstitutionRSAToHMAC(t *testing.T) {
	rsaKey, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	// 正常用 RS256 签发
	iss := NewIssuerForKey(AlgRS256, "rsa1", rsaKey)
	tok, err := iss.Issue(asymmetricClaims(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")

	// 攻击者把头部 alg 改成 HS256，kid 不变（密钥库注册的仍是 RSA 密钥）
	header := headerJSON{Alg: "HS256", Typ: "JWT", KID: "rsa1"}
	hb, _ := json.Marshal(header)
	parts[0] = base64.RawURLEncoding.EncodeToString(hb)
	// 用 RSA 公钥的 DER 字节当 HMAC 密钥伪造签名（经典 alg-confusion 手法）
	pubDER, err := publicKeyDER(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	forgedInput := parts[0] + "." + parts[1]
	forgedSig, err := sign(AlgHS256, pubDER, []byte(forgedInput))
	if err != nil {
		t.Fatal(err)
	}
	parts[2] = base64.RawURLEncoding.EncodeToString(forgedSig)
	forged := strings.Join(parts, ".")

	// 校验器同时放行 HMAC 与 RSA 族，证明拒绝来自族不一致而非白名单
	v := NewVerifier(
		resolverWith(ResolvedKey{KeyID: "rsa1", Alg: AlgRS256, Material: &rsaKey.PublicKey}),
		0, AlgorithmsOfFamilies(FamilyHMAC, FamilyRSA, FamilyECDSA)...)
	_, err = v.Verify(forged)
	te, ok := err.(*Error)
	if !ok {
		t.Fatalf("want *Error, got %T", err)
	}
	t.Logf("input=(RS256->HS256 forged token) reason=%s msg=%s", te.Reason, te.Message)
	if te.Reason != ReasonAlgSubstitution {
		t.Fatalf("alg substitution must be rejected as ALG_SUBSTITUTION, got %s", te.Reason)
	}
}

// TestAlgSubstitutionECDSAToNone ECDSA 令牌头被改成 none：白名单先挡住，
// 与族不一致必须得到可区分结论。
func TestAlgSubstitutionECDSAToNone(t *testing.T) {
	ec, err := GenerateECDSAKey(AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	iss := NewIssuerForKey(AlgES256, "ec1", ec)
	tok, err := iss.Issue(asymmetricClaims(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	header := headerJSON{Alg: "none", Typ: "JWT", KID: "ec1"}
	hb, _ := json.Marshal(header)
	parts[0] = base64.RawURLEncoding.EncodeToString(hb)
	forged := strings.Join(parts, ".")

	v := NewVerifier(
		resolverWith(ResolvedKey{KeyID: "ec1", Alg: AlgES256, Material: &ec.PublicKey}),
		0, AllAlgorithms()...)
	_, err = v.Verify(forged)
	te := err.(*Error)
	t.Logf("input=(ES256->none forged token) reason=%s", te.Reason)
	if te.Reason != ReasonAlgNotAllowed {
		t.Fatalf("alg=none must be ALG_NOT_ALLOWED, got %s", te.Reason)
	}
}

// TestKeyTypeMismatchDistinctFromSubstitution：
// 族一致（头=RS256、注册 alg=RS256），但密钥材料被错配成 ECDSA 公钥，
// 必须得到 KEY_TYPE_MISMATCH，与换算法伪造、签名不匹配均不同。
func TestKeyTypeMismatchDistinctFromSubstitution(t *testing.T) {
	rsaKey, _ := GenerateRSAKey(2048)
	ecKey, _ := GenerateECDSAKey(AlgES256)

	iss := NewIssuerForKey(AlgRS256, "mix", rsaKey)
	tok, err := iss.Issue(asymmetricClaims(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// 注册 alg 仍是 RS256（族一致），但材料错放成 ECDSA 公钥
	v := NewVerifier(
		resolverWith(ResolvedKey{KeyID: "mix", Alg: AlgRS256, Material: &ecKey.PublicKey}),
		0, AllAlgorithms()...)
	_, err = v.Verify(tok)
	te := err.(*Error)
	t.Logf("input=(RS256 token, ECDSA public key configured) reason=%s", te.Reason)
	if te.Reason != ReasonKeyTypeMismatch {
		t.Fatalf("wrong material for family must be KEY_TYPE_MISMATCH, got %s", te.Reason)
	}
}

// TestAsymmetricSignatureMismatch：算法、族、密钥类型全对，但签名被篡改。
func TestAsymmetricSignatureMismatch(t *testing.T) {
	rsaKey, _ := GenerateRSAKey(2048)
	iss := NewIssuerForKey(AlgRS256, "rsa1", rsaKey)
	tok, err := iss.Issue(asymmetricClaims(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[0] ^= 0xFF // 翻转签名字节
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)

	v := NewVerifier(
		resolverWith(ResolvedKey{KeyID: "rsa1", Alg: AlgRS256, Material: &rsaKey.PublicKey}),
		0, AllAlgorithms()...)
	_, err = v.Verify(strings.Join(parts, "."))
	te := err.(*Error)
	t.Logf("input=(RS256 token, flipped signature byte) reason=%s", te.Reason)
	if te.Reason != ReasonSignatureMismatch {
		t.Fatalf("flipped signature must be SIGNATURE_MISMATCH, got %s", te.Reason)
	}
}

// TestRejectionReasonsRemainDistinct 新四类安全相关结论必须彼此可区分。
func TestRejectionReasonsRemainDistinct(t *testing.T) {
	reasons := []Reason{
		ReasonAlgNotAllowed, ReasonAlgSubstitution,
		ReasonKeyTypeMismatch, ReasonSignatureMismatch,
	}
	seen := map[Reason]bool{}
	for _, r := range reasons {
		if seen[r] {
			t.Fatalf("duplicate reason %q", r)
		}
		seen[r] = true
	}
	t.Logf("security-relevant distinct reasons: %v", reasons)
}
