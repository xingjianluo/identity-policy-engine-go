package token

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Algorithm 表示支持的签名算法（对称 HMAC、非对称 RSA/ECDSA）。
type Algorithm string

const (
	AlgHS256 Algorithm = "HS256"
	AlgHS384 Algorithm = "HS384"
	AlgHS512 Algorithm = "HS512"
)

// Claims 是令牌携带的声明集合。
type Claims struct {
	Subject   string
	SessionID string
	Roles     []string
	Attrs     map[string]string
	IssuedAt  time.Time
	NotBefore time.Time
	ExpiresAt time.Time
	KeyID     string
}

// claimsJSON 是 Claims 的序列化形态，必需字段用指针以检测缺失。
type claimsJSON struct {
	Subject   *string           `json:"sub"`
	SessionID *string           `json:"sid"`
	Roles     []string          `json:"roles,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	IssuedAt  *int64            `json:"iat"`
	NotBefore int64             `json:"nbf,omitempty"`
	ExpiresAt *int64            `json:"exp"`
	KeyID     string            `json:"kid,omitempty"`
}

// headerJSON 是令牌头部。
type headerJSON struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	KID string `json:"kid"`
}

// Issuer 负责签发令牌。alg 与 key 在构造时绑定，令牌头不接受外部指定算法。
type Issuer struct {
	alg Algorithm
	kid string
	key any
	now func() time.Time
}

// NewIssuer 构造 HMAC（HS256/HS384/HS512）签发器，兼容既有对称密钥用法。
func NewIssuer(alg Algorithm, kid string, secret []byte) *Issuer {
	return &Issuer{alg: alg, kid: kid, key: secret, now: time.Now}
}

// NewIssuerForKey 构造与任意算法族密钥材料绑定的签发器。
// 仅做轻量校验；具体密码学错误在签发时统一以普通错误返回。
func NewIssuerForKey(alg Algorithm, kid string, key any) *Issuer {
	return &Issuer{alg: alg, kid: kid, key: key, now: time.Now}
}

// Issue 签发一条令牌。iat/exp 由 Issuer 根据 ttl 填充。
func (i *Issuer) Issue(c Claims, ttl time.Duration) (string, error) {
	if !knownAlgorithm(i.alg) {
		return "", fmt.Errorf("unsupported algorithm %q", i.alg)
	}
	now := i.now()
	c.IssuedAt = now
	c.ExpiresAt = now.Add(ttl)
	c.KeyID = i.kid

	header := headerJSON{Alg: string(i.alg), Typ: "JWT", KID: i.kid}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	payload := claimsJSON{
		Subject:   &c.Subject,
		SessionID: &c.SessionID,
		Roles:     c.Roles,
		Attrs:     c.Attrs,
		IssuedAt:  unixPtr(c.IssuedAt),
		ExpiresAt: unixPtr(c.ExpiresAt),
		KeyID:     c.KeyID,
	}
	if !c.NotBefore.IsZero() {
		payload.NotBefore = c.NotBefore.Unix()
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	enc := base64.RawURLEncoding
	input := enc.EncodeToString(hb) + "." + enc.EncodeToString(pb)
	sig, err := sign(i.alg, i.key, []byte(input))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return input + "." + enc.EncodeToString(sig), nil
}

func unixPtr(t time.Time) *int64 { v := t.Unix(); return &v }

// Verifier 负责校验令牌。
type Verifier struct {
	allowed  map[Algorithm]bool
	resolver KeyResolver
	leeway   time.Duration
	now      func() time.Time
}

// NewVerifier 构造校验器：resolver 解析密钥，leeway 为时间容差，
// allowed 为允许接受的签名算法白名单（可用 AlgorithmsOfFamilies 按族配置）。
func NewVerifier(resolver KeyResolver, leeway time.Duration, allowed ...Algorithm) *Verifier {
	m := make(map[Algorithm]bool, len(allowed))
	for _, a := range allowed {
		m[a] = true
	}
	return &Verifier{allowed: m, resolver: resolver, leeway: leeway, now: time.Now}
}

// fail 构造对外错误，只暴露可区分原因，不透出底层错误细节。
func fail(r Reason, format string, args ...any) *Error {
	return &Error{Reason: r, Message: fmt.Sprintf(format, args...)}
}

// Verify 校验令牌并返回声明；失败时返回 *Error，原因彼此可区分。
//
// 关键的拒绝顺序（先于任何密码学运算）：
//  1. 头部算法不在白名单/不被支持  -> ALG_NOT_ALLOWED
//  2. 头部算法族与密钥注册算法族不一致 -> ALG_SUBSTITUTION（换算法伪造）
//  3. 密钥材料类型与算法对不上       -> KEY_TYPE_MISMATCH
//  4. 签名与内容确实不匹配           -> SIGNATURE_MISMATCH
func (v *Verifier) Verify(tok string) (Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return Claims{}, fail(ReasonMalformed, "token must have 3 segments, got %d", len(parts))
	}
	enc := base64.RawURLEncoding

	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return Claims{}, fail(ReasonMalformed, "header is not valid base64url")
	}
	var header headerJSON
	if err := json.Unmarshal(hb, &header); err != nil {
		return Claims{}, fail(ReasonMalformed, "header is not valid JSON")
	}

	alg := Algorithm(header.Alg)
	if !v.allowed[alg] || !knownAlgorithm(alg) {
		return Claims{}, fail(ReasonAlgNotAllowed, "algorithm %q is not allowed", header.Alg)
	}

	now := v.now()
	rk, ok := v.resolver.Resolve(header.KID, now)
	if !ok {
		return Claims{}, fail(ReasonUnknownKey, "no active key for kid %q", header.KID)
	}

	// 以“密钥注册时的算法族”为信任锚，拒绝头部算法跨族替换，
	// 例如 RS256 被改成 HS256、ES256 被改成 none 等。
	if familyFor(rk.Alg) != familyFor(alg) {
		return Claims{}, fail(ReasonAlgSubstitution,
			"token alg %q does not match registered key alg %q for kid %q",
			alg, rk.Alg, header.KID)
	}

	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return Claims{}, fail(ReasonMalformed, "signature is not valid base64url")
	}
	switch verr := verifySignature(alg, rk.Material, []byte(parts[0]+"."+parts[1]), sig); verr {
	case nil:
	case errKeyTypeMismatch:
		return Claims{}, fail(ReasonKeyTypeMismatch,
			"key material for kid %q cannot be used with alg %q", header.KID, alg)
	default:
		return Claims{}, fail(ReasonSignatureMismatch, "signature verification failed")
	}

	pb, err := enc.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fail(ReasonMalformed, "payload is not valid base64url")
	}
	var cj claimsJSON
	if err := json.Unmarshal(pb, &cj); err != nil {
		return Claims{}, fail(ReasonMalformed, "payload is not valid JSON")
	}

	// 必需声明缺失检查
	switch {
	case cj.Subject == nil || *cj.Subject == "":
		return Claims{}, fail(ReasonMissingClaim, "required claim %q is missing", "sub")
	case cj.SessionID == nil || *cj.SessionID == "":
		return Claims{}, fail(ReasonMissingClaim, "required claim %q is missing", "sid")
	case cj.IssuedAt == nil:
		return Claims{}, fail(ReasonMissingClaim, "required claim %q is missing", "iat")
	case cj.ExpiresAt == nil:
		return Claims{}, fail(ReasonMissingClaim, "required claim %q is missing", "exp")
	}

	exp := time.Unix(*cj.ExpiresAt, 0)
	if now.After(exp.Add(v.leeway)) {
		return Claims{}, fail(ReasonExpired, "token expired at %s (leeway %s)", exp.UTC(), v.leeway)
	}
	if cj.NotBefore != 0 {
		nbf := time.Unix(cj.NotBefore, 0)
		if now.Add(v.leeway).Before(nbf) {
			return Claims{}, fail(ReasonNotYetValid, "token not valid before %s (leeway %s)", nbf.UTC(), v.leeway)
		}
	}

	return Claims{
		Subject:   *cj.Subject,
		SessionID: *cj.SessionID,
		Roles:     cj.Roles,
		Attrs:     cj.Attrs,
		IssuedAt:  time.Unix(*cj.IssuedAt, 0),
		NotBefore: time.Unix(cj.NotBefore, 0),
		ExpiresAt: exp,
		KeyID:     cj.KeyID,
	}, nil
}
