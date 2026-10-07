// Package token 提供本地令牌的签发与校验能力。
package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

// Algorithm 表示令牌签名算法。
type Algorithm string

const (
	// 对称算法族 HMAC
	AlgHS256 Algorithm = "HS256"
	AlgHS384 Algorithm = "HS384"
	AlgHS512 Algorithm = "HS512"

	// 非对称算法族 RSA（PKCS#1 v1.5）
	AlgRS256 Algorithm = "RS256"
	AlgRS384 Algorithm = "RS384"
	AlgRS512 Algorithm = "RS512"

	// 非对称算法族 ECDSA（P-256/P-384/P-521，ASN.1 编码签名）
	AlgES256 Algorithm = "ES256"
	AlgES384 Algorithm = "ES384"
	AlgES512 Algorithm = "ES512"
)

// Family 表示算法族。算法族用于把头部算法与密钥绑定，
// 防止「拿到公钥后把非对称算法改写成对称算法」的伪造攻击。
type Family string

const (
	FamilyHMAC  Family = "HMAC"
	FamilyRSA   Family = "RSA"
	FamilyECDSA Family = "ECDSA"
)

// FamilyOf 返回算法所属的算法族；未知算法返回空串。
func FamilyOf(a Algorithm) Family {
	switch a {
	case AlgHS256, AlgHS384, AlgHS512:
		return FamilyHMAC
	case AlgRS256, AlgRS384, AlgRS512:
		return FamilyRSA
	case AlgES256, AlgES384, AlgES512:
		return FamilyECDSA
	default:
		return ""
	}
}

// hashFor 返回算法对应的哈希构造函数；未知算法返回 nil。
func hashFor(a Algorithm) func() hash.Hash {
	switch a {
	case AlgHS256, AlgRS256, AlgES256:
		return sha256.New
	case AlgHS384, AlgRS384, AlgES384:
		return sha512.New384
	case AlgHS512, AlgRS512, AlgES512:
		return sha512.New
	default:
		return nil
	}
}

// cryptoHashFor 返回算法对应的 crypto.Hash；未知算法返回 0。
func cryptoHashFor(a Algorithm) crypto.Hash {
	switch a {
	case AlgHS256, AlgRS256, AlgES256:
		return crypto.SHA256
	case AlgHS384, AlgRS384, AlgES384:
		return crypto.SHA384
	case AlgHS512, AlgRS512, AlgES512:
		return crypto.SHA512
	default:
		return 0
	}
}

// ResolvedKey 是密钥解析的结果：密钥材料 + 该密钥绑定的算法族。
// 解析接口本身不依赖任何密钥库实现，避免包循环。
type ResolvedKey struct {
	Algorithm Algorithm        // 密钥注册时声明的算法（与头部算法必须同族）
	Family    Family           // 密钥绑定的算法族
	HMAC      []byte           // Family == HMAC 时有效
	Signer    crypto.Signer    // 非对称私钥（签发侧）
	Public    crypto.PublicKey // 非对称公钥（校验侧可只提供它）
}

// publicKey 优先取显式公钥，其次取签发器的公钥。
func (rk ResolvedKey) publicKey() crypto.PublicKey {
	if rk.Public != nil {
		return rk.Public
	}
	if rk.Signer != nil {
		return rk.Signer.Public()
	}
	return nil
}

// KeyResolver 按密钥 ID 查找签名密钥（带算法族绑定）。
type KeyResolver interface {
	Resolve(kid string, at time.Time) (ResolvedKey, bool)
}

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

// Issuer 负责签发令牌。
type Issuer struct {
	alg    Algorithm
	kid    string
	signer crypto.Signer // 非对称私钥；HMAC 时为 nil
	hmac   []byte        // HMAC 密钥；非对称时为 nil
	now    func() time.Time
}

// NewIssuer 用解析后的密钥构造签发器。
func NewIssuer(rk ResolvedKey) *Issuer {
	i := &Issuer{alg: rk.Algorithm, kid: "", now: time.Now}
	if rk.Family == FamilyHMAC {
		i.hmac = rk.HMAC
	} else {
		i.signer = rk.Signer
	}
	return i
}

// WithKID 覆盖写入令牌头部/声明的密钥 ID。
func (i *Issuer) WithKID(kid string) *Issuer { i.kid = kid; return i }

// HMACKey 构造一个对称算法密钥。
func HMACKey(alg Algorithm, kid string, secret []byte) ResolvedKey {
	return ResolvedKey{Algorithm: alg, Family: FamilyHMAC, HMAC: secret}
}

var errKeyType = errors.New("key type mismatch")

// sign 用给定密钥对 input 计算签名；底层密码库错误不直接外抛。
func sign(alg Algorithm, rk ResolvedKey, input []byte) (sig []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			sig = nil
			err = fmt.Errorf("%w: signing panic", errKeyType)
		}
	}()
	hh := hashFor(alg)
	if hh == nil {
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
	switch FamilyOf(alg) {
	case FamilyHMAC:
		if rk.Family != FamilyHMAC || rk.HMAC == nil {
			return nil, fmt.Errorf("%w: %s requires an HMAC key", errKeyType, alg)
		}
		mac := hmac.New(hh, rk.HMAC)
		mac.Write(input)
		return mac.Sum(nil), nil
	case FamilyRSA:
		if rk.Family != FamilyRSA || rk.Signer == nil {
			return nil, fmt.Errorf("%w: %s requires an RSA private key", errKeyType, alg)
		}
		digest := hashSum(hh, input)
		if _, ok := rk.Signer.Public().(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("%w: %s requires an RSA key", errKeyType, alg)
		}
		s, e := rk.Signer.Sign(rand.Reader, digest, cryptoHashFor(alg))
		if e != nil {
			return nil, fmt.Errorf("rsa sign: %w", e)
		}
		return s, nil
	case FamilyECDSA:
		if rk.Family != FamilyECDSA || rk.Signer == nil {
			return nil, fmt.Errorf("%w: %s requires an ECDSA private key", errKeyType, alg)
		}
		if _, ok := rk.Signer.Public().(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("%w: %s requires an ECDSA key", errKeyType, alg)
		}
		digest := hashSum(hh, input)
		s, e := rk.Signer.Sign(rand.Reader, digest, cryptoHashFor(alg))
		if e != nil {
			return nil, fmt.Errorf("ecdsa sign: %w", e)
		}
		return s, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

func hashSum(h func() hash.Hash, input []byte) []byte {
	m := h()
	m.Write(input)
	return m.Sum(nil)
}

// Issue 签发一条令牌。iat/exp 由 Issuer 根据 ttl 填充。
func (i *Issuer) Issue(c Claims, ttl time.Duration) (string, error) {
	if hashFor(i.alg) == nil {
		return "", fmt.Errorf("unsupported algorithm %q", i.alg)
	}
	now := i.now()
	c.IssuedAt = now
	c.ExpiresAt = now.Add(ttl)
	c.KeyID = i.kid

	rk := ResolvedKey{Algorithm: i.alg, Family: FamilyOf(i.alg), HMAC: i.hmac, Signer: i.signer}

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
	sig, err := sign(i.alg, rk, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + enc.EncodeToString(sig), nil
}

func unixPtr(t time.Time) *int64 { v := t.Unix(); return &v }

// ParseUnverified 只做结构解析并提取声明，不校验签名、不检查时间、不查密钥。
// 它仅供历史回放/审计使用：回放要还原的是「当初那条输入」，
// 不应受当前时间、令牌时效或密钥轮换状态影响。
// 任何线上判定路径都必须使用 Verify，不得用本函数替代。
func ParseUnverified(tok string) (Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return Claims{}, fail(ReasonMalformed, "token must have 3 segments, got %d", len(parts))
	}
	enc := base64.RawURLEncoding
	pb, err := enc.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fail(ReasonMalformed, "payload is not valid base64url")
	}
	var cj claimsJSON
	if err := json.Unmarshal(pb, &cj); err != nil {
		return Claims{}, fail(ReasonMalformed, "payload is not valid JSON")
	}
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
	return Claims{
		Subject:   *cj.Subject,
		SessionID: *cj.SessionID,
		Roles:     cj.Roles,
		Attrs:     cj.Attrs,
		IssuedAt:  time.Unix(*cj.IssuedAt, 0),
		NotBefore: time.Unix(cj.NotBefore, 0),
		ExpiresAt: time.Unix(*cj.ExpiresAt, 0),
		KeyID:     cj.KeyID,
	}, nil
}

// Verifier 负责校验令牌。
type Verifier struct {
	allowed  map[Algorithm]bool
	families map[Family]bool // nil 表示不按族限制
	resolver KeyResolver
	leeway   time.Duration
	now      func() time.Time
}

// NewVerifier 构造校验器：resolver 解析密钥，leeway 为时间容差，
// allowed 为允许接受的签名算法白名单（精确到算法）。
func NewVerifier(resolver KeyResolver, leeway time.Duration, allowed ...Algorithm) *Verifier {
	m := make(map[Algorithm]bool, len(allowed))
	fams := map[Family]bool{}
	for _, a := range allowed {
		m[a] = true
		if f := FamilyOf(a); f != "" {
			fams[f] = true
		}
	}
	return &Verifier{allowed: m, families: fams, resolver: resolver, leeway: leeway, now: time.Now}
}

// fail 构造对外错误，只暴露可区分原因，不透出底层错误细节。
func fail(r Reason, format string, args ...any) *Error {
	return &Error{Reason: r, Message: fmt.Sprintf(format, args...)}
}

// Verify 校验令牌并返回声明；失败时返回 *Error，原因可区分。
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
	fam := FamilyOf(alg)
	// 1) 算法白名单：未知算法或未被配置放行，一律拒绝。
	if !v.allowed[alg] || hashFor(alg) == nil {
		return Claims{}, fail(ReasonAlgNotAllowed, "algorithm %q is not allowed", header.Alg)
	}

	now := v.now()
	rk, ok := v.resolver.Resolve(header.KID, now)
	if !ok {
		return Claims{}, fail(ReasonUnknownKey, "no active key for kid %q", header.KID)
	}

	// 2) 防换算法伪造：非对称算法被改写成对称算法（或对称被改写成非对称）。
	if rk.Family != fam {
		switch {
		case rk.Family != FamilyHMAC && fam == FamilyHMAC:
			return Claims{}, fail(ReasonAlgSubstitution,
				"header downgrades a %s key to symmetric algorithm %q", rk.Family, header.Alg)
		case rk.Family == FamilyHMAC && fam != FamilyHMAC:
			return Claims{}, fail(ReasonAlgSubstitution,
				"header upgrades an HMAC key to asymmetric algorithm %q", header.Alg)
		default:
			return Claims{}, fail(ReasonKeyAlgMismatch,
				"key family %s does not match algorithm family %s", rk.Family, fam)
		}
	}
	// 3) 同族但算法精确不匹配（如密钥是 RS256、头部写 RS512；或 P-256 配 ES384）。
	if rk.Algorithm != "" && rk.Algorithm != alg {
		return Claims{}, fail(ReasonKeyAlgMismatch,
			"key %q is bound to algorithm %q, but header says %q", header.KID, rk.Algorithm, header.Alg)
	}

	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return Claims{}, fail(ReasonMalformed, "signature is not valid base64url")
	}
	input := []byte(parts[0] + "." + parts[1])
	// 4) 签名确实不匹配（底层任何密码库报错都归一为此原因，不原样外抛）。
	if err := verifySignature(alg, rk, input, sig); err != nil {
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

// verifySignature 按算法族校验签名。任何失败（含密钥类型错误、底层库错误）
// 都返回普通 error，由上层统一归一为 SIGNATURE_MISMATCH。
func verifySignature(alg Algorithm, rk ResolvedKey, input, sig []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errKeyType
		}
	}()
	hh := hashFor(alg)
	if hh == nil {
		return errKeyType
	}
	switch fam := FamilyOf(alg); fam {
	case FamilyHMAC:
		if rk.Family != FamilyHMAC || rk.HMAC == nil {
			return errKeyType
		}
		mac := hmac.New(hh, rk.HMAC)
		mac.Write(input)
		expect := mac.Sum(nil)
		if !hmac.Equal(sig, expect) {
			return errors.New("hmac mismatch")
		}
		return nil
	case FamilyRSA:
		pub, ok := rk.publicKey().(*rsa.PublicKey)
		if rk.Family != FamilyRSA || !ok || pub == nil {
			return errKeyType
		}
		return rsa.VerifyPKCS1v15(pub, cryptoHashFor(alg), hashSum(hh, input), sig)
	case FamilyECDSA:
		pub, ok := rk.publicKey().(*ecdsa.PublicKey)
		if rk.Family != FamilyECDSA || !ok || pub == nil {
			return errKeyType
		}
		if !ecdsa.VerifyASN1(pub, hashSum(hh, input), sig) {
			return errors.New("ecdsa mismatch")
		}
		return nil
	default:
		return errKeyType
	}
}
