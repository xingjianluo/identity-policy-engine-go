package token

import "time"

// Algorithm 表示支持的签名算法。
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

// KeyResolver 按密钥 ID 查找签名密钥。
type KeyResolver interface {
	Resolve(kid string, at time.Time) (key []byte, ok bool)
}

// Issuer 负责签发令牌。
type Issuer struct {
	alg Algorithm
	kid string
	key []byte
	now func() time.Time
}

func NewIssuer(alg Algorithm, kid string, key []byte) *Issuer {
	return &Issuer{alg: alg, kid: kid, key: key, now: time.Now}
}

// Issue 签发一条令牌。
func (i *Issuer) Issue(c Claims, ttl time.Duration) (string, error) {
	return "", nil
}

// Verifier 负责校验令牌。
type Verifier struct {
	allowed  map[Algorithm]bool
	resolver KeyResolver
	leeway   time.Duration
	now      func() time.Time
}

func NewVerifier(resolver KeyResolver, leeway time.Duration, allowed ...Algorithm) *Verifier {
	m := make(map[Algorithm]bool, len(allowed))
	for _, a := range allowed {
		m[a] = true
	}
	return &Verifier{allowed: m, resolver: resolver, leeway: leeway, now: time.Now}
}

// Verify 校验令牌并返回声明；失败时返回 *Error，原因可区分。
func (v *Verifier) Verify(tok string) (Claims, error) {
	return Claims{}, nil
}
