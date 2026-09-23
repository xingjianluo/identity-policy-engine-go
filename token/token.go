// Package token 实现仅依赖标准库的紧凑 JWT 风格令牌（JWS 结构）的签发与校验，
// 支持 HS256 / RS256 / ES256 三种签名算法。
//
// 令牌结构为 base64url(header).base64url(payload).base64url(signature)，
// 头部固定包含 alg / typ / kid。校验失败一律返回 *VerifyError，
// 其 Reason 字段给出可区分的拒绝原因，底层库错误不会透出到对外接口。
package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"
)

// Algorithm 令牌签名算法标识。
type Algorithm string

const (
	HS256 Algorithm = "HS256"
	RS256 Algorithm = "RS256"
	ES256 Algorithm = "ES256"
)

// Reason 令牌校验被拒绝的可区分原因。
type Reason string

const (
	ReasonMalformed           Reason = "token_malformed"
	ReasonAlgorithmNotAllowed Reason = "algorithm_not_allowed"
	ReasonKeyIDMissing        Reason = "kid_missing"
	ReasonKeyNotFound         Reason = "key_not_found"
	ReasonSignatureInvalid    Reason = "signature_invalid"
	ReasonClaimsMissing       Reason = "claims_missing"
	ReasonTokenExpired        Reason = "token_expired"
	ReasonTokenNotYetValid    Reason = "token_not_yet_valid"
)

// Claims 令牌中携带的声明。
type Claims struct {
	Issuer     string                 `json:"iss,omitempty"`
	Subject    string                 `json:"sub,omitempty"`
	Audience   []string               `json:"aud,omitempty"`
	ExpiresAt  int64                  `json:"exp,omitempty"`
	NotBefore  int64                  `json:"nbf,omitempty"`
	IssuedAt   int64                  `json:"iat,omitempty"`
	ID         string                 `json:"jti,omitempty"`
	Roles      []string               `json:"roles,omitempty"`
	Attributes map[string]string      `json:"attr,omitempty"`
	Extra      map[string]interface{} `json:"ext,omitempty"`
}

// header JWS 受保护头部。
type header struct {
	Alg Algorithm `json:"alg"`
	Typ string    `json:"typ"`
	Kid string    `json:"kid"`
}

// VerifyError 对外暴露的令牌校验错误，不夹带底层库错误信息。
type VerifyError struct {
	Reason Reason
	Detail string
}

func (e *VerifyError) Error() string {
	if e.Detail != "" {
		return string(e.Reason) + ": " + e.Detail
	}
	return string(e.Reason)
}

func errf(reason Reason, detail string) *VerifyError {
	return &VerifyError{Reason: reason, Detail: detail}
}

// KeyLookup 根据 kid 与 alg 查找可用的验签公钥/对称密钥。
type KeyLookup func(kid string, alg Algorithm) (interface{}, error)

var b64 = base64.RawURLEncoding

// Sign 使用指定算法与密钥对声明进行签名，kid 写入受保护头部。
// signingKey 的期望类型：HS256 -> []byte；RS256 -> *rsa.PrivateKey；
// ES256 -> *ecdsa.PrivateKey（P-256 曲线）。
func Sign(claims Claims, alg Algorithm, kid string, signingKey interface{}) (string, error) {
	if kid == "" {
		return "", errf(ReasonKeyIDMissing, "signing key id is required")
	}
	hdr := header{Alg: alg, Typ: "JWT", Kid: kid}
	hb, err := json.Marshal(&hdr)
	if err != nil {
		// 头部内容完全由本库构造，理论上不会失败；不透出底层错误。
		return "", errf(ReasonMalformed, "header encoding failed")
	}
	pb, err := json.Marshal(&claims)
	if err != nil {
		return "", errf(ReasonMalformed, "claims encoding failed")
	}
	signingInput := b64.EncodeToString(hb) + "." + b64.EncodeToString(pb)
	sig, err := sign(alg, signingKey, []byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64.EncodeToString(sig), nil
}

func sign(alg Algorithm, key interface{}, input []byte) ([]byte, error) {
	sum := sha256.Sum256(input)
	switch alg {
	case HS256:
		secret, ok := key.([]byte)
		if !ok || len(secret) == 0 {
			return nil, errf(ReasonSignatureInvalid, "invalid symmetric key")
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write(input)
		return mac.Sum(nil), nil
	case RS256:
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errf(ReasonSignatureInvalid, "invalid rsa private key")
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
		if err != nil {
			return nil, errf(ReasonSignatureInvalid, "rsa signing failed")
		}
		return sig, nil
	case ES256:
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok || priv.Curve.Params() == nil || priv.Curve.Params().Name != "P-256" {
			return nil, errf(ReasonSignatureInvalid, "invalid ecdsa p-256 private key")
		}
		r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
		if err != nil {
			return nil, errf(ReasonSignatureInvalid, "ecdsa signing failed")
		}
		return marshalECDSASignature(r, s, 32), nil
	default:
		return nil, errf(ReasonAlgorithmNotAllowed, "unsupported signing algorithm")
	}
}

func marshalECDSASignature(r, s *big.Int, size int) []byte {
	out := make([]byte, size*2)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[size-len(rb):size], rb)
	copy(out[2*size-len(sb):], sb)
	return out
}

// Verify 校验令牌结构、算法白名单、签名与时间类声明（含容差）。
// 任何失败都返回 *VerifyError，调用方可据 Reason 做区分处理。
func Verify(raw string, allowed map[Algorithm]bool, leeway time.Duration, now time.Time, lookup KeyLookup) (*Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, errf(ReasonMalformed, "token must have three non-empty parts")
	}

	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, errf(ReasonMalformed, "header is not valid base64url")
	}
	var hdr header
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, errf(ReasonMalformed, "header is not valid json")
	}
	if hdr.Alg == "" {
		return nil, errf(ReasonMalformed, "alg missing in header")
	}
	if !allowed[hdr.Alg] {
		return nil, errf(ReasonAlgorithmNotAllowed, "algorithm is not allowed")
	}
	if hdr.Kid == "" {
		return nil, errf(ReasonKeyIDMissing, "kid missing in header")
	}

	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, errf(ReasonMalformed, "payload is not valid base64url")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, errf(ReasonMalformed, "signature is not valid base64url")
	}

	key, err := lookup(hdr.Kid, hdr.Alg)
	if err != nil {
		var ve *VerifyError
		if errors.As(err, &ve) {
			return nil, ve
		}
		return nil, errf(ReasonKeyNotFound, "verification key unavailable")
	}

	signingInput := parts[0] + "." + parts[1]
	if !verifySignature(hdr.Alg, key, []byte(signingInput), sig) {
		return nil, errf(ReasonSignatureInvalid, "signature does not verify")
	}

	var claims Claims
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, errf(ReasonMalformed, "payload is not valid json")
	}
	if claims.Subject == "" || claims.ExpiresAt == 0 {
		return nil, errf(ReasonClaimsMissing, "sub and exp are required")
	}

	// nbf 优先于 exp 判定，保证两种时间问题可区分。
	if claims.NotBefore != 0 {
		if now.Add(leeway).Before(time.Unix(claims.NotBefore, 0)) {
			return nil, errf(ReasonTokenNotYetValid, "token not yet valid")
		}
	}
	if now.Add(-leeway).After(time.Unix(claims.ExpiresAt, 0)) {
		return nil, errf(ReasonTokenExpired, "token expired")
	}
	return &claims, nil
}

func verifySignature(alg Algorithm, key interface{}, input, sig []byte) bool {
	sum := sha256.Sum256(input)
	switch alg {
	case HS256:
		secret, ok := key.([]byte)
		if !ok {
			return false
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write(input)
		return hmac.Equal(sig, mac.Sum(nil))
	case RS256:
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) == nil
	case ES256:
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || pub.Curve.Params() == nil || pub.Curve.Params().Name != "P-256" || len(sig) != 64 {
			return false
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(pub, sum[:], r, s)
	default:
		return false
	}
}
