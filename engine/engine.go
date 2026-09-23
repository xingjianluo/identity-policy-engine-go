// Package engine 组合令牌校验、密钥仓库、会话仓库与策略引擎，
// 对外提供统一的本地身份校验与访问策略判定接口。
//
// 判定链路（短路）：
//  1. 令牌结构/算法白名单/签名/时间声明校验；
//  2. 令牌 jti 对应会话的吊销与生命周期校验；
//  3. 基于会话身份的 RBAC+ABAC 策略判定。
//
// 任一环节失败都会返回可区分的阶段与原因码，且不暴露底层库错误。
package engine

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/keystore"
	"github.com/xingjianluo/identity-policy-engine-go/policy"
	"github.com/xingjianluo/identity-policy-engine-go/session"
	"github.com/xingjianluo/identity-policy-engine-go/token"
)

// Config 引擎配置。
type Config struct {
	AllowedAlgorithms map[token.Algorithm]bool
	Leeway            time.Duration // 令牌时间声明容差（exp/nbf）
	Issuer            string        // 非空时要求令牌 iss 与之相等
	Clock             func() time.Time
}

// AuthFailureReason 对外统一的拒绝阶段原因。
type AuthFailureReason string

const (
	ReasonTokenRejected AuthFailureReason = "token_rejected"
	ReasonSessionReject AuthFailureReason = "session_rejected"
	ReasonPolicyDenied  AuthFailureReason = "policy_denied"
)

// 校验阶段标识。
const (
	stageToken   = "token"
	stageSession = "session"
	stagePolicy  = "policy"
)

// AuthError 身份校验错误：阶段 + 可区分原因码，不含底层库错误信息。
type AuthError struct {
	Stage  string
	Reason string // token.Reason / session.Status
	Detail string
}

func (e *AuthError) Error() string { return e.Stage + "/" + e.Reason }

// Identity 校验通过后的身份信息。
type Identity struct {
	Subject string
	Roles   []string
	Attrs   map[string]string
	TokenID string
}

// AccessRequest 一次访问请求。
type AccessRequest struct {
	RawToken      string
	Action        string
	Resource      string
	ResourceAttrs map[string]string
	Env           map[string]string
}

// AccessResult 访问判定结果及完整依据链。
type AccessResult struct {
	Allowed bool
	Reason  AuthFailureReason
	Stage   string // 被拒绝的环节
	Code    string // 可区分的细粒度原因码（token.Reason / session.Status / policy.Decision）
	Detail  string
	Token   *token.Claims
	Session *session.Session
	Policy  *policy.Result
}

// Engine 身份与策略判定引擎门面。
type Engine struct {
	cfg      Config
	keys     *keystore.Store
	sessions *session.Store
	policies *policy.Engine
}

// New 创建引擎；未提供时钟时使用系统时钟，未配置算法白名单时默认允许全部三种算法。
func New(cfg Config, keys *keystore.Store, sessions *session.Store, policies *policy.Engine) *Engine {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.AllowedAlgorithms == nil {
		cfg.AllowedAlgorithms = map[token.Algorithm]bool{
			token.HS256: true,
			token.RS256: true,
			token.ES256: true,
		}
	}
	return &Engine{cfg: cfg, keys: keys, sessions: sessions, policies: policies}
}

// IssueToken 使用当前活跃密钥签发令牌并建立对应会话，返回令牌字符串。
// 令牌的 jti 即为会话 ID，会话过期时间与令牌 exp 对齐。
func (e *Engine) IssueToken(subject string, roles []string, attrs map[string]string, ttl time.Duration) (string, error) {
	now := e.cfg.Clock()
	k := e.keys.ActiveSigningKey(now)
	if k == nil {
		return "", &AuthError{Stage: stageToken, Reason: "no_active_key", Detail: "no active signing key"}
	}
	id, err := newTokenID()
	if err != nil {
		return "", &AuthError{Stage: stageToken, Reason: "internal_error", Detail: "could not issue token id"}
	}
	claims := token.Claims{
		Issuer:     e.cfg.Issuer,
		Subject:    subject,
		ExpiresAt:  now.Add(ttl).Unix(),
		IssuedAt:   now.Unix(),
		ID:         id,
		Roles:      append([]string(nil), roles...),
		Attributes: cloneAttrs(attrs),
	}
	raw, err := token.Sign(claims, k.Algorithm, k.ID, k.SigningKey)
	if err != nil {
		return "", &AuthError{Stage: stageToken, Reason: "signing_failed", Detail: "token signing failed"}
	}
	sess := session.Session{
		ID:        id,
		Subject:   subject,
		ExpiresAt: now.Add(ttl),
		Roles:     append([]string(nil), roles...),
		Attrs:     cloneAttrs(attrs),
		CreatedAt: now,
	}
	if err := e.sessions.Create(sess); err != nil {
		return "", &AuthError{Stage: stageSession, Reason: "create_failed", Detail: "session could not be created"}
	}
	return raw, nil
}

func newTokenID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func cloneAttrs(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Authenticate 仅做令牌 + 会话校验，返回身份或可区分的拒绝原因。
func (e *Engine) Authenticate(raw string) (*Identity, *AuthError) {
	now := e.cfg.Clock()
	claims, err := token.Verify(raw, e.cfg.AllowedAlgorithms, e.cfg.Leeway, now,
		func(kid string, alg token.Algorithm) (interface{}, error) {
			return e.keys.VerifyKey(kid, alg, now)
		})
	if err != nil {
		ve, ok := err.(*token.VerifyError)
		if !ok {
			return nil, &AuthError{Stage: stageToken, Reason: "internal_error", Detail: "token verification failed"}
		}
		return nil, &AuthError{Stage: stageToken, Reason: string(ve.Reason), Detail: ve.Detail}
	}
	if e.cfg.Issuer != "" && claims.Issuer != e.cfg.Issuer {
		return nil, &AuthError{Stage: stageToken, Reason: string(token.ReasonClaimsMissing), Detail: "issuer mismatch"}
	}

	sess, status := e.sessions.Check(claims.ID, now)
	if status != session.StatusValid {
		return nil, &AuthError{Stage: stageSession, Reason: string(status), Detail: "session is not usable"}
	}

	return &Identity{
		Subject: sess.Subject,
		Roles:   append([]string(nil), sess.Roles...),
		Attrs:   cloneAttrs(sess.Attrs),
		TokenID: sess.ID,
	}, nil
}

// Authorize 完成令牌、会话与策略的完整判定，返回带依据链的结果。
func (e *Engine) Authorize(req AccessRequest) *AccessResult {
	now := e.cfg.Clock()
	res := &AccessResult{}

	claims, terr := token.Verify(req.RawToken, e.cfg.AllowedAlgorithms, e.cfg.Leeway, now,
		func(kid string, alg token.Algorithm) (interface{}, error) {
			return e.keys.VerifyKey(kid, alg, now)
		})
	if terr != nil {
		ve, ok := terr.(*token.VerifyError)
		code, detail := "internal_error", "token verification failed"
		if ok {
			code, detail = string(ve.Reason), ve.Detail
		}
		res.Allowed, res.Reason, res.Stage, res.Code, res.Detail = false, ReasonTokenRejected, stageToken, code, detail
		return res
	}
	res.Token = claims
	if e.cfg.Issuer != "" && claims.Issuer != e.cfg.Issuer {
		res.Allowed, res.Reason, res.Stage, res.Code, res.Detail =
			false, ReasonTokenRejected, stageToken, string(token.ReasonClaimsMissing), "issuer mismatch"
		return res
	}

	sess, status := e.sessions.Check(claims.ID, now)
	if status != session.StatusValid {
		res.Session = sess
		res.Allowed, res.Reason, res.Stage, res.Code, res.Detail =
			false, ReasonSessionReject, stageSession, string(status), "session is not usable"
		return res
	}
	res.Session = sess

	in := policy.Input{
		Subject:       sess.Subject,
		Roles:         sess.Roles,
		SubjectAttrs:  sess.Attrs,
		Action:        req.Action,
		Resource:      req.Resource,
		ResourceAttrs: req.ResourceAttrs,
		Env:           req.Env,
	}
	pr := e.policies.Evaluate(in)
	res.Policy = pr
	if pr.Decision == policy.DecisionAllow {
		res.Allowed = true
		return res
	}
	res.Allowed = false
	res.Reason = ReasonPolicyDenied
	res.Stage = stagePolicy
	res.Code = string(pr.Decision)
	res.Detail = "policy decision: " + string(pr.Decision)
	return res
}

// Policies 暴露策略引擎以便外部发布/轮换策略。
func (e *Engine) Policies() *policy.Engine { return e.policies }

// Keys 暴露密钥仓库以便外部登记/轮换密钥。
func (e *Engine) Keys() *keystore.Store { return e.keys }

// Sessions 暴露会话仓库以便外部吊销会话。
func (e *Engine) Sessions() *session.Store { return e.sessions }
