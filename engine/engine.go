// Package engine 组合令牌校验、会话检查与策略判定，提供统一入口。
package engine

import (
	"github.com/xingjianluo/identity-policy-engine-go/policy"
	"github.com/xingjianluo/identity-policy-engine-go/session"
	"github.com/xingjianluo/identity-policy-engine-go/token"
)

// Stage 表示判定失败的阶段。
type Stage string

const (
	StageOK      Stage = "OK"
	StageToken   Stage = "TOKEN"
	StageSession Stage = "SESSION"
	StagePolicy  Stage = "POLICY"
)

// Result 是一次完整判定的结果。
type Result struct {
	Allowed bool
	Stage   Stage
	Reason  token.Reason // 仅 StageToken 时有值
	Trace   policy.Trace // 仅 StagePolicy 时有值
}

// Engine 是身份校验与策略判定引擎。
type Engine struct {
	verifier *token.Verifier
	sessions *session.Store
	policies *policy.Engine
}

func New(v *token.Verifier, s *session.Store, p *policy.Engine) *Engine {
	return &Engine{verifier: v, sessions: s, policies: p}
}

// Authorize 依次执行令牌校验、会话检查与策略判定。
// 任一阶段失败即返回，结论与依据均可区分、可追溯。
func (e *Engine) Authorize(tok, action, resource string) Result {
	claims, err := e.verifier.Verify(tok)
	if err != nil {
		reason := token.ReasonMalformed
		if te, ok := err.(*token.Error); ok {
			reason = te.Reason
		}
		return Result{Allowed: false, Stage: StageToken, Reason: reason}
	}

	if !e.sessions.Valid(claims.SessionID) {
		return Result{Allowed: false, Stage: StageSession}
	}

	trace := e.policies.Evaluate(policy.Request{
		Subject:  claims.Subject,
		Roles:    claims.Roles,
		Action:   action,
		Resource: resource,
		Attrs:    claims.Attrs,
	})
	return Result{
		Allowed: trace.Decision == policy.DecisionPermit,
		Stage:   StagePolicy,
		Trace:   trace,
	}
}
