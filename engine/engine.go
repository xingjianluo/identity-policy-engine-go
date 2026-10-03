// Package engine 组合令牌校验、会话检查与策略判定，提供统一入口，
// 并支持按历史策略版本回放当时的判定。
package engine

import (
	"fmt"

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
	Allowed       bool
	Stage         Stage
	Reason        token.Reason // 仅 StageToken 时有值
	PolicyVersion int64        // 仅 StagePolicy 时有值：判定所用策略版本
	Trace         policy.Trace // 仅 StagePolicy 时有值
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

// Authorize 依次执行令牌校验、会话检查与策略判定（始终使用最新策略版本）。
// 任一阶段失败即返回，结论与依据均可区分、可追溯。
func (e *Engine) Authorize(tok, action, resource string) Result {
	return e.authorize(tok, action, resource, 0)
}

// Replay 拿着历史输入与当时的策略版本号，把当时的策略判定重新算一遍。
// 令牌与会话只做与当时相同的前置校验；策略判定严格使用指定版本，
// 结论与依据和当初完全一致。版本不存在时返回错误，不给出判定结论。
func (e *Engine) Replay(tok, action, resource string, policyVersion int64) (Result, error) {
	if policyVersion < 1 {
		return Result{}, fmt.Errorf("%w: replay version %d", policy.ErrUnknownVersion, policyVersion)
	}
	// 先确认版本存在，避免未知版本被吞成一次普通判定。
	if _, err := e.policies.Replay(policyVersion, policy.Request{}); err != nil {
		return Result{}, err
	}
	return e.authorize(tok, action, resource, policyVersion), nil
}

func (e *Engine) authorize(tok, action, resource string, replayVersion int64) Result {
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

	req := policy.Request{
		Subject:  claims.Subject,
		Roles:    claims.Roles,
		Action:   action,
		Resource: resource,
		Attrs:    claims.Attrs,
	}

	var trace policy.Trace
	if replayVersion > 0 {
		// Replay 入口已确认版本存在，此处不会再返回错误。
		trace, _ = e.policies.Replay(replayVersion, req)
	} else {
		trace = e.policies.Evaluate(req)
	}
	return Result{
		Allowed:       trace.Decision == policy.DecisionPermit,
		Stage:         StagePolicy,
		PolicyVersion: trace.Version,
		Trace:         trace,
	}
}
