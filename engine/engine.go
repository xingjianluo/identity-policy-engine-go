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
	trace := e.policies.Evaluate(req)
	return Result{
		Allowed:       trace.Decision == policy.DecisionPermit,
		Stage:         StagePolicy,
		PolicyVersion: trace.Version,
		Trace:         trace,
	}
}

// Replay 拿着历史输入（原始令牌字符串）与当时的策略版本号，把当时的
// 策略结论与依据原样重算。
//
// 回放是取证/审计用途，不是实时授权，因此刻意不受当前时间影响：
//   - 只从令牌载荷还原当初的主体、角色与属性输入，不校验签名、
//     不解析密钥、不检查 exp/nbf——令牌如今已过期、未生效，或其签名
//     密钥已轮换/吊销，都不会改变回放结论；
//   - 不检查会话当前是否存在、已吊销或已过期；
//   - 策略判定严格使用指定的历史版本。
//
// 版本号不存在时返回包装了 policy.ErrUnknownVersion 的错误，
// 令牌结构无法解析时返回 *token.Error（Reason 可区分），
// 二者都不会伪装成一条判定结论。
func (e *Engine) Replay(tok, action, resource string, policyVersion int64) (Result, error) {
	claims, err := token.DecodeClaims(tok)
	if err != nil {
		return Result{}, err
	}
	req := policy.Request{
		Subject:  claims.Subject,
		Roles:    claims.Roles,
		Action:   action,
		Resource: resource,
		Attrs:    claims.Attrs,
	}
	return e.ReplayRequest(req, policyVersion)
}

// ReplayRequest 用调用方已留存的原始输入与版本号回放，语义同 Replay：
// 不做任何令牌/会话时效检查，仅在指定的不可变版本上重算策略结论。
// 适合当初输入不以令牌形式保存的场景。
func (e *Engine) ReplayRequest(req policy.Request, policyVersion int64) (Result, error) {
	if policyVersion < 1 {
		return Result{}, fmt.Errorf("%w: replay version %d", policy.ErrUnknownVersion, policyVersion)
	}
	// 先确认版本存在，避免未知版本被吞成一次普通判定。
	if _, err := e.policies.Replay(policyVersion, policy.Request{}); err != nil {
		return Result{}, err
	}
	// 版本已确认存在，此处不会再返回错误。
	trace, _ := e.policies.Replay(policyVersion, req)
	return Result{
		// 仅表示「当时那条策略结论是否放行」，不代表此刻的实时访问授权。
		Allowed:       trace.Decision == policy.DecisionPermit,
		Stage:         StagePolicy,
		PolicyVersion: trace.Version,
		Trace:         trace,
	}, nil
}
