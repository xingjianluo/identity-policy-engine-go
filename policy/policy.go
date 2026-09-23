// Package policy 提供基于角色与属性的访问策略判定。
package policy

import (
	"fmt"
	"strings"
	"sync"
)

// Effect 表示策略效果。
type Effect string

const (
	EffectPermit Effect = "PERMIT"
	EffectDeny   Effect = "DENY"
)

// Decision 表示判定结论。
type Decision string

const (
	DecisionPermit          Decision = "PERMIT"
	DecisionDeny            Decision = "DENY"             // 显式拒绝（拒绝优先，含冲突场景）
	DecisionNoMatch         Decision = "NO_MATCH"         // 缺少匹配策略
	DecisionConditionFailed Decision = "CONDITION_FAILED" // 角色/动作/资源匹配但属性条件不满足
)

// Request 是一次访问请求。
type Request struct {
	Subject  string
	Roles    []string
	Action   string
	Resource string
	Attrs    map[string]string
}

// Policy 是一条策略规则。
type Policy struct {
	ID        string
	Effect    Effect
	Roles     []string          // 任一角色命中即可
	Actions   []string          // 支持 "*" 通配
	Resources []string          // 支持 "*" 通配
	Condition map[string]string // 请求属性需全部满足
}

// Trace 记录判定依据，保证结论可追溯。
type Trace struct {
	Decision       Decision
	MatchedPermits []string
	MatchedDenies  []string
	ConditionFails []string
	Explanation    string
}

func (t Trace) String() string {
	return fmt.Sprintf("decision=%s permits=%v denies=%v conditionFails=%v why=%s",
		t.Decision, t.MatchedPermits, t.MatchedDenies, t.ConditionFails, t.Explanation)
}

// Engine 是策略判定引擎，采用拒绝优先（deny-overrides）合成策略。
// 策略集通过写锁原子替换，同一输入在更新前后各自可复现。
type Engine struct {
	mu       sync.RWMutex
	policies []Policy
}

func NewEngine() *Engine { return &Engine{} }

// SetPolicies 原子替换策略集，保证更新前后同一输入结论可复现。
func (e *Engine) SetPolicies(ps []Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := make([]Policy, len(ps))
	copy(cp, ps)
	e.policies = cp
}

// snapshot 返回当前策略集的拷贝。
func (e *Engine) snapshot() []Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cp := make([]Policy, len(e.policies))
	copy(cp, e.policies)
	return cp
}

func matchAny(patterns []string, value string) bool {
	for _, p := range patterns {
		if p == "*" || p == value {
			return true
		}
	}
	return false
}

func matchRole(policyRoles, reqRoles []string) bool {
	for _, pr := range policyRoles {
		for _, rr := range reqRoles {
			if pr == "*" || pr == rr {
				return true
			}
		}
	}
	return false
}

// conditionSatisfied 检查请求属性是否满足策略条件的全部键值。
func conditionSatisfied(cond map[string]string, attrs map[string]string) (string, bool) {
	for k, want := range cond {
		got, ok := attrs[k]
		if !ok || got != want {
			return k, false
		}
	}
	return "", true
}

// Evaluate 对请求进行判定并返回带依据的结论。
// 合成规则：任一 DENY 命中即拒绝（拒绝优先，冲突时 DENY 胜出）；
// 否则任一 PERMIT 命中即允许；若仅因属性条件未满足则返回 CONDITION_FAILED；
// 完全无策略覆盖则返回 NO_MATCH。
func (e *Engine) Evaluate(req Request) Trace {
	trace := Trace{Decision: DecisionNoMatch}
	roleActionMatched := false

	for _, p := range e.snapshot() {
		if !matchRole(p.Roles, req.Roles) {
			continue
		}
		if !matchAny(p.Actions, req.Action) || !matchAny(p.Resources, req.Resource) {
			continue
		}
		roleActionMatched = true
		if missKey, ok := conditionSatisfied(p.Condition, req.Attrs); !ok {
			trace.ConditionFails = append(trace.ConditionFails,
				fmt.Sprintf("%s(attr %q)", p.ID, missKey))
			continue
		}
		if p.Effect == EffectDeny {
			trace.MatchedDenies = append(trace.MatchedDenies, p.ID)
		} else {
			trace.MatchedPermits = append(trace.MatchedPermits, p.ID)
		}
	}

	switch {
	case len(trace.MatchedDenies) > 0:
		trace.Decision = DecisionDeny
		if len(trace.MatchedPermits) > 0 {
			trace.Explanation = fmt.Sprintf(
				"conflict: deny policies %v override permit policies %v",
				trace.MatchedDenies, trace.MatchedPermits)
		} else {
			trace.Explanation = fmt.Sprintf("denied by policies %v", trace.MatchedDenies)
		}
	case len(trace.MatchedPermits) > 0:
		trace.Decision = DecisionPermit
		trace.Explanation = fmt.Sprintf("permitted by policies %v", trace.MatchedPermits)
	case roleActionMatched:
		trace.Decision = DecisionConditionFailed
		trace.Explanation = fmt.Sprintf(
			"role/action matched but attribute conditions failed: %s",
			strings.Join(trace.ConditionFails, ", "))
	default:
		trace.Decision = DecisionNoMatch
		trace.Explanation = "no policy covers this role/action/resource"
	}
	return trace
}
