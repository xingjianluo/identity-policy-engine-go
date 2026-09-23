// Package policy 提供基于角色与属性的访问策略判定。
package policy

import "fmt"

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
	DecisionDeny            Decision = "DENY"             // 显式拒绝或拒绝优先
	DecisionNoMatch         Decision = "NO_MATCH"         // 缺少匹配策略
	DecisionConditionFailed Decision = "CONDITION_FAILED" // 角色匹配但属性条件不满足
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
type Engine struct {
	policies []Policy
}

func NewEngine() *Engine { return &Engine{} }

// SetPolicies 原子替换策略集，保证更新前后同一输入结论可复现。
func (e *Engine) SetPolicies(ps []Policy) {}

// Evaluate 对请求进行判定并返回带依据的结论。
func (e *Engine) Evaluate(req Request) Trace { return Trace{} }
