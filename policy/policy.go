// Package policy 提供基于角色与属性的访问策略判定。
package policy

import (
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
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
	VersionNum     int // 本次判定依据的策略版本号（未发布时为 0）
	Decision       Decision
	MatchedPermits []string
	MatchedDenies  []string
	ConditionFails []string
	Explanation    string
}

func (t Trace) String() string {
	return fmt.Sprintf("version=%d decision=%s permits=%v denies=%v conditionFails=%v why=%s",
		t.VersionNum, t.Decision, t.MatchedPermits, t.MatchedDenies, t.ConditionFails, t.Explanation)
}

// snapshot 是一份不可变的策略快照：发布后任何路径都不再修改其切片。
// 引擎始终原子地整份替换快照，因此并发发布与判定混合时，每次判定看到的
// 都是某个完整版本，绝不会出现半新半旧的策略集。
type snapshot struct {
	version  int
	policies []Policy
}

// Engine 是策略判定引擎，采用拒绝优先（deny-overrides）合成策略。
// 当前策略集通过原子指针整份替换；每次发布形成不可变版本并永久保留，
// 支持按版本号做确定性历史回放。
type Engine struct {
	current atomic.Pointer[snapshot]
	// publishMu 把并发发布串行化；已发布版本此后只读，回放无需加锁。
	publishMu chan struct{}
	history   atomic.Pointer[[]*Version]
}

func NewEngine() *Engine {
	e := &Engine{publishMu: make(chan struct{}, 1)}
	hist := []*Version{}
	e.history.Store(&hist)
	return e
}

// clonePolicies 返回策略集的深拷贝（含切片与 map），隔离调用方后续修改。
func clonePolicies(ps []Policy) []Policy {
	cp := make([]Policy, len(ps))
	for i, p := range ps {
		c := p
		if p.Roles != nil {
			c.Roles = append([]string(nil), p.Roles...)
		}
		if p.Actions != nil {
			c.Actions = append([]string(nil), p.Actions...)
		}
		if p.Resources != nil {
			c.Resources = append([]string(nil), p.Resources...)
		}
		if p.Condition != nil {
			c.Condition = make(map[string]string, len(p.Condition))
			for k, v := range p.Condition {
				c.Condition[k] = v
			}
		}
		cp[i] = c
	}
	return cp
}

// SetPolicies 更新工作区策略集，但不发布版本（保持既有调用习惯）。
// 需要形成不可变版本时调用 Publish。
func (e *Engine) SetPolicies(ps []Policy) {
	cp := clonePolicies(ps)
	e.current.Store(&snapshot{version: 0, policies: cp})
}

// currentSnapshot 返回当前工作区快照；从未设置过策略时返回空快照。
func (e *Engine) currentSnapshot() *snapshot {
	cur := e.current.Load()
	if cur == nil {
		return &snapshot{}
	}
	return cur
}

// latestSnapshot 返回判定应使用的快照：优先最新已发布版本，否则当前工作区。
func (e *Engine) latestSnapshot() *snapshot {
	hist := *e.history.Load()
	if n := len(hist); n > 0 {
		v := hist[n-1]
		return &snapshot{version: v.Number, policies: v.policies}
	}
	return e.currentSnapshot()
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
// 条件键按字典序检查，保证 Trace.ConditionFails 的顺序确定可复现。
func conditionSatisfied(cond map[string]string, attrs map[string]string) (string, bool) {
	keys := make([]string, 0, len(cond))
	for k := range cond {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		got, ok := attrs[k]
		if !ok || got != cond[k] {
			return k, false
		}
	}
	return "", true
}

// evaluateOn 在给定快照上执行纯函数式判定，保证同快照同输入结果一致。
func evaluateOn(snap *snapshot, req Request) Trace {
	trace := Trace{VersionNum: snap.version, Decision: DecisionNoMatch}
	roleActionMatched := false

	for _, p := range snap.policies {
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

// Evaluate 始终在“最新已发布版本”上判定；若尚未发布过任何版本，
// 则在当前工作区（版本号 0）上判定。每次判定只读一个完整快照，
// 不会出现半新半旧的策略集或跨版本串用依据。
func (e *Engine) Evaluate(req Request) Trace {
	return evaluateOn(e.latestSnapshot(), req)
}
