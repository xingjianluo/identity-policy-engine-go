// Package policy 提供基于角色与属性的访问策略判定，
// 支持策略集的不可变版本化发布与按历史版本回放。
package policy

import (
	"errors"
	"fmt"
	"sort"
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
// Version 记录结论所依据的策略版本；同版本同输入回放必须得到完全相同的 Trace。
type Trace struct {
	Version        int64
	Decision       Decision
	MatchedPermits []string
	MatchedDenies  []string
	ConditionFails []string
	Explanation    string
}

func (t Trace) String() string {
	return fmt.Sprintf("version=%d decision=%s permits=%v denies=%v conditionFails=%v why=%s",
		t.Version, t.Decision, t.MatchedPermits, t.MatchedDenies, t.ConditionFails, t.Explanation)
}

// Version 是一次不可变的策略发布。发布后其中的策略切片不再变化，
// 历史回放永远依据当时冻结的那份拷贝。
type Version struct {
	Number    int64
	CreatedAt int64 // unix 秒，由发布方提供，便于演示排序
	policies  []Policy
}

// Policies 返回该版本冻结策略的深拷贝；调用方修改返回的策略
// （含角色/动作/资源切片与条件 map）不会影响版本本身或其他读取者。
func (v *Version) Policies() []Policy {
	return clonePolicies(v.policies)
}

// ErrUnknownVersion 表示回放时指定的版本号不存在。
var ErrUnknownVersion = errors.New("unknown policy version")

// Engine 是策略判定引擎，采用拒绝优先（deny-overrides）合成策略。
// 每次 Publish 都生成一个不可变版本；Evaluate 始终基于最新版本的
// 原子快照，并发发布与并发判定之间不会出现半新半旧的策略集。
type Engine struct {
	mu       sync.RWMutex
	versions []*Version
	latest   *Version // 指向 versions 最后一个元素；读取只解引用一次
	now      func() int64
}

func NewEngine() *Engine {
	return &Engine{now: func() int64 { return 0 }}
}

// cloneStrings 返回独立拷贝；入参为 nil 时保持 nil，语义不变。
func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	cp := make([]string, len(s))
	copy(cp, s)
	return cp
}

// clonePolicies 深拷贝策略（含所有切片与 map），冻结后调用方再修改
// 原切片或其中的角色/动作/资源/条件都不会影响已发布版本。
func clonePolicies(ps []Policy) []Policy {
	cp := make([]Policy, len(ps))
	copy(cp, ps)
	for i := range cp {
		cp[i].Roles = cloneStrings(cp[i].Roles)
		cp[i].Actions = cloneStrings(cp[i].Actions)
		cp[i].Resources = cloneStrings(cp[i].Resources)
		if cp[i].Condition != nil {
			c := make(map[string]string, len(cp[i].Condition))
			for k, v := range cp[i].Condition {
				c[k] = v
			}
			cp[i].Condition = c
		}
	}
	return cp
}

// Publish 发布一个不可变新版本，返回新版本号（从 1 开始单调递增）。
// 发布动作与版本切换在同一把写锁内完成，对读者而言要么看到旧版本、
// 要么看到完整新版本，不存在中间态。
func (e *Engine) Publish(ps []Policy) int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := int64(len(e.versions)) + 1
	v := &Version{Number: n, CreatedAt: e.now(), policies: clonePolicies(ps)}
	e.versions = append(e.versions, v)
	e.latest = v
	return n
}

// SetPolicies 原子替换策略集（等价于发布一个新版本），兼容旧用法。
func (e *Engine) SetPolicies(ps []Policy) { e.Publish(ps) }

// LatestVersion 返回当前最新版本号；从未发布时返回 0。
func (e *Engine) LatestVersion() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.latest == nil {
		return 0
	}
	return e.latest.Number
}

// snapshot 返回最新版本及其冻结策略。一次判定只解引用一次 latest，
// 因此整条依据链全部来自同一个版本，不会跨版本串依据。
func (e *Engine) snapshot() *Version {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.latest
}

// versionAt 按版本号取出不可变版本。
func (e *Engine) versionAt(n int64) (*Version, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if n < 1 || int(n) > len(e.versions) {
		return nil, fmt.Errorf("%w: %d", ErrUnknownVersion, n)
	}
	v := e.versions[n-1]
	if v == nil || v.Number != n {
		return nil, fmt.Errorf("%w: %d", ErrUnknownVersion, n)
	}
	return v, nil
}

// Replay 用指定历史版本对同一输入重新判定。
// 因为版本内容不可变、判定为纯函数，结论与依据与当时完全一致。
func (e *Engine) Replay(version int64, req Request) (Trace, error) {
	v, err := e.versionAt(version)
	if err != nil {
		return Trace{}, err
	}
	return evaluate(v, req), nil
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
// 条件按键名排序后判定，保证失败依据的顺序在回放间也完全稳定。
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

// Evaluate 始终对最新版本进行判定并返回带版本号与依据的结论。
func (e *Engine) Evaluate(req Request) Trace {
	return evaluate(e.snapshot(), req)
}

// evaluate 是纯函数：同一不可变版本 + 同一输入 => 完全相同的 Trace。
func evaluate(v *Version, req Request) Trace {
	trace := Trace{Decision: DecisionNoMatch}
	if v != nil {
		trace.Version = v.Number
	}
	roleActionMatched := false

	var policies []Policy
	if v != nil {
		policies = v.policies
	}

	for _, p := range policies {
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
