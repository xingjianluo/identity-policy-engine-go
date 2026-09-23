// Package policy 实现基于角色（RBAC）与属性（ABAC）的访问策略判定，
// 采用不可变版本快照：策略更新前后同一输入的判定都可复现并追溯依据。
//
// 判定规则：
//   - 角色（任一命中）、动作（任一命中或为空）、资源（精确或 "*"）均匹配的规则为候选规则；
//   - 候选规则的属性条件按 AND 全部评估，任一不满足则该规则不生效，失败条件记录在依据中；
//   - 生效的 deny 规则永远优先于生效的 allow 规则（策略冲突 => deny_by_rule）；
//   - 存在候选规则但因条件不满足而无规则生效 => condition_failed；
//   - 没有任何候选规则 => no_matching_rule。
package policy

import (
	"errors"
	"sync"
	"sync/atomic"
)

// Effect 策略效果。
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Condition 单个属性条件：Subject/Resource/Env 属性的等值或不等比较。
type Condition struct {
	Source   string `json:"source"` // "subject" | "resource" | "env"
	Key      string `json:"key"`
	Operator string `json:"op"` // "eq" | "ne"
	Value    string `json:"value"`
}

// Rule 一条策略规则。
type Rule struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Effect     Effect      `json:"effect"`
	Roles      []string    `json:"roles"`    // 为空表示不限制角色
	Actions    []string    `json:"actions"`  // 为空表示匹配全部动作
	Resource   string      `json:"resource"` // 精确匹配，"*" 表示全部
	Conditions []Condition `json:"conditions"`
	Priority   int         `json:"priority"` // 仅用于溯源排序，不影响 deny 优先
}

// Decision 判定结论（可区分）。
type Decision string

const (
	DecisionAllow           Decision = "allow"
	DecisionDenyByRule      Decision = "deny_by_rule"
	DecisionNoMatchingRule  Decision = "no_matching_rule"
	DecisionConditionDenied Decision = "condition_failed"
)

// RuleTrace 判定依据中候选规则的评估情况。
type RuleTrace struct {
	RuleID          string     `json:"rule_id"`
	RuleName        string     `json:"rule_name"`
	Effect          Effect     `json:"effect"`
	Matched         bool       `json:"matched"` // 角色/动作/资源/条件是否全部满足
	FailedCondition *Condition `json:"failed_condition,omitempty"`
}

// Input 策略判定输入。
type Input struct {
	Subject       string            `json:"subject"`
	Roles         []string          `json:"roles"`
	SubjectAttrs  map[string]string `json:"subject_attrs"`
	Action        string            `json:"action"`
	Resource      string            `json:"resource"`
	ResourceAttrs map[string]string `json:"resource_attrs"`
	Env           map[string]string `json:"env"`
}

// Result 判定结果及可追溯依据。
type Result struct {
	Decision    Decision    `json:"decision"`
	Version     int64       `json:"version"`
	MatchedRule *RuleTrace  `json:"matched_rule,omitempty"`
	Evaluated   []RuleTrace `json:"evaluated"`
}

// Snapshot 某一版本的不可变策略集合。
type Snapshot struct {
	Version int64  `json:"version"`
	Rules   []Rule `json:"rules"`
}

// Engine 线程安全的策略引擎，当前版本原子切换，历史版本保留以供复现。
type Engine struct {
	current atomic.Pointer[Snapshot]
	mu      sync.RWMutex
	history map[int64]*Snapshot
}

// NewEngine 创建策略引擎，初始为 0 号空快照。
func NewEngine() *Engine {
	e := &Engine{history: make(map[int64]*Snapshot)}
	e.current.Store(&Snapshot{Version: 0, Rules: []Rule{}})
	e.history[0] = e.current.Load()
	return e
}

func cloneRules(in []Rule) []Rule {
	out := make([]Rule, len(in))
	for i, r := range in {
		r.Roles = cloneStringSlice(r.Roles)
		r.Actions = cloneStringSlice(r.Actions)
		if r.Conditions != nil {
			r.Conditions = append([]Condition(nil), r.Conditions...)
		}
		out[i] = r
	}
	return out
}

func cloneStringSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// Replace 以新规则集合生成新版本并原子切换，返回新版本号。
// 传入的切片会被深拷贝，调用方之后修改 rules 不会影响已发布快照。
func (e *Engine) Replace(rules []Rule) int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	version := e.current.Load().Version + 1
	snap := &Snapshot{Version: version, Rules: cloneRules(rules)}
	e.history[version] = snap
	e.current.Store(snap)
	return version
}

// SnapshotAt 返回指定版本快照（用于复现历史判定）；版本不存在时返回错误。
func (e *Engine) SnapshotAt(version int64) (*Snapshot, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	snap, ok := e.history[version]
	if !ok {
		return nil, errors.New("policy version not found")
	}
	return snap, nil
}

// Current 返回当前版本号。
func (e *Engine) Current() int64 {
	return e.current.Load().Version
}

// Evaluate 使用当前版本快照进行判定；deny 优先于 allow。
func (e *Engine) Evaluate(in Input) *Result {
	return EvaluateWith(e.current.Load(), in)
}

// EvaluateWith 使用指定版本快照进行判定（纯函数，结果可复现）。
func EvaluateWith(snap *Snapshot, in Input) *Result {
	res := &Result{Decision: DecisionNoMatchingRule, Version: snap.Version, Evaluated: []RuleTrace{}}

	var allowFired, denyFired *RuleTrace
	for i := range snap.Rules {
		r := &snap.Rules[i]
		if !structuralMatch(r, in) {
			continue
		}
		tr := RuleTrace{RuleID: r.ID, RuleName: r.Name, Effect: r.Effect, Matched: true}
		if failed := firstFailedCondition(r.Conditions, in); failed != nil {
			fc := *failed
			tr.Matched = false
			tr.FailedCondition = &fc
		}
		res.Evaluated = append(res.Evaluated, tr)
		if !tr.Matched {
			continue
		}
		if r.Effect == EffectDeny && denyFired == nil {
			denyFired = &res.Evaluated[len(res.Evaluated)-1]
		}
		if r.Effect == EffectAllow && allowFired == nil {
			allowFired = &res.Evaluated[len(res.Evaluated)-1]
		}
	}

	switch {
	case denyFired != nil:
		res.Decision = DecisionDenyByRule
		res.MatchedRule = denyFired
	case allowFired != nil:
		res.Decision = DecisionAllow
		res.MatchedRule = allowFired
	case len(res.Evaluated) > 0:
		res.Decision = DecisionConditionDenied
	}
	return res
}

func structuralMatch(r *Rule, in Input) bool {
	if !matchAny(r.Roles, in.Roles) {
		return false
	}
	if !matchAction(r.Actions, in.Action) {
		return false
	}
	if r.Resource != "*" && r.Resource != in.Resource {
		return false
	}
	return true
}

// matchAny 规则值为空表示不限制（通配）；否则要求输入至少命中其一，"*" 为通配项。
func matchAny(wanted, have []string) bool {
	if len(wanted) == 0 {
		return true
	}
	for _, w := range wanted {
		if w == "*" {
			return true
		}
		for _, h := range have {
			if w == h {
				return true
			}
		}
	}
	return false
}

func matchAction(wanted []string, action string) bool {
	if len(wanted) == 0 {
		return true
	}
	for _, w := range wanted {
		if w == "*" || w == action {
			return true
		}
	}
	return false
}

func firstFailedCondition(conds []Condition, in Input) *Condition {
	for i := range conds {
		c := &conds[i]
		attrs := map[string]string(nil)
		switch c.Source {
		case "subject":
			attrs = in.SubjectAttrs
		case "resource":
			attrs = in.ResourceAttrs
		case "env":
			attrs = in.Env
		}
		got := attrs[c.Key]
		switch c.Operator {
		case "eq":
			if got != c.Value {
				return c
			}
		case "ne":
			if got == c.Value {
				return c
			}
		default:
			// 不支持的操作符按条件不满足处理并留痕。
			return c
		}
	}
	return nil
}
