package policy

import (
	"fmt"
	"sync"
	"testing"
)

func readerInput() Input {
	return Input{
		Subject:       "alice",
		Roles:         []string{"reader"},
		SubjectAttrs:  map[string]string{"dept": "platform"},
		Action:        "read",
		Resource:      "doc:design",
		ResourceAttrs: map[string]string{"classification": "public"},
		Env:           map[string]string{"network": "corp"},
	}
}

func logResult(t *testing.T, tag string, in Input, r *Result) {
	t.Helper()
	t.Logf("input[%s] subject=%s roles=%v action=%s resource=%s resAttrs=%v env=%v",
		tag, in.Subject, in.Roles, in.Action, in.Resource, in.ResourceAttrs, in.Env)
	for _, tr := range r.Evaluated {
		failed := ""
		if tr.FailedCondition != nil {
			c := tr.FailedCondition
			failed = fmt.Sprintf(" failedAt=%s.%s %s %q", c.Source, c.Key, c.Operator, c.Value)
		}
		t.Logf("  basis: rule=%s effect=%s matched=%v%s", tr.RuleID, tr.Effect, tr.Matched, failed)
	}
	t.Logf("decision: v%d %s matchedRule=%v", r.Version, r.Decision,
		func() string {
			if r.MatchedRule != nil {
				return r.MatchedRule.RuleID
			}
			return "<none>"
		}())
}

func TestDenyOverridesAllowConflict(t *testing.T) {
	e := NewEngine()
	e.Replace([]Rule{
		{ID: "allow", Effect: EffectAllow, Roles: []string{"reader"}, Actions: []string{"read"}, Resource: "doc:design"},
		{ID: "deny", Effect: EffectDeny, Roles: []string{"reader"}, Actions: []string{"read"}, Resource: "doc:design"},
	})
	in := readerInput()
	r := e.Evaluate(in)
	logResult(t, "conflicting allow+deny", in, r)
	if r.Decision != DecisionDenyByRule || r.MatchedRule.RuleID != "deny" {
		t.Fatalf("decision=%s matched=%v, want deny_by_rule/deny", r.Decision, r.MatchedRule)
	}
}

func TestAllowPath(t *testing.T) {
	e := NewEngine()
	e.Replace([]Rule{
		{ID: "allow", Effect: EffectAllow, Roles: []string{"reader"}, Actions: []string{"read"}, Resource: "doc:design"},
	})
	in := readerInput()
	r := e.Evaluate(in)
	logResult(t, "simple allow", in, r)
	if r.Decision != DecisionAllow || r.MatchedRule.RuleID != "allow" {
		t.Fatalf("decision=%s", r.Decision)
	}
}

func TestNoMatchingRule(t *testing.T) {
	e := NewEngine()
	e.Replace([]Rule{
		{ID: "allow", Effect: EffectAllow, Roles: []string{"writer"}, Actions: []string{"write"}, Resource: "doc:design"},
	})
	in := readerInput()
	r := e.Evaluate(in)
	logResult(t, "no structural match", in, r)
	if r.Decision != DecisionNoMatchingRule || len(r.Evaluated) != 0 {
		t.Fatalf("decision=%s evaluated=%d", r.Decision, len(r.Evaluated))
	}
}

func TestConditionFailedIsDistinct(t *testing.T) {
	e := NewEngine()
	e.Replace([]Rule{
		{ID: "allow-on-corp", Effect: EffectAllow, Roles: []string{"reader"}, Actions: []string{"read"},
			Resource: "doc:design",
			Conditions: []Condition{
				{Source: "resource", Key: "classification", Operator: "eq", Value: "public"},
				{Source: "env", Key: "network", Operator: "eq", Value: "corp"},
			}},
	})
	in := readerInput()
	in.ResourceAttrs["classification"] = "secret" // 第一条条件失败
	r := e.Evaluate(in)
	logResult(t, "candidate rule condition fails", in, r)
	if r.Decision != DecisionConditionDenied {
		t.Fatalf("decision=%s want condition_failed", r.Decision)
	}
	if r.Evaluated[0].FailedCondition == nil ||
		r.Evaluated[0].FailedCondition.Key != "classification" {
		t.Fatal("failed condition must be recorded in trace")
	}
}

func TestConditionsEqAndNe(t *testing.T) {
	cases := []struct {
		name string
		op   string
		want Decision
	}{
		{"eq satisfied", "eq", DecisionAllow},
		{"ne satisfied", "ne", DecisionConditionDenied}, // classification == public => ne 失败
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine()
			e.Replace([]Rule{
				{ID: "r", Effect: EffectAllow, Roles: []string{"reader"}, Actions: []string{"read"},
					Resource: "doc:design",
					Conditions: []Condition{
						{Source: "resource", Key: "classification", Operator: tc.op, Value: "public"},
					}},
			})
			r := e.Evaluate(readerInput())
			if r.Decision != tc.want {
				t.Fatalf("op=%s decision=%s want=%s", tc.op, r.Decision, tc.want)
			}
		})
	}
}

func TestDenyRuleWithFailedConditionDoesNotDeny(t *testing.T) {
	e := NewEngine()
	e.Replace([]Rule{
		{ID: "allow", Effect: EffectAllow, Roles: []string{"reader"}, Actions: []string{"read"}, Resource: "*"},
		{ID: "deny-secret", Effect: EffectDeny, Roles: []string{"reader"}, Actions: []string{"read"}, Resource: "*",
			Conditions: []Condition{{Source: "resource", Key: "classification", Operator: "eq", Value: "secret"}}},
	})
	in := readerInput() // public => deny 条件不成立
	r := e.Evaluate(in)
	logResult(t, "deny rule present but condition false", in, r)
	if r.Decision != DecisionAllow {
		t.Fatalf("decision=%s want allow", r.Decision)
	}
}

func TestWildcardRoleAndActions(t *testing.T) {
	e := NewEngine()
	e.Replace([]Rule{
		{ID: "r", Effect: EffectAllow, Roles: nil, Actions: nil, Resource: "*"},
	})
	in := readerInput()
	in.Roles = []string{"anything"}
	r := e.Evaluate(in)
	if r.Decision != DecisionAllow {
		t.Fatalf("wildcard rule decision=%s", r.Decision)
	}
}

func TestVersionedSnapshotsReproducible(t *testing.T) {
	e := NewEngine()
	v1 := e.Replace([]Rule{
		{ID: "deny-all", Effect: EffectDeny, Roles: nil, Actions: nil, Resource: "*"},
	})
	in := readerInput()
	r1 := e.Evaluate(in)
	if r1.Decision != DecisionDenyByRule || r1.Version != v1 {
		t.Fatalf("v1 decision=%s", r1.Decision)
	}

	v2 := e.Replace([]Rule{
		{ID: "allow", Effect: EffectAllow, Roles: []string{"reader"}, Actions: []string{"read"}, Resource: "doc:design"},
	})
	r2 := e.Evaluate(in)
	logResult(t, "after Replace (v2)", in, r2)
	if r2.Decision != DecisionAllow || r2.Version != v2 {
		t.Fatalf("v2 decision=%s version=%d", r2.Decision, r2.Version)
	}

	// 用历史 v1 快照重放同一输入，结论必须与更新前一致。
	snap1, err := e.SnapshotAt(v1)
	if err != nil {
		t.Fatal(err)
	}
	r1again := EvaluateWith(snap1, in)
	if r1again.Decision != r1.Decision || r1again.Version != v1 {
		t.Fatalf("historical replay decision=%s want=%s", r1again.Decision, r1.Decision)
	}
	t.Logf("input replayed against v1 after update | decision: v%d %s (reproducible)",
		r1again.Version, r1again.Decision)
	if e.Current() != v2 {
		t.Fatalf("current=%d want=%d", e.Current(), v2)
	}
}

func TestReplaceDeepCopiesRules(t *testing.T) {
	e := NewEngine()
	rules := []Rule{
		{ID: "r", Effect: EffectAllow, Roles: []string{"reader"}, Actions: []string{"read"}, Resource: "doc:design"},
	}
	v := e.Replace(rules)
	// 发布后外部修改入参不得影响已发布快照。
	rules[0].Effect = EffectDeny
	rules[0].Roles[0] = "hacker"
	snap, err := e.SnapshotAt(v)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Rules[0].Effect != EffectAllow || snap.Rules[0].Roles[0] != "reader" {
		t.Fatal("published snapshot must be immutable against caller mutation")
	}
}

func TestSnapshotAtUnknownVersion(t *testing.T) {
	e := NewEngine()
	if _, err := e.SnapshotAt(999); err == nil {
		t.Fatal("unknown version must return error")
	}
}

func TestConcurrentEvaluateWhileReplacing(t *testing.T) {
	e := NewEngine()
	e.Replace([]Rule{{ID: "deny", Effect: EffectDeny, Roles: nil, Actions: nil, Resource: "*"}})

	var wg sync.WaitGroup
	const n = 32
	decisions := make([]map[Decision]int, n)
	start := make(chan struct{})
	for g := 0; g < n; g++ {
		wg.Add(1)
		decisions[g] = map[Decision]int{}
		go func(idx int) {
			defer wg.Done()
			<-start
			for i := 0; i < 500; i++ {
				r := e.Evaluate(readerInput())
				decisions[idx][r.Decision]++
			}
		}(g)
	}
	wg2 := sync.WaitGroup{}
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		<-start
		allow := []Rule{{ID: "allow", Effect: EffectAllow, Roles: []string{"reader"},
			Actions: []string{"read"}, Resource: "doc:design"}}
		deny := []Rule{{ID: "deny", Effect: EffectDeny, Roles: nil, Actions: nil, Resource: "*"}}
		for i := 0; i < 100; i++ {
			e.Replace(allow)
			e.Replace(deny)
		}
	}()
	close(start)
	wg.Wait()
	wg2.Wait()

	// 每次判定只能看到某一个完整版本：结论只可能是 allow 或 deny_by_rule，
	// 绝不可能出现半成品状态（no_matching_rule / condition_failed）。
	for g, m := range decisions {
		for d := range m {
			if d != DecisionAllow && d != DecisionDenyByRule {
				t.Fatalf("goroutine %d observed torn decision %s", g, d)
			}
		}
		t.Logf("worker %d decisions: allow=%d deny=%d", g, m[DecisionAllow], m[DecisionDenyByRule])
	}
}
