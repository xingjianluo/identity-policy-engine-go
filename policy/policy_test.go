package policy

import (
	"testing"
)

func baseRequest() Request {
	return Request{
		Subject:  "alice",
		Roles:    []string{"editor"},
		Action:   "read",
		Resource: "doc/1",
		Attrs:    map[string]string{"dept": "eng"},
	}
}

func TestPermit(t *testing.T) {
	e := NewEngine()
	e.SetPolicies([]Policy{
		{ID: "p1", Effect: EffectPermit, Roles: []string{"editor"},
			Actions: []string{"read"}, Resources: []string{"doc/*", "doc/1"}},
	})
	tr := e.Evaluate(baseRequest())
	t.Logf("input=%+v trace=%s", baseRequest(), tr)
	if tr.Decision != DecisionPermit {
		t.Fatalf("decision = %s, want PERMIT", tr.Decision)
	}
}

func TestDenyOverridesPermitOnConflict(t *testing.T) {
	e := NewEngine()
	e.SetPolicies([]Policy{
		{ID: "permit-read", Effect: EffectPermit, Roles: []string{"editor"},
			Actions: []string{"read"}, Resources: []string{"doc/1"}},
		{ID: "deny-doc1", Effect: EffectDeny, Roles: []string{"editor"},
			Actions: []string{"read"}, Resources: []string{"doc/1"}},
	})
	tr := e.Evaluate(baseRequest())
	t.Logf("input=%+v trace=%s", baseRequest(), tr)
	if tr.Decision != DecisionDeny {
		t.Fatalf("conflict must resolve to DENY, got %s", tr.Decision)
	}
	if len(tr.MatchedDenies) == 0 || len(tr.MatchedPermits) == 0 {
		t.Fatalf("trace must record both sides of the conflict: %+v", tr)
	}
}

func TestNoMatch(t *testing.T) {
	e := NewEngine()
	e.SetPolicies([]Policy{
		{ID: "p1", Effect: EffectPermit, Roles: []string{"admin"},
			Actions: []string{"*"}, Resources: []string{"*"}},
	})
	req := baseRequest() // 角色 editor 不被任何策略覆盖
	tr := e.Evaluate(req)
	t.Logf("input=%+v trace=%s", req, tr)
	if tr.Decision != DecisionNoMatch {
		t.Fatalf("decision = %s, want NO_MATCH", tr.Decision)
	}
}

func TestConditionFailed(t *testing.T) {
	e := NewEngine()
	e.SetPolicies([]Policy{
		{ID: "p1", Effect: EffectPermit, Roles: []string{"editor"},
			Actions: []string{"read"}, Resources: []string{"doc/1"},
			Condition: map[string]string{"dept": "finance"}},
	})
	req := baseRequest() // dept=eng，不满足 finance 条件
	tr := e.Evaluate(req)
	t.Logf("input=%+v trace=%s", req, tr)
	if tr.Decision != DecisionConditionFailed {
		t.Fatalf("decision = %s, want CONDITION_FAILED", tr.Decision)
	}
	if len(tr.ConditionFails) == 0 {
		t.Fatal("trace must record which condition failed")
	}
}

func TestDecisionsAreDistinct(t *testing.T) {
	// 同一角色下三种否定结论必须可区分
	e := NewEngine()
	e.SetPolicies([]Policy{
		{ID: "deny-write", Effect: EffectDeny, Roles: []string{"editor"},
			Actions: []string{"write"}, Resources: []string{"*"}},
		{ID: "cond-read", Effect: EffectPermit, Roles: []string{"editor"},
			Actions: []string{"read"}, Resources: []string{"*"},
			Condition: map[string]string{"clearance": "high"}},
	})
	cases := []struct {
		name string
		req  Request
		want Decision
	}{
		{"deny", Request{Roles: []string{"editor"}, Action: "write", Resource: "x"}, DecisionDeny},
		{"condition", Request{Roles: []string{"editor"}, Action: "read", Resource: "x"}, DecisionConditionFailed},
		{"nomatch", Request{Roles: []string{"editor"}, Action: "delete", Resource: "x"}, DecisionNoMatch},
	}
	for _, c := range cases {
		tr := e.Evaluate(c.req)
		t.Logf("case=%s input=%+v trace=%s", c.name, c.req, tr)
		if tr.Decision != c.want {
			t.Fatalf("case %s: decision = %s, want %s", c.name, tr.Decision, c.want)
		}
	}
}

func TestReproducibleAcrossPolicyUpdates(t *testing.T) {
	e := NewEngine()
	req := baseRequest()

	v1 := []Policy{
		{ID: "p1", Effect: EffectPermit, Roles: []string{"editor"},
			Actions: []string{"read"}, Resources: []string{"doc/1"}},
	}
	e.SetPolicies(v1)
	first := e.Evaluate(req)
	again := e.Evaluate(req)
	if first.Decision != again.Decision || first.Explanation != again.Explanation {
		t.Fatal("same input under same policies must be reproducible")
	}
	t.Logf("policies v1: input=%+v trace=%s", req, first)

	// 更新策略集后，同一输入的新结论也必须稳定可复现
	v2 := []Policy{
		{ID: "p2", Effect: EffectDeny, Roles: []string{"editor"},
			Actions: []string{"read"}, Resources: []string{"doc/1"}},
	}
	e.SetPolicies(v2)
	updated := e.Evaluate(req)
	updatedAgain := e.Evaluate(req)
	t.Logf("policies v2: input=%+v trace=%s", req, updated)
	if updated.Decision != DecisionDeny {
		t.Fatalf("after update decision = %s, want DENY", updated.Decision)
	}
	if updated.Decision != updatedAgain.Decision {
		t.Fatal("decision after update must be reproducible")
	}
	if first.Decision == updated.Decision {
		t.Fatal("policy update must change the decision for this input")
	}
}

func TestWildcardMatching(t *testing.T) {
	e := NewEngine()
	e.SetPolicies([]Policy{
		{ID: "all", Effect: EffectPermit, Roles: []string{"*"},
			Actions: []string{"*"}, Resources: []string{"*"}},
	})
	tr := e.Evaluate(Request{Roles: []string{"nobody"}, Action: "anything", Resource: "anywhere"})
	t.Logf("wildcard policy trace=%s", tr)
	if tr.Decision != DecisionPermit {
		t.Fatalf("decision = %s, want PERMIT", tr.Decision)
	}
}
