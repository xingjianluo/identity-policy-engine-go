package policy

import "testing"

// TestPublishDeepFreezesInput 发布后，调用方就地修改当初传入的
// 角色/动作/资源切片元素或条件 map 键值，已发布版本必须丝毫不受影响：
// 线上判定与历史回放的结论、命中策略与依据都保持原样。
func TestPublishDeepFreezesInput(t *testing.T) {
	e := NewEngine()
	req := baseRequest() // alice / editor / read / doc/1 / dept=eng

	roles := []string{"editor"}
	actions := []string{"read"}
	resources := []string{"doc/1"}
	cond := map[string]string{"dept": "eng"}
	input := []Policy{{
		ID: "p1", Effect: EffectPermit,
		Roles: roles, Actions: actions, Resources: resources,
		Condition: cond,
	}}
	n := e.Publish(input)

	before := e.Evaluate(req)
	t.Logf("input=%+v published v%d trace=%s", req, n, before)
	if before.Decision != DecisionPermit {
		t.Fatalf("baseline must be PERMIT, got %s", before)
	}

	// 调用方就地篡改当初传进去的那份数据：切片元素与条件键值全改。
	roles[0] = "nobody"
	actions[0] = "write"
	resources[0] = "doc/secret"
	cond["dept"] = "finance"
	cond["injected"] = "x"
	input[0].Effect = EffectDeny

	after := e.Evaluate(req)
	t.Logf("after mutating caller-held data: trace=%s", after)
	if !tracesEqual(after, before) {
		t.Fatalf("published version drifted after caller mutation:\n before=%s\n after=%s", before, after)
	}

	replay, err := e.Replay(n, req)
	if err != nil {
		t.Fatal(err)
	}
	if !tracesEqual(replay, before) {
		t.Fatalf("replay v%d drifted after caller mutation:\n before=%s\n replay=%s", n, before, replay)
	}
	t.Logf("replay v%d after caller mutation: %s (unchanged)", n, replay)
}

// TestReadCopyIsIndependent 把某个版本的策略读出来后，就地修改返回值里的
// 角色/动作/资源/条件，不能改脏版本本身，也不能影响别人再读、再回放。
func TestReadCopyIsIndependent(t *testing.T) {
	e := NewEngine()
	req := baseRequest()

	n := e.Publish([]Policy{{
		ID: "p1", Effect: EffectPermit,
		Roles: []string{"editor"}, Actions: []string{"read"}, Resources: []string{"doc/1"},
		Condition: map[string]string{"dept": "eng"},
	}})

	before := e.Evaluate(req)
	t.Logf("input=%+v published v%d trace=%s", req, n, before)

	v, err := e.versionAt(n)
	if err != nil {
		t.Fatal(err)
	}
	// 读出一份后往死里改：元素、追加、条件键值、效果全改。
	leaked := v.Policies()
	leaked[0].Roles[0] = "nobody"
	leaked[0].Actions[0] = "write"
	leaked[0].Resources[0] = "doc/secret"
	leaked[0].Condition["dept"] = "finance"
	leaked[0].Effect = EffectDeny
	leaked[0].ID = "forged"

	// 版本自己再读一份，必须是干净的。
	fresh := v.Policies()
	if fresh[0].ID != "p1" || fresh[0].Effect != EffectPermit ||
		fresh[0].Roles[0] != "editor" || fresh[0].Actions[0] != "read" ||
		fresh[0].Resources[0] != "doc/1" || fresh[0].Condition["dept"] != "eng" ||
		len(fresh[0].Condition) != 1 {
		t.Fatalf("mutating the read copy dirtied the version: %+v", fresh[0])
	}

	// 线上判定与历史回放都不受影响。
	after := e.Evaluate(req)
	if !tracesEqual(after, before) {
		t.Fatalf("live evaluation drifted after mutating read copy:\n before=%s\n after=%s", before, after)
	}
	replay, err := e.Replay(n, req)
	if err != nil {
		t.Fatal(err)
	}
	if !tracesEqual(replay, before) {
		t.Fatalf("replay v%d drifted after mutating read copy:\n before=%s\n replay=%s", n, before, replay)
	}
	t.Logf("replay v%d after mutating read copy: %s (unchanged)", n, replay)
}
