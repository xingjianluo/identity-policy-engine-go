package policy

import "testing"

// samplePolicies 构造一份各字段都非空的策略，便于逐字段篡改验证。
func samplePolicies() []Policy {
	return []Policy{{
		ID:        "p1",
		Effect:    EffectPermit,
		Roles:     []string{"editor"},
		Actions:   []string{"read"},
		Resources: []string{"doc/1"},
		Condition: map[string]string{"dept": "eng"},
	}}
}

// TestPublishDeepCopiesAllFields 发布后无论怎么改调用方手里的原始数据
// （切片元素、角色/动作/资源的底层数组、条件 map），已发布版本都不许动。
func TestPublishDeepCopiesAllFields(t *testing.T) {
	e := NewEngine()
	req := baseRequest()

	src := samplePolicies()
	n := e.Publish(src)
	before := e.Evaluate(req)
	if before.Decision != DecisionPermit {
		t.Fatalf("baseline must PERMIT, got %s", before.Decision)
	}

	// 1) 改顶层元素：Effect / ID
	src[0].Effect = EffectDeny
	src[0].ID = "mutated-id"

	// 2) 就地改角色/动作/资源切片底层数组里的元素
	src[0].Roles[0] = "admin"
	src[0].Actions[0] = "write"
	src[0].Resources[0] = "doc/999"

	// 3) 就地改条件 map 的键值
	src[0].Condition["dept"] = "finance"
	src[0].Condition["newkey"] = "newval"

	// 4) append 注入新策略（共享容量时也不能串入）
	src = append(src, Policy{ID: "injected", Effect: EffectDeny,
		Roles: []string{"*"}, Actions: []string{"*"}, Resources: []string{"*"}})

	after, err := e.Replay(n, req)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input=%+v version=%d trace-after-caller-mutation=%s", req, n, after)
	if after.Decision != DecisionPermit || after.Version != n ||
		len(after.MatchedPermits) != 1 || after.MatchedPermits[0] != "p1" {
		t.Fatalf("frozen v%d drifted after mutating publish input: %s", n, after)
	}
}

// TestPoliciesReturnIsIndependent 从版本读出的策略是独立一份：
// 改读出来的角色/动作/资源/条件，版本本身和后续读取都不受影响。
func TestPoliciesReturnIsIndependent(t *testing.T) {
	e := NewEngine()
	n := e.Publish(samplePolicies())
	v, err := e.versionAt(n)
	if err != nil {
		t.Fatal(err)
	}

	got := v.Policies()
	got[0].ID = "mutated"
	got[0].Roles[0] = "admin"
	got[0].Actions[0] = "write"
	got[0].Resources[0] = "doc/999"
	got[0].Condition["dept"] = "finance"
	got[0].Roles = append(got[0].Roles, "superuser")

	again := v.Policies()
	again[0].ID = "mutated-by-second-reader" // 第二个读取者改自己那份
	again[0].Roles[0] = "role-from-reader2"

	first := v.Policies()
	if first[0].ID != "p1" ||
		first[0].Roles[0] != "editor" || len(first[0].Roles) != 1 ||
		first[0].Actions[0] != "read" ||
		first[0].Resources[0] != "doc/1" ||
		first[0].Condition["dept"] != "eng" {
		t.Fatalf("frozen version got dirty via Policies() copies: %+v", first[0])
	}
	if _, ok := first[0].Condition["newkey"]; ok {
		t.Fatal("condition map must not gain keys from other readers")
	}

	// 判定结果依旧基于冻结版本
	tr, _ := e.Replay(n, baseRequest())
	t.Logf("version=%d policies remain pristine, trace=%s", n, tr)
	if tr.Decision != DecisionPermit || tr.MatchedPermits[0] != "p1" {
		t.Fatalf("evaluation must still use pristine frozen policies: %s", tr)
	}
}
