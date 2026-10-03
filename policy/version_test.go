package policy

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// TestVersionedPublishAndReplay 验证：发布形成不可变版本，线上用最新版本，
// 拿着历史输入与版本号可以把当时的结论和依据完全一致地重算出来。
func TestVersionedPublishAndReplay(t *testing.T) {
	e := NewEngine()
	req := baseRequest() // alice / editor / read / doc/1 / dept=eng

	v1 := []Policy{
		{ID: "p1", Effect: EffectPermit, Roles: []string{"editor"},
			Actions: []string{"read"}, Resources: []string{"doc/1"}},
	}
	n1 := e.Publish(v1)
	if n1 != 1 || e.LatestVersion() != 1 {
		t.Fatalf("first publish: num=%d latest=%d", n1, e.LatestVersion())
	}

	// 发布后篡改调用方原切片，不影响已冻结版本
	v1[0].Effect = EffectDeny
	v1 = append(v1, Policy{ID: "injected"})

	tr1 := e.Evaluate(req)
	t.Logf("input=%+v live trace(v%d)=%s", req, tr1.Version, tr1)
	if tr1.Decision != DecisionPermit {
		t.Fatalf("v1 frozen policies must still PERMIT, got %s", tr1.Decision)
	}

	// 发布 v2：显式拒绝
	n2 := e.Publish([]Policy{
		{ID: "p2", Effect: EffectDeny, Roles: []string{"editor"},
			Actions: []string{"read"}, Resources: []string{"doc/1"}},
	})
	if e.LatestVersion() != 2 {
		t.Fatalf("latest = %d, want 2", e.LatestVersion())
	}
	tr2 := e.Evaluate(req)
	t.Logf("input=%+v live trace(v%d)=%s", req, tr2.Version, tr2)
	if tr2.Decision != DecisionDeny || tr2.Version != 2 {
		t.Fatalf("live evaluation must use v2 DENY, got v%d %s", tr2.Version, tr2.Decision)
	}

	// 发布 v3：改成条件不满足
	n3 := e.Publish([]Policy{
		{ID: "p3", Effect: EffectPermit, Roles: []string{"editor"},
			Actions: []string{"read"}, Resources: []string{"doc/1"},
			Condition: map[string]string{"dept": "finance"}},
	})

	// 用同一输入回放历史版本，结论与依据必须逐字段一致
	replay1, err := e.Replay(n1, req)
	if err != nil {
		t.Fatal(err)
	}
	if !tracesEqual(replay1, tr1) {
		t.Fatalf("replay v1=%+v differs from original=%+v", replay1, tr1)
	}
	t.Logf("replay v1: %s (matches original)", replay1)

	replay2, err := e.Replay(n2, req)
	if err != nil {
		t.Fatal(err)
	}
	if replay2.Decision != DecisionDeny || replay2.Version != 2 ||
		len(replay2.MatchedDenies) != 1 || replay2.MatchedDenies[0] != "p2" {
		t.Fatalf("replay v2 must reproduce DENY/p2, got %s", replay2)
	}
	t.Logf("replay v2: %s (matches original)", replay2)

	// 线上最新已是 v3，但 v1/v2 回放不受影响
	if live := e.Evaluate(req); live.Version != n3 || live.Decision != DecisionConditionFailed {
		t.Fatalf("latest must be v3 CONDITION_FAILED, got v%d %s", live.Version, live.Decision)
	}
	again1, _ := e.Replay(n1, req)
	if !tracesEqual(again1, replay1) {
		t.Fatal("replaying v1 twice must be identical")
	}
	t.Logf("live uses v3 while replay v1 stays PERMIT: versions are isolated")
}

// TestReplayUnknownVersion 未知版本号必须返回可识别的错误。
func TestReplayUnknownVersion(t *testing.T) {
	e := NewEngine()
	e.Publish(nil)
	_, err := e.Replay(99, baseRequest())
	if !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("want ErrUnknownVersion, got %v", err)
	}
	t.Logf("replay v99 -> %v", err)
}

// TestFrozenVersionExposesCopy 版本对外暴露的策略切片必须是拷贝。
func TestFrozenVersionExposesCopy(t *testing.T) {
	e := NewEngine()
	n := e.Publish([]Policy{{ID: "p1", Effect: EffectPermit,
		Roles: []string{"editor"}, Actions: []string{"read"},
		Resources: []string{"doc/*"}, Condition: map[string]string{"dept": "eng"}}})
	v, err := e.versionAt(n)
	if err != nil {
		t.Fatal(err)
	}
	ps := v.Policies()
	ps[0].ID = "mutated"
	again := v.Policies()
	if again[0].ID != "p1" {
		t.Fatal("mutating Policies() return must not affect frozen version")
	}
	t.Logf("frozen v%d policies remain immutable: %s", n, again[0].ID)
}

// TestConditionEvidenceOrderStable 多条件失败的依据顺序必须稳定可复现。
func TestConditionEvidenceOrderStable(t *testing.T) {
	e := NewEngine()
	e.Publish([]Policy{{ID: "p1", Effect: EffectPermit, Roles: []string{"editor"},
		Actions: []string{"read"}, Resources: []string{"doc/1"},
		Condition: map[string]string{"a": "1", "b": "2", "c": "3"}}})
	req := Request{Roles: []string{"editor"}, Action: "read", Resource: "doc/1"}
	first := e.Evaluate(req)
	for i := 0; i < 20; i++ {
		tr, _ := e.Replay(1, req)
		if !tracesEqual(tr, first) {
			t.Fatalf("iteration %d: trace %s != %s", i, tr, first)
		}
	}
	t.Logf("condition evidence stable across 20 replays: %v", first.ConditionFails)
}

// TestConcurrentPublishAndEvaluate 并发发布与并发判定混在一起时：
// 每次判定的 Trace 必须完整来自某一个版本，版本号自洽，不出现半新半旧。
func TestConcurrentPublishAndEvaluate(t *testing.T) {
	e := NewEngine()
	e.Publish([]Policy{{ID: "v1-allow", Effect: EffectPermit,
		Roles: []string{"editor"}, Actions: []string{"read"}, Resources: []string{"doc/1"}}})

	const publishers = 8
	const evaluators = 16
	const rounds = 300

	publish := func(version int64, eff Effect, id string) []Policy {
		return []Policy{{ID: id, Effect: eff,
			Roles: []string{"editor"}, Actions: []string{"read"}, Resources: []string{"doc/1"}}}
	}

	var wg sync.WaitGroup
	bad := make(chan string, publishers*rounds+evaluators*rounds)

	for p := 0; p < publishers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				var n int64
				if (p+r)%2 == 0 {
					n = e.Publish(publish(0, EffectPermit, fmt.Sprintf("pub-%d-%d", p, r)))
				} else {
					n = e.Publish(publish(0, EffectDeny, fmt.Sprintf("pub-%d-%d", p, r)))
				}
				if n < 1 || n > e.LatestVersion() {
					bad <- fmt.Sprintf("publisher %d round %d: nonsensical version %d", p, r, n)
				}
			}
		}(p)
	}

	req := baseRequest()
	for w := 0; w < evaluators; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				tr := e.Evaluate(req)
				// Trace 自洽性检查：版本号必须是已发布版本；
				// 依据策略 ID 必须与结论一致（同一发布内只有一条策略，且 ID 前缀可识别）。
				if tr.Version < 1 || tr.Version > e.LatestVersion() {
					bad <- fmt.Sprintf("evaluator %d: stale/impossible version %d", w, tr.Version)
					continue
				}
				switch tr.Decision {
				case DecisionPermit:
					if len(tr.MatchedPermits) != 1 || len(tr.MatchedDenies) != 0 {
						bad <- fmt.Sprintf("evaluator %d: PERMIT with mixed evidence v%d: %s", w, tr.Version, tr)
					}
				case DecisionDeny:
					if len(tr.MatchedDenies) != 1 || len(tr.MatchedPermits) != 0 {
						bad <- fmt.Sprintf("evaluator %d: DENY with mixed evidence v%d: %s", w, tr.Version, tr)
					}
				default:
					bad <- fmt.Sprintf("evaluator %d: unexpected decision %s v%d", w, tr.Decision, tr.Version)
				}
			}
		}(w)
	}
	wg.Wait()
	close(bad)
	for msg := range bad {
		t.Fatal(msg)
	}
	t.Logf("%d publishers + %d evaluators x %d rounds: every trace came from a single coherent version",
		publishers, evaluators, rounds)
}

func tracesEqual(a, b Trace) bool {
	if a.Version != b.Version || a.Decision != b.Decision || a.Explanation != b.Explanation {
		return false
	}
	return sameStrings(a.MatchedPermits, b.MatchedPermits) &&
		sameStrings(a.MatchedDenies, b.MatchedDenies) &&
		sameStrings(a.ConditionFails, b.ConditionFails)
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
