package policy

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func v1Policies() []Policy {
	return []Policy{
		{ID: "allow-read", Effect: EffectPermit, Roles: []string{"editor"},
			Actions: []string{"read"}, Resources: []string{"doc/1"}},
	}
}

func v2Policies() []Policy {
	return []Policy{
		// v2 收紧：同输入变成 DENY
		{ID: "deny-read", Effect: EffectDeny, Roles: []string{"editor"},
			Actions: []string{"read"}, Resources: []string{"doc/1"}},
	}
}

// TestHistoricalReplayMatchesOriginalDecision 发布 v1 后记录判定，
// 再发布结论相反的 v2；用原输入+版本号回放 v1，必须得到与当时完全一致的
// 结论、命中策略与依据链，且线上（最新版本）判定已切换为 v2 结论。
func TestHistoricalReplayMatchesOriginalDecision(t *testing.T) {
	e := NewEngine()
	req := baseRequest()

	e.SetPolicies(v1Policies())
	v1 := e.Publish()
	original := e.Evaluate(req) // 记录 v1 时的判定
	t.Logf("v1 live: version=%d input=%+v trace=%s", v1, req, original)
	if original.Decision != DecisionPermit || original.VersionNum != 1 {
		t.Fatalf("v1 decision = %s ver=%d", original.Decision, original.VersionNum)
	}

	e.SetPolicies(v2Policies())
	v2 := e.Publish()
	liveNow := e.Evaluate(req)
	t.Logf("v2 live: version=%d trace=%s", v2, liveNow)
	if liveNow.Decision != DecisionDeny || liveNow.VersionNum != 2 {
		t.Fatalf("latest publish must govern live decisions, got %s ver=%d",
			liveNow.Decision, liveNow.VersionNum)
	}

	// 回放 v1：结论与依据链必须和当时逐字段一致
	replayed, err := e.EvaluateVersion(v1, req)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("replay v%d: trace=%s", v1, replayed)
	if replayed.Decision != original.Decision {
		t.Fatalf("replayed decision %s != original %s", replayed.Decision, original.Decision)
	}
	if replayed.VersionNum != original.VersionNum || replayed.VersionNum != v1 {
		t.Fatalf("replayed version = %d, want %d", replayed.VersionNum, v1)
	}
	if !sameStringSlice(replayed.MatchedPermits, original.MatchedPermits) ||
		!sameStringSlice(replayed.MatchedDenies, original.MatchedDenies) ||
		!sameStringSlice(replayed.ConditionFails, original.ConditionFails) {
		t.Fatalf("replayed basis chain %+v != original %+v", replayed, original)
	}
	if replayed.Explanation != original.Explanation {
		t.Fatalf("replayed explanation %q != original %q",
			replayed.Explanation, original.Explanation)
	}
}

// TestReplayIsStableAcrossSubsequentPublishes 多次发布后反复回放任意历史版本，
// 结果始终一致。
func TestReplayIsStableAcrossSubsequentPublishes(t *testing.T) {
	e := NewEngine()
	req := baseRequest()

	e.SetPolicies(v1Policies())
	n1 := e.Publish()
	e.SetPolicies(v2Policies())
	n2 := e.Publish()
	e.SetPolicies(v1Policies())
	n3 := e.Publish()

	first, _ := e.EvaluateVersion(n1, req)
	for i := 0; i < 5; i++ {
		got, err := e.EvaluateVersion(n1, req)
		if err != nil || got.String() != first.String() {
			t.Fatalf("replay of v%d changed: %+v err=%v", n1, got, err)
		}
	}
	d2, _ := e.EvaluateVersion(n2, req)
	d3, _ := e.EvaluateVersion(n3, req)
	t.Logf("stable replay: v1=%s | v2=%s | v3(live)=%s", first, d2, d3)
	if d2.Decision != DecisionDeny || d3.Decision != DecisionPermit {
		t.Fatalf("historical versions mixed up: v2=%s v3=%s", d2.Decision, d3.Decision)
	}
	if e.CurrentVersion() != 3 {
		t.Fatalf("current version = %d, want 3", e.CurrentVersion())
	}
}

// TestVersionIsImmutable 发布后篡改调用方手里的切片，并通过 VersionAt 拿到的
// 策略做验证，历史版本内容不得受影响。
func TestVersionIsImmutable(t *testing.T) {
	e := NewEngine()
	ps := v1Policies()
	e.SetPolicies(ps)
	n := e.Publish()

	// 篡改 SetPolicies 的入参与 Publish 前的工作区来源
	ps[0].ID = "MUTATED-BY-CALLER"
	e.SetPolicies([]Policy{{ID: "workspace-only", Effect: EffectDeny,
		Roles: []string{"*"}, Actions: []string{"*"}, Resources: []string{"*"}}})

	v, ok := e.VersionAt(n)
	if !ok {
		t.Fatal("published version must be retrievable")
	}
	got := v.Policies()
	if len(got) != 1 || got[0].ID != "allow-read" {
		t.Fatalf("published version was mutated: %+v", got)
	}
	got[0].ID = "MUTATED-VIA-ACCESSOR"
	again, _ := e.VersionAt(n)
	if again.Policies()[0].ID != "allow-read" {
		t.Fatal("version content leaked through Policies() accessor")
	}

	tr, err := e.EvaluateVersion(n, baseRequest())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("immutable v%d replay after tampering: %s", n, tr)
	if tr.Decision != DecisionPermit {
		t.Fatalf("tampered surroundings changed historical result: %s", tr.Decision)
	}
}

func TestUnknownVersionReplay(t *testing.T) {
	e := NewEngine()
	_, err := e.EvaluateVersion(99, baseRequest())
	if !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("want ErrUnknownVersion, got %v", err)
	}
	t.Logf("replay v99 rejected: %v", err)
}

// TestConcurrentPublishAndEvaluate 并发发布与并发判定混合：
//   - 版本号必须恰好为 1..publishers，无跳号无重复；
//   - 每次判定携带的依据版本必须存在，且按该版本回放结果一致；
//   - 不得出现半新半旧（决策为 PERMIT 时命中名单必须来自同一版本）。
func TestConcurrentPublishAndEvaluate(t *testing.T) {
	e := NewEngine()
	req := baseRequest()
	e.SetPolicies(v1Policies())
	e.Publish() // v1 = PERMIT

	const publishers = 20
	const evaluators = 32
	const rounds = 200

	var wg sync.WaitGroup
	var pubMu sync.Mutex
	issued := map[int]bool{1: true}
	bad := make(chan string, publishers+evaluators*rounds)

	// 并发发布：交替发布 PERMIT(v1 形态) 与 DENY(v2 形态)
	for p := 0; p < publishers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			var ps []Policy
			if p%2 == 0 {
				ps = v2Policies()
			} else {
				ps = v1Policies()
			}
			e.SetPolicies(ps)
			n := e.Publish()
			pubMu.Lock()
			if n < 1 || issued[n] {
				bad <- fmt.Sprintf("publisher %d got duplicate/invalid version %d", p, n)
			}
			issued[n] = true
			pubMu.Unlock()
		}(p)
	}

	// 并发判定：每次结果必须在其声明的版本上自洽可回放
	for w := 0; w < evaluators; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				tr := e.Evaluate(req)
				if tr.VersionNum < 1 || tr.VersionNum > publishers+1 {
					bad <- fmt.Sprintf("decision referenced impossible version %d", tr.VersionNum)
					continue
				}
				// 同版本回放必须与实时判定逐字段一致，证明没有串版本
				rt, err := e.EvaluateVersion(tr.VersionNum, req)
				if err != nil {
					bad <- "replay during concurrency: " + err.Error()
					continue
				}
				if rt.String() != tr.String() {
					bad <- fmt.Sprintf("torn read: live=%s replay=%s", tr, rt)
				}
			}
		}()
	}
	wg.Wait()
	close(bad)
	for msg := range bad {
		t.Fatal(msg)
	}
	if e.CurrentVersion() != publishers+1 {
		t.Fatalf("versions = %d, want %d (no gaps/duplicates)",
			e.CurrentVersion(), publishers+1)
	}
	t.Logf("concurrent: %d publishes produced versions 1..%d; %d evaluators x %d rounds always replay-consistent",
		publishers, e.CurrentVersion(), evaluators, rounds)
}

func sameStringSlice(a, b []string) bool {
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
