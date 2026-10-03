package policy

import (
	"errors"
	"time"
)

// Version 是一次不可变的策略发布。发布后策略切片不再被任何路径修改，
// 因此同版本下同一输入永远得到同一结论与同一依据链。
type Version struct {
	Number    int
	CreatedAt time.Time
	policies  []Policy
}

// Policies 返回该版本策略集的拷贝，调用方可自由修改而不影响版本本身。
func (v *Version) Policies() []Policy {
	return clonePolicies(v.policies)
}

// ErrUnknownVersion 表示请求回放的版本号从未发布过。
var ErrUnknownVersion = errors.New("unknown policy version")

// publish 以当前工作区策略集形成一个新的不可变版本并成为最新版本。
// 并发发布经由容量为 1 的信号量串行化：版本号单调递增、绝不跳号，
// 历史只追加，已发布内容此后只读。
func (e *Engine) publish(now time.Time) int {
	e.publishMu <- struct{}{}
	defer func() { <-e.publishMu }()

	old := *e.history.Load()
	next := make([]*Version, len(old)+1)
	copy(next, old)

	num := len(old) + 1
	// 深拷贝工作区策略，封进不可变版本；之后工作区再被 SetPolicies 替换，
	// 也与历史版本完全无关。
	v := &Version{Number: num, CreatedAt: now, policies: clonePolicies(e.currentSnapshot().policies)}
	next[len(old)] = v
	e.history.Store(&next)
	return num
}

// Publish 发布当前工作区策略集的一个不可变版本，返回新版本号。
func (e *Engine) Publish() int {
	return e.publish(timeNow())
}

// CurrentVersion 返回最新发布的版本号；从未发布返回 0。
func (e *Engine) CurrentVersion() int {
	hist := *e.history.Load()
	return len(hist)
}

// VersionAt 返回指定版本号的不可变版本；不存在返回 nil, false。
func (e *Engine) VersionAt(number int) (*Version, bool) {
	hist := *e.history.Load()
	if number < 1 || number > len(hist) {
		return nil, false
	}
	return hist[number-1], true
}

// EvaluateVersion 用指定历史版本对请求做确定性回放：
// 输入与版本号相同，重算出的结论、命中策略与依据链必须与当时完全一致。
// 版本不存在返回 ErrUnknownVersion。
func (e *Engine) EvaluateVersion(version int, req Request) (Trace, error) {
	v, ok := e.VersionAt(version)
	if !ok {
		return Trace{}, ErrUnknownVersion
	}
	// 直接在版本的不可变切片上判定；版本内容永不修改，因此无需拷贝。
	return evaluateOn(&snapshot{version: v.Number, policies: v.policies}, req), nil
}

// Version 返回该 Trace 所依据的策略版本号（未携带时为 0）。
func (t Trace) Version() int {
	return t.VersionNum
}

// timeNow 便于测试注入；默认 time.Now。
var timeNow = time.Now
