// 端到端演示：本地生成密钥 -> HS256 签发存量令牌 -> 轮换到 RS256 ->
// 新旧令牌在重叠窗口并行校验 -> 换算法伪造被拒绝 -> 策略发布与历史回放。
//
// 运行：go run ./cmd/demo
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/engine"
	"github.com/xingjianluo/identity-policy-engine-go/keys"
	"github.com/xingjianluo/identity-policy-engine-go/policy"
	"github.com/xingjianluo/identity-policy-engine-go/session"
	"github.com/xingjianluo/identity-policy-engine-go/token"
)

func step(n int, title string) {
	fmt.Printf("\n=== 步骤 %d：%s ===\n", n, title)
}

func showAuthorize(tag string, eng *engine.Engine, tok, action, resource string) engine.Result {
	res := eng.Authorize(tok, action, resource)
	verdict := "拒绝"
	if res.Allowed {
		verdict = "放行"
	}
	fmt.Printf("[%-22s] 结论=%-4s 阶段=%s", tag, verdict, res.Stage)
	if res.Stage == engine.StageToken {
		fmt.Printf(" 原因=%s", res.Reason)
	}
	if res.Stage == engine.StagePolicy {
		fmt.Printf("\n    依据版本=v%d 决策=%s 命中PERMIT=%v 命中DENY=%v 条件失败=%v\n    解释=%s",
			res.Trace.VersionNum, res.Trace.Decision,
			res.Trace.MatchedPermits, res.Trace.MatchedDenies,
			res.Trace.ConditionFails, res.Trace.Explanation)
	}
	fmt.Println()
	return res
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

// forgeAlg 只把令牌头 alg 改掉，其余两段原样保留（模拟换算法伪造）。
func forgeAlg(tok, alg string) string {
	parts := strings.Split(tok, ".")
	var hdr map[string]any
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(raw, &hdr)
	hdr["alg"] = alg
	hb, _ := json.Marshal(hdr)
	parts[0] = base64.RawURLEncoding.EncodeToString(hb)
	return strings.Join(parts, ".")
}

func main() {
	now := time.Now()

	// ---------- 1. 密钥：HS256 存量对称密钥 ----------
	step(1, "准备密钥：HS256 对称（存量）")
	ks := keys.NewStore()
	must(ks.Add(keys.Key{ID: "hmac-1", Alg: token.AlgHS256, Material: []byte("legacy-shared-secret"),
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour)}))
	fmt.Println("已注册 hmac-1/HS256，生效窗口覆盖当前时刻")

	// ---------- 2. 会话 ----------
	ss := session.NewStore()
	ss.Create(session.Session{ID: "sess-1", Subject: "alice", ExpiresAt: now.Add(time.Hour)})

	// ---------- 3. 策略 v1 发布 ----------
	step(2, "发布策略 v1（reader 可读 doc/1）")
	pe := policy.NewEngine()
	pe.SetPolicies([]policy.Policy{
		{ID: "allow-read", Effect: policy.EffectPermit, Roles: []string{"reader"},
			Actions: []string{"read"}, Resources: []string{"doc/1"}},
	})
	v1 := pe.Publish()
	fmt.Printf("已发布不可变版本 v%d，线上判定始终使用最新版本\n", v1)

	// 校验器放行 HMAC + RSA 两个族（按族配置）
	verifier := token.NewVerifier(ks, 30*time.Second,
		token.AlgorithmsOfFamilies(token.FamilyHMAC, token.FamilyRSA)...)
	eng := engine.New(verifier, ss, pe)

	// ---------- 4. 用存量 HS256 签发令牌 ----------
	step(3, "用 HS256 签发存量令牌")
	legacyIss := token.NewIssuer(token.AlgHS256, "hmac-1", []byte("legacy-shared-secret"))
	legacyTok, err := legacyIss.Issue(token.Claims{
		Subject: "alice", SessionID: "sess-1", Roles: []string{"reader"},
		Attrs: map[string]string{"dept": "eng"},
	}, 30*time.Minute)
	must(err)
	fmt.Printf("存量令牌（前 48 字符）：%s...\n", legacyTok[:48])
	showAuthorize("存量 HS256 令牌", eng, legacyTok, "read", "doc/1")

	// ---------- 5. 轮换到 RS256：本地生成 RSA 密钥，重叠窗口并行可用 ----------
	step(4, "轮换到 RS256（本地生成 RSA-2048，无需证书/外部服务）")
	rsaKey, err := token.GenerateRSAKey(2048)
	must(err)
	must(ks.Add(keys.Key{ID: "rsa-1", Alg: token.AlgRS256, Material: rsaKey,
		NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour)}))
	fmt.Println("已注册 rsa-1/RS256；hmac-1 仍在窗口内 -> 重叠窗口并行可用")

	// 新签发自动走最新密钥
	cur, ok := ks.Current(now)
	must2(ok)
	fmt.Printf("Current() 自动选中的签发密钥：%s/%s\n", cur.ID, cur.Alg)
	newIss := token.NewIssuerForKey(cur.Alg, cur.ID, cur.Material)
	newTok, err := newIss.Issue(token.Claims{
		Subject: "alice", SessionID: "sess-1", Roles: []string{"reader"},
		Attrs: map[string]string{"dept": "eng"},
	}, 30*time.Minute)
	must(err)

	step(5, "重叠窗口：老令牌继续放行，新 RS256 令牌同样放行")
	showAuthorize("老 HS256 令牌", eng, legacyTok, "read", "doc/1")
	showAuthorize("新 RS256 令牌", eng, newTok, "read", "doc/1")

	// ---------- 6. 换算法伪造 ----------
	step(6, "攻击演示：把 RS256 令牌头 alg 改成 HS256（kid 仍为 rsa-1）")
	forged := forgeAlg(newTok, "HS256")
	res := showAuthorize("换算法伪造令牌", eng, forged, "read", "doc/1")
	fmt.Printf("拒绝结论 ALG_SUBSTITUTION 与另外三类结论彼此可区分：\n")
	fmt.Printf("  %s / %s / %s / %s\n",
		token.ReasonAlgNotAllowed, token.ReasonAlgSubstitution,
		token.ReasonKeyTypeMismatch, token.ReasonSignatureMismatch)
	if res.Reason != token.ReasonAlgSubstitution {
		fmt.Println("演示异常：伪造令牌未被正确拒绝")
		os.Exit(1)
	}

	// ---------- 7. 旧密钥退役 ----------
	step(7, "重叠窗口结束：吊销旧 HMAC 密钥")
	ks.Retire("hmac-1")
	showAuthorize("老令牌（旧密钥已吊销）", eng, legacyTok, "read", "doc/1")
	showAuthorize("RSA 令牌不受影响", eng, newTok, "read", "doc/1")

	// ---------- 8. 策略 v2 + 历史回放 ----------
	step(8, "发布策略 v2（reader 对 doc/1 显式 DENY）并回放 v1")
	pe.SetPolicies([]policy.Policy{
		{ID: "deny-read", Effect: policy.EffectDeny, Roles: []string{"reader"},
			Actions: []string{"read"}, Resources: []string{"doc/1"}},
	})
	v2 := pe.Publish()
	fmt.Printf("已发布 v%d，线上立即切换\n", v2)
	req := policy.Request{Subject: "alice", Roles: []string{"reader"},
		Action: "read", Resource: "doc/1", Attrs: map[string]string{"dept": "eng"}}
	live := pe.Evaluate(req)
	fmt.Printf("线上（最新 v%d）：%s\n", live.VersionNum, live)

	replayed, err := pe.EvaluateVersion(v1, req)
	must(err)
	fmt.Printf("回放 v%d（原输入+版本号重算）：%s\n", v1, replayed)
	fmt.Println("回放结论、命中策略、条件失败与解释与 v1 当时完全一致")

	fmt.Println("\n演示完成：签发 -> 跨族轮换 -> 判定 -> 攻击拒绝 -> 版本回放 全链路在本地跑通")
}

func must2(ok bool) {
	if !ok {
		fmt.Fprintln(os.Stderr, "fatal: expected value missing")
		os.Exit(1)
	}
}
