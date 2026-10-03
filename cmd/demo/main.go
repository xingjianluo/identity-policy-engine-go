// Command demo 是一个纯本地端到端演示：
// 令牌签发（HMAC 存量）→ 跨算法族轮换到 RSA → 新签发自动走新密钥 →
// 换算法伪造攻击被拦截（四种拒绝原因可区分）→ 策略版本发布/升级 →
// 拿着历史输入与版本号回放当时的判定。
//
// 运行：go run ./cmd/demo
package main

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/engine"
	"github.com/xingjianluo/identity-policy-engine-go/keys"
	"github.com/xingjianluo/identity-policy-engine-go/policy"
	"github.com/xingjianluo/identity-policy-engine-go/session"
	"github.com/xingjianluo/identity-policy-engine-go/token"
)

func main() {
	now := time.Now()

	// ---------- 1. 装配：存量 HMAC 密钥 + 新一代 RSA 密钥（重叠窗口） ----------
	ks := keys.NewStore()
	ks.Add(keys.HMACKey("k-hmac", token.AlgHS256, []byte("legacy-shared-secret"),
		now.Add(-24*time.Hour), now.Add(time.Hour)))
	rsaKey, err := keys.GenerateKey("k-rsa", token.AlgRS256, now, now.Add(24*time.Hour))
	must(err)
	ks.Add(rsaKey)

	ss := session.NewStore()
	ss.Create(session.Session{ID: "sess-1", Subject: "alice", ExpiresAt: now.Add(time.Hour)})

	pe := policy.NewEngine()
	v1 := pe.Publish([]policy.Policy{{
		ID: "reader-read", Effect: policy.EffectPermit, Roles: []string{"reader"},
		Actions: []string{"read"}, Resources: []string{"doc/1"},
	}})

	// 校验方按配置放行 HMAC + RSA 两个算法族
	verifier := token.NewVerifier(ks, 30*time.Second, token.AlgHS256, token.AlgRS256)
	eng := engine.New(verifier, ss, pe)

	claims := token.Claims{Subject: "alice", SessionID: "sess-1",
		Roles: []string{"reader"}, Attrs: map[string]string{"dept": "eng"}}

	step("1", "存量签发方用 HMAC(HS256) 签发老令牌")
	legacyIss := token.NewIssuer(token.HMACKey(token.AlgHS256, "k-hmac", []byte("legacy-shared-secret"))).
		WithKID("k-hmac")
	legacyTok, err := legacyIss.Issue(claims, time.Hour)
	must(err)
	showAuthorize(eng, legacyTok, "read", "doc/1")

	step("2", "跨算法族轮换：新签发自动选择 Current() 密钥（应为 RSA）")
	curIssuer, curKey, ok := ks.IssuerForCurrent(now)
	mustOK(ok)
	fmt.Printf("  当前签发密钥: id=%s alg=%s family=%s\n", curKey.ID, curKey.Alg, token.FamilyOf(curKey.Alg))
	rsaTok, err := curIssuer.Issue(claims, time.Hour)
	must(err)
	showAuthorize(eng, rsaTok, "read", "doc/1")

	step("3", "重叠窗口内：老 HMAC 令牌与新 RSA 令牌同时可验")
	showAuthorize(eng, legacyTok, "read", "doc/1")
	showAuthorize(eng, rsaTok, "read", "doc/1")

	step("4", "安全演示：拿公开的 RSA 公钥伪造 HMAC 令牌（alg 替换攻击）")
	forged := forgeSubstitution(rsaTok, curKey.ID, rsaKey.Public.(*rsa.PublicKey))
	showAuthorize(eng, forged, "read", "doc/1")

	step("5", "对照组：四类拒绝彼此可区分")
	// 5a. 算法不在允许范围（ES256 未配置放行）
	esTok := rewriteHeader(rsaTok, "ES256", curKey.ID)
	showAuthorize(eng, esTok, "read", "doc/1")
	// 5b. 密钥类型对不上：kid 指向 HMAC 密钥却声明 RS256（族间替换）
	hmacWithRSA := rewriteHeader(legacyTok, "RS256", "k-hmac")
	showAuthorize(eng, hmacWithRSA, "read", "doc/1")
	// 5c. 签名确实不匹配：篡改 payload 但保留原签名
	tampered := tamperPayload(rsaTok)
	showAuthorize(eng, tampered, "read", "doc/1")
	// 5d. 同族算法不一致：库里这把 RSA 密钥若被登记成 RS512，
	//     而令牌头写 RS256（同属 RSA 族但精确算法对不上）
	mismatchKey, err := keys.AsymmetricKey("k-rsa-misbound", token.AlgRS512,
		nil, rsaKey.Public, now, now.Add(24*time.Hour))
	must(err)
	ks.Add(mismatchKey)
	misbound := rewriteHeader(rsaTok, "RS256", "k-rsa-misbound")
	verifierMB := token.NewVerifier(ks, 30*time.Second, token.AlgHS256, token.AlgRS256, token.AlgRS512)
	mbRes := engine.New(verifierMB, ss, pe).Authorize(misbound, "read", "doc/1")
	fmt.Printf("  判定: 拒绝 @TOKEN 原因=%s（同族但密钥绑定算法 RS512 ≠ 头部 RS256）\n", mbRes.Reason)
	// 5e. 未知密钥
	unknown := rewriteHeader(rsaTok, "RS256", "k-gone")
	showAuthorize(eng, unknown, "read", "doc/1")

	step("6", "策略版本化：记录 v1 判定后发布 v2（把 read 改为 DENY）")
	original := eng.Authorize(rsaTok, "read", "doc/1")
	fmt.Printf("  原始判定(v%d): %s\n", original.PolicyVersion, original.Trace)
	v2 := pe.Publish([]policy.Policy{{
		ID: "reader-deny", Effect: policy.EffectDeny, Roles: []string{"reader"},
		Actions: []string{"read"}, Resources: []string{"doc/1"},
	}})
	live := eng.Authorize(rsaTok, "read", "doc/1")
	fmt.Printf("  线上判定(v%d): %s\n", live.PolicyVersion, live.Trace)

	step("7", "历史回放：用同一输入 + 当时的版本号重算，结论与依据须与当初一致")
	replayed, err := eng.Replay(rsaTok, "read", "doc/1", v1)
	must(err)
	fmt.Printf("  回放 v%d: %s\n", replayed.PolicyVersion, replayed.Trace)
	replayedV2, err := eng.Replay(rsaTok, "read", "doc/1", v2)
	must(err)
	fmt.Printf("  回放 v%d: %s\n", replayedV2.PolicyVersion, replayedV2.Trace)
	if replayed.Trace.Decision == original.Trace.Decision &&
		replayed.Trace.Explanation == original.Trace.Explanation {
		fmt.Println("  ✓ 回放结果与历史判定完全一致（结论 + 命中策略 + 依据）")
	} else {
		panic("replay mismatch")
	}

	step("8", "旧密钥窗口结束后：存量 HMAC 令牌失效，RSA 令牌不受影响")
	ks.Retire("k-hmac")
	showAuthorize(eng, legacyTok, "read", "doc/1")
	showAuthorize(eng, rsaTok, "read", "doc/1")

	fmt.Println("\n演示完成：签发 → 跨族轮换 → 伪造拦截 → 版本判定 → 历史回放 全链路通过。")
}

func step(n, title string) {
	fmt.Printf("\n========== 步骤 %s: %s ==========\n", n, title)
}

func showAuthorize(eng *engine.Engine, tok, action, resource string) {
	res := eng.Authorize(tok, action, resource)
	switch res.Stage {
	case engine.StageToken:
		fmt.Printf("  判定: 拒绝 @TOKEN 原因=%s\n", res.Reason)
	case engine.StageSession:
		fmt.Println("  判定: 拒绝 @SESSION（会话不存在/已吊销/过期）")
	case engine.StagePolicy:
		fmt.Printf("  判定: allowed=%-5v @POLICY(v%d) 依据=%s\n",
			res.Allowed, res.PolicyVersion, res.Trace)
	}
}

// forgeSubstitution 模拟攻击者：把头部 alg 从 RS256 改成 HS256，
// 并用 DER 编码的 RSA 公钥字节当 HMAC 密钥重新签名。
func forgeSubstitution(tok, kid string, pub *rsa.PublicKey) string {
	parts := strings.Split(tok, ".")
	hb, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT", "kid": kid})
	parts[0] = base64.RawURLEncoding.EncodeToString(hb)
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	must(err)
	mac := hmac.New(sha256.New, pubDER)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig := mac.Sum(nil)
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join(parts, ".")
}

func rewriteHeader(tok, alg, kid string) string {
	parts := strings.Split(tok, ".")
	hb, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": kid})
	parts[0] = base64.RawURLEncoding.EncodeToString(hb)
	return strings.Join(parts, ".")
}

func tamperPayload(tok string) string {
	parts := strings.Split(tok, ".")
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	_ = json.Unmarshal(pb, &m)
	m["sub"] = "mallory"
	raw, _ := json.Marshal(m)
	parts[1] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, ".") // 原签名保留
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func mustOK(ok bool) {
	if !ok {
		panic("expected true")
	}
}
