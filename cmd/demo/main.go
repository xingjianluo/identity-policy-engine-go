// 命令行 demo：本地生成密钥、签发令牌、建立会话并演示一次完整的
// 身份校验与策略判定流程（含密钥轮换并行与 deny 优先）。
//
// 运行：go run ./cmd/demo
package main

import (
	"fmt"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/engine"
	"github.com/xingjianluo/identity-policy-engine-go/keystore"
	"github.com/xingjianluo/identity-policy-engine-go/policy"
	"github.com/xingjianluo/identity-policy-engine-go/session"
	"github.com/xingjianluo/identity-policy-engine-go/token"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	keys := keystore.NewStore()
	sessions := session.NewStore()
	policies := policy.NewEngine()

	// 1) 登记第一把 HMAC 密钥（旧），并预登记轮换后的第二把密钥（新），
	//    两者生效窗口重叠 => 轮换期内并行可用。
	oldSecret, err := keystore.GenerateHMACKey()
	must(err)
	newSecret, err := keystore.GenerateHMACKey()
	must(err)
	must(keys.Add(keystore.SigningKey{
		ID: "k-hmac-1", Algorithm: token.HS256,
		SigningKey: oldSecret, VerifyKey: oldSecret,
		NotBefore: now.Add(-2 * time.Hour), ExpiresAt: now.Add(1 * time.Hour),
	}))
	must(keys.Add(keystore.SigningKey{
		ID: "k-hmac-2", Algorithm: token.HS256,
		SigningKey: newSecret, VerifyKey: newSecret,
		NotBefore: now.Add(-30 * time.Minute), ExpiresAt: now.Add(24 * time.Hour),
	}))

	eng := engine.New(engine.Config{
		AllowedAlgorithms: map[token.Algorithm]bool{token.HS256: true, token.RS256: true, token.ES256: true},
		Leeway:            30 * time.Second,
		Issuer:            "local-demo",
		Clock:             clock,
	}, keys, sessions, policies)

	// 2) 用旧密钥签发令牌（ActiveSigningKey 选择 NotBefore 最新的 k-hmac-2，
	//    这里先演示轮换前由旧密钥签发的令牌仍可校验：手动构造）。
	oldKey, _ := keys.Get("k-hmac-1")
	claims := token.Claims{
		Issuer: "local-demo", Subject: "alice",
		ID: "sess-old", ExpiresAt: now.Add(10 * time.Minute).Unix(), IssuedAt: now.Unix(),
		Roles: []string{"reader"}, Attributes: map[string]string{"dept": "platform"},
	}
	oldToken, err := token.Sign(claims, token.HS256, oldKey.ID, oldKey.SigningKey)
	must(err)
	must(sessions.Create(session.Session{
		ID: "sess-old", Subject: "alice", ExpiresAt: now.Add(10 * time.Minute),
		Roles: []string{"reader"}, Attrs: map[string]string{"dept": "platform"},
	}))

	// 3) 发布 v1 策略：reader 可读 docs；另有一条 deny 禁止读 secret 文档（deny 优先）。
	v1 := policies.Replace([]policy.Rule{
		{ID: "r-allow-read", Name: "reader can read docs", Effect: policy.EffectAllow,
			Roles: []string{"reader"}, Actions: []string{"read"}, Resource: "doc:design"},
		{ID: "r-deny-secret", Name: "deny secret docs", Effect: policy.EffectDeny,
			Roles: []string{"reader"}, Actions: []string{"read"}, Resource: "doc:design",
			Conditions: []policy.Condition{{Source: "resource", Key: "classification", Operator: "eq", Value: "secret"}}},
	})
	fmt.Printf("policy version: v%d\n\n", v1)

	check := func(tag, raw string, req engine.AccessRequest) {
		r := eng.Authorize(req)
		fmt.Printf("[%s] action=%s resource=%s resourceAttrs=%v\n  allowed=%v",
			tag, req.Action, req.Resource, req.ResourceAttrs, r.Allowed)
		if !r.Allowed {
			fmt.Printf(" reason=%s code=%s detail=%s", r.Reason, r.Code, r.Detail)
		}
		if r.Policy != nil {
			fmt.Printf("\n  policy=v%s", r.Policy.Decision)
			for _, t := range r.Policy.Evaluated {
				fmt.Printf("\n    trace rule=%s effect=%s matched=%v", t.RuleID, t.Effect, t.Matched)
				if t.FailedCondition != nil {
					fmt.Printf(" failedAt=%s.%s %s %q", t.FailedCondition.Source,
						t.FailedCondition.Key, t.FailedCondition.Operator, t.FailedCondition.Value)
				}
			}
		}
		fmt.Print("\n")
	}

	// 旧密钥令牌在轮换重叠窗口内仍可校验且被授权。
	check("old-key token within rotation overlap", oldToken, engine.AccessRequest{
		RawToken: oldToken, Action: "read", Resource: "doc:design",
		ResourceAttrs: map[string]string{"classification": "public"},
	})

	// 同一身份访问密级文档 => deny 优先。
	check("deny overrides allow", oldToken, engine.AccessRequest{
		RawToken: oldToken, Action: "read", Resource: "doc:design",
		ResourceAttrs: map[string]string{"classification": "secret"},
	})

	// 4) 用当前活跃密钥（新）签发新令牌，条件不满足 => condition_failed 之外的 allow 正常路径；
	//    再演示吊销会话即时拒绝。
	newToken, err := eng.IssueToken("bob", []string{"writer"}, map[string]string{"dept": "sales"}, 10*time.Minute)
	must(err)
	check("new-key token, unmatched resource", newToken, engine.AccessRequest{
		RawToken: newToken, Action: "write", Resource: "doc:unknown",
	})

	// 从新令牌中取 jti 以吊销会话。
	id, aerr := eng.Authenticate(newToken)
	must(aerrAsError(aerr))
	sessions.Revoke(id.TokenID)
	check("after session revocation", newToken, engine.AccessRequest{
		RawToken: newToken, Action: "read", Resource: "doc:design",
	})

	// 5) 时间推进到旧密钥过期之后：旧令牌签名密钥不再可用，新令牌仍有效。
	now = now.Add(2 * time.Hour)
	check("old key expired beyond window", oldToken, engine.AccessRequest{
		RawToken: oldToken, Action: "read", Resource: "doc:design",
	})
}

func aerrAsError(e *engine.AuthError) error {
	if e == nil {
		return nil
	}
	return fmt.Errorf("%s/%s: %s", e.Stage, e.Reason, e.Detail)
}
