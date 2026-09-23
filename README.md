# identity-policy-engine-go

一套**纯本地运行**的身份校验与访问策略判定引擎。使用本地对称密钥与内存状态模拟令牌签发、会话与策略数据，不依赖任何外部服务或真实凭据，仅使用 Go 标准库。

## 包结构

| 包 | 职责 |
|---|---|
| `token` | 令牌签发与校验（JWT 风格的三段式紧凑格式），可区分的拒绝原因 |
| `keys` | 签名密钥生命周期管理：生效窗口、轮换并行、吊销 |
| `session` | 内存会话存储：创建、吊销、过期检查 |
| `policy` | 基于角色与属性的策略判定，拒绝优先合成 |
| `engine` | 组合以上三阶段（令牌 → 会话 → 策略）的统一判定入口 |

## 校验流程

`engine.Authorize(token, action, resource)` 依次执行三个阶段，任一阶段失败即返回，失败阶段与原因均可区分：

1. **令牌校验（Stage=TOKEN）**
   - 结构解析：必须是 `base64url(header).base64url(payload).base64url(signature)` 三段，否则 `MALFORMED`。
   - 算法白名单：仅接受构造 `Verifier` 时声明的算法（HS256/HS384/HS512），否则 `ALG_NOT_ALLOWED`。
   - 密钥解析：按头部 `kid` 在密钥库中查找**当前时刻处于生效窗口且未吊销**的密钥，找不到则 `UNKNOWN_KEY`。
   - 签名比对：HMAC 常量时间比较，不符则 `SIGNATURE_MISMATCH`。
   - 必需声明：`sub`、`sid`、`iat`、`exp` 缺失则 `MISSING_CLAIM`。
   - 时间检查：`exp`/`nbf` 校验附带可配置的时间容差（leeway），过期 `EXPIRED`、未生效 `NOT_YET_VALID`。
   - 所有错误统一封装为 `*token.Error`，只暴露 `Reason` 与说明信息，**底层库异常不会透出到对外接口**。
2. **会话检查（Stage=SESSION）**：会话必须存在、未吊销、未过期，否则拒绝。
3. **策略判定（Stage=POLICY）**：见下节。

## 密钥轮换

- 每个密钥带 `NotBefore`/`NotAfter` 生效窗口与 `Retired` 吊销标记。
- 轮换时先 `Add` 新密钥，旧密钥保留宽限窗口：**窗口内新旧密钥并行可用**，旧密钥签发的存量令牌继续有效，新签发通过 `Current()` 自动选用最新密钥。
- 窗口结束或调用 `Retire` 后，旧密钥立即不可解析，对应令牌以 `UNKNOWN_KEY` 拒绝。
- 密钥材料入库与出库均做拷贝，调用方无法篡改库内状态；全部操作在读写锁保护下完成，并发校验不会误用已吊销/过期密钥。

## 策略判定规则

策略由「角色 + 动作 + 资源 + 属性条件」组成，动作/资源/角色支持 `*` 通配。合成规则为**拒绝优先（deny-overrides）**：

| 结论 | 含义 |
|---|---|
| `PERMIT` | 至少一条 PERMIT 策略命中，且无 DENY 命中 |
| `DENY` | 任一 DENY 策略命中（冲突时 DENY 胜出，Trace 同时记录冲突双方） |
| `CONDITION_FAILED` | 角色/动作/资源匹配，但属性条件不满足（Trace 记录缺失的属性键） |
| `NO_MATCH` | 没有任何策略覆盖该角色/动作/资源 |

每次判定返回 `Trace`（命中的 PERMIT/DENY 策略 ID、失败的条件、人类可读解释），保证结论可追溯。策略集通过 `SetPolicies` 原子替换，同一输入在同一策略版本下结论完全可复现。

## 验证方法

```bash
go build ./...          # 编译
go test ./... -v        # 运行全部测试，日志打印输入与判定依据
go test ./... -race     # 竞态检测（并发吊销/轮换/判定稳定性）
```

测试覆盖：

- **令牌篡改**：改 payload、伪造签名 → `SIGNATURE_MISMATCH`；`alg=none`、越白名单算法 → `ALG_NOT_ALLOWED`；过期/未生效/缺声明/未知密钥各有独立原因（`token` 包）。
- **密钥轮换**：窗口内新旧并行、窗口外旧密钥失效、吊销立即生效、32 并发 × 500 轮解析稳定（`keys` 包）。
- **会话生命周期**：吊销/过期/未知会话拒绝，吊销后 32 并发 × 500 轮无一放行（`session` 包）。
- **策略冲突**：PERMIT+DENY 冲突判 DENY 且 Trace 记录双方；`NO_MATCH` 与 `CONDITION_FAILED` 可区分；策略更新前后同一输入各自可复现（`policy` 包）。
- **端到端**：三阶段失败原因可区分、轮换全链路、32 并发 × 300 轮判定结果稳定（`engine` 包）。

## 最小使用示例

```go
ks := keys.NewStore()
ks.Add(keys.Key{ID: "k1", Material: []byte("secret-1"),
    NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)})

ss := session.NewStore()
ss.Create(session.Session{ID: "s1", Subject: "alice", ExpiresAt: time.Now().Add(time.Hour)})

pe := policy.NewEngine()
pe.SetPolicies([]policy.Policy{{
    ID: "allow-read", Effect: policy.EffectPermit, Roles: []string{"reader"},
    Actions: []string{"read"}, Resources: []string{"doc/1"},
}})

verifier := token.NewVerifier(ks, 30*time.Second, token.AlgHS256)
eng := engine.New(verifier, ss, pe)

issuer := token.NewIssuer(token.AlgHS256, "k1", []byte("secret-1"))
tok, _ := issuer.Issue(token.Claims{Subject: "alice", SessionID: "s1",
    Roles: []string{"reader"}}, 10*time.Minute)

res := eng.Authorize(tok, "read", "doc/1")
// res.Allowed == true, res.Trace 记录判定依据
```
