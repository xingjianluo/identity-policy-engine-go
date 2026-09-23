# 本地身份校验与访问策略判定引擎

一套完全本地运行的身份校验与访问策略判定引擎，用本地生成的密钥与内存状态模拟
令牌签发、会话与策略数据。**不依赖任何外部服务、网络或真实凭据**，除 Go 标准库外
无第三方依赖。适用于在隔离环境中验证不同令牌形态、密钥轮换与策略冲突下，
判定结论的一致性与可解释性。

## 能力概览

- **令牌签发与校验（`token` 包）**：JWS 结构的紧凑令牌
  （`base64url(header).base64url(payload).base64url(signature)`），支持
  HS256（HMAC-SHA256）、RS256（RSA PKCS#1 v1.5 + SHA256）、
  ES256（ECDSA P-256 + SHA256）；支持 `exp` / `nbf` 的可配置时间容差（leeway）。
- **密钥生命周期（`keystore` 包）**：每把密钥带 `not_before` / `expires_at`
  生效窗口与吊销标记；轮换期间新旧密钥在窗口重叠区内并行可用；吊销即时生效。
- **会话生命周期（`session` 包）**：令牌 `jti` 对应内存会话；吊销、过期、
  未生效、不存在均给出独立状态；并发校验不存在已吊销会话被短暂放行的窗口。
- **RBAC + ABAC 策略判定（`policy` 包）**：角色、动作、资源匹配 +
  属性条件（subject / resource / env 的 `eq` / `ne`）；
  策略以**不可变版本快照**原子发布，历史版本保留，同一输入在策略更新前后都可复现；
  判定结果附带每条候选规则的评估留痕。
- **统一门面（`engine` 包）**：把上述环节串成“令牌 → 会话 → 策略”短路链路，
  返回结构化的拒绝阶段、细粒度原因码与完整依据链。

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `token/token.go` | 令牌结构、签发、签名验签、时间声明校验、可区分错误类型 |
| `keystore/keystore.go` | 线程安全密钥仓库、生效窗口、轮换与吊销 |
| `keystore/keys.go` | 本地随机密钥生成（HMAC/RSA/ECDSA）与密钥材质校验 |
| `session/session.go` | 线程安全会话仓库、状态判定、快照隔离 |
| `policy/policy.go` | 规则模型、版本化快照、deny 优先判定与依据留痕 |
| `engine/engine.go` | 门面：`IssueToken` / `Authenticate` / `Authorize` |
| `cmd/demo/main.go` | 端到端演示（轮换并行、deny 优先、吊销、旧密钥失效） |

## 校验流程

`Engine.Authorize(req)` 依次执行，任一环节失败即短路返回：

1. **令牌校验**（`token.Verify`）
   1. 结构必须为三段且各段非空、均为合法 base64url；头部为合法 JSON 且含 `alg`。
   2. `alg` 必须在引擎配置的算法白名单内（否则 `algorithm_not_allowed`）。
   3. 头部必须携带 `kid`（否则 `kid_missing`）。
   4. 通过 `kid + alg + 当前时间` 向密钥仓库取验签密钥；仓库只返回处于生效窗口内、
      未吊销、算法匹配的密钥，否则得到 `key_not_found`。
   5. 验签，签名不符为 `signature_invalid`（载荷或头部任何字节被篡改都会落入此原因）。
   6. 解析声明，`sub` 与 `exp` 为必填，缺失为 `claims_missing`。
   7. 时间判定（应用 leeway）：`nbf` 未到为 `token_not_yet_valid`，
      `exp` 已过为 `token_expired`。
   8. 引擎配置了 issuer 时额外要求 `iss` 相等。
2. **会话校验**（`session.Check`，以令牌 `jti` 为会话 ID）
   - 判定顺序：`not_found` → `revoked` → `not_started` → `expired` → `valid`。
   - 会话是独立于令牌的吊销凭据：令牌本身未过期时，会话仍可被即时吊销。
3. **策略判定**（`policy.Evaluate`）
   - 以会话中的身份（角色/属性）结合请求的动作、资源、资源属性、环境属性做判定。

对外只暴露结构化原因码（`AuthError{Stage, Reason}` / `AccessResult{Stage, Code}`），
底层加密库的错误一律在包边界转换为自有错误，**不会透出到对外接口**。

## 拒绝原因码（可区分）

| 阶段 | 原因码 | 含义 |
| --- | --- | --- |
| token | `token_malformed` | 结构/编码/头部 JSON 非法 |
| token | `algorithm_not_allowed` | 头部算法不在白名单 |
| token | `kid_missing` | 头部缺少密钥标识 |
| token | `key_not_found` | 密钥不存在、已吊销、超出窗口或算法不匹配 |
| token | `signature_invalid` | 签名不通过（含令牌被篡改） |
| token | `claims_missing` | 缺少 `sub`/`exp` 或 issuer 不符 |
| token | `token_expired` | 超过 `exp`（含 leeway 判定） |
| token | `token_not_yet_valid` | 早于 `nbf` |
| session | `not_found` / `revoked` / `not_started` / `expired` | 会话四种状态 |
| policy | `deny_by_rule` | 命中生效的 deny 规则（**deny 永远优先**） |
| policy | `condition_failed` | 有候选规则但属性条件均不满足 |
| policy | `no_matching_rule` | 角色/动作/资源结构上无候选规则 |
| policy | `allow` | 命中生效 allow 且无生效 deny |

## 密钥轮换规则

- 每把密钥有 `[not_before, expires_at)` 半开生效窗口；仓库对同一时刻可持有多把活跃密钥。
- 轮换方法：先把新密钥以“与旧窗口重叠”的 `not_before` 登记入库（`Add`），
  此时新令牌用 `ActiveSigningKey`（自动选择 `not_before` 最新的活跃密钥）签发；
  旧窗口内已签发的令牌在旧密钥 `expires_at` 前仍可验签。旧窗口结束后旧密钥自动失效，
  需要提前停用可调用 `Revoke` 立即吊销。
- `VerifyKey` 的取密钥与窗口/吊销/算法判断在同一把读锁临界区内完成并返回不可变材料，
  因此并发校验中不会误用刚过期或已吊销的密钥。

## 策略判定规则

- **候选规则**：角色任一命中（规则角色为空表示不限制，`*` 为通配）、
  动作任一命中（为空表示全部）、资源精确相等（`*` 表示全部）。
- **属性条件**：候选规则的条件按 AND 全部评估，支持 `eq` / `ne`，
  属性来源为 `subject` / `resource` / `env`；第一个失败条件会记录在依据链中。
- **冲突解决**：所有生效规则中只要存在 `deny` 即 `deny_by_rule`，
  与规则顺序、优先级无关；无生效 deny 且存在生效 allow 才为 `allow`。
- **结论区分**：候选规则存在但都因条件失败 → `condition_failed`；
  结构上无候选 → `no_matching_rule`。
- **版本化可复现**：`Replace(rules)` 深拷贝规则生成新版本并原子切换；
  `SnapshotAt(v)` 可取回任意历史版本，`EvaluateWith(snapshot, input)` 为纯函数，
  同一输入在任何版本上的结论都可复现。判定结果 `Result.Evaluated`
  列出全部候选规则及其效果、是否命中、失败条件，构成可追溯依据。

## 并发性保证

- 密钥/会话仓库使用 `sync.RWMutex`，读取返回**深拷贝快照**，
  状态与时间窗口的判断在单个临界区内完成；外部修改返回值不影响仓库内部。
- 策略当前版本以 `atomic.Pointer` 指向不可变快照，更新只做原子切换；
  并发判定不可能观察到半成品规则集（测试中以“结论只能是 allow 或 deny_by_rule”断言）。
- 并发测试采用两阶段屏障：所有 worker 在吊销前完成一批次（必须全部成功）→
  主线程执行吊销 → 屏障放行后一批次（必须全部以 `revoked` 拒绝），
  在 `-race` 下重复运行验证不存在短暂放行窗口。

## 验证方法

要求 Go 1.25+（开发环境为 Go 1.26，仅用标准库）。

```bash
# 全部单元/并发测试（-race 下重复多轮）
go test ./... -race -count=5

# 查看带“输入 + 判定依据”日志的详细测试输出
go test ./... -v

# 静态检查
go vet ./...

# 端到端演示：轮换重叠并行、deny 优先、会话吊销、旧密钥过期失效
go run ./cmd/demo
```

测试覆盖要点：

- **令牌**：三种算法签发/验签；签名字节翻转、载荷 `sub` 篡改、
  头部算法混淆、算法白名单拒绝、结构畸形、未知 kid、声明缺失、
  `exp`/`nbf` 超容差与容差内通过。
- **密钥**：轮换重叠区双密钥可用、旧密钥过期后不可用而新密钥可用、
  吊销即时、未到 `not_before` 不可用、算法不匹配、登记校验、快照隔离、并发吊销。
- **会话**：四种状态原因可区分、重复创建、快照隔离、并发吊销零放行。
- **策略**：deny 优先冲突、allow、无匹配、条件失败、`eq`/`ne`、
  deny 条件不满足时不拒绝、通配规则、历史版本复现、发布快照不可被外部修改、
  并发替换下结论稳定。
- **端到端（engine）**：上述场景经完整链路后的原因码集合互不相同。

## 使用示例

```go
now := time.Now()
keys := keystore.NewStore()
secret, _ := keystore.GenerateHMACKey()
_ = keys.Add(keystore.SigningKey{
    ID: "k1", Algorithm: token.HS256,
    SigningKey: secret, VerifyKey: secret,
    NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
})
eng := engine.New(engine.Config{
    AllowedAlgorithms: map[token.Algorithm]bool{token.HS256: true},
    Leeway:            5 * time.Second,
    Issuer:            "local",
}, keys, session.NewStore(), policy.NewEngine())

eng.Policies().Replace([]policy.Rule{{
    ID: "r1", Effect: policy.EffectAllow,
    Roles: []string{"reader"}, Actions: []string{"read"}, Resource: "doc:1",
}})

raw, _ := eng.IssueToken("alice", []string{"reader"}, map[string]string{"dept": "platform"}, time.Hour)
res := eng.Authorize(engine.AccessRequest{
    RawToken: raw, Action: "read", Resource: "doc:1",
    ResourceAttrs: map[string]string{"classification": "public"},
})
// res.Allowed == true；失败时 res.Reason/res.Code 给出可区分原因，
// res.Token / res.Session / res.Policy 提供完整判定依据链。
```
