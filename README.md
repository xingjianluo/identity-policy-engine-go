# identity-policy-engine-go

一套**纯本地运行**的身份校验与访问策略判定引擎。密钥（含 RSA/ECDSA 非对称密钥对）全部在进程内生成，令牌签发/校验、会话与策略数据均为内存状态，**不依赖任何外部服务或真实证书**，仅使用 Go 标准库。

## 包结构

| 包 | 职责 |
|---|---|
| `token` | 令牌签发与校验（JWT 风格三段式紧凑格式），对称/非对称多算法族，可区分的拒绝原因 |
| `keys` | 签名密钥生命周期管理：生效窗口、**跨算法族轮换**并行、吊销、材料深拷贝 |
| `session` | 内存会话存储：创建、吊销、过期检查 |
| `policy` | 基于角色与属性的策略判定，拒绝优先合成，**不可变版本发布与历史回放** |
| `engine` | 组合以上三阶段（令牌 → 会话 → 策略）的统一判定入口 |
| `cmd/demo` | 可直接运行的端到端演示：签发 → 跨族轮换 → 判定 → 攻击拒绝 → 版本回放 |

## 支持的算法族

| 族 | 算法 | 密钥材料（签发 / 校验） |
|---|---|---|
| HMAC（对称） | `HS256` `HS384` `HS512` | `[]byte` 共享密钥 |
| RSA（RSASSA-PKCS#1 v1.5） | `RS256` `RS384` `RS512` | `*rsa.PrivateKey` / `*rsa.PublicKey` |
| ECDSA（定长 r‖s 编码） | `ES256` `ES384` `ES512` | `*ecdsa.PrivateKey` / `*ecdsa.PublicKey` |

- 本地密钥生成：`token.GenerateRSAKey(2048)`、`token.GenerateECDSAKey(token.AlgES256)`，无外部依赖。
- 签发器：HMAC 用 `token.NewIssuer(alg, kid, secret)`；非对称用 `token.NewIssuerForKey(alg, kid, privateKey)`。
- 校验方按**算法族**决定放行范围：`token.AlgorithmsOfFamilies(token.FamilyHMAC, token.FamilyRSA, token.FamilyECDSA)`；也可用 `token.AllAlgorithms()` 放行全部。

### 与既有令牌的兼容范围

- **存量 HS256/HS384/HS512 令牌不受影响**：签名格式与验证逻辑保持不变，HMAC 常量时间比对照旧。
- 每条密钥在密钥库中**自带注册算法**（`keys.Key.Alg`）。跨算法族轮换时新旧密钥可分属不同族（例如老 `HS256`、新 `RS256`），在重叠窗口内同时可解析：老令牌继续验过，`Store.Current()` 自动选最新密钥，新签发自动走新族。
- 升级校验方时，若要同时接受对称与非对称令牌，需在白名单里同时声明两个族；只声明单族则只放行该族。

### 防换算法伪造（alg-substitution / alg-confusion）

信任锚是**密钥注册时的算法族**，而不是令牌头自报的 `alg`。校验时按以下顺序给出彼此可区分的结论，且全部在任何密码学运算之前完成族判定：

| 对外原因 | 触发情形 |
|---|---|
| `ALG_NOT_ALLOWED` | 头部算法不在校验方白名单，或根本不受支持（如 `none`） |
| `ALG_SUBSTITUTION` | 头部算法与该 `kid` 注册算法**不在同一族**（如把 RS256 改成 HS256、ES256 改成 none） |
| `KEY_TYPE_MISMATCH` | 族一致，但配置的密钥材料类型与算法对不上（如 RS256 的 kid 下挂了 ECDSA 公钥、[]byte） |
| `SIGNATURE_MISMATCH` | 算法、族、密钥类型都正确，但签名与令牌内容确实不匹配 |

典型攻击——拿到 RSA 公钥后把头部从 `RS256` 改成 `HS256`、再拿公钥 DER 字节当 HMAC 共享密钥伪造签名——会在族比对处直接以 `ALG_SUBSTITUTION` 拒绝，永远不会走到“拿公钥做 HMAC”那一步。**底层密码库的原始报错不会透出对外接口**，一律收敛为上述 `*token.Error`。

## 校验流程

`engine.Authorize(token, action, resource)` 依次执行三个阶段，任一阶段失败即返回，失败阶段与原因均可区分：

1. **令牌校验（Stage=TOKEN）**：结构解析（`MALFORMED`）→ 算法白名单（`ALG_NOT_ALLOWED`）→ 密钥解析（`UNKNOWN_KEY`）→ 族一致性（`ALG_SUBSTITUTION`）→ 材料类型（`KEY_TYPE_MISMATCH`）→ 签名比对（`SIGNATURE_MISMATCH`）→ 必需声明（`MISSING_CLAIM`）→ `exp`/`nbf` 时间容差（`EXPIRED`/`NOT_YET_VALID`）。
2. **会话检查（Stage=SESSION）**：会话必须存在、未吊销、未过期。
3. **策略判定（Stage=POLICY）**：见下节，Trace 携带所依据的策略版本号。

## 密钥轮换

- 每个密钥带 `NotBefore`/`NotAfter` 生效窗口、`Retired` 吊销标记以及固定的 `Alg`。
- 轮换先 `Add` 新密钥（可跨族），旧密钥保留宽限窗口：**窗口内新旧并行可用**；窗口结束或 `Retire` 后旧令牌以 `UNKNOWN_KEY` 拒绝。
- `Add` 会校验材料与算法族是否匹配（RS/ES 算法挂 `[]byte`、HS 算法挂非对称密钥等都会被拒绝入库），并对材料做深拷贝（非对称密钥经 PKCS#8/PKIX 序列化再解析）；`Resolve`/`Current` 返回的也是独立拷贝。

## 版本化策略与历史回放

- 工作区策略用 `SetPolicies` 更新；调用 `Publish()` 后形成一个**不可变版本**（单调递增版本号、创建时间、策略深拷贝），此后任何路径都不会修改它。
- `Evaluate` **始终在最新已发布版本**上判定；每次判定只读一个完整的原子快照，并发发布与并发判定混合时不会出现半新半旧的策略集，也不会把不同版本的命中依据串在一起。
- 历史回放：`EvaluateVersion(version, req)` 用当时的不可变版本对同一输入重算，返回的**结论、命中的 PERMIT/DENY、失败条件、解释**与当时完全一致；版本号从 1 开始，未知版本返回 `ErrUnknownVersion`。
- 确定性细节：属性条件按键名字典序检查，`Trace.ConditionFails` 顺序稳定；策略切片顺序保持发布时顺序。
- 合成规则仍为**拒绝优先（deny-overrides）**：

| 结论 | 含义 |
|---|---|
| `PERMIT` | 至少一条 PERMIT 命中，且无 DENY 命中 |
| `DENY` | 任一 DENY 命中（冲突时 Trace 同时记录双方） |
| `CONDITION_FAILED` | 角色/动作/资源匹配但属性条件不满足 |
| `NO_MATCH` | 没有任何策略覆盖该角色/动作/资源 |

## 本地验证方法

```bash
go build ./...                    # 编译
go vet ./...                      # 静态检查
go test ./... -v                  # 全量测试，日志打印输入与各条判定依据链
go test ./... -race -count=1      # 带竞态检测，禁用缓存保证稳定复现
go run ./cmd/demo                 # 端到端演示：签发/跨族轮换/攻击拒绝/版本回放
```

本轮新增/强化的测试覆盖：

- **非对称往返**：RS256/384/512、ES256/384/512 全 6 算法本地签发+校验通过（`token` 包）。
- **换算法伪造**：RS256→HS256 拿公钥字节伪造 HMAC 签名 → `ALG_SUBSTITUTION`；ES256→`none` → `ALG_NOT_ALLOWED`（`token` 包）。
- **算法与密钥不匹配**：族一致但材料错配 → `KEY_TYPE_MISMATCH`；签名翻转 → `SIGNATURE_MISMATCH`，四类安全结论可区分；入库侧族/材料错配被 `keys.Store.Add` 拒绝。
- **跨算法族轮换**：HMAC→RSA 重叠窗口双族并行、新签发自动走 RS256、旧密钥吊销后老令牌 `UNKNOWN_KEY`（`keys`、`engine` 包）。
- **历史版本回放**：发布结论相反的 v2 后回放 v1，结论与依据链逐字段一致；版本不可变、未知版本报错（`policy` 包）。
- **并发稳定性**：20 路并发发布 + 32 路 × 200 轮并发判定，版本号 1..N 无跳号/重复，每次实时判定都能在其声明版本上原样回放（`-race` 下通过）。
- 既有用例（令牌篡改、会话吊销、策略冲突、三阶段端到端等）全部保持通过。

## 最小使用示例

```go
ks := keys.NewStore()
_ = ks.Add(keys.Key{ID: "k1", Alg: token.AlgHS256, Material: []byte("secret-1"),
    NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)})

ss := session.NewStore()
ss.Create(session.Session{ID: "s1", Subject: "alice", ExpiresAt: time.Now().Add(time.Hour)})

pe := policy.NewEngine()
pe.SetPolicies([]policy.Policy{{
    ID: "allow-read", Effect: policy.EffectPermit, Roles: []string{"reader"},
    Actions: []string{"read"}, Resources: []string{"doc/1"},
}})
pe.Publish() // 形成不可变 v1；后续可用 pe.EvaluateVersion(1, req) 回放

verifier := token.NewVerifier(ks, 30*time.Second,
    token.AlgorithmsOfFamilies(token.FamilyHMAC, token.FamilyRSA, token.FamilyECDSA)...)
eng := engine.New(verifier, ss, pe)

issuer := token.NewIssuer(token.AlgHS256, "k1", []byte("secret-1"))
tok, _ := issuer.Issue(token.Claims{Subject: "alice", SessionID: "s1",
    Roles: []string{"reader"}}, 10*time.Minute)

res := eng.Authorize(tok, "read", "doc/1")
// res.Allowed == true，res.Trace.VersionNum == 1，Trace 记录完整判定依据
```
