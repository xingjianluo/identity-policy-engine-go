# identity-policy-engine-go

一套**纯本地运行**的身份校验与访问策略判定引擎。本地生成对称/非对称密钥并在内存中模拟令牌签发、会话与策略数据，不依赖任何外部服务、真实证书或网络，仅使用 Go 标准库。

## 包结构

| 包 | 职责 |
|---|---|
| `token` | 令牌签发与校验（JWT 风格三段式紧凑格式），支持 HMAC/RSA/ECDSA 三个算法族，可区分的拒绝原因 |
| `keys` | 签名密钥生命周期管理：生效窗口、**跨算法族**轮换并行、吊销、本地密钥生成 |
| `session` | 内存会话存储：创建、吊销、过期检查 |
| `policy` | 基于角色与属性的策略判定，拒绝优先合成，**不可变版本化发布与历史回放** |
| `engine` | 组合以上三阶段（令牌 → 会话 → 策略）的统一判定入口，支持按版本回放 |
| `cmd/demo` | 可直接运行的端到端演示：签发 → 跨族轮换 → 伪造拦截 → 版本判定 → 历史回放 |

## 支持的算法族

| 族 | 算法 | 密钥 |
|---|---|---|
| HMAC（对称） | `HS256` / `HS384` / `HS512` | 共享密钥 |
| RSA（非对称，PKCS#1 v1.5 签名） | `RS256` / `RS384` / `RS512` | RSA-2048 私钥/公钥 |
| ECDSA（非对称，ASN.1 签名） | `ES256`(P-256) / `ES384`(P-384) / `ES512`(P-521) | EC 私钥/公钥 |

- 签发与校验全部本地完成：`keys.GenerateKey` 在本地生成随机 HMAC 密钥、RSA-2048 或对应 P 曲线私钥；校验方只需在密钥库登记公钥（`keys.AsymmetricKey` 的 `publicKey` 参数）。
- **兼容范围**：既有 HS256/HS384/HS512 存量令牌的格式与签名算法完全不变，引入非对称支持后照常签发与校验。校验方通过 `token.NewVerifier(resolver, leeway, allowed...)` 按**精确算法**配置放行清单；不放行的算法一律拒绝。允许「HMAC + RSA + ECDSA」混用，例如轮换窗口内同时放行 `HS256, RS256`。

## 校验流程

`engine.Authorize(token, action, resource)` 依次执行三个阶段，任一阶段失败即返回，失败阶段与原因均可区分：

1. **令牌校验（Stage=TOKEN）**，顺序很关键：
   - 结构解析：必须是 `base64url(header).base64url(payload).base64url(signature)` 三段，否则 `MALFORMED`。
   - 算法白名单：头部 `alg` 未知或不在校验方配置的放行清单内 → `ALG_NOT_ALLOWED`。
   - 密钥解析：按头部 `kid` 查找**当前时刻处于生效窗口且未吊销**的密钥，找不到则 `UNKNOWN_KEY`。每把密钥在入库时绑定了自己的算法/算法族。
   - **算法族绑定检查（防换算法伪造）**：头部算法族必须与密钥绑定族一致。典型攻击是「攻击者只拿到公开的 RSA/ECDSA 公钥，把头部 `alg` 从 RS256 改成 HS256，再把公钥字节当 HMAC 密钥重新签名」——这种非对称↔对称的族间替换一律以 `ALG_SUBSTITUTION` 拒绝。
   - **同族精确算法检查**：族一致但算法对不上（密钥登记为 RS512、头部写 RS256，或 P-256 密钥配 ES384）→ `KEY_ALG_MISMATCH`。
   - 签名比对：HMAC 常量时间比较，RSA 用 `rsa.VerifyPKCS1v15`，ECDSA 用 `ecdsa.VerifyASN1`；签名确实不符 → `SIGNATURE_MISMATCH`。
   - 必需声明：`sub`、`sid`、`iat`、`exp` 缺失 → `MISSING_CLAIM`。
   - 时间检查：`exp`/`nbf` 校验附带可配置 leeway，过期 `EXPIRED`、未生效 `NOT_YET_VALID`。
   - 所有错误统一封装为 `*token.Error`，只暴露 `Reason` 与说明信息，**底层密码库报错不会原样透出到对外接口**。
2. **会话检查（Stage=SESSION）**：会话必须存在、未吊销、未过期。
3. **策略判定（Stage=POLICY）**：始终对**最新发布版本**判定，结果带 `PolicyVersion`。

四类与签名相关的拒绝互斥且可区分：

| 原因 | 触发条件 |
|---|---|
| `ALG_NOT_ALLOWED` | 头部算法不在校验方放行清单（或未知） |
| `ALG_SUBSTITUTION` | 头部算法族与密钥绑定族不一致（非对称↔对称伪造，双向都拦） |
| `KEY_ALG_MISMATCH` | 同族但精确算法/曲线与密钥登记信息不一致 |
| `SIGNATURE_MISMATCH` | 算法与密钥都对，但签名确实校验不过（含篡改 payload、用错公钥） |

## 密钥轮换（支持跨算法族）

- 每个密钥带 `Alg`（绑定算法）、`NotBefore`/`NotAfter` 生效窗口与 `Retired` 标记。
- 轮换允许新旧密钥属于**不同算法族**：先 `Add` 新族密钥（如 RSA），旧族密钥（如 HMAC）保留宽限窗口。窗口内 `Resolve` 两者都可解析，**老令牌继续验过，新签发通过 `Current()`/`IssuerForCurrent()` 自动走 NotBefore 最新的新密钥**。
- 窗口结束或 `Retire` 后，旧密钥立即不可解析，对应令牌以 `UNKNOWN_KEY` 拒绝。
- HMAC 材料入库/出库均拷贝；全部操作在读写锁保护下完成，并发校验不会误用已吊销/过期密钥或跨族密钥。

## 版本化策略与历史回放

- `Publish([]Policy) int64` 每次发布都生成一个**不可变版本**（版本号从 1 单调递增）：策略切片被深拷贝冻结，调用方事后修改原切片不影响已发布版本。
- 线上 `Evaluate`/`engine.Authorize` **始终使用最新版本**；一次判定只解引用一次最新版本快照，因此整条依据链来自同一个版本——并发发布与并发判定混跑时不会出现半新半旧的策略集，也不会把不同版本的依据串在一起。
- 历史回放：`policy.Engine.Replay(version, req)` 或 `engine.Replay(tok, action, resource, version)`，拿某次历史判定的**输入 + 当时版本号**即可重算。因为版本不可变、判定是纯函数（多属性条件按键名排序，依据顺序也稳定），回放得到的结论、命中的 PERMIT/DENY 策略 ID、失败条件与解释与当初**逐字段一致**。版本号不存在返回 `policy.ErrUnknownVersion`。
- 判定结论合成规则仍为**拒绝优先（deny-overrides）**：

| 结论 | 含义 |
|---|---|
| `PERMIT` | 至少一条 PERMIT 命中且无 DENY 命中 |
| `DENY` | 任一 DENY 命中（冲突时 DENY 胜出，Trace 同时记录双方） |
| `CONDITION_FAILED` | 角色/动作/资源匹配，但属性条件不满足 |
| `NO_MATCH` | 没有任何策略覆盖 |

`Trace` 现额外携带 `Version` 字段，标明依据来自哪个策略版本。

## 本地验证方法

```bash
go build ./...              # 编译
go vet ./...                # 静态检查
go test ./... -v            # 运行全部测试，日志打印输入与各条判定依据
go test ./... -race -count=1   # 带竞态检测、强制重跑，结果可稳定复现
go run ./cmd/demo           # 端到端演示：8 个步骤串起完整链路
```

测试覆盖（均含输入与依据链日志）：

- **非对称签发/校验**：RS256/384/512、ES256/384/512 全算法本地签发并只用公钥验签（`token` 包）。
- **换算法伪造**：RS256→HS256（仅改头部、以及用公钥 DER 字节当 HMAC 密钥重签）、HS256→RS256 双向都判 `ALG_SUBSTITUTION`（`token` 与 `engine` 包）。
- **算法/密钥不匹配**：RS512 密钥配 RS256 头部、P-384 密钥配 ES256 头部 → `KEY_ALG_MISMATCH`；与 `ALG_NOT_ALLOWED`、`SIGNATURE_MISMATCH` 用例互相对照，原因彼此可区分。
- **存量兼容**：在「HMAC+RSA+ECDSA」混合放行清单下，老 HS256 令牌照常验签。
- **跨算法族轮换**：HMAC→RSA 重叠窗口双族并行、`Current()` 自动切到 RSA、窗口结束/吊销后老 HMAC 令牌 `UNKNOWN_KEY`（`keys` 与 `engine` 包），含 24 并发 × 200 轮跨族判定稳定性。
- **版本化与回放**：多版本发布后线上跟随最新、用历史输入+版本号回放结论与依据逐字段一致、冻结版本不受调用方修改影响、未知版本报错、多条件失败依据顺序稳定。
- **并发稳定性**：8 发布者 + 16 判定者 × 300 轮混跑，每条 Trace 都完整来自单一自洽版本（`-race`）。
- 既有的令牌篡改、会话吊销、策略冲突、端到端三阶段等用例全部保留，无回归。

## 最小使用示例

```go
ks := keys.NewStore()
now := time.Now()
// 存量 HMAC 密钥与新 RSA 密钥在重叠窗口内并存
ks.Add(keys.HMACKey("k-hmac", token.AlgHS256, []byte("legacy-secret"),
    now.Add(-24*time.Hour), now.Add(time.Hour)))
rsaKey, _ := keys.GenerateKey("k-rsa", token.AlgRS256, now, now.Add(24*time.Hour))
ks.Add(rsaKey)

ss := session.NewStore()
ss.Create(session.Session{ID: "s1", Subject: "alice", ExpiresAt: now.Add(time.Hour)})

pe := policy.NewEngine()
v1 := pe.Publish([]policy.Policy{{
    ID: "allow-read", Effect: policy.EffectPermit, Roles: []string{"reader"},
    Actions: []string{"read"}, Resources: []string{"doc/1"},
}})

verifier := token.NewVerifier(ks, 30*time.Second, token.AlgHS256, token.AlgRS256)
eng := engine.New(verifier, ss, pe)

// 新签发自动选择当前最新密钥（此处为 RSA）
issuer, _, _ := ks.IssuerForCurrent(now)
tok, _ := issuer.Issue(token.Claims{Subject: "alice", SessionID: "s1",
    Roles: []string{"reader"}}, 10*time.Minute)

res := eng.Authorize(tok, "read", "doc/1") // Allowed==true, Trace.Version==v1

// 后续发布 v2 后，仍可用 v1 回放历史结论
replayed, err := eng.Replay(tok, "read", "doc/1", v1)
```
