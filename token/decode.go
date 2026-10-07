// 历史回放专用的令牌解码：只还原令牌当初携带的输入（声明），
// 不做签名校验、密钥解析与 exp/nbf 时效检查。
package token

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// DecodeClaims 仅解析令牌结构并还原载荷中的声明，用于历史回放。
//
// 它刻意不做以下任何检查，因此绝不能用于实时访问授权：
//   - 不校验签名（签名可能因密钥轮换/吊销而无法再验证）；
//   - 不解析密钥、不检查算法白名单与算法族；
//   - 不检查 exp/nbf（回放的意义就是还原令牌如今已过期后的当时结论）。
//
// 仅当令牌结构无法解析（非三段式、base64 或 JSON 非法）时返回错误，
// 保证回放失败的原因可识别，而不是被伪装成一条判定结论。
func DecodeClaims(tok string) (Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return Claims{}, fail(ReasonMalformed, "token must have 3 segments, got %d", len(parts))
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fail(ReasonMalformed, "payload is not valid base64url")
	}
	var cj claimsJSON
	if err := json.Unmarshal(pb, &cj); err != nil {
		return Claims{}, fail(ReasonMalformed, "payload is not valid JSON")
	}
	c := Claims{Roles: cj.Roles, Attrs: cj.Attrs, KeyID: cj.KeyID}
	if cj.Subject != nil {
		c.Subject = *cj.Subject
	}
	if cj.SessionID != nil {
		c.SessionID = *cj.SessionID
	}
	if cj.IssuedAt != nil {
		c.IssuedAt = time.Unix(*cj.IssuedAt, 0)
	}
	if cj.ExpiresAt != nil {
		c.ExpiresAt = time.Unix(*cj.ExpiresAt, 0)
	}
	if cj.NotBefore != 0 {
		c.NotBefore = time.Unix(cj.NotBefore, 0)
	}
	return c, nil
}
