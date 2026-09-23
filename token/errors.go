// Package token 提供本地令牌的签发与校验能力。
package token

// Reason 表示令牌校验失败的可区分原因。
type Reason string

const (
	ReasonNone              Reason = ""                   // 校验通过
	ReasonMalformed         Reason = "MALFORMED"          // 令牌结构无法解析
	ReasonAlgNotAllowed     Reason = "ALG_NOT_ALLOWED"    // 签名算法不在允许列表
	ReasonUnknownKey        Reason = "UNKNOWN_KEY"        // 找不到对应的密钥
	ReasonSignatureMismatch Reason = "SIGNATURE_MISMATCH" // 签名校验失败
	ReasonExpired           Reason = "EXPIRED"            // 令牌已过期
	ReasonNotYetValid       Reason = "NOT_YET_VALID"      // 令牌尚未生效
	ReasonMissingClaim      Reason = "MISSING_CLAIM"      // 必需声明缺失
)

// Error 是对外暴露的校验错误，只包含可区分原因，不透出底层库异常。
type Error struct {
	Reason  Reason
	Message string
}

func (e *Error) Error() string { return string(e.Reason) + ": " + e.Message }
