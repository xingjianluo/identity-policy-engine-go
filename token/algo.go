package token

// 本文件定义令牌支持的签名算法及其算法族划分。
//
// 对称族（HMAC）：HS256 / HS384 / HS512，签发与校验使用同一把共享密钥。
// RSA 族（RSASSA-PKCS#1 v1.5）：RS256 / RS384 / RS512，私钥签发、公钥校验。
// ECDSA 族：ES256 / ES384 / ES512，私钥签发、公钥校验。
//
// 算法族是防“换算法伪造”的关键边界：令牌头声明的算法与密钥注册的算法
// 必须属于同一族，否则按算法替换攻击拒绝（见 ReasonAlgSubstitution）。

// Family 表示算法族。
type Family string

const (
	FamilyHMAC  Family = "HMAC"
	FamilyRSA   Family = "RSA"
	FamilyECDSA Family = "ECDSA"
)

const (
	AlgRS256 Algorithm = "RS256"
	AlgRS384 Algorithm = "RS384"
	AlgRS512 Algorithm = "RS512"
	AlgES256 Algorithm = "ES256"
	AlgES384 Algorithm = "ES384"
	AlgES512 Algorithm = "ES512"
)

// familyFor 返回算法所属的族；未知算法返回空串。
func familyFor(a Algorithm) Family {
	return FamilyFor(a)
}

// FamilyFor 返回算法所属的族；未知算法返回空串。
func FamilyFor(a Algorithm) Family {
	switch a {
	case AlgHS256, AlgHS384, AlgHS512:
		return FamilyHMAC
	case AlgRS256, AlgRS384, AlgRS512:
		return FamilyRSA
	case AlgES256, AlgES384, AlgES512:
		return FamilyECDSA
	default:
		return ""
	}
}

// knownAlgorithm 判断算法是否受支持（属于某个已知算法族）。
func knownAlgorithm(a Algorithm) bool {
	return familyFor(a) != ""
}

// AllAlgorithms 返回引擎支持的全部算法，便于校验方按“放行全部算法族”配置。
func AllAlgorithms() []Algorithm {
	return []Algorithm{
		AlgHS256, AlgHS384, AlgHS512,
		AlgRS256, AlgRS384, AlgRS512,
		AlgES256, AlgES384, AlgES512,
	}
}

// AlgorithmsOfFamilies 按算法族生成算法白名单，校验方据此决定放行哪些算法族。
// 未知族会被忽略。
func AlgorithmsOfFamilies(families ...Family) []Algorithm {
	var out []Algorithm
	for _, a := range AllAlgorithms() {
		for _, f := range families {
			if familyFor(a) == f {
				out = append(out, a)
				break
			}
		}
	}
	return out
}
