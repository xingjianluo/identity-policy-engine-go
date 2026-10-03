package engine

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// forgeAlgHeader 仅替换令牌头部的 alg，payload 与签名段保持不变，
// 用于模拟换算法（alg-substitution）伪造。
func forgeAlgHeader(t *testing.T, tok, alg string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token must have 3 segments: %q", tok)
	}
	var hdr map[string]any
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatal(err)
	}
	hdr["alg"] = alg
	hb, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	parts[0] = base64.RawURLEncoding.EncodeToString(hb)
	return strings.Join(parts, ".")
}
