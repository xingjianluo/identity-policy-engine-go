package token

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestDecodeClaimsForReplay 回放专用解码：不验签、不查密钥、不看时效，
// 只还原输入；结构损坏才返回可识别的 MALFORMED。
func TestDecodeClaimsForReplay(t *testing.T) {
	iss := NewIssuer(HMACKey(AlgHS256, "k1", []byte("secret-1"))).WithKID("k1")
	want := Claims{Subject: "alice", SessionID: "sess-1",
		Roles: []string{"reader"}, Attrs: map[string]string{"dept": "eng"}}

	// 1) 已过期令牌：仍能还原当初输入
	expired, err := iss.Issue(want, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeClaims(expired)
	if err != nil {
		t.Fatalf("decoding an expired token for replay must not error: %v", err)
	}
	if got.Subject != "alice" || got.SessionID != "sess-1" ||
		len(got.Roles) != 1 || got.Roles[0] != "reader" || got.Attrs["dept"] != "eng" {
		t.Fatalf("replay decode mismatch: %+v", got)
	}
	t.Logf("expired token decoded for replay: sub=%s roles=%v attrs=%v exp=%s",
		got.Subject, got.Roles, got.Attrs, got.ExpiresAt.Format(time.RFC3339))

	// 2) 签名被破坏 / 用错密钥：DecodeClaims 不验签，输入照常还原
	wrong := NewIssuer(HMACKey(AlgHS256, "k1", []byte("other-secret"))).WithKID("k1")
	badSig, err := wrong.Issue(want, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeClaims(badSig); err != nil || got.Subject != "alice" {
		t.Fatalf("decode must ignore signature, got claims=%+v err=%v", got, err)
	}
	t.Log("wrong-signature token payload still decoded for replay (signature intentionally ignored)")

	// 3) 结构损坏：必须返回 MALFORMED，且可识别
	for _, bad := range []string{"", "only.one", "a.b.c", "not-a-token"} {
		_, err := DecodeClaims(bad)
		var te *Error
		if !errors.As(err, &te) || te.Reason != ReasonMalformed {
			t.Fatalf("malformed token %q must yield *Error/MALFORMED, got %v", bad, err)
		}
		if !strings.Contains(err.Error(), string(ReasonMalformed)) {
			t.Fatalf("error message must carry reason, got %v", err)
		}
	}
	t.Log("malformed/garbage tokens yield recognizable MALFORMED error")
}
