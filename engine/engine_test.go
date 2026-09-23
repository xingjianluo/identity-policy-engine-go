package engine

import (
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/identity-policy-engine-go/keystore"
	"github.com/xingjianluo/identity-policy-engine-go/policy"
	"github.com/xingjianluo/identity-policy-engine-go/session"
	"github.com/xingjianluo/identity-policy-engine-go/token"
)

type harness struct {
	eng    *Engine
	now    time.Time
	oldSec []byte
	newSec []byte
}

func newHarness(t *testing.T, allowed map[token.Algorithm]bool) *harness {
	t.Helper()
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	now := base
	clock := func() time.Time { return now }

	keys := keystore.NewStore()
	sessions := session.NewStore()
	policies := policy.NewEngine()

	oldSec, err := keystore.GenerateHMACKey()
	if err != nil {
		t.Fatal(err)
	}
	newSec, err := keystore.GenerateHMACKey()
	if err != nil {
		t.Fatal(err)
	}
	// 旧密钥 [t0-2h, t0+1h)；新密钥 [t0-30m, t0+24h)，重叠 1.5 小时。
	mustAddKey(t, keys, "k-old", token.HS256, oldSec, oldSec, now.Add(-2*time.Hour), now.Add(time.Hour))
	mustAddKey(t, keys, "k-new", token.HS256, newSec, newSec, now.Add(-30*time.Minute), now.Add(24*time.Hour))

	eng := New(Config{
		AllowedAlgorithms: allowed,
		Leeway:            5 * time.Second,
		Issuer:            "local-test",
		Clock:             clock,
	}, keys, sessions, policies)

	policies.Replace([]policy.Rule{
		{ID: "reader-read", Name: "reader reads docs", Effect: policy.EffectAllow,
			Roles: []string{"reader"}, Actions: []string{"read"}, Resource: "doc:design"},
		{ID: "deny-secret", Name: "deny secret docs", Effect: policy.EffectDeny,
			Roles: []string{"reader"}, Actions: []string{"read"}, Resource: "doc:design",
			Conditions: []policy.Condition{{Source: "resource", Key: "classification", Operator: "eq", Value: "secret"}}},
	})

	return &harness{
		eng:    eng,
		now:    now,
		oldSec: oldSec,
		newSec: newSec,
	}
}

func mustAddKey(t *testing.T, s *keystore.Store, id string, alg token.Algorithm, sk, vk interface{}, nb, exp time.Time) {
	t.Helper()
	if err := s.Add(keystore.SigningKey{
		ID: id, Algorithm: alg, SigningKey: sk, VerifyKey: vk, NotBefore: nb, ExpiresAt: exp,
	}); err != nil {
		t.Fatalf("add key %s: %v", id, err)
	}
}

func readReq(raw, classification string) AccessRequest {
	return AccessRequest{
		RawToken: raw, Action: "read", Resource: "doc:design",
		ResourceAttrs: map[string]string{"classification": classification},
	}
}

func TestEndToEndAllowAndDeny(t *testing.T) {
	h := newHarness(t, map[token.Algorithm]bool{token.HS256: true})

	raw, err := h.eng.IssueToken("alice", []string{"reader"}, map[string]string{"dept": "platform"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("issued token: %.70s...", raw)

	r := h.eng.Authorize(readReq(raw, "public"))
	t.Logf("input classification=public | decision: allowed=%v stage=%s code=%s", r.Allowed, r.Stage, r.Code)
	if !r.Allowed || r.Policy.Decision != policy.DecisionAllow {
		t.Fatalf("public doc should be allowed, got %+v", r)
	}

	r = h.eng.Authorize(readReq(raw, "secret"))
	t.Logf("input classification=secret | decision: allowed=%v reason=%s code=%s matchedRule=%s",
		r.Allowed, r.Reason, r.Code, r.Policy.MatchedRule.RuleID)
	if r.Allowed || r.Code != string(policy.DecisionDenyByRule) || r.Policy.MatchedRule.RuleID != "deny-secret" {
		t.Fatalf("secret doc must be deny_by_rule, got %+v", r)
	}
}

func TestEndToEndTamperedToken(t *testing.T) {
	h := newHarness(t, map[token.Algorithm]bool{token.HS256: true})
	raw, err := h.eng.IssueToken("alice", []string{"reader"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(raw, ".")
	sig, _ := b64decode(parts[2])
	sig[0] ^= 0x01
	parts[2] = b64encode(sig)
	tampered := strings.Join(parts, ".")

	r := h.eng.Authorize(readReq(tampered, "public"))
	t.Logf("input tampered token | decision: allowed=%v reason=%s code=%s", r.Allowed, r.Reason, r.Code)
	if r.Allowed || r.Reason != ReasonTokenRejected || r.Code != string(token.ReasonSignatureInvalid) {
		t.Fatalf("tampered token: %+v", r)
	}
}

func TestEndToEndAlgorithmNotAllowed(t *testing.T) {
	// 引擎只允许 RS256，但用 HMAC 密钥签发 => 算法不在白名单。
	h := newHarness(t, map[token.Algorithm]bool{token.RS256: true})
	raw, err := h.eng.IssueToken("alice", []string{"reader"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := h.eng.Authorize(readReq(raw, "public"))
	t.Logf("input HS256 token, allowlist=RS256 | decision: code=%s", r.Code)
	if r.Allowed || r.Code != string(token.ReasonAlgorithmNotAllowed) {
		t.Fatalf("alg not allowed: %+v", r)
	}
}

func TestEndToEndKeyRotationWindow(t *testing.T) {
	h := newHarness(t, map[token.Algorithm]bool{token.HS256: true})

	// 用“旧密钥”手工签发一张令牌并建会话，模拟轮换前已签发的令牌。
	oldKey, ok := h.eng.Keys().Get("k-old")
	if !ok {
		t.Fatal("old key missing")
	}
	claims := token.Claims{
		Issuer: "local-test", Subject: "alice", ID: "legacy-session",
		ExpiresAt: h.now.Add(30 * time.Minute).Unix(), IssuedAt: h.now.Unix(),
		Roles: []string{"reader"},
	}
	legacy, err := token.Sign(claims, token.HS256, oldKey.ID, oldKey.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.eng.Sessions().Create(session.Session{
		ID: "legacy-session", Subject: "alice", Roles: []string{"reader"},
		ExpiresAt: h.now.Add(30 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	// 新签发使用活跃（最新）密钥 k-new。
	newTok, err := h.eng.IssueToken("bob", []string{"reader"}, nil, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id, aerr := h.eng.Authenticate(newTok)
	if aerr != nil {
		t.Fatal(aerr)
	}
	// k-new 签发令牌的 jti 对应会话，确认其验签用的是新密钥：直接判允许。
	r := h.eng.Authorize(readReq(newTok, "public"))
	t.Logf("input new-key token during overlap | decision: allowed=%v", r.Allowed)
	if !r.Allowed {
		t.Fatalf("new token: %+v", r)
	}

	// 重叠窗口内旧密钥令牌仍被接受。
	r = h.eng.Authorize(readReq(legacy, "public"))
	t.Logf("input legacy token during overlap | decision: allowed=%v code=%s", r.Allowed, r.Code)
	if !r.Allowed {
		t.Fatalf("legacy token must work in overlap: %+v", r)
	}
	_ = id
}

func TestEndToEndSessionRevocationImmediate(t *testing.T) {
	h := newHarness(t, map[token.Algorithm]bool{token.HS256: true})
	raw, err := h.eng.IssueToken("alice", []string{"reader"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id, aerr := h.eng.Authenticate(raw)
	if aerr != nil {
		t.Fatal(aerr)
	}
	h.eng.Sessions().Revoke(id.TokenID)
	r := h.eng.Authorize(readReq(raw, "public"))
	t.Logf("input token after session revoke | decision: allowed=%v reason=%s code=%s",
		r.Allowed, r.Reason, r.Code)
	if r.Allowed || r.Reason != ReasonSessionReject || r.Code != string(session.StatusRevoked) {
		t.Fatalf("revoked session: %+v", r)
	}
}

func TestEndToEndMissingSession(t *testing.T) {
	h := newHarness(t, map[token.Algorithm]bool{token.HS256: true})
	oldKey, _ := h.eng.Keys().Get("k-old")
	claims := token.Claims{
		Issuer: "local-test", Subject: "ghost", ID: "no-such-session",
		ExpiresAt: h.now.Add(time.Hour).Unix(), Roles: []string{"reader"},
	}
	raw, err := token.Sign(claims, token.HS256, oldKey.ID, oldKey.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	r := h.eng.Authorize(readReq(raw, "public"))
	t.Logf("input valid token without session | decision: code=%s", r.Code)
	if r.Allowed || r.Code != string(session.StatusNotFound) {
		t.Fatalf("missing session: %+v", r)
	}
}

func TestEndToEndConcurrentAuthorizeRevoke(t *testing.T) {
	h := newHarness(t, map[token.Algorithm]bool{token.HS256: true})
	raw, err := h.eng.IssueToken("alice", []string{"reader"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id, aerr := h.eng.Authenticate(raw)
	if aerr != nil {
		t.Fatal(aerr)
	}

	const n = 64
	const preIter = 100
	const postIter = 200
	var wg sync.WaitGroup
	start := make(chan struct{})
	ready := make(chan struct{}, n)
	proceed := make(chan struct{})
	var acceptedAfter, rejectedAfter int64
	var mu sync.Mutex

	for g := 0; g < n; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < preIter; i++ {
				if r := h.eng.Authorize(readReq(raw, "public")); !r.Allowed {
					t.Errorf("pre-revocation authorize rejected: %s/%s", r.Reason, r.Code)
					return
				}
			}
			ready <- struct{}{}
			<-proceed
			for i := 0; i < postIter; i++ {
				r := h.eng.Authorize(readReq(raw, "public"))
				mu.Lock()
				if r.Allowed {
					acceptedAfter++
				} else if r.Code == string(session.StatusRevoked) {
					rejectedAfter++
				}
				mu.Unlock()
			}
		}()
	}
	close(start)
	for g := 0; g < n; g++ {
		<-ready
	}
	h.eng.Sessions().Revoke(id.TokenID)
	close(proceed)
	wg.Wait()

	t.Logf("input concurrent Authorize: pre=%d all allowed | post=%d revoked, accepted=%d",
		n*preIter, rejectedAfter, acceptedAfter)
	if acceptedAfter != 0 {
		t.Fatalf("revoked session accepted %d times concurrently", acceptedAfter)
	}
	if rejectedAfter != n*postIter {
		t.Fatalf("post-revocation rejected=%d want=%d", rejectedAfter, n*postIter)
	}
}

func b64decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
func b64encode(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
