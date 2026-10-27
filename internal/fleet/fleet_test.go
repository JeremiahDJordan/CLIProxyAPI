package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	cliproxysession "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/session"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

var t0 = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

const claudeUserID = `{"device_id":"0000000000000000000000000000000000000000000000000000000000000000","account_uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","session_id":"11111111-2222-4333-8444-555555555555"}`

func digest(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func testSettings(t *testing.T, extra string) Settings {
	t.Helper()
	yaml := "enabled: true\nkeys:\n" +
		"  - name: claude-code\n    sha256: " + digest("claude-secret") + "\n    providers: [claude]\n" +
		"  - name: codex\n    sha256: " + digest("codex-secret") + "\n    providers: [codex]\n" + extra
	s, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	return s
}

func claudeCodeRequest(body string) pluginapi.RequestInterceptRequest {
	if body == "" {
		encoded, _ := json.Marshal(claudeUserID)
		body = `{"model":"claude-opus-5-5","metadata":{"user_id":` + string(encoded) + `}}`
	}
	return pluginapi.RequestInterceptRequest{
		RequestID:    "req-1",
		SourceFormat: "claude",
		Headers: http.Header{
			"User-Agent":               {"claude-cli/2.1.280 (external, cli)"},
			"X-App":                    {"cli"},
			"Anthropic-Beta":           {"claude-code-20250219,interleaved-thinking-2025-05-14"},
			"X-Claude-Code-Session-Id": {"cc-session-1"},
		},
		Body:     []byte(body),
		Metadata: map[string]any{"request_path": "/v1/messages"},
	}
}

func codexRequest() pluginapi.RequestInterceptRequest {
	return pluginapi.RequestInterceptRequest{
		RequestID:    "req-2",
		SourceFormat: "openai-response",
		Headers: http.Header{
			"User-Agent": {"codex_cli_rs/0.164.0 (Mac OS 27.0.1; arm64) Terminal"},
			"Originator": {"codex_cli_rs"},
			"Session-Id": {"codex-session-1"},
		},
	}
}

func scopeFor(s Settings, name string) string {
	for _, k := range s.Keys {
		if k.Name == name {
			return k.CallerScope
		}
	}
	return ""
}

func TestParseConfigDefaultsAndValidation(t *testing.T) {
	s := testSettings(t, "")
	if !s.Exclusive || !s.GateEnabled || !s.SchedulerEnabled || !s.DenyUnknownCallers {
		t.Fatalf("defaults not applied: %+v", s)
	}
	if s.ClaudeCacheTTL != 5*time.Minute || s.ClaudeExtendedCacheTTL != time.Hour || s.CodexIdleTTL != time.Hour {
		t.Fatalf("ttl defaults wrong: %v %v %v", s.ClaudeCacheTTL, s.ClaudeExtendedCacheTTL, s.CodexIdleTTL)
	}
	if !s.GatedProviders["claude"] || !s.GatedProviders["codex"] || !s.ClaudeEntrypoints["sdk-ts"] {
		t.Fatalf("provider/entrypoint defaults wrong: %+v", s)
	}
	for _, bad := range []string{
		"keys:\n  - name: a\n    sha256: nothex\n    providers: [claude]\n",
		"keys:\n  - name: a\n    sha256: " + digest("x") + "\n",
		"keys:\n  - name: a\n    sha256: " + digest("x") + "\n    providers: [claude]\n  - name: a\n    sha256: " + digest("y") + "\n    providers: [codex]\n",
		"scheduler:\n  codex-idle-ttl: soon\n",
	} {
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
	none, _ := ParseConfig(nil)
	if none.Exclusive {
		t.Fatal("exclusive must default false without keys")
	}
}

func TestCallerScopeMatchesHost(t *testing.T) {
	for _, principal := range []string{"fleet:claude-code", "fleet:codex"} {
		if CallerScope(principal) != cliproxysession.CallerScope(principal) {
			t.Fatalf("caller scope for %s differs from host implementation", principal)
		}
	}
}

func TestAuthenticateKeys(t *testing.T) {
	s := testSettings(t, "")
	cases := []struct {
		headers http.Header
		want    string
	}{
		{http.Header{"Authorization": {"Bearer claude-secret"}}, "fleet:claude-code"},
		{http.Header{"X-Api-Key": {"codex-secret"}}, "fleet:codex"},
		{http.Header{"Authorization": {"Bearer wrong"}}, ""},
		{http.Header{}, ""},
	}
	for _, c := range cases {
		resp := Authenticate(s, pluginapi.FrontendAuthRequest{Headers: c.headers})
		if resp.Authenticated != (c.want != "") || resp.Principal != c.want {
			t.Errorf("headers %v: got %+v, want principal %q", c.headers, resp, c.want)
		}
	}
}

func TestGateAcceptsNativeClaudeCodeAndCodex(t *testing.T) {
	s := testSettings(t, "")
	if d := Evaluate(s, Classify(s, claudeCodeRequest("")), "claude", scopeFor(s, "claude-code")); !d.Allow {
		t.Fatalf("native Claude Code rejected: %+v", d)
	}
	if d := Evaluate(s, Classify(s, codexRequest()), "codex", scopeFor(s, "codex")); !d.Allow {
		t.Fatalf("official Codex rejected: %+v", d)
	}
}

func TestGateRejectsImpostorsAndTranslation(t *testing.T) {
	s := testSettings(t, "")
	claudeScope, codexScope := scopeFor(s, "claude-code"), scopeFor(s, "codex")

	copiedUA := claudeCodeRequest("")
	copiedUA.Headers = http.Header{"User-Agent": {"claude-cli/2.1.280 (external, cli)"}}
	if d := Evaluate(s, Classify(s, copiedUA), "claude", claudeScope); d.Allow || d.Code != "fleet_claude_client" {
		t.Errorf("copied User-Agent allowed: %+v", d)
	}

	openAIForClaude := claudeCodeRequest("")
	openAIForClaude.SourceFormat = "openai"
	if d := Evaluate(s, Classify(s, openAIForClaude), "claude", claudeScope); d.Allow || d.Code != "fleet_claude_format" {
		t.Errorf("translated OpenAI request allowed for Claude: %+v", d)
	}

	sdkPy := claudeCodeRequest("")
	sdkPy.Headers.Set("User-Agent", "claude-cli/2.1.280 (external, sdk-py)")
	if d := Evaluate(s, Classify(s, sdkPy), "claude", claudeScope); d.Allow {
		t.Errorf("non-native entrypoint allowed: %+v", d)
	}

	uaOnly := codexRequest()
	uaOnly.Headers.Del("Originator")
	if d := Evaluate(s, Classify(s, uaOnly), "codex", codexScope); d.Allow || d.Code != "fleet_codex_client" {
		t.Errorf("Codex without Originator allowed: %+v", d)
	}

	other := codexRequest()
	other.Headers.Set("User-Agent", "pi/1.0")
	if d := Evaluate(s, Classify(s, other), "codex", codexScope); d.Allow {
		t.Errorf("non-Codex User-Agent allowed: %+v", d)
	}

	chat := codexRequest()
	chat.SourceFormat = "openai"
	if d := Evaluate(s, Classify(s, chat), "codex", codexScope); d.Allow || d.Code != "fleet_codex_format" {
		t.Errorf("Chat Completions request allowed for Codex: %+v", d)
	}
}

func TestGatePrincipalScoping(t *testing.T) {
	s := testSettings(t, "")
	if d := Evaluate(s, Classify(s, claudeCodeRequest("")), "claude", scopeFor(s, "codex")); d.Allow || d.Code != "fleet_key_provider_denied" {
		t.Errorf("codex key reached Claude: %+v", d)
	}
	if d := Evaluate(s, Classify(s, codexRequest()), "codex", scopeFor(s, "claude-code")); d.Allow || d.Code != "fleet_key_provider_denied" {
		t.Errorf("claude key reached Codex: %+v", d)
	}
	if d := Evaluate(s, Classify(s, codexRequest()), "gemini", scopeFor(s, "codex")); d.Allow {
		t.Errorf("codex key reached an unlisted provider: %+v", d)
	}
	if d := Evaluate(s, Classify(s, codexRequest()), "codex", ""); d.Allow || d.Code != "fleet_unknown_caller" {
		t.Errorf("unknown caller reached Codex: %+v", d)
	}
	open := testSettings(t, "gate:\n  deny-unknown-callers: false\n")
	if d := Evaluate(open, Classify(open, codexRequest()), "codex", ""); !d.Allow {
		t.Errorf("unknown caller should pass when allowed: %+v", d)
	}
	if d := Evaluate(s, Classification{}, "gemini", ""); !d.Allow {
		t.Errorf("ungated provider without a fleet key should pass: %+v", d)
	}
}

func TestDenialIsJSON403(t *testing.T) {
	resp := Denial(Decision{Code: "fleet_x", Reason: "nope"})
	if !resp.Terminate || resp.StatusCode != http.StatusForbidden || !strings.Contains(string(resp.ResponseBody), `"fleet_x"`) {
		t.Fatalf("unexpected denial %+v", resp)
	}
}

func claudeHeaders(fiveUtil, weekUtil float64, fiveReset, weekReset time.Time, extra map[string]string) http.Header {
	h := http.Header{}
	h.Set("Anthropic-Ratelimit-Unified-5h-Status", "allowed")
	h.Set("Anthropic-Ratelimit-Unified-5h-Utilization", strconv.FormatFloat(fiveUtil, 'f', 2, 64))
	h.Set("Anthropic-Ratelimit-Unified-5h-Reset", strconv.FormatInt(fiveReset.Unix(), 10))
	h.Set("Anthropic-Ratelimit-Unified-7d-Status", "allowed")
	h.Set("Anthropic-Ratelimit-Unified-7d-Utilization", strconv.FormatFloat(weekUtil, 'f', 2, 64))
	h.Set("Anthropic-Ratelimit-Unified-7d-Reset", strconv.FormatInt(weekReset.Unix(), 10))
	h.Set("Anthropic-Ratelimit-Unified-Overage-Status", "rejected")
	for k, v := range extra {
		h.Set(k, v)
	}
	return h
}

func TestParseClaudeWindows(t *testing.T) {
	b := NewQuotaBook()
	h := claudeHeaders(0.4, 0.9, t0.Add(2*time.Hour), t0.Add(48*time.Hour), map[string]string{
		"Anthropic-Ratelimit-Unified-7d_oi-Status":      "rejected",
		"Anthropic-Ratelimit-Unified-7d_oi-Reset":       strconv.FormatInt(t0.Add(24*time.Hour).Unix(), 10),
		"Anthropic-Ratelimit-Unified-7d_oi-Utilization": "1.0",
	})
	if !b.Observe("claude", "a", "claude-opus-5-5", h, t0) {
		t.Fatal("headers not recognized")
	}
	a, _ := b.Snapshot("a")
	if _, ok := a.Windows["overage"]; ok {
		t.Fatal("overage must not be a scheduling window")
	}
	if a.Windows["5h"].Kind != kindFiveHour || a.Windows["7d"].Kind != kindWeekly || !a.Windows["7d_oi"].Rejected {
		t.Fatalf("windows parsed wrong: %+v", a.Windows)
	}
	if a.ModelWeekly["claude-opus-5-5"] != "7d_oi" {
		t.Fatalf("model-specific weekly not mapped: %+v", a.ModelWeekly)
	}
	opus := ViewFor(a, "claude-opus-5-5", t0)
	if !opus.WeeklyBlock || opus.WeeklyWindow != "7d_oi" {
		t.Fatalf("opus view should be blocked by 7d_oi: %+v", opus)
	}
	sonnet := ViewFor(a, "claude-sonnet-5-5", t0)
	if sonnet.WeeklyBlock || sonnet.WeeklyWindow != "7d" || !sonnet.WeeklyResetAt.Equal(t0.Add(48*time.Hour)) {
		t.Fatalf("sonnet view should use the general weekly window: %+v", sonnet)
	}
}

func TestParseCodexWindows(t *testing.T) {
	h := http.Header{}
	h.Set("X-Codex-Primary-Used-Percent", "35")
	h.Set("X-Codex-Primary-Window-Minutes", "300")
	h.Set("X-Codex-Primary-Reset-After-Seconds", "3600")
	h.Set("X-Codex-Secondary-Used-Percent", "60")
	h.Set("X-Codex-Secondary-Window-Minutes", "10080")
	h.Set("X-Codex-Secondary-Reset-At", strconv.FormatInt(t0.Add(72*time.Hour).Unix(), 10))
	h.Set("X-Codex-Bengalfox-Secondary-Used-Percent", "100")
	h.Set("X-Codex-Bengalfox-Secondary-Window-Minutes", "10080")
	h.Set("X-Codex-Bengalfox-Secondary-Reset-At", strconv.FormatInt(t0.Add(24*time.Hour).Unix(), 10))
	h.Set("X-Codex-Code-Review-Primary-Used-Percent", "100")
	h.Set("X-Codex-Code-Review-Primary-Window-Minutes", "300")
	h.Set("X-Codex-Code-Review-Primary-Reset-After-Seconds", "60")
	b := NewQuotaBook()
	b.Observe("codex", "c", "gpt-6-1-codex-spark", h, t0)
	a, _ := b.Snapshot("c")
	if _, ok := a.Windows["code-review-primary"]; ok {
		t.Fatal("code-review windows must be ignored")
	}
	if w := a.Windows["primary"]; w.Kind != kindFiveHour || w.Used != 0.35 || !w.ResetAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("primary parsed wrong: %+v", w)
	}
	if w := a.Windows["secondary"]; w.Kind != kindWeekly || !w.ResetAt.Equal(t0.Add(72*time.Hour)) {
		t.Fatalf("secondary parsed wrong: %+v", w)
	}
	if a.ModelWeekly["gpt-6-1-codex-spark"] != "bengalfox-secondary" {
		t.Fatalf("named limit not mapped to the model: %+v", a.ModelWeekly)
	}
	if v := ViewFor(a, "gpt-6-1-codex-spark", t0); !v.WeeklyBlock {
		t.Fatalf("spark should be blocked by its named weekly limit: %+v", v)
	}
	if v := ViewFor(a, "gpt-6-1", t0); v.Excluded() || v.WeeklyWindow != "secondary" {
		t.Fatalf("other models should use the shared weekly window: %+v", v)
	}
}

func TestWindowRefreshesAfterReset(t *testing.T) {
	w := Window{Kind: kindFiveHour, Used: 1, Rejected: true, ResetAt: t0, Period: fiveHourPeriod}
	if !w.Exhausted(t0.Add(-time.Minute)) {
		t.Fatal("window should be exhausted before its reset")
	}
	if w.Exhausted(t0.Add(time.Minute)) {
		t.Fatal("window should refresh after its reset")
	}
	if e := w.effective(t0.Add(11 * time.Hour)); !e.ResetAt.Equal(t0.Add(15 * time.Hour)) {
		t.Fatalf("next reset projected wrong: %v", e.ResetAt)
	}
}

func TestManualResetDetection(t *testing.T) {
	b := NewQuotaBook()
	b.Observe("claude", "a", "m", claudeHeaders(0.9, 0.95, t0.Add(3*time.Hour), t0.Add(48*time.Hour), nil), t0)
	b.Observe("claude", "a", "m", claudeHeaders(0.0, 0.0, t0.Add(5*time.Hour), t0.Add(7*24*time.Hour), nil), t0.Add(time.Minute))
	a, _ := b.Snapshot("a")
	if a.ManualResets == 0 {
		t.Fatal("early reset not detected")
	}
	if a.Windows["7d"].Used != 0 {
		t.Fatal("latest observation must replace the window")
	}
}

func candidates(ids ...string) []pluginapi.SchedulerAuthCandidate {
	out := make([]pluginapi.SchedulerAuthCandidate, 0, len(ids))
	for _, id := range ids {
		out = append(out, pluginapi.SchedulerAuthCandidate{ID: id, Provider: "claude", Priority: 0})
	}
	return out
}

func rankIDs(r []Ranked) string {
	ids := make([]string, len(r))
	for i, x := range r {
		ids[i] = x.AuthID
	}
	return strings.Join(ids, ",")
}

func TestRankWeeklySoonestWithExclusions(t *testing.T) {
	b := NewQuotaBook()
	// soon: weekly resets in 1 day; later: 3 days; latest: 5 days.
	b.Observe("claude", "soon", "m", claudeHeaders(0.2, 0.5, t0.Add(time.Hour), t0.Add(24*time.Hour), nil), t0)
	b.Observe("claude", "later", "m", claudeHeaders(0.2, 0.5, t0.Add(time.Hour), t0.Add(72*time.Hour), nil), t0)
	b.Observe("claude", "latest", "m", claudeHeaders(0.2, 0.1, t0.Add(time.Hour), t0.Add(120*time.Hour), nil), t0)
	if got := rankIDs(Rank(b, candidates("latest", "later", "soon"), "m", t0)); got != "soon,later,latest" {
		t.Fatalf("order = %s", got)
	}
	// Exhaust soon's 5-hour window: the next soonest weekly account wins.
	b.Observe("claude", "soon", "m", claudeHeaders(1.0, 0.6, t0.Add(time.Hour), t0.Add(24*time.Hour), map[string]string{"Anthropic-Ratelimit-Unified-5h-Status": "rejected"}), t0)
	if got := rankIDs(Rank(b, candidates("latest", "later", "soon"), "m", t0)); got != "later,latest" {
		t.Fatalf("5h-exhausted account not skipped: %s", got)
	}
	// After the 5-hour window resets, soon returns to the front.
	if got := rankIDs(Rank(b, candidates("latest", "later", "soon"), "m", t0.Add(2*time.Hour))); got != "soon,later,latest" {
		t.Fatalf("5h reset not honored: %s", got)
	}
	// Weekly exhaustion also excludes.
	b.Observe("claude", "later", "m", claudeHeaders(0.1, 1.0, t0.Add(time.Hour), t0.Add(72*time.Hour), map[string]string{"Anthropic-Ratelimit-Unified-7d-Status": "rejected"}), t0)
	if got := rankIDs(Rank(b, candidates("later", "latest"), "m", t0)); got != "latest" {
		t.Fatalf("weekly-exhausted account not skipped: %s", got)
	}
}

func TestRankUnknownAfterKnownAndTieBreak(t *testing.T) {
	b := NewQuotaBook()
	reset := t0.Add(48 * time.Hour)
	b.Observe("claude", "more-left", "m", claudeHeaders(0.1, 0.2, t0.Add(time.Hour), reset, nil), t0)
	b.Observe("claude", "less-left", "m", claudeHeaders(0.1, 0.7, t0.Add(time.Hour), reset, nil), t0)
	c := candidates("new-b", "less-left", "new-a", "more-left")
	c[0].Priority = 5 // higher host priority sorts first among unknown accounts
	if got := rankIDs(Rank(b, c, "m", t0)); got != "more-left,less-left,new-b,new-a" {
		t.Fatalf("order = %s", got)
	}
}

func pickReq(session string, ids ...string) pluginapi.SchedulerPickRequest {
	return pluginapi.SchedulerPickRequest{
		Provider:   "claude",
		Model:      "m",
		Options:    pluginapi.SchedulerOptions{Headers: http.Header{"X-Claude-Code-Session-Id": {session}}},
		Candidates: candidates(ids...),
	}
}

func newTestPlugin(t *testing.T, extra string) (*Plugin, *time.Time) {
	t.Helper()
	p := New()
	now := t0
	p.Now = func() time.Time { return now }
	p.settings = testSettings(t, extra)
	return p, &now
}

func TestPickAffinityHonorsClaudeCacheLifetime(t *testing.T) {
	p, now := newTestPlugin(t, "")
	p.Book.Observe("claude", "later", "m", claudeHeaders(0.1, 0.5, t0.Add(time.Hour), t0.Add(72*time.Hour), nil), t0)
	resp, d := p.Pick(pickReq("s1", "later"))
	if resp.AuthID != "later" || !resp.Handled {
		t.Fatalf("first pick: %+v %+v", resp, d)
	}
	// A sooner-weekly account appears; the session stays put while its cache is warm.
	p.Book.Observe("claude", "soon", "m", claudeHeaders(0.1, 0.5, t0.Add(time.Hour), t0.Add(24*time.Hour), nil), t0)
	*now = t0.Add(4 * time.Minute)
	if resp, d := p.Pick(pickReq("s1", "later", "soon")); resp.AuthID != "later" || d.Reason != "affinity" {
		t.Fatalf("warm session moved: %+v %+v", resp, d)
	}
	// Idle past the default 5-minute Claude cache: re-placed by the weekly rule.
	*now = now.Add(6 * time.Minute)
	if resp, d := p.Pick(pickReq("s1", "later", "soon")); resp.AuthID != "soon" || !strings.HasPrefix(d.Reason, "affinity-expired") {
		t.Fatalf("cold session not re-placed: %+v %+v", resp, d)
	}
	// A new session goes straight to the soonest weekly account.
	if resp, _ := p.Pick(pickReq("s2", "later", "soon")); resp.AuthID != "soon" {
		t.Fatalf("new session: %+v", resp)
	}
}

func TestPickExtendedClaudeCacheAndCodexTTL(t *testing.T) {
	p, now := newTestPlugin(t, "scheduler:\n  codex-idle-ttl: 30m\n")
	p.Book.Observe("claude", "later", "m", claudeHeaders(0.1, 0.5, t0.Add(time.Hour), t0.Add(72*time.Hour), nil), t0)
	// The session's request asked for a one-hour cache.
	body := `{"system":[{"type":"text","text":"x","cache_control":{"type":"ephemeral","ttl":"1h"}}]}`
	req := claudeCodeRequest(body)
	req.Headers.Set("X-Claude-Code-Session-Id", "s-long")
	raw, _ := json.Marshal(req)
	p.Handle(pluginabi.MethodRequestInterceptBefore, raw)
	p.Pick(pickReq("s-long", "later"))
	p.Book.Observe("claude", "soon", "m", claudeHeaders(0.1, 0.5, t0.Add(time.Hour), t0.Add(24*time.Hour), nil), t0)
	*now = t0.Add(40 * time.Minute)
	if resp, d := p.Pick(pickReq("s-long", "later", "soon")); resp.AuthID != "later" || d.Reason != "affinity" {
		t.Fatalf("1h cache session moved at 40m: %+v %+v", resp, d)
	}
	if ttl := p.Sessions.TTLFor(p.Settings(), "codex", "x"); ttl != 30*time.Minute {
		t.Fatalf("codex ttl = %v", ttl)
	}
}

func TestPickRebindsWhenBoundAccountExhausted(t *testing.T) {
	p, now := newTestPlugin(t, "")
	p.Book.Observe("claude", "a", "m", claudeHeaders(0.1, 0.5, t0.Add(time.Hour), t0.Add(24*time.Hour), nil), t0)
	p.Book.Observe("claude", "b", "m", claudeHeaders(0.1, 0.5, t0.Add(time.Hour), t0.Add(72*time.Hour), nil), t0)
	if resp, _ := p.Pick(pickReq("s", "a", "b")); resp.AuthID != "a" {
		t.Fatalf("first pick %+v", resp)
	}
	*now = t0.Add(time.Minute)
	p.Book.Observe("claude", "a", "m", claudeHeaders(1, 0.5, t0.Add(time.Hour), t0.Add(24*time.Hour), map[string]string{"Anthropic-Ratelimit-Unified-5h-Status": "rejected"}), *now)
	if resp, d := p.Pick(pickReq("s", "a", "b")); resp.AuthID != "b" || d.Reason != "affinity-rebind-excluded" {
		t.Fatalf("exhausted binding kept: %+v %+v", resp, d)
	}
}

func TestPickFallsBackWhenAllExcludedOrUnhandled(t *testing.T) {
	p, _ := newTestPlugin(t, "")
	p.Book.Observe("claude", "a", "m", claudeHeaders(1, 0.5, t0.Add(time.Hour), t0.Add(24*time.Hour), map[string]string{"Anthropic-Ratelimit-Unified-5h-Status": "rejected"}), t0)
	if resp, d := p.Pick(pickReq("s", "a")); resp.Handled || d.Reason != "all-excluded-fallback" {
		t.Fatalf("all-excluded should defer to host: %+v %+v", resp, d)
	}
	req := pickReq("s", "a")
	req.Provider = "gemini"
	if resp, _ := p.Pick(req); resp.Handled {
		t.Fatal("unscheduled provider must not be handled")
	}
}

func TestHandleEndToEnd(t *testing.T) {
	p, _ := newTestPlugin(t, "")
	cfg := "enabled: true\nkeys:\n  - name: codex\n    sha256: " + digest("codex-secret") + "\n    providers: [codex]\n"
	raw, _ := json.Marshal(map[string]any{"config_yaml": []byte(cfg), "schema_version": pluginabi.SchemaVersion})
	var env struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(p.Handle(pluginabi.MethodPluginRegister, raw), &env); err != nil || !env.OK {
		t.Fatalf("register failed: %s", env.Result)
	}
	var reg registration
	_ = json.Unmarshal(env.Result, &reg)
	c := reg.Capabilities
	if !c.FrontendAuthProvider || !c.FrontendAuthProviderExclusive || !c.Scheduler || !c.RequestInterceptor || !c.UsagePlugin || !c.WebSocketResponseObserver || !c.RequestInterceptorOmitBodyAfter {
		t.Fatalf("capabilities wrong: %+v", c)
	}

	// Usage records feed the quota book; a pick then uses them.
	rec := pluginapi.UsageRecord{Provider: "codex", AuthID: "acct", Model: "gpt-6-1", ResponseHeaders: http.Header{
		"X-Codex-Secondary-Used-Percent":   {"10"},
		"X-Codex-Secondary-Window-Minutes": {"10080"},
		"X-Codex-Secondary-Reset-At":       {strconv.FormatInt(t0.Add(30*time.Hour).Unix(), 10)},
	}}
	raw, _ = json.Marshal(rec)
	p.Handle(pluginabi.MethodUsageHandle, raw)
	pick := pluginapi.SchedulerPickRequest{Provider: "codex", Model: "gpt-6-1", Candidates: []pluginapi.SchedulerAuthCandidate{{ID: "fresh"}, {ID: "acct"}}}
	raw, _ = json.Marshal(pick)
	_ = json.Unmarshal(p.Handle(pluginabi.MethodSchedulerPick, raw), &env)
	var picked pluginapi.SchedulerPickResponse
	_ = json.Unmarshal(env.Result, &picked)
	if picked.AuthID != "acct" {
		t.Fatalf("pick through ABI = %+v", picked)
	}

	// A WebSocket rate-limit event is parsed with upstream's helper.
	ev := pluginapi.WebSocketResponseEvent{Provider: "codex", AuthID: "ws", Model: "gpt-6-1", Payload: []byte(`{"type":"codex.rate_limits","rate_limits":{"primary":{"used_percent":100,"window_minutes":300,"reset_after_seconds":600},"secondary":{"used_percent":20,"window_minutes":10080,"reset_after_seconds":86400}}}`)}
	raw, _ = json.Marshal(ev)
	p.Handle(pluginabi.MethodWebSocketResponseEvent, raw)
	if a, ok := p.Book.Snapshot("ws"); !ok || !ViewFor(a, "gpt-6-1", p.Now()).FiveHourBlock {
		t.Fatalf("websocket rate limits not tracked: %+v", a)
	}

	// Gate through the ABI: a Chat Completions call to Codex with the codex key is denied.
	after := codexRequest()
	after.RequestID = "unseen"
	after.SourceFormat = "openai"
	after.ToFormat = "codex"
	after.CallerScope = cliproxysession.CallerScope("fleet:codex")
	raw, _ = json.Marshal(after)
	_ = json.Unmarshal(p.Handle(pluginabi.MethodRequestInterceptAfter, raw), &env)
	var ir pluginapi.RequestInterceptResponse
	_ = json.Unmarshal(env.Result, &ir)
	if !ir.Terminate || ir.StatusCode != http.StatusForbidden {
		t.Fatalf("gate via ABI did not deny: %+v", ir)
	}

	// Management status renders without key digests.
	_ = json.Unmarshal(p.Handle(pluginabi.MethodManagementHandle, []byte(`{"Method":"GET","Path":"/status"}`)), &env)
	var mr pluginapi.ManagementResponse
	_ = json.Unmarshal(env.Result, &mr)
	if mr.StatusCode != http.StatusOK || strings.Contains(string(mr.Body), digest("codex-secret")) || !strings.Contains(string(mr.Body), `"fleet_codex_format"`) {
		t.Fatalf("status response wrong: %d %s", mr.StatusCode, mr.Body)
	}
	if strings.Contains(string(p.Handle("nope", nil)), `"ok":true`) {
		t.Fatal("unknown method must error")
	}
}

func TestPickMixedRouteUsesCandidateProvider(t *testing.T) {
	p, _ := newTestPlugin(t, "")
	req := pickReq("s", "a", "b")
	req.Provider = ""
	if resp, d := p.Pick(req); !resp.Handled || d.Provider != "claude" {
		t.Fatalf("mixed single-provider route not handled: %+v %+v", resp, d)
	}
	req.Candidates[1].Provider = "codex"
	if resp, _ := p.Pick(req); resp.Handled {
		t.Fatal("mixed multi-provider route must defer to the host")
	}
}
