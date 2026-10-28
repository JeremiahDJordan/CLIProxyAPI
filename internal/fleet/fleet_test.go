package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
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
	if !s.Exclusive || !s.GateEnabled || !s.SchedulerEnabled {
		t.Fatalf("defaults not applied: %+v", s)
	}
	if s.ClaudeCacheTTL != 5*time.Minute || s.ClaudeExtendedCacheTTL != time.Hour || s.CodexIdleTTL != time.Hour {
		t.Fatalf("ttl defaults wrong: %v %v %v", s.ClaudeCacheTTL, s.ClaudeExtendedCacheTTL, s.CodexIdleTTL)
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
	// The gate needs exclusive fleet keys; otherwise host-authenticated keys could reach
	// routes the gate never inspects.
	for _, insecure := range []string{"", "exclusive: false\nkeys:\n  - name: a\n    sha256: " + digest("x") + "\n    providers: [claude]\n"} {
		if _, err := ParseConfig([]byte(insecure)); err == nil {
			t.Errorf("gate without exclusive fleet keys must be rejected: %q", insecure)
		}
	}
	none, err := ParseConfig([]byte("gate:\n  enabled: false\n"))
	if err != nil || none.Exclusive {
		t.Fatalf("scheduler-only config without keys should parse non-exclusive: %+v %v", none, err)
	}
}

func TestCallerScopeMatchesHost(t *testing.T) {
	for _, k := range testSettings(t, "").Keys {
		if k.CallerScope == "" || k.CallerScope != cliproxysession.CallerScope("fleet:"+k.Name) {
			t.Fatalf("caller scope for %s differs from the host's", k.Name)
		}
	}
}

func TestAuthenticateKeys(t *testing.T) {
	s := testSettings(t, "")
	cases := []struct {
		headers      http.Header
		method, path string
		want         string
	}{
		{http.Header{"Authorization": {"Bearer claude-secret"}}, "POST", "/v1/messages", "fleet:claude-code"},
		{http.Header{"X-Api-Key": {"codex-secret"}}, "POST", "/v1/responses", "fleet:codex"},
		{http.Header{"Authorization": {"Bearer wrong"}}, "POST", "/v1/messages", ""},
		{http.Header{}, "POST", "/v1/messages", ""},
	}
	for _, c := range cases {
		resp := Authenticate(s, pluginapi.FrontendAuthRequest{Method: c.method, Path: c.path, Headers: c.headers})
		if resp.Authenticated != (c.want != "") || resp.Principal != c.want || resp.DenyStatusCode != 0 {
			t.Errorf("headers %v: got %+v, want principal %q", c.headers, resp, c.want)
		}
	}
}

// Fleet keys reach only routes the client gate inspects; credentialed routes that skip
// request interceptors (search, live/realtime, media, Gemini) are refused.
func TestAuthenticateRouteAllowlist(t *testing.T) {
	s := testSettings(t, "")
	claude := http.Header{"Authorization": {"Bearer claude-secret"}}
	codex := http.Header{"Authorization": {"Bearer codex-secret"}}
	for _, c := range []struct {
		headers      http.Header
		method, path string
		allowed      bool
	}{
		{claude, "GET", "/v1/models", true},
		{claude, "POST", "/v1/messages/count_tokens", true},
		{codex, "GET", "/v1/responses", true},
		{codex, "POST", "/backend-api/codex/responses/compact", true},
		{codex, "POST", "/v1/responses/compact/", true},
		{claude, "POST", "/v1/alpha/search", false},
		{codex, "POST", "/backend-api/codex/alpha/search", false},
		{codex, "POST", "/v1/realtime/client_secrets", false},
		{codex, "GET", "/v1/realtime", false},
		{codex, "POST", "/v1/images/generations", false},
		{codex, "POST", "/v1/chat/completions", false},
		{codex, "POST", "/v1/messages", false},
		{claude, "POST", "/v1/responses", false},
		{claude, "POST", "/v1beta/models/gemini:generateContent", false},
	} {
		resp := Authenticate(s, pluginapi.FrontendAuthRequest{Method: c.method, Path: c.path, Headers: c.headers})
		if c.allowed && !resp.Authenticated {
			t.Errorf("%s %s should be allowed: %+v", c.method, c.path, resp)
		}
		if !c.allowed && (resp.Authenticated || resp.DenyStatusCode != http.StatusForbidden) {
			t.Errorf("%s %s should be denied with 403: %+v", c.method, c.path, resp)
		}
	}
}

func TestGateAcceptsNativeClaudeCodeAndCodex(t *testing.T) {
	s := testSettings(t, "")
	if d := Evaluate(s, Classify(claudeCodeRequest("")), "claude", scopeFor(s, "claude-code")); !d.Allow {
		t.Fatalf("native Claude Code rejected: %+v", d)
	}
	if d := Evaluate(s, Classify(codexRequest()), "codex", scopeFor(s, "codex")); !d.Allow {
		t.Fatalf("official Codex rejected: %+v", d)
	}
}

func TestGateRejectsImpostorsAndTranslation(t *testing.T) {
	s := testSettings(t, "")
	claudeScope, codexScope := scopeFor(s, "claude-code"), scopeFor(s, "codex")

	copiedUA := claudeCodeRequest("")
	copiedUA.Headers = http.Header{"User-Agent": {"claude-cli/2.1.280 (external, cli)"}}
	if d := Evaluate(s, Classify(copiedUA), "claude", claudeScope); d.Allow || d.Code != "fleet_claude_client" {
		t.Errorf("copied User-Agent allowed: %+v", d)
	}

	openAIForClaude := claudeCodeRequest("")
	openAIForClaude.SourceFormat = "openai"
	if d := Evaluate(s, Classify(openAIForClaude), "claude", claudeScope); d.Allow || d.Code != "fleet_claude_format" {
		t.Errorf("translated OpenAI request allowed for Claude: %+v", d)
	}

	sdkPy := claudeCodeRequest("")
	sdkPy.Headers.Set("User-Agent", "claude-cli/2.1.280 (external, sdk-py)")
	if d := Evaluate(s, Classify(sdkPy), "claude", claudeScope); d.Allow {
		t.Errorf("non-native entrypoint allowed: %+v", d)
	}

	uaOnly := codexRequest()
	uaOnly.Headers.Del("Originator")
	if d := Evaluate(s, Classify(uaOnly), "codex", codexScope); d.Allow || d.Code != "fleet_codex_client" {
		t.Errorf("Codex without Originator allowed: %+v", d)
	}

	other := codexRequest()
	other.Headers.Set("User-Agent", "pi/1.0")
	if d := Evaluate(s, Classify(other), "codex", codexScope); d.Allow {
		t.Errorf("non-Codex User-Agent allowed: %+v", d)
	}

	chat := codexRequest()
	chat.SourceFormat = "openai"
	if d := Evaluate(s, Classify(chat), "codex", codexScope); d.Allow || d.Code != "fleet_codex_format" {
		t.Errorf("Chat Completions request allowed for Codex: %+v", d)
	}
}

func TestGatePrincipalScoping(t *testing.T) {
	s := testSettings(t, "")
	if d := Evaluate(s, Classify(claudeCodeRequest("")), "claude", scopeFor(s, "codex")); d.Allow || d.Code != "fleet_key_provider_denied" {
		t.Errorf("codex key reached Claude: %+v", d)
	}
	if d := Evaluate(s, Classify(codexRequest()), "codex", scopeFor(s, "claude-code")); d.Allow || d.Code != "fleet_key_provider_denied" {
		t.Errorf("claude key reached Codex: %+v", d)
	}
	if d := Evaluate(s, Classify(codexRequest()), "gemini", scopeFor(s, "codex")); d.Allow {
		t.Errorf("codex key reached an unlisted provider: %+v", d)
	}
	if d := Evaluate(s, Classify(codexRequest()), "codex", ""); d.Allow || d.Code != "fleet_unknown_caller" {
		t.Errorf("unknown caller reached Codex: %+v", d)
	}
	// Removed settings that could only weaken the gate are ignored.
	legacy := testSettings(t, "gate:\n  deny-unknown-callers: false\n  providers: [claude]\n")
	if d := Evaluate(legacy, Classify(codexRequest()), "codex", ""); d.Allow || d.Code != "fleet_unknown_caller" {
		t.Errorf("legacy settings must not open the gate: %+v", d)
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
	h.Set("X-Codex-Active-Limit", "codex_bengalfox")
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

// Accounts without quota data get one probe first so their windows can be compared;
// once probed they rank after known accounts until probeRetry passes.
func TestRankProbesUnknownThenKnownAndTieBreak(t *testing.T) {
	b := NewQuotaBook()
	reset := t0.Add(48 * time.Hour)
	b.Observe("claude", "more-left", "m", claudeHeaders(0.1, 0.2, t0.Add(time.Hour), reset, nil), t0)
	b.Observe("claude", "less-left", "m", claudeHeaders(0.1, 0.7, t0.Add(time.Hour), reset, nil), t0)
	c := candidates("new-b", "less-left", "new-a", "more-left")
	c[0].Priority = 5 // higher host priority sorts first among unknown accounts
	if got := rankIDs(Rank(b, c, "m", t0)); got != "new-b,new-a,more-left,less-left" {
		t.Fatalf("unprobed order = %s", got)
	}
	b.NoteProbe("new-b", t0)
	b.NoteProbe("new-a", t0)
	if got := rankIDs(Rank(b, c, "m", t0.Add(time.Minute))); got != "more-left,less-left,new-b,new-a" {
		t.Fatalf("probed order = %s", got)
	}
	if got := rankIDs(Rank(b, c, "m", t0.Add(probeRetry))); got != "new-b,new-a,more-left,less-left" {
		t.Fatalf("order after probe retry = %s", got)
	}
}

// Concurrent new sessions probe an unknown account only once.
func TestPickConcurrentProbesOnce(t *testing.T) {
	p, _ := newTestPlugin(t, "")
	p.Book.Observe("claude", "known", "m", claudeHeaders(0.1, 0.5, t0.Add(time.Hour), t0.Add(72*time.Hour), nil), t0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	probes := 0
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			resp, _ := p.Pick(pluginapi.SchedulerPickRequest{Provider: "claude", Model: "m", Candidates: candidates("known", "fresh"),
				Options: pluginapi.SchedulerOptions{Metadata: map[string]any{"canonical_session_id": "s" + strconv.Itoa(i)}}})
			if resp.AuthID == "fresh" {
				mu.Lock()
				probes++
				mu.Unlock()
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if probes != 1 {
		t.Fatalf("unknown account probed %d times, want 1", probes)
	}
}

// A new session probes an unknown account once; the next new session goes to the
// known account, and a session with a warm cache stays on its account.
func TestPickProbesUnknownOnceAndKeepsAffinity(t *testing.T) {
	p, now := newTestPlugin(t, "")
	p.Book.Observe("claude", "known", "m", claudeHeaders(0.1, 0.5, t0.Add(time.Hour), t0.Add(72*time.Hour), nil), t0)
	pick := func(session string) (pluginapi.SchedulerPickResponse, PickDecision) {
		return p.Pick(pluginapi.SchedulerPickRequest{Provider: "claude", Model: "m", Candidates: candidates("known", "fresh"),
			Options: pluginapi.SchedulerOptions{Metadata: map[string]any{"canonical_session_id": session}}})
	}
	if resp, d := pick("warm"); resp.AuthID != "fresh" || d.Reason != "probe-unknown" {
		t.Fatalf("first pick should probe the unknown account: %+v %+v", resp, d)
	}
	*now = t0.Add(time.Minute)
	if resp, d := pick("other"); resp.AuthID != "known" || d.Reason != "weekly-soonest" {
		t.Fatalf("probed account should not be probed again: %+v %+v", resp, d)
	}
	if resp, d := pick("warm"); resp.AuthID != "fresh" || d.Reason != "affinity" {
		t.Fatalf("warm session should keep its account: %+v %+v", resp, d)
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
	if !c.FrontendAuthProvider || !c.FrontendAuthProviderExclusive || !c.Scheduler || !c.RequestInterceptor || !c.UsagePlugin || !c.WebSocketResponseObserver || !c.RequestInterceptorOmitBodyAfter || !c.SchedulerAcrossPriorities {
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
	if picked.AuthID != "fresh" {
		t.Fatalf("first pick through ABI should probe the unknown account: %+v", picked)
	}
	_ = json.Unmarshal(p.Handle(pluginabi.MethodSchedulerPick, raw), &env)
	_ = json.Unmarshal(env.Result, &picked)
	if picked.AuthID != "acct" {
		t.Fatalf("second pick through ABI = %+v", picked)
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
	after.Metadata = map[string]any{"selected_auth_provider": "codex"}
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
	if got := string(p.Handle("nope", nil)); got != `{"ok":false,"error":{"code":"unknown_method","message":"unknown method: nope"}}` {
		t.Fatalf("unknown method envelope = %s", got)
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

// Only the limit named by X-Codex-Active-Limit becomes model-specific; a response for
// a normal model carrying another limit's exhausted window does not exclude it.
func TestCodexActiveLimitSelectsModelWindow(t *testing.T) {
	h := http.Header{}
	h.Set("X-Codex-Secondary-Used-Percent", "20")
	h.Set("X-Codex-Secondary-Window-Minutes", "10080")
	h.Set("X-Codex-Secondary-Reset-At", strconv.FormatInt(t0.Add(72*time.Hour).Unix(), 10))
	for _, limit := range []string{"Bengalfox", "Other"} {
		h.Set("X-Codex-"+limit+"-Secondary-Used-Percent", "100")
		h.Set("X-Codex-"+limit+"-Secondary-Window-Minutes", "10080")
		h.Set("X-Codex-"+limit+"-Secondary-Reset-At", strconv.FormatInt(t0.Add(24*time.Hour).Unix(), 10))
	}
	for _, active := range []string{"codex", ""} {
		h.Set("X-Codex-Active-Limit", active)
		b := NewQuotaBook()
		b.Observe("codex", "c", "gpt-6-1", h, t0)
		a, _ := b.Snapshot("c")
		if len(a.ModelWeekly) != 0 {
			t.Fatalf("active %q: unrelated named limit mapped: %+v", active, a.ModelWeekly)
		}
		if v := ViewFor(a, "gpt-6-1", t0); v.Excluded() || v.WeeklyWindow != "secondary" {
			t.Fatalf("active %q: normal model should use the shared window: %+v", active, v)
		}
	}
}

// WebSocket additional limits use upstream's identifier alphabet (dots, mixed case).
func TestCodexWebSocketAdditionalLimitParsed(t *testing.T) {
	headers := helps.ParseCodexQuotaEventHeaders([]byte(`{"type":"codex.rate_limits","meteredLimitName":"GPT-5.3-Codex-Spark",
		"rateLimit":{"primary":{"usedPercent":10,"windowMinutes":10080,"resetAfterSeconds":300000}},
		"additionalRateLimits":[{"limitName":"GPT-5.3-Codex-Spark","rateLimit":{
			"primary":{"usedPercent":20,"windowMinutes":300,"resetAfterSeconds":600},
			"secondary":{"usedPercent":100,"windowMinutes":10080,"resetAfterSeconds":120000}}}]}`))
	if len(headers) == 0 {
		t.Fatal("upstream parser produced no headers")
	}
	b := NewQuotaBook()
	if !b.Observe("codex", "c", "gpt-5.3-codex-spark", headers, t0) {
		t.Fatalf("no windows recognized from %v", headers)
	}
	a, _ := b.Snapshot("c")
	if a.ModelWeekly["gpt-5.3-codex-spark"] != "additional-gpt-5.3-codex-spark-secondary" {
		t.Fatalf("spark weekly not mapped: %+v windows=%v", a.ModelWeekly, a.Windows)
	}
	if v := ViewFor(a, "gpt-5.3-codex-spark", t0); !v.WeeklyBlock {
		t.Fatalf("exhausted spark weekly should exclude spark: %+v", v)
	}
}

// Model-specific windows observed under the resolved model also apply to the alias
// the scheduler sees.
func TestObserveMapsAliasToModelWindow(t *testing.T) {
	b := NewQuotaBook()
	b.Observe("claude", "a", "claude-opus-5-5", claudeHeaders(0.1, 0.2, t0.Add(time.Hour), t0.Add(72*time.Hour), map[string]string{
		"Anthropic-Ratelimit-Unified-7d_oi-Utilization": "1.0",
		"Anthropic-Ratelimit-Unified-7d_oi-Reset":       strconv.FormatInt(t0.Add(48*time.Hour).Unix(), 10),
	}), t0, "opus")
	a, _ := b.Snapshot("a")
	if v := ViewFor(a, "opus", t0); !v.WeeklyBlock || v.WeeklyWindow != "7d_oi" {
		t.Fatalf("alias should use the model window: %+v", v)
	}
}

// The gate uses the provider the host reports for the selected credential: native Codex
// compaction (ToFormat openai-response) passes, an ambiguous format without it fails
// closed, and a Codex-only key cannot reach a Claude credential even if earlier usage
// records for the same auth ID came from a Codex account.
func TestGateUsesHostReportedProvider(t *testing.T) {
	p, _ := newTestPlugin(t, "")
	run := func(toFormat string, meta map[string]any) pluginapi.RequestInterceptResponse {
		req := codexRequest()
		req.ToFormat = toFormat
		req.CallerScope = scopeFor(p.Settings(), "codex")
		req.Metadata = meta
		raw, _ := json.Marshal(req)
		var env struct {
			Result pluginapi.RequestInterceptResponse `json:"result"`
		}
		_ = json.Unmarshal(p.Handle(pluginabi.MethodRequestInterceptAfter, raw), &env)
		return env.Result
	}
	if resp := run("openai-response", map[string]any{"selected_auth_id": "a"}); !resp.Terminate ||
		!strings.Contains(string(resp.ResponseBody), "fleet_unresolved_provider") {
		t.Fatalf("ambiguous format without provider should fail closed: %+v", resp)
	}
	if resp := run("openai-response", map[string]any{"selected_auth_provider": "codex"}); resp.Terminate {
		t.Fatalf("official Codex compaction rejected: %s", resp.ResponseBody)
	}
	// A stale Codex observation for the same auth ID must not open the gate.
	rec, _ := json.Marshal(pluginapi.UsageRecord{Provider: "codex", AuthID: "account.json", Model: "gpt-6-1"})
	p.Handle(pluginabi.MethodUsageHandle, rec)
	if resp := run("claude", map[string]any{"selected_auth_id": "account.json", "selected_auth_provider": "claude"}); !resp.Terminate ||
		!strings.Contains(string(resp.ResponseBody), "fleet_key_provider_denied") {
		t.Fatalf("codex key reached a Claude credential: %+v", resp)
	}
	if resp := run("claude", map[string]any{"selected_auth_id": "account.json"}); !resp.Terminate {
		t.Fatalf("unambiguous claude target without provider metadata must still be gated: %+v", resp)
	}
}

// Claude Code sessions identified only by metadata.user_id keep their one-hour cache
// lifetime because both hooks use the host's canonical session identity.
func TestMetadataSessionKeepsExtendedCache(t *testing.T) {
	p, now := newTestPlugin(t, "")
	p.Book.Observe("claude", "later", "m", claudeHeaders(0.1, 0.5, t0.Add(time.Hour), t0.Add(72*time.Hour), nil), t0)
	encoded, _ := json.Marshal(claudeUserID)
	req := claudeCodeRequest(`{"model":"m","metadata":{"user_id":` + string(encoded) + `},"system":[{"type":"text","text":"x","cache_control":{"type":"ephemeral","ttl":"1h"}}]}`)
	req.Headers.Del("X-Claude-Code-Session-Id")
	raw, _ := json.Marshal(req)
	p.Handle(pluginabi.MethodRequestInterceptBefore, raw)
	session := cliproxyauth.CanonicalSessionID(req.Headers, req.Body, nil)
	if session == "" {
		t.Fatal("fixture has no metadata session")
	}
	pick := func(ids ...string) (pluginapi.SchedulerPickResponse, PickDecision) {
		return p.Pick(pluginapi.SchedulerPickRequest{Provider: "claude", Model: "m", Candidates: candidates(ids...),
			Options: pluginapi.SchedulerOptions{Metadata: map[string]any{"canonical_session_id": session}}})
	}
	pick("later")
	p.Book.Observe("claude", "soon", "m", claudeHeaders(0.1, 0.5, t0.Add(time.Hour), t0.Add(24*time.Hour), nil), t0)
	*now = t0.Add(40 * time.Minute)
	if resp, d := pick("later", "soon"); resp.AuthID != "later" || d.Reason != "affinity" {
		t.Fatalf("1h metadata session moved at 40m: %+v %+v", resp, d)
	}
}

// Subagent sessions (session header plus body metadata.agent_id) keep their one-hour
// cache: the scheduler uses the host's canonical identity instead of re-deriving a
// weaker header-only one.
func TestSubagentSessionUsesHostCanonicalIdentity(t *testing.T) {
	p, now := newTestPlugin(t, "")
	p.Book.Observe("claude", "later", "m", claudeHeaders(0.1, 0.5, t0.Add(time.Hour), t0.Add(72*time.Hour), nil), t0)
	encoded, _ := json.Marshal(claudeUserID)
	req := claudeCodeRequest(`{"model":"m","metadata":{"user_id":` + string(encoded) + `,"agent_id":"worker-1"},"system":[{"type":"text","text":"x","cache_control":{"type":"ephemeral","ttl":"1h"}}]}`)
	raw, _ := json.Marshal(req)
	p.Handle(pluginabi.MethodRequestInterceptBefore, raw)
	canonical := cliproxyauth.CanonicalSessionID(req.Headers, req.Body, nil)
	if canonical == cliproxyauth.CanonicalSessionID(req.Headers, nil, nil) {
		t.Fatalf("fixture must make the body-derived identity differ from the header-only one: %q", canonical)
	}
	pick := func(ids ...string) (pluginapi.SchedulerPickResponse, PickDecision) {
		return p.Pick(pluginapi.SchedulerPickRequest{Provider: "claude", Model: "m", Candidates: candidates(ids...),
			Options: pluginapi.SchedulerOptions{Headers: req.Headers, Metadata: map[string]any{"canonical_session_id": canonical}}})
	}
	pick("later")
	p.Book.Observe("claude", "soon", "m", claudeHeaders(0.1, 0.5, t0.Add(time.Hour), t0.Add(24*time.Hour), nil), t0)
	*now = t0.Add(40 * time.Minute)
	if resp, d := pick("later", "soon"); resp.AuthID != "later" || d.Reason != "affinity" {
		t.Fatalf("1h subagent session moved at 40m: %+v %+v", resp, d)
	}
}

// A route alias retargeted from a model-specific Codex limit to one metered by the shared
// limit stops using the old model window; a response without X-Codex-Active-Limit keeps it.
func TestCodexSharedLimitClearsStaleAlias(t *testing.T) {
	headers := func(active string) http.Header {
		h := http.Header{}
		h.Set("X-Codex-Secondary-Used-Percent", "20")
		h.Set("X-Codex-Secondary-Window-Minutes", "10080")
		h.Set("X-Codex-Secondary-Reset-At", strconv.FormatInt(t0.Add(72*time.Hour).Unix(), 10))
		h.Set("X-Codex-Spark-Secondary-Used-Percent", "100")
		h.Set("X-Codex-Spark-Secondary-Window-Minutes", "10080")
		h.Set("X-Codex-Spark-Secondary-Reset-At", strconv.FormatInt(t0.Add(24*time.Hour).Unix(), 10))
		if active != "" {
			h.Set("X-Codex-Active-Limit", active)
		}
		return h
	}
	b := NewQuotaBook()
	b.Observe("codex", "c", "gpt-spark", headers("codex_spark"), t0, "fast")
	a, _ := b.Snapshot("c")
	if v := ViewFor(a, "fast", t0); v.WeeklyWindow != "spark-secondary" || !v.WeeklyBlock {
		t.Fatalf("alias should start on the Spark window: %+v", v)
	}
	b.Observe("codex", "c", "gpt-6-1", headers(""), t0, "fast")
	a, _ = b.Snapshot("c")
	if v := ViewFor(a, "fast", t0); v.WeeklyWindow != "spark-secondary" {
		t.Fatalf("a response without an active limit must not clear the alias: %+v", v)
	}
	for _, shared := range []string{"codex", "premium"} {
		b.Observe("codex", "c", "gpt-spark", headers("codex_spark"), t0, "fast")
		b.Observe("codex", "c", "gpt-6-1", headers(shared), t0, "fast")
		a, _ = b.Snapshot("c")
		if v := ViewFor(a, "fast", t0); v.WeeklyWindow != "secondary" || v.Excluded() {
			t.Fatalf("%s: retargeted alias should use the shared window: %+v", shared, v)
		}
		if _, ok := a.ModelWeekly["gpt-spark"]; !ok {
			t.Fatalf("%s: the Spark model keeps its own association: %+v", shared, a.ModelWeekly)
		}
	}
}

// A WebSocket update that still names Spark but omits its weekly window keeps the Spark
// association, so the exhausted weekly window keeps excluding the account.
func TestCodexPartialNamedUpdateKeepsWeeklyBlock(t *testing.T) {
	b := NewQuotaBook()
	full := helps.ParseCodexQuotaEventHeaders([]byte(`{"type":"codex.rate_limits","metered_limit_name":"GPT-5.3-Codex-Spark",
		"rate_limits":{"primary":{"used_percent":20,"window_minutes":10080,"reset_after_seconds":300000}},
		"additional_rate_limits":{"GPT-5.3-Codex-Spark":{"primary":{"used_percent":10,"window_minutes":300,"reset_after_seconds":600},
			"secondary":{"used_percent":100,"window_minutes":10080,"reset_after_seconds":120000}}}}`))
	partial := helps.ParseCodexQuotaEventHeaders([]byte(`{"type":"codex.rate_limits","metered_limit_name":"GPT-5.3-Codex-Spark",
		"rate_limits":{"primary":{"used_percent":20,"window_minutes":10080,"reset_after_seconds":299999}},
		"additional_rate_limits":{"GPT-5.3-Codex-Spark":{"primary":{"used_percent":10,"window_minutes":300,"reset_after_seconds":599},"secondary":null}}}`))
	b.Observe("codex", "c", "gpt-spark", full, t0, "fast")
	b.Observe("codex", "c", "gpt-spark", partial, t0.Add(time.Second), "fast")
	a, _ := b.Snapshot("c")
	for _, model := range []string{"gpt-spark", "fast"} {
		if v := ViewFor(a, model, t0.Add(time.Second)); !v.WeeklyBlock {
			t.Fatalf("%s lost its exhausted Spark weekly window on a partial update: %+v %+v", model, v, a.ModelWeekly)
		}
	}
}
