package archive

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestRedactHeaders(t *testing.T) {
	h := http.Header{
		"Authorization":          {"Bearer sk-fake-authorization-0001"},
		"Proxy-Authorization":    {"Basic ZmFrZTpmYWtl"},
		"X-Api-Key":              {"sk-ant-fake-0002"},
		"X-Goog-Api-Key":         {"AIzaFAKEFAKEFAKE0003"},
		"Cookie":                 {"session=fake-cookie-0004"},
		"Set-Cookie":             {"id=fake-cookie-0005; Path=/"},
		"Sec-Websocket-Protocol": {"realtime, openai-insecure-api-key.sk-fake-0006", "OpenAI-Insecure-API-Key.sk-fake-0007"},
		"X-Management-Key":       {"fake-management-key-0009"},
		"Anthropic-Beta":         {"oauth-2025-04-20"},
		"Session_id":             {"keep-me"},
	}
	// Non-canonical spellings set directly on the map are covered too.
	h["x-api-key"] = []string{"sk-fake-lowercase-0008"}
	out := RedactHeaders(h)
	for name, values := range out {
		for _, value := range values {
			if strings.Contains(value, "fake") || strings.Contains(value, "FAKE") || strings.Contains(value, "ZmFr") {
				t.Fatalf("%s kept a credential: %q", name, value)
			}
		}
	}
	if got := out["Authorization"]; !slices.Equal(got, []string{Redacted}) {
		t.Fatalf("Authorization = %v", got)
	}
	if got := out["Sec-Websocket-Protocol"]; !slices.Equal(got, []string{"realtime, " + Redacted, Redacted}) {
		t.Fatalf("Sec-WebSocket-Protocol = %v", got)
	}
	if got := out["Anthropic-Beta"]; !slices.Equal(got, []string{"oauth-2025-04-20"}) {
		t.Fatalf("Anthropic-Beta = %v", got)
	}
	if got := out["Session_id"]; !slices.Equal(got, []string{"keep-me"}) {
		t.Fatalf("Session_id = %v", got)
	}
	// The input is not modified.
	if h.Get("Authorization") != "Bearer sk-fake-authorization-0001" {
		t.Fatal("RedactHeaders modified its input")
	}
}

func TestRedactQuery(t *testing.T) {
	allow := QueryAllowlist{"beta": BoolValue, "alt": EnumValue("sse"), "client_version": VersionValue}
	cases := map[string]string{
		"beta=true":                          "beta=true",
		"beta=yes":                           "beta=[redacted]",
		"key=AIzaFAKE0001&alt=sse":           "key=[redacted]&alt=sse",
		"alt=json":                           "alt=[redacted]",
		"value=fake-0002&password=fake-03":   "value=[redacted]&password=[redacted]",
		"code=fake-0004&state=fake-0005":     "code=[redacted]&state=[redacted]",
		"client_version=0.50.0":              "client_version=0.50.0",
		"client_version=1;rm":                "client_version=[redacted]",
		"AIzaSyFAKEFAKEFAKEFAKEFAKEFAKE0006": "[redacted]",
		"Key=fake-0007":                      "Key=[redacted]",
		"%zz=1":                              "[redacted]",
		"":                                   "",
		"beta=true&&beta=false":              "beta=true&beta=false",
		// A key sent as a parameter name is redacted with its value.
		"sk-ant-fake0008=1&beta=true": "[redacted]&beta=true",
		"AIzaFAKEFAKE0009=x":          "[redacted]",
		"abcdefghFAKE0123456789=x":    "[redacted]",
	}
	for in, want := range cases {
		if got := RedactQuery(in, allow); got != want {
			t.Errorf("RedactQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQueryNames(t *testing.T) {
	got := QueryNames("code=fake-0001&state=fake-0002&password=x&AIzaSyFAKEFAKEFAKEFAKEFAKEFAKE0003&value=&sk-fake0004=1&AIzaFAKEFAKE0005=")
	want := []string{"code", "state", "password", Redacted, "value", Redacted, Redacted}
	if !slices.Equal(got, want) {
		t.Fatalf("QueryNames = %v, want %v", got, want)
	}
}

func TestRedactHeadersByNameAndURL(t *testing.T) {
	h := http.Header{
		"X-Custom-Token":                       {"fake-custom-token-0001"},
		"X-Auth-Token":                         {"fake-auth-token-0002"},
		"Api-Key":                              {"fake-api-key-0003"},
		"X-Amz-Security-Token":                 {"fake-amz-token-0004"},
		"X-Client-Secret":                      {"fake-client-secret-0005"},
		"X-Upstream-Password":                  {"fake-password-0006"},
		"X-Request-Signature":                  {"fake-signature-0007"},
		"X-Session-Cookie":                     {"fake-session-cookie-0008"},
		"Www-Authenticate":                     {"Bearer realm=fake-realm-0009"},
		"Referer":                              {"https://app.example/oauth/cb?code=fake-code-0010&state=fake-state-0011"},
		"Location":                             {"https://app.example/cb?code=fake-code-0012#access_token=fake-token-0013&state=fake-state-0014"},
		"Content-Location":                     {"/v1/files?sig=fake-sig-0015"},
		"Link":                                 {`<https://api.example/v1/models?page_token=fake-page-0016>; rel="next"`},
		"X-Original-Url":                       {"/v1/messages?key=fake-key-0017"},
		"Origin":                               {"https://app.example"},
		"Session_id":                           {"019a-session"},
		"X-Claude-Code-Session-Id":             {"claude-session"},
		"X-Parent-Session-Id":                  {"parent-session"},
		"X-Codex-Turn-Metadata":                {`{"turn_id":"t1"}`},
		"Anthropic-Ratelimit-Tokens-Remaining": {"12345"},
		"User-Agent":                           {"claude-cli/2.0"},
	}
	out := RedactHeaders(h)
	for name, values := range out {
		for _, value := range values {
			if strings.Contains(value, "fake") {
				t.Fatalf("%s kept a credential: %q", name, value)
			}
		}
	}
	want := map[string]string{
		"Referer":          "https://app.example/oauth/cb?code=[redacted]&state=[redacted]",
		"Location":         "https://app.example/cb?code=[redacted]#access_token=[redacted]&state=[redacted]",
		"Content-Location": "/v1/files?sig=[redacted]",
		"Link":             `<https://api.example/v1/models?page_token=[redacted]>; rel="next"`,
		"X-Original-Url":   "/v1/messages?key=[redacted]",
		"Origin":           "https://app.example",
		"X-Custom-Token":   Redacted,
		"Www-Authenticate": Redacted,

		"Session_id":                           "019a-session",
		"X-Claude-Code-Session-Id":             "claude-session",
		"X-Parent-Session-Id":                  "parent-session",
		"X-Codex-Turn-Metadata":                `{"turn_id":"t1"}`,
		"Anthropic-Ratelimit-Tokens-Remaining": "12345",
		"User-Agent":                           "claude-cli/2.0",
	}
	for name, value := range want {
		if got := out[name]; !slices.Equal(got, []string{value}) {
			t.Errorf("%s = %v, want %q", name, got, value)
		}
	}
	urls := map[string]string{
		"https://user:fake-pass-0018@app.example/x": "https://app.example/x",
		"mailto:fake-0019@example.com":              Redacted,
		"http://[::1":                               Redacted,
		"null":                                      "null",
	}
	for value, want := range urls {
		if got := RedactURL(value); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestQueryValueRules(t *testing.T) {
	models := map[string]bool{
		"gpt-realtime":                         true,
		"gpt-4o-realtime-preview-2024-12-17":   true,
		"gemini-2.0-flash-live-001":            true,
		"claude-sonnet-4-5@20250929":           true,
		"models/gemini-2.5-flash":              true,
		"sk-proj-fakefakefake":                 false,
		"sk-ant-api03-fake":                    false,
		"AIzaSyFAKEFAKEFAKEFAKEFAKEFAKEFAKE00": false,
		"ya29.a0fakefake":                      false,
		"0123456789abcdef0123456789abcdef":     false,
		"gpt-" + strings.Repeat("a", 70):       false,
		"GPT-4o":                               false,
		"":                                     false,
	}
	for value, want := range models {
		if got := ModelValue(value); got != want {
			t.Errorf("ModelValue(%q) = %v, want %v", value, got, want)
		}
	}
	versions := map[string]bool{
		"0.50.0":                              true,
		"1.2.3-beta.1":                        true,
		"0.46.0-alpha.3+build.7":              true,
		"v1.2":                                true,
		"abc":                                 false,
		"sk-fake":                             false,
		"1.2.3-AbCdEfGhIjKlMnOp":              false,
		"1;rm":                                false,
		"1." + strings.Repeat("1.", 40) + "1": false,
	}
	for value, want := range versions {
		if got := VersionValue(value); got != want {
			t.Errorf("VersionValue(%q) = %v, want %v", value, got, want)
		}
	}
}

// Only the token-count rate-limit headers keep their values; a rate-limit
// name never exempts any other credential part, nor a singular "token".
func TestRedactRateLimitHeaders(t *testing.T) {
	kept := []string{
		"Anthropic-Ratelimit-Tokens-Remaining",
		"Anthropic-Ratelimit-Tokens-Limit",
		"Anthropic-Ratelimit-Input-Tokens-Reset",
		"Anthropic-Ratelimit-Output-Tokens-Remaining",
		"Anthropic-Ratelimit-Requests-Remaining",
		"Anthropic-Ratelimit-Unified-5h-Utilization",
		"X-Ratelimit-Limit-Tokens",
		"X-Ratelimit-Remaining-Tokens",
		"X-Ratelimit-Reset-Tokens",
		"X-Ratelimit-Remaining-Tokens-Minute",
		"X-Ratelimit-Remaining-Requests",
		"Ratelimit-Remaining",
	}
	redacted := []string{
		"X-Ratelimit-Api-Key",
		"X-Ratelimit-Secret",
		"X-Ratelimit-Bypass-Token",
		"X-Ratelimit-Access-Tokens",
		"X-Ratelimit-Token",
		"X-Ratelimit-Auth",
		"X-Ratelimit-Session",
		"X-Ratelimit-Signature",
		"X-Ratelimit-Password",
		"X-Ratelimit-Cookie",
		"X-Secret-Ratelimit-Remaining-Tokens",
		"X-Token-Ratelimit-Remaining-Tokens",
		"X-Ratelimit-Remaining-Tokens-Key",
	}
	h := http.Header{}
	for _, name := range kept {
		h[name] = []string{"12345"}
	}
	for _, name := range redacted {
		h[name] = []string{"fake-ratelimit-credential-0001"}
	}
	out := RedactHeaders(h)
	for _, name := range kept {
		if got := out[name]; !slices.Equal(got, []string{"12345"}) {
			t.Errorf("%s = %v, want the count kept", name, got)
		}
	}
	for _, name := range redacted {
		if got := out[name]; !slices.Equal(got, []string{Redacted}) {
			t.Errorf("%s = %v, want %s", name, got, Redacted)
		}
	}
}
