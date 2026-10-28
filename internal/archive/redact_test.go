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
	}
	for in, want := range cases {
		if got := RedactQuery(in, allow); got != want {
			t.Errorf("RedactQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQueryNames(t *testing.T) {
	got := QueryNames("code=fake-0001&state=fake-0002&password=x&AIzaSyFAKEFAKEFAKEFAKEFAKEFAKE0003&value=")
	want := []string{"code", "state", "password", Redacted, "value"}
	if !slices.Equal(got, want) {
		t.Fatalf("QueryNames = %v, want %v", got, want)
	}
}
