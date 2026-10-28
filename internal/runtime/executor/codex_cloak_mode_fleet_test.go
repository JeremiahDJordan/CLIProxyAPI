package executor

import (
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// Fleet fork: Codex cloaking defaults to "auto", which keeps an official Codex
// client's own identity (helps.IsOfficialCodexClient, shared with the fleet gate) and
// cloaks every other client.
func TestCodexCloakModeFleet(t *testing.T) {
	official := http.Header{}
	official.Set("User-Agent", "codex_cli_rs/0.164.0 (Mac OS 27.2.0; arm64) Apple_Terminal/470")
	official.Set("Originator", "codex_cli_rs")
	copiedUA := http.Header{}
	copiedUA.Set("User-Agent", "codex_cli_rs/0.164.0")
	copiedUA.Set("Originator", "pi")
	other := http.Header{}
	other.Set("User-Agent", "curl/8.7.1")
	t3 := http.Header{}
	t3.Set("User-Agent", "T3 Code/0.164.0 (Mac OS 27.0.1; arm64) xterm-256color (T3 Code; 0.1.2)")
	t3.Set("Originator", "T3 Code")
	desktop := http.Header{}
	desktop.Set("User-Agent", official.Get("User-Agent"))
	desktop.Set("Originator", "Codex Desktop/27.1")

	for _, tc := range []struct {
		name, settings string
		client         http.Header
		wantUA         string
		wantOriginator string
	}{
		{"default auto keeps official client", "codex: {}\n", official, official.Get("User-Agent"), "codex_cli_rs"},
		{"default auto cloaks other client", "codex: {}\n", other, codexUserAgent, codexOriginator},
		{"auto keeps a versioned originator the gate admits", "codex: {}\n", desktop, official.Get("User-Agent"), "Codex Desktop/27.1"},
		{"auto keeps T3 Code's identity", "codex: {}\n", t3, t3.Get("User-Agent"), "T3 Code"},
		{"auto cloaks copied user agent with wrong originator", "codex: {cloak-mode: auto}\n", copiedUA, codexUserAgent, codexOriginator},
		{"always overwrites official client", "codex: {cloak-mode: always}\n", official, codexUserAgent, codexOriginator},
		{"v8 upstream path is honored", "upstream: {codex: {cloak-mode: always}}\n", official, codexUserAgent, codexOriginator},
		{"never leaves headers", "codex: {cloak-mode: never}\n", other, "curl/8.7.1", ""},
		{"legacy disable still means never", "codex: {disable-codex-cloaking: true}\n", other, "curl/8.7.1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.ParseConfigBytes([]byte(tc.settings))
			if err != nil {
				t.Fatal(err)
			}
			auth := &cliproxyauth.Auth{Provider: "codex", Metadata: map[string]any{"access_token": "test-oauth"}}
			out := http.Header{}
			out.Set("User-Agent", tc.client.Get("User-Agent"))
			if o := tc.client.Get("Originator"); o != "" {
				out.Set("Originator", o)
			}
			applyCodexCloakingHeaders(out, tc.client, cfg, auth)
			if got := out.Get("User-Agent"); got != tc.wantUA {
				t.Fatalf("User-Agent = %q, want %q", got, tc.wantUA)
			}
			if got := out.Get("Originator"); got != tc.wantOriginator {
				t.Fatalf("Originator = %q, want %q", got, tc.wantOriginator)
			}
		})
	}
}
