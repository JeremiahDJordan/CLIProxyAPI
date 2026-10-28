package multiagentv2

import "testing"

// Fleet fork: T3 Code runs the official Codex app-server under its own originator.
func TestIsCodexClientUserAgentAcceptsT3CodeFleet(t *testing.T) {
	for ua, want := range map[string]bool{
		"T3 Code/0.164.0 (Mac OS 27.0.1; arm64) xterm-256color (T3 Code; 0.1.2)": true,
		"codex_cli_rs/0.164.0 (Mac OS 27.0.1; arm64) Terminal":                   true,
		"T3 Codex/1.0":         false,
		"curl/8.7.1 T3 Code/1": false,
	} {
		if got := IsCodexClientUserAgent(ua); got != want {
			t.Errorf("IsCodexClientUserAgent(%q) = %v, want %v", ua, got, want)
		}
	}
}
