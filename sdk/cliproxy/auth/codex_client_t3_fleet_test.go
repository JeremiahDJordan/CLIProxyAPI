package auth

import (
	"context"
	"net/http"
	"testing"
)

// Fleet fork: T3 Code runs the official Codex app-server under its own originator.
func TestCodexClientRequestAcceptsT3CodeFleet(t *testing.T) {
	headers := http.Header{"User-Agent": {"T3 Code/0.164.0 (Mac OS 27.0.1; arm64) xterm-256color (T3 Code; 0.1.2)"}}
	if !IsCodexClientRequest(context.Background(), headers) {
		t.Fatal("T3 Code's Codex app-server is not treated as a Codex client")
	}
	if IsCodexClientUserAgent("T3 Codex/1.0") {
		t.Fatal("a different product name is treated as a Codex client")
	}
}
