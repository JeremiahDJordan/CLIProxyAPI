package helps

import (
	"net/http"
	"strings"

	multiagentv2 "github.com/router-for-me/CLIProxyAPI/v8/internal/client/codex/optimize-multi-agent-v2"
)

// codexOfficialOriginators lists the Originator values sent by official Codex clients
// (compared case-insensitively, optionally followed by "/version"). "T3 Code" runs the
// official Codex app-server under its own originator, which OpenAI recognizes.
var codexOfficialOriginators = []string{"codex_cli_rs", "codex-tui", "codex desktop", "codex_exec", "t3 code"}

// IsOfficialCodexClient reports whether a request carries an official Codex client
// identity in both User-Agent and Originator. The fleet gate admits only these clients
// and Codex cloak-mode auto keeps their identity; both must agree.
func IsOfficialCodexClient(headers http.Header) bool {
	return headers != nil && CodexClientUserAgent(headers) && OfficialCodexOriginator(headers)
}

// CodexClientUserAgent reports whether the User-Agent is a Codex client's.
func CodexClientUserAgent(headers http.Header) bool {
	return headers != nil && multiagentv2.IsCodexClientUserAgent(headers.Get("User-Agent"))
}

// OfficialCodexOriginator reports whether the Originator is an official Codex client's.
func OfficialCodexOriginator(headers http.Header) bool {
	if headers == nil {
		return false
	}
	originator := strings.ToLower(strings.TrimSpace(headers.Get("Originator")))
	for _, official := range codexOfficialOriginators {
		if originator == official || strings.HasPrefix(originator, official+"/") {
			return true
		}
	}
	return false
}
