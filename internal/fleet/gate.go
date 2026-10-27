package fleet

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	multiagentv2 "github.com/router-for-me/CLIProxyAPI/v8/internal/client/codex/optimize-multi-agent-v2"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// Source formats reported by the host's request handlers.
const (
	sourceClaude    = "claude"
	sourceResponses = "openai-response"
)

var extendedCacheTTL = regexp.MustCompile(`"ttl"\s*:\s*"1h"`)

// Classification is computed from the original client request before credential
// selection, where the untranslated body is available.
type Classification struct {
	SourceFormat     string
	ClaudeConfirmed  bool
	ClaudeEntrypoint string
	CodexClient      bool
	Session          string
	ExtendedCache    bool
	at               time.Time
}

// Classifier caches classifications by request ID between the before- and
// after-selection interceptor calls.
type Classifier struct {
	mu    sync.Mutex
	byReq map[string]Classification
}

// NewClassifier returns an empty classifier.
func NewClassifier() *Classifier { return &Classifier{byReq: map[string]Classification{}} }

// Classify inspects a request as it arrives from the client.
func Classify(settings Settings, req pluginapi.RequestInterceptRequest) Classification {
	c := Classification{SourceFormat: strings.ToLower(strings.TrimSpace(req.SourceFormat))}
	c.Session = SessionFromHeaders(req.Headers)
	if c.Session == "" {
		c.Session = sessionFromMetadata(req.Metadata)
	}
	if c.SourceFormat == sourceClaude {
		path, _ := req.Metadata["request_path"].(string)
		countTokens := strings.Contains(path, "count_tokens")
		d := helps.DetectClaudeCodeRequest(req.Headers, req.Body, countTokens)
		c.ClaudeEntrypoint = strings.ToLower(d.Entrypoint)
		c.ClaudeConfirmed = d.Confirmed && settings.ClaudeEntrypoints[c.ClaudeEntrypoint]
		c.ExtendedCache = extendedCacheTTL.Match(req.Body)
	}
	c.CodexClient = IsCodexClient(settings, req.Headers)
	return c
}

// IsCodexClient requires both an official Codex User-Agent and an accepted Originator.
func IsCodexClient(settings Settings, headers http.Header) bool {
	if !multiagentv2.IsCodexClientUserAgent(headerGet(headers, "User-Agent")) {
		return false
	}
	originator := strings.ToLower(strings.TrimSpace(headerGet(headers, "Originator")))
	if originator == "" {
		return false
	}
	for _, allowed := range settings.CodexOriginators {
		if originator == allowed || strings.HasPrefix(originator, allowed+"/") {
			return true
		}
	}
	return false
}

// Store remembers a classification for the after-selection check.
func (c *Classifier) Store(requestID string, cl Classification, now time.Time) {
	if requestID == "" {
		return
	}
	cl.at = now
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byReq[requestID] = cl
	if len(c.byReq) > 2048 {
		for id, v := range c.byReq {
			if now.Sub(v.at) > 15*time.Minute {
				delete(c.byReq, id)
			}
		}
	}
}

// Load returns a stored classification.
func (c *Classifier) Load(requestID string) (Classification, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cl, ok := c.byReq[requestID]
	return cl, ok
}

// Decision is a gate outcome.
type Decision struct {
	Allow  bool
	Code   string
	Reason string
}

// KeyForScope returns the fleet key whose principal produced the caller scope.
func KeyForScope(settings Settings, scope string) (Key, bool) {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return Key{}, false
	}
	for _, k := range settings.Keys {
		if subtle.ConstantTimeCompare([]byte(k.CallerScope), []byte(scope)) == 1 {
			return k, true
		}
	}
	return Key{}, false
}

// Evaluate decides whether a request may reach its selected provider format.
func Evaluate(settings Settings, cl Classification, toFormat, callerScope string) Decision {
	target := strings.ToLower(strings.TrimSpace(toFormat))
	key, known := KeyForScope(settings, callerScope)
	if known && !key.Providers[target] {
		return Decision{Code: "fleet_key_provider_denied", Reason: "client key " + key.Name + " is not allowed to use " + target + " models"}
	}
	if !settings.GateEnabled || !settings.GatedProviders[target] {
		return Decision{Allow: true}
	}
	if !known && settings.DenyUnknownCallers {
		return Decision{Code: "fleet_unknown_caller", Reason: "subscription models require a fleet client key"}
	}
	switch target {
	case "claude":
		if cl.SourceFormat != sourceClaude {
			return Decision{Code: "fleet_claude_format", Reason: "Claude subscription models accept only native Anthropic Messages requests from Claude Code (got " + emptyAs(cl.SourceFormat, "unknown") + ")"}
		}
		if !cl.ClaudeConfirmed {
			return Decision{Code: "fleet_claude_client", Reason: "Claude subscription models accept only requests confirmed as native Claude Code"}
		}
	case "codex":
		if cl.SourceFormat != sourceResponses {
			return Decision{Code: "fleet_codex_format", Reason: "Codex subscription models accept only Responses API or WebSocket requests from Codex (got " + emptyAs(cl.SourceFormat, "unknown") + ")"}
		}
		if !cl.CodexClient {
			return Decision{Code: "fleet_codex_client", Reason: "Codex subscription models accept only official Codex clients (User-Agent and Originator)"}
		}
	}
	return Decision{Allow: true}
}

// Denial renders a gate rejection as a terminating interceptor response.
func Denial(d Decision) pluginapi.RequestInterceptResponse {
	body, _ := json.Marshal(map[string]any{"error": map[string]string{
		"type":    "permission_error",
		"code":    d.Code,
		"message": d.Reason,
	}})
	return pluginapi.RequestInterceptResponse{
		Terminate:       true,
		StatusCode:      http.StatusForbidden,
		ResponseHeaders: http.Header{"Content-Type": []string{"application/json"}},
		ResponseBody:    body,
	}
}

// Authenticate checks a presented client key against the configured digests.
func Authenticate(settings Settings, req pluginapi.FrontendAuthRequest) pluginapi.FrontendAuthResponse {
	presented := presentedKey(req)
	if presented == "" || len(settings.Keys) == 0 {
		return pluginapi.FrontendAuthResponse{Authenticated: false}
	}
	digest := sha256.Sum256([]byte(presented))
	for _, k := range settings.Keys {
		if subtle.ConstantTimeCompare(digest[:], k.Digest[:]) == 1 {
			return pluginapi.FrontendAuthResponse{
				Authenticated: true,
				Principal:     k.Principal(),
				Metadata:      map[string]string{"fleet_key": k.Name},
			}
		}
	}
	return pluginapi.FrontendAuthResponse{Authenticated: false}
}

func presentedKey(req pluginapi.FrontendAuthRequest) string {
	if auth := strings.TrimSpace(headerGet(req.Headers, "Authorization")); auth != "" {
		if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
			return strings.TrimSpace(auth[7:])
		}
	}
	for _, name := range []string{"X-Api-Key", "X-Goog-Api-Key"} {
		if v := strings.TrimSpace(headerGet(req.Headers, name)); v != "" {
			return v
		}
	}
	if v := strings.TrimSpace(req.Query.Get("key")); v != "" {
		return v
	}
	return ""
}

func emptyAs(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
