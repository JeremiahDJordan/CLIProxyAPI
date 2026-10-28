package fleet

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// Source formats reported by the host's request handlers.
const (
	sourceClaude    = "claude"
	sourceResponses = "openai-response"
)

// Classification is computed from the original client request before credential
// selection, where the untranslated body is available.
type Classification struct {
	SourceFormat    string
	ClaudeConfirmed bool
	CodexClient     bool
	Session         string
	ExtendedCache   bool
	at              time.Time
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
func Classify(req pluginapi.RequestInterceptRequest) Classification {
	c := Classification{SourceFormat: strings.ToLower(strings.TrimSpace(req.SourceFormat))}
	// The host's canonical derivation covers explicit session headers and Claude Code's
	// metadata.user_id; the scheduler derives the same identity from its pick metadata.
	c.Session = cliproxyauth.CanonicalSessionID(req.Headers, req.Body, req.Metadata)
	if c.SourceFormat == sourceClaude {
		path, _ := req.Metadata["request_path"].(string)
		countTokens := strings.Contains(path, "count_tokens")
		// Confirmed already requires a native Claude Code entrypoint. Claude Code's helper
		// requests (for example session titles under the Agent SDK) omit the claude-code
		// beta but keep every other signal, so those are accepted as well.
		d := helps.DetectClaudeCodeRequest(req.Headers, req.Body, countTokens)
		c.ClaudeConfirmed = d.Confirmed || (d.NativeClient && d.XAppCLI && d.UserAgent && d.MetadataUserID)
		c.ExtendedCache = helps.ClaudePayloadHas1hTTL(req.Body)
	}
	c.CodexClient = helps.IsOfficialCodexClient(req.Headers)
	return c
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

// Evaluate decides whether a request may reach the provider of its selected credential.
func Evaluate(settings Settings, cl Classification, provider, callerScope string) Decision {
	target := strings.ToLower(strings.TrimSpace(provider))
	if target == "" && settings.GateEnabled {
		return Decision{Code: "fleet_unresolved_provider", Reason: "the selected credential's provider could not be determined"}
	}
	key, known := KeyForScope(settings, callerScope)
	if known && !key.Providers[target] {
		return Decision{Code: "fleet_key_provider_denied", Reason: "client key " + key.Name + " is not allowed to use " + target + " models"}
	}
	if !settings.GateEnabled || !subscriptionProviders[target] {
		return Decision{Allow: true}
	}
	if !known {
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
			if !RouteAllowed(k, req.Method, req.Path) {
				return pluginapi.FrontendAuthResponse{
					DenyStatusCode: http.StatusForbidden,
					DenyMessage:    "fleet_route_denied: client key " + k.Name + " may not use " + req.Method + " " + req.Path,
				}
			}
			return pluginapi.FrontendAuthResponse{
				Authenticated: true,
				Principal:     k.Principal(),
				Metadata:      map[string]string{"fleet_key": k.Name},
			}
		}
	}
	return pluginapi.FrontendAuthResponse{Authenticated: false}
}

// RouteAllowed limits fleet keys to the routes the client gate inspects. Other
// provider-reaching routes (search, live/realtime, images, video, audio, Gemini)
// select credentials without request interceptors, so they are denied outright.
func RouteAllowed(k Key, method, path string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	path = strings.TrimRight(strings.TrimSpace(path), "/")
	if method == http.MethodGet && (path == "/v1/models" || strings.HasPrefix(path, "/v1/models/")) {
		return true
	}
	if k.Providers["claude"] && method == http.MethodPost &&
		(path == "/v1/messages" || path == "/v1/messages/count_tokens") {
		return true
	}
	if k.Providers["codex"] {
		for _, prefix := range []string{"/v1", "/backend-api/codex"} {
			switch {
			case path == prefix+"/responses" && (method == http.MethodPost || method == http.MethodGet):
				return true
			case path == prefix+"/responses/compact" && method == http.MethodPost:
				return true
			}
		}
	}
	return false
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
