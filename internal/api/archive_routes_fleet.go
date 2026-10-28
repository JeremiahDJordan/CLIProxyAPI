package api

// Fleet fork: request archive route classes (design section 1). Every route
// the server registers must appear here; TestArchiveRouteClassificationIsExhaustive
// fails otherwise, so a new upstream route cannot slip into full capture
// unreviewed. At run time an unknown route is metadata-only.

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/archive"
)

var (
	archiveClaudeQuery   = archive.QueryAllowlist{"beta": archive.BoolValue}
	archiveGeminiQuery   = archive.QueryAllowlist{"alt": archive.EnumValue("sse"), "$alt": archive.EnumValue("sse")}
	archiveModelsQuery   = archive.QueryAllowlist{"client_version": archive.VersionValue}
	archiveRealtimeQuery = archive.QueryAllowlist{"model": archive.ModelValue}
)

// archiveInferenceRoutes are provider-reaching routes, captured in full. The
// value is the route's typed query allowlist; other parameters are redacted.
var archiveInferenceRoutes = map[string]archive.QueryAllowlist{
	"GET /v1/models":                 archiveModelsQuery,
	"GET /v1/models/*model":          archiveModelsQuery,
	"POST /v1/chat/completions":      nil,
	"POST /v1/completions":           nil,
	"POST /v1/images/generations":    nil,
	"POST /v1/images/edits":          nil,
	"POST /v1/videos":                nil,
	"POST /v1/videos/generations":    nil,
	"POST /v1/videos/edits":          nil,
	"POST /v1/videos/extensions":     nil,
	"GET /v1/videos/:request_id":     nil,
	"POST /v1/audio/speech":          nil,
	"POST /v1/tts":                   nil,
	"POST /v1/messages":              archiveClaudeQuery,
	"POST /v1/messages/count_tokens": archiveClaudeQuery,
	"GET /v1/responses":              nil,
	"POST /v1/responses":             nil,
	"POST /v1/responses/compact":     nil,
	"POST /v1/alpha/search":          nil,
	"POST /v1/live":                  archiveRealtimeQuery,
	"POST /v1/realtime":              archiveRealtimeQuery,
	"POST /v1/realtime/calls":        archiveRealtimeQuery,

	"POST /openai/v1/videos":                  nil,
	"GET /openai/v1/videos/:video_id":         nil,
	"GET /openai/v1/videos/:video_id/content": {"variant": archive.EnumValue("video", "thumbnail", "spritesheet")},

	"GET /backend-api/codex/responses":          nil,
	"POST /backend-api/codex/responses":         nil,
	"POST /backend-api/codex/responses/compact": nil,
	"POST /backend-api/codex/alpha/search":      nil,

	"GET /v1beta/models":          {"pageSize": archive.UintValue(4)},
	"POST /v1beta/interactions":   archiveGeminiQuery,
	"POST /v1beta/models/*action": archiveGeminiQuery,
	"GET /v1beta/models/*action":  archiveGeminiQuery,
}

// archiveMetadataRoutes are credential and control routes: metadata only.
var archiveMetadataRoutes = map[string]struct{}{
	"GET /":                {},
	"GET /healthz":         {},
	"HEAD /healthz":        {},
	"GET /management.html": {},
	"GET /keep-alive":      {},

	// OAuth callbacks carry authorization codes.
	"GET /anthropic/callback":   {},
	"GET /codex/callback":       {},
	"GET /antigravity/callback": {},
	"GET /callback":             {},
	"GET /devin/callback":       {},

	// Handlers that mint or redeem credentials.
	"POST /v1/realtime/client_secrets":              {},
	"POST /v1/realtime/sessions":                    {},
	"POST /v1/realtime/transcription_sessions":      {},
	"POST /v1/realtime/translations/client_secrets": {},

	// The realtime/sideband WebSocket relay has no frame tap yet.
	"GET /v1/realtime":                {},
	"GET /v1/realtime/calls/:call_id": {},
	"GET /v1/live/:call_id":           {},
	"GET /v1/realtime/translations":   {},
	"POST /v1/realtime/translations":  {},

	// Call control.
	"POST /v1/realtime/calls/:call_id/hangup": {},
	"POST /v1/realtime/calls/:call_id/accept": {},
	"POST /v1/realtime/calls/:call_id/reject": {},
	"POST /v1/realtime/calls/:call_id/refer":  {},
}

// archiveMetadataPrefixes cover the management APIs and plugin resources.
var archiveMetadataPrefixes = []string{"/v0/management", "/v8/management", "/v0/resource/plugins"}

// classifyArchiveRoute returns the class of a registered method and route
// pattern and whether the pattern is known. Routes dispatched outside the
// route table (NoRoute, with an empty pattern) are metadata-only.
func (s *Server) classifyArchiveRoute(method, pattern string) (archive.RouteClass, archive.QueryAllowlist, bool) {
	if pattern == "" {
		return archive.RouteMetadataOnly, nil, true
	}
	key := method + " " + pattern
	if allow, ok := archiveInferenceRoutes[key]; ok {
		return archive.RouteInference, allow, true
	}
	if _, ok := archiveMetadataRoutes[key]; ok {
		return archive.RouteMetadataOnly, nil, true
	}
	for _, prefix := range archiveMetadataPrefixes {
		if pattern == prefix || strings.HasPrefix(pattern, prefix+"/") {
			return archive.RouteMetadataOnly, nil, true
		}
	}
	// AttachWebsocketRoute: the AI Studio provider relay, not client traffic.
	if method == "GET" && s != nil {
		s.wsRouteMu.Lock()
		_, ws := s.wsRoutes[pattern]
		s.wsRouteMu.Unlock()
		if ws {
			return archive.RouteMetadataOnly, nil, true
		}
	}
	return archive.RouteMetadataOnly, nil, false
}
