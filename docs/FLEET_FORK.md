# Fleet WebSocket changes

Based on upstream v8.0.29. Theo's video describes the behavior, but no public
source fork was found under t3dotgg, TheoBr, pingdotgg or t3-oss on 2026-10-14.
These changes are an independent implementation, not a copy of his private code.

- Codex OAuth credentials without a transport preference use upstream WebSockets
  for downstream WebSocket requests. Explicit `websockets: false` is respected.
  API-key endpoints remain opt-in. HTTP clients keep the HTTP executor.
- The Codex model catalog advertises `prefer_websockets: true` for known,
  exclusively Codex routes, including synthesized aliases. Mixed or non-Codex
  routes remain conservative.
- Existing upstream connection reuse, continuation replay, HTTP fallback and
  disconnect handling are retained. Enable routing.session-affinity separately
  to keep a conversation on its account; no client configurations are changed.

Run `go test ./internal/client/codex/models ./internal/runtime/executor
./sdk/api/handlers/openai` (on one line), then `go test ./...` and build the server.
Tests use synthetic credentials and local upstreams, not subscription accounts.
