# Fleet fork changes

Branch `fleet`, based on upstream **v8.0.45** (`ad8bdd3f`; rebased from v8.0.44 on
2026-10-27). Earlier work on v8.0.29 is
preserved on `fleet-websockets`. Theo's video describes the behavior, but no public
source fork was found under t3dotgg, TheoBr, pingdotgg or t3-oss on 2026-10-14. These
changes are an independent implementation, not a copy of his private code.

## 1. Codex WebSocket default (core patch, carried forward)

Upstream v8.0.45 still returns `false` from `codexWebsocketsEnabled` when a credential
has no `websockets` setting, and the catalog only forces `prefer_websockets: false` on
non-Codex routes. The fork commit is therefore still needed and was cherry-picked
unchanged:

- Codex OAuth credentials without a transport preference use upstream WebSockets
  for downstream WebSocket requests. Explicit `websockets: false` is respected.
  API-key endpoints remain opt-in. HTTP clients keep the HTTP executor.
- The Codex model catalog advertises `prefer_websockets: true` for known,
  exclusively Codex routes, including synthesized aliases. Mixed or non-Codex
  routes remain conservative.

Tests: `internal/client/codex/models/websockets_default_test.go`,
`internal/runtime/executor/codex_websockets_default_test.go`.

## 2. Fleet policy plugin (one small core hook)

`internal/fleet` (logic, unit-tested) and `cmd/fleet-plugin` (cgo shim exporting the
standard plugin ABI) implement per-tool client keys, a native Claude Code / Codex
client gate, provider quota tracking and the weekly-reset-first scheduler with
cache-aware affinity. It lives in the main module so it can reuse upstream's
`helps.DetectClaudeCodeRequest`, `helps.ParseCodexQuotaEventHeaders` and
`multiagentv2.IsCodexClientUserAgent`. See `cmd/fleet-plugin/README.md`.

The only core change it needs: `applyRequestAfterAuthInterceptor`
(`sdk/cliproxy/auth/conductor_execution.go`) passes the selected credential's provider
to after-auth interceptors as `selected_auth_provider`, in a copy of the request
metadata, so the gate can tell which provider an `openai-response` request (for
example compaction) will reach. Test: `sdk/cliproxy/auth/conductor_fleet_provider_test.go`.

Plugins require the host built with `CGO_ENABLED=1` (`plugins/` is upstream's ignored
runtime directory, hence `cmd/fleet-plugin`).

Cloaking stays on as a backstop in case the client gate is ever disabled, so a
non-native client never reaches a provider under its own identity. Claude uses
upstream's default `auto` mode (only unconfirmed clients are cloaked). Codex gains
`upstream.codex.cloak-mode` (`auto` default, `always`, `never`; the legacy
`disable-codex-cloaking: true` still means `never`): `auto` keeps an official Codex
client's own `User-Agent` and `Originator` (official User-Agent prefix plus an official
originator) and applies the built-in identity to every other client, on both HTTP/SSE
and WebSocket paths, instead of upstream's unconditional overwrite. Tests:
`internal/runtime/executor/codex_cloak_mode_fleet_test.go`.

Run `go test ./internal/fleet/ ./internal/client/codex/models ./internal/runtime/executor`
then `go test ./...`. On v8.0.45, upstream's own
`TestDevinApplyPatchRejectionCarriesLogDiagnostic`, `TestModelsMultiAgentClientConfigAndReload`
and three `TestCodexClientModelsResponse*` tests fail on the unmodified tag too. Tests use synthetic credentials and local upstreams only.
