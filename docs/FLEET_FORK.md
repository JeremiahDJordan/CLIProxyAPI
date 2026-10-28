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
`helps.DetectClaudeCodeRequest`, `helps.ClaudePayloadHas1hTTL`,
`helps.ParseCodexQuotaEventHeaders`, `cliproxysession.CallerScope` and
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
client's own `User-Agent` and `Originator` (`helps.IsOfficialCodexClient`, the same check
the gate uses) and applies the built-in identity to every other client, on both HTTP/SSE
and WebSocket paths, instead of upstream's unconditional overwrite. Tests:
`internal/runtime/executor/codex_cloak_mode_fleet_test.go`.

T3 Code (and Z6) run the official Codex app-server with the originator `T3 Code`
(User-Agent `T3 Code/<codex version> …`); OpenAI tailors the model catalog to it, for
example the Sol Ultrafast tier. The fork treats it as an official Codex client
everywhere upstream distinguishes one, so its identity passes through unchanged:
`helps.IsOfficialCodexClient` (gate and cloak-mode `auto`),
`multiagentv2.IsCodexClientUserAgent` (Responses `response.failed` framing and
multi-agent v2) and `cliproxyauth.IsCodexClientUserAgent` (SIWC credential choice).
Upstream v8.0.45 would instead rewrite it to its built-in `codex-tui` identity. Tests:
`*t3*_fleet_test.go` and the T3 Code cases in the gate and cloak-mode tests.

## 3. Request archive recorder, slice 1a (off by default)

`internal/archive` and `internal/api/archive*_fleet.go` implement the first slice of the
fleet request archive (fleet repository, `docs/PROXY-REQUEST-ARCHIVE-DESIGN.md`, revision 6,
sections 1-7): the recorder core, the transport observer and the client body tee. Executor
taps, attempts, usage, WebSocket turns, the v8 status route and the shipper come later; they
attach to the `*archive.Ingress` carried in the request context
(`archive.IngressFromContext`).

- Configuration `archive: {enabled, spool_dir, segment_seconds, segment_max_mb, queue_mb,
  blob_threshold_mb, body_free_gb, hard_free_gb}` (v8 layout: `observability.archive`), read
  once per process, when the first server is built; that first configuration wins, also when
  it is disabled. Disabled installs nothing and opens no file.
- Start refuses (logged and counted as a gap in `/var/lib/cliproxyapi/archive-state`) unless
  the spool is on ZFS and holds `.fleet-archive-spool`, and the spool root and `blobs/` are
  both mode 2770 and owned by group `fleet-archive`; it also refuses while
  `codex.response-steering` is on.
- The observer is the outermost gin middleware. Inference routes record redacted headers,
  the typed-allowlisted query and the client body; credential and control routes record
  metadata only. `archive_routes_fleet.go` classifies every registered route and
  `TestArchiveRouteClassificationIsExhaustive` fails on a new unclassified route.

Core hooks: two lines in `internal/api/server.go` (install in `NewServer`, stop in `Stop`),
the `Archive` field in `internal/config/config.go` and its v8 path in `config_v8.go`.

## 4. Restarts without interrupting work

Upstream closes the HTTP server at once on SIGTERM, cutting off responses that are still
streaming and every open Codex WebSocket. `internal/fleetdrain`, `internal/api/drain_fleet.go`,
`sdk/cliproxy/drain_fleet.go` and `openai_responses_websocket_drain_fleet.go` change that:

- A tracker per API server counts HTTP requests in flight (outermost middleware, inside the
  archive observer; only the activity route is exempt), open Responses WebSockets (the
  request stops counting once it is upgraded) and their turns. The socket's reader admits
  each frame the moment it is read, before parsing, so a frame on its way to the handler is
  never mistaken for an idle socket. `GET /v0/management/fleet/activity` (management key)
  reports `{requests, websockets, websocket_turns, steering_websockets, draining, quiet}`;
  `quiet` means no request, turn or steering WebSocket is in flight. An installer restarts
  in such a moment.
- On SIGTERM, before anything else stops (`DrainFleet`, 75 s, then upstream's 30 s shutdown,
  within systemd's `TimeoutStopSec=120`): the base listener closes; connections already
  accepted are still sniffed, routed and adopted by the HTTP server (the mux listener now
  hands over a connection it has taken even if it was closed meanwhile); with keep-alives
  off, every HTTP/1 connection (tracked through `http.Server.ConnState`) finishes its
  response, including the writes net/http makes after the handler returns, and closes.
  `http.Server.Shutdown` is not used for this because net/http drops a request read after
  Shutdown starts; it runs last, for HTTP/2 GOAWAY. Idle Responses WebSockets close with
  1012 (service restart) and busy ones after the turns read before the drain began; a
  turn read after that is dropped (the client sees the close and resends to the next
  process), while interrupts are still handled. Codex checks its cached socket
  before each turn and reconnects when it is closed.
- Limits: with `codex.response-steering` on (off at homelab; the archive also refuses it),
  the duplex executor keeps a session in one handler turn and reports no per-response
  state, so each steering WebSocket counts as busy for its whole life and is closed only
  when a drain times out; a warning is logged at start. Realtime/live WebSockets count as
  requests while open; the fleet gate refuses those routes.
- Under systemd socket activation (`LISTEN_PID`/`LISTEN_FDS`, one TCP socket) the server
  serves on the inherited socket, which outlives the process, so connections arriving
  during a drain or restart wait in the kernel queue for the next process instead of being
  refused. The socket's address wins over the configured one (logged when they differ).

Core hooks: in `internal/api/server.go` the drain fields, their install line, the listener
call, the `ConnState` hook, accept-loop accounting and the drain branch in `Start`; routing
accounting in `protocol_multiplexer.go`; the queued count and the hand-over in
`mux_listener.go`; one route in `server_management.go`; one line in
`sdk/cliproxy/service_lifecycle.go` (drain before `Shutdown`); in the Responses WebSocket
handler and reader, the socket count, admission and the drain close.
