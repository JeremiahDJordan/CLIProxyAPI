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

## 3. Request archive recorder, slices 1a and 1b (off by default)

`internal/archive` and the files below implement the recorder of the fleet request archive
(fleet repository, `docs/PROXY-REQUEST-ARCHIVE-DESIGN.md`, revision 8, sections 1-6). Slice 1a
built the core, the transport observer and the client body tee; slice 1b (`RecorderVersion
"1b"`) adds the executor taps, attempts, usage, the gate decision and client key name,
Responses WebSocket turns and frames, downstream content and the identities of section 5. The
v8 status route, the shipper's assembly and ClickHouse come later.

- Configuration `archive: {enabled, spool_dir, segment_seconds, segment_max_mb, queue_mb,
  blob_threshold_mb, body_free_gb, hard_free_gb}` (v8 layout: `observability.archive`), read
  once per process, when the first server is built; that first configuration wins, also when
  it is disabled. Disabled installs nothing and opens no file; every tap is one nil check.
- Start runs its disk work (statfs, the boot lock, the boot event) on its own goroutine and
  gives up after 5 s: capture stays off for the process, and a start that finishes later is
  stopped at once and reports a `start_timeout` gap. Start refuses (logged and counted as a
  gap in `/var/lib/cliproxyapi/archive-state`) unless the spool is on ZFS and holds
  `.fleet-archive-spool`, and the spool root and `blobs/` are both mode 2770 and owned by group
  `fleet-archive`; it also refuses while `codex.response-steering` is on. The writer re-runs
  these checks every space check (10 s) and before recovering from a failure, so a spool that
  is unmounted or changed stops capture until it is safe again.
- Stop never blocks shutdown on the spool: it waits at most 2 s (or half the context's time)
  for requests and WebSocket turns in flight to queue their final events, finalizes the rest
  itself (`ended: shutdown`), and waits at most 10 s for the writer.
- The observer is the outermost gin middleware. Inference routes record redacted headers, the
  typed-allowlisted query and the client body; credential and control routes record metadata
  only. `archive_routes_fleet.go` classifies every registered route and
  `TestArchiveRouteClassificationIsExhaustive` fails on a new unclassified route. The observer
  removes every `X-Z6-*` header before any handler runs and records the tags in
  `ingress_start`.
- Executor taps: `RecordAPIRequest`, `RecordAPIResponseMetadata`, `AppendAPIResponseChunk`,
  `RecordAPIResponseError` and the upstream WebSocket helpers in
  `internal/runtime/executor/helps/logging_helpers.go` call `internal/archive/upstream.go`
  before their own request-log checks (`RecordAPIWebsocketUpgradeRejection` records once).
  The usage reporter's record is tapped in `publishRecord`.
- Attempts: `newUpstreamAttemptContext` opens an archive attempt per upstream attempt; it is
  described where the after-auth interceptor runs (credential, provider, model, the plugin
  scheduler's `pick_reason`, carried back in the request metadata like the selection ID) and
  ended where the conductor records the result (`MarkResult`, `reportHomeResult`,
  `recordAvailabilityNeutralResult`). An attempt takes its `attempt_seq` when first used, so
  unused attempt contexts leave no gap; each outbound request is a `sub_attempt`. Attempts left
  open close with their request.
- Responses WebSocket: every client frame is a turn (`ws_turn`) with its own `ingress_id`,
  allocated by the reader on receipt, before admission, epoch or auth checks, including
  `response.interrupt`. The turn travels in `WebsocketInput.Archive` and is attached to that
  turn's execution context, so its upstream traffic is recorded on it. With steering on for a
  connection (possible only through a reload) its turns are not recorded and a
  `steering_turns` gap is counted.

Core hooks: in `internal/api/server.go` the install line, the content tap line after response
compression and the stop line; one line in `accessAuthMiddleware` (gate code of a fleet
denial); the `Archive` field in `internal/config/config.go` and its v8 path in `config_v8.go`;
the taps in `helps/logging_helpers.go` and `usage_helpers.go`; in `sdk/cliproxy/auth` one line
each in `newUpstreamAttemptContext`, `applyRequestAfterAuthInterceptor` (two),
`pickViaPluginScheduler`, `MarkResult`, `reportHomeResult` and
`recordAvailabilityNeutralResult` (`archive_fleet.go` holds the rest); `Reason` in
`pluginapi.SchedulerPickResponse` (set by the fleet plugin); `Archive` in
`executor.WebsocketInput`; in the Responses WebSocket handler, reader and writer the turn
hooks (`openai_responses_websocket_archive_fleet.go` holds the rest).

### 3.1 Spool envelope (version 1)

Each line is one JSON object, written with HTML escaping off. Envelope fields, on every event:
`v` (1), `boot_id`, `seq` (per boot, from 1, no gaps), `ts` (RFC 3339 UTC, microseconds),
`type`; when they apply: `ingress_id`, `connection_id` (the WebSocket connection's own
`ingress_id`), `turn_seq` (from 1), `attempt_seq` (from 1), `sub_attempt` (from 0),
`capture` (`full`, `metadata_only`, `dropped_body`, `body_unread`), `body_dropped` (why a
body was not captured), `capture_drops` (on `ingress_end`), and `body`.

**`body` is the only field that holds a body, and the only place a blob is referenced.**
`body = {form: text|base64|blob, content_encoding?, bytes, sha256, value?}`; `sha256` and
`bytes` describe the exact bytes; `text` and `base64` carry `value`; `blob` has no `value` and
names `blobs/<sha256>`, which is in the spool (fsynced) once the event is written. Events that
may carry `body`: `client_body`, `upstream_request`, `upstream_event`, `upstream_ws`
(`ws_event` `request`, `upgrade_rejection` or `response`), `downstream_event` and
`client_ws_frame`. A body-carrying event written while bodies are off has
`capture: dropped_body` and `body_dropped` instead of `body`.

| `type` | Per-type fields |
| --- | --- |
| `boot` | `recorder_version`, `redaction_version`, `envelope_version`, build, `boot_started_at`, `pid`, `hostname`, `free_bytes`, `capture_state`, `response_steering`, `config` |
| `shutdown`, `heartbeat` | recorder counters: `queue_bytes`, `queue_limit`, `events_written`, `bytes_written`, `segments_closed`, `blobs_written`, `blobs_reused`, `blobs_rewritten`, `writer_errors`, `tap_panics`, `free_bytes`, `capture_state`, `drops`; `reason` on shutdown |
| `gap` | `reason`, `since`, `drops` (reason → events, bodies, bytes), `prior_boot_id`, `error` |
| `ingress_start` | `kind` (`http`, `ws_connection`), `method`, `path`, `route`, `route_class`, `query`, `client_ip`, `proto`, `host`, `content_length`, `transfer_encoding`, `headers`, `sessions` (`session_id`, `claude_session_id`, `claude_agent_id`, `codex_session_id`, `codex_turn_id`), `z6` (`z6_environment_id`, `z6_thread_id`, `z6_other`); for a WebSocket turn: `kind: ws_turn`, `message_type`, `frame_type`, `model`, `previous_response_id`, `codex_turn_id` and `codex_turn_id_source` (`frame` from `client_metadata.x-codex-turn-metadata`, or `header`), `ws_session_id` |
| `client_body` | `wire_bytes`, `delivered_bytes`, `truncated`, `eof`, `ended`, `content_length`, `content_encoding`, `drop_reason`, `read_error` |
| `attempt_start` | `auth_id`, `provider`, `model`, `requested_model`, `pick_reason`, `session_id` |
| `upstream_request` | `transport`, `url` (query values allowlisted), `method`, `headers`, `provider`, `auth_id`, `auth_label`, `auth_type`; the outbound body |
| `upstream_response_meta` | `status`, `headers` |
| `upstream_event` | `chunk_seq` (per sub-attempt from 1; empty chunks are counted, not written); the chunk exactly as the executor read it (an SSE line, or a whole non-streamed or error body) |
| `upstream_error` | `class` (`canceled`, `timeout`, `eof_unexpected`, `other`), `error` (redacted text) |
| `upstream_ws` | `ws_event` (`request`, `handshake`, `upgrade_rejection`, `error`, `response`), `url`, `headers`, `status`, `response_headers`, `stage`, `class`, `error`, `frame_seq`, `trimmed` (Codex frames are whitespace-trimmed before the tap), auth fields; the frame or rejection body |
| `usage` | `source` (`upstream` or `reporter`), `event` (`message_start`, `message_delta`, `response.completed`, `body`, `usageMetadata`, ...), `model`, `usage` (the provider's usage object, or the reporter's token breakdown) |
| `attempt_end` | the attempt's description, `success`, `status`, `error` (redacted), `ended` (`result`, `request_end`, `shutdown`), `gate` (`allow`, `deny`), `gate_code`, `requests`, `duration_us`, `upstream_response_ids`, `previous_response_id`, `output_item_ids` |
| `downstream_event` | `offset`; one write of the response body before compression |
| `client_ws_frame` | `direction` (`in`, `out`), `message_type`, `write_error`; the frame (client frames before any rewriting, downstream frames after restoration) |
| `ingress_end` | `kind`, `ended` (`request_end`, `shutdown`; `turn_end` for turns), response summary (`status`, `header_written`, `bytes_written`, `content_encoding`, `first_byte_at`, `duration_us`, `hijacked`, `gin_aborted`, `abort`, `panic_type`, `auth_decision`, `auth_provider`), `headers`, `gate_code`, `client_key` (the key's configured name), `attempts`, `first_token_at`, `upstream_response_ids`, `previous_response_id`, `output_item_ids`; for turns `outcome`, `status`, `frames_out`, `bytes_out` |
| `metadata_only` | `started_at`, `method`, `path`, `route`, `route_class`, `query_names`, `client_ip`, response summary |

Redaction (version 1) covers every header, URL and error text the taps record, inbound and
outbound: credential headers and name parts, `Sec-WebSocket-Protocol` key entries, URL-valued
headers, query values outside the route or upstream allowlist, and in free text URLs,
authorization schemes, values of credential-like names and key-shaped words. Bodies are kept
as sent. `TestArchiveRedactsCredentials` feeds fake credentials through every tap.

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
