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
  it is disabled. Disabled installs nothing and opens no file; every tap is one nil check
  (`archive.Installed`). Taps reserve an event's whole size, body included, before they copy
  anything, so a body the queue refuses is counted and never allocated. JSON a tap inspects
  (upstream events and bodies, usage objects, client WebSocket frames) is read through a view
  of its bytes (`archive.BytesView`), never copied whole: identities, models and frame fields
  are kept as copies of their own of at most 256 bytes (longer values are dropped), and a
  usage object or a turn's fields are copied only once their event is reserved. A panic
  recovered in a tap that had found its request counts a drop against that request.
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
  itself (`ended: shutdown`, which counts a drop), and waits at most 10 s for the writer. Stop
  clears `archive.Current` first, so no new request or turn is recorded (a refused turn counts
  against its connection); taps of requests in flight keep recording through their own ingress
  (`archive.Installed` stays true): metadata in full, bodies as `dropped_body` (`stopped`),
  and after the writer's final drain everything is dropped and counted against the request.
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
  The usage reporter's record is tapped in `publishRecord`. Antigravity keeps its request-log
  body only while request logging is on, so it calls `RecordAPIRequestSent` with the bytes it
  sends; Devin's request-log body is a JSON rendering of a protobuf that carries the
  credential, so it calls `RecordAPIRequestBodyNotCaptured` (`body_dropped: not_captured`).
  Codex HTTP requests (responses, compact, images) call `RecordAPIRequestOnWire`, which records
  the request's own body as sent: zstd, with `body.content_encoding`, when
  `upstream.codex.upstream-request-compression` compresses it. When the upstream rejects a zstd
  body (400 or 415), `doCodexRequest` records the rejected response (status, headers and up to
  1 MiB of body; a longer body counts a drop) before discarding it, and the uncompressed resend
  as a new `sub_attempt` of the same attempt with `resend: compression_rejected`.
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
  turn's execution context, so its upstream traffic is recorded on it (a turn that is not
  recorded is detached from its connection). The error frame answering a rejected interrupt is
  recorded on the interrupt's own turn. With steering on for a
  connection (possible only through a reload) its turns are not recorded, their execution is
  detached from the connection (no turn traffic is recorded on it), the connection counts a
  drop (its `ingress_end` has `capture_drops`) and a `steering_turns` gap is counted.

Core hooks: in `internal/api/server.go` the install line, the content tap line after response
compression and the stop line; one line in `accessAuthMiddleware` (gate code of a fleet
denial); the `Archive` field in `internal/config/config.go` and its v8 path in `config_v8.go`;
the taps in `helps/logging_helpers.go` and `usage_helpers.go`, and the request taps of
`antigravity_executor_request.go` (one call), `devin_executor.go` (two calls),
`codex_executor_execute.go` (two), `codex_executor_stream.go` (one),
`recordCodexOpenAIImageRequest` (which takes the request instead of its headers) and
`doCodexRequest` (two lines, the rejected response and the resend); in
`sdk/cliproxy/auth` one line
each in `newUpstreamAttemptContext`, `applyRequestAfterAuthInterceptor` (two),
`pickViaPluginScheduler`, `MarkResult`, `reportHomeResult` and
`recordAvailabilityNeutralResult` (`archive_fleet.go` holds the rest); `Reason` in
`pluginapi.SchedulerPickResponse` (set by the fleet plugin); `Archive` in
`executor.WebsocketInput`; in the Responses WebSocket handler, reader and writer the turn
hooks, and `writeResponsesWebsocketPayloadForTurn` behind `writeResponsesWebsocketPayload`
(`openai_responses_websocket_archive_fleet.go` holds the rest).

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
`capture: dropped_body` and `body_dropped` (`low_space_body`, `low_space_hard`, `stopped`,
`writer_error`, `queue_full`) instead of `body`; an outbound body the executor's tap cannot
record as sent has `body_dropped: not_captured` (Devin). Every `dropped_body` counts in its
request's `capture_drops`; `not_captured` is not a gap. `content_encoding` names the encoding
of bytes recorded encoded: a `client_body` as received, a Codex `upstream_request` sent zstd.

A request is capture-incomplete when its `ingress_end` has `capture_drops` above zero, when it
has no `ingress_end`, or when any of its events lies in a suspect range (below). `ended:
shutdown` (Stop finalized the request or turn while it was still running) always has
`capture_drops` of at least 1: what it did afterwards is not recorded. A tap panic recovered
while recording for a request, and a steering connection's unrecorded turns, count there too.

Suspect ranges: when an fsync of a segment fails, the events written to it since its last
successful fsync may be missing or damaged on disk even though a later fsync (the close is
retried) succeeds. The writer records them as a range `{boot_id, segment, first_seq,
last_seq}` (`segment` without `.open.jsonl`/`.closed.jsonl`), persisted with the drop
counters (in the state directory, off the spool's pool) before the writer retries the
segment's close, which can hang, and reported in the `suspect` list of the next gap
(`writer_error` at recovery, or `carried_over` by the next boot); the gap itself is fsynced
before the range is cleared. An event written whose reused blob could not be written again is
a range of one. Assembly must treat every request with an event in a suspect range as
capture-incomplete. A range can be reported twice (when persisting the cleared counters after
its gap fails, the next boot reports it again), so assembly dedupes ranges on `(boot_id,
segment, first_seq, last_seq)`.

| `type` | Per-type fields |
| --- | --- |
| `boot` | `recorder_version`, `redaction_version`, `envelope_version`, build, `boot_started_at`, `pid`, `hostname`, `free_bytes`, `capture_state`, `response_steering`, `config` |
| `shutdown`, `heartbeat` | recorder counters: `queue_bytes`, `queue_limit`, `events_written`, `bytes_written`, `segments_closed`, `blobs_written`, `blobs_reused`, `blobs_rewritten`, `writer_errors`, `tap_panics`, `free_bytes`, `capture_state`, `drops`; `reason` on shutdown |
| `gap` | `reason`, `since`, `drops` (reason → events, bodies, bytes), `suspect` (suspect ranges), `prior_boot_id`, `error` |
| `ingress_start` | `kind` (`http`, `ws_connection`), `method`, `path`, `route`, `route_class`, `query`, `client_ip`, `proto`, `host`, `content_length`, `transfer_encoding`, `headers`, `sessions` (`session_id`, `claude_session_id`, `claude_agent_id`, `codex_session_id`, `codex_turn_id`), `z6` (`z6_environment_id`, `z6_thread_id`, `z6_other`); for a WebSocket turn: `kind: ws_turn`, `message_type`, `frame_type`, `model`, `previous_response_id`, `codex_turn_id` and `codex_turn_id_source` (`frame` from `client_metadata.x-codex-turn-metadata`, or `header`), `ws_session_id` (frame fields over 256 bytes are left out) |
| `client_body` | `wire_bytes`, `delivered_bytes`, `truncated`, `eof`, `ended`, `content_length`, `content_encoding`, `drop_reason`, `read_error` |
| `attempt_start` | `auth_id`, `provider`, `model`, `requested_model`, `pick_reason`, `session_id` |
| `upstream_request` | `transport`, `url` (query values allowlisted), `method`, `headers`, `resend` (`compression_rejected`: the executor's own resend of the attempt's request, as a new `sub_attempt`), `provider`, `auth_id`, `auth_label`, `auth_type`; the outbound body as sent |
| `upstream_response_meta` | `status`, `headers` |
| `upstream_event` | `chunk_seq` (per sub-attempt from 1; empty chunks are counted, not written); the chunk exactly as the executor read it (an SSE line, or a whole non-streamed or error body) |
| `upstream_error` | `class` (`canceled`, `timeout`, `eof_unexpected`, `other`), `error` (redacted text) |
| `upstream_ws` | `ws_event` (`request`, `handshake`, `upgrade_rejection`, `error`, `response`), `url`, `headers`, `status`, `response_headers`, `stage`, `class`, `error`, `frame_seq`, `trimmed` (Codex frames are whitespace-trimmed before the tap), auth fields; the frame or rejection body |
| `usage` | `source` (`upstream` or `reporter`), `event` (`message_start`, `message_delta`, `response.completed`, `body`, `usageMetadata`, ...), `model`, `usage` (the provider's usage object, or the reporter's token breakdown, redacted as below) |
| `attempt_end` | the attempt's description, `success`, `status`, `error` (redacted), `ended` (`result`, `request_end`, `shutdown`), `gate` (`allow`, `deny`), `gate_code`, `requests`, `duration_us`, `upstream_response_ids`, `previous_response_id`, `output_item_ids` |
| `downstream_event` | `offset`; one write of the response body before compression |
| `client_ws_frame` | `direction` (`in`, `out`), `message_type`, `write_error`; the frame (client frames before any rewriting, downstream frames after restoration) |
| `ingress_end` | `kind`, `ended` (`request_end`, `shutdown` (capture-incomplete); `turn_end` for turns), response summary (`status`, `header_written`, `bytes_written`, `content_encoding`, `first_byte_at`, `duration_us`, `hijacked`, `gin_aborted`, `abort`, `panic_type`, `auth_decision`, `auth_provider`), `headers`, `gate_code`, `client_key` (the key's configured name), `attempts`, `first_token_at`, `upstream_response_ids`, `previous_response_id`, `output_item_ids`; for turns `outcome`, `status`, `frames_out`, `bytes_out` |
| `metadata_only` | `started_at`, `method`, `path`, `route`, `route_class`, `query_names`, `client_ip`, response summary |

Redaction (version 1) covers every header, URL and error text the taps record, inbound and
outbound: credential headers and name parts, `Sec-WebSocket-Protocol` key entries, URL-valued
headers, query values outside the route or upstream allowlist, and in free text URLs,
authorization schemes, values of credential-like names and key-shaped words. Credential name
parts are `key`, `token`, `secret`, `password`, `auth`, `cookie`, `session`, `signature` and
`credential` (session ID headers and `Access-Control-Allow-Credentials` are kept). JSON copied into
metadata (`usage`) is redacted by `RedactJSON`: every string under a member with a credential
name (as for headers, except token counts such as `input_tokens` or `promptTokenCount` and the
usage reporter's `token_breakdown`, whose `quality` is kept) becomes `[redacted]`, numbers, booleans and nulls are kept, and any other string is redacted
when it looks like a key or passed through the free-text rules. Bodies are kept as sent.
`TestArchiveRedactsCredentials` feeds fake credentials through every tap.

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
