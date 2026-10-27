# Fleet gateway policy plugin

`fleet` is a standard CLIProxyAPI shared-library plugin (C ABI, `cgo`) that adds:

1. **Per-tool client keys** (`frontend_auth`). Keys are configured as SHA-256 digests only.
   Each key names the provider formats it may reach (`claude`, `codex`). With keys
   configured the plugin is the **exclusive** request authenticator, so
   `access.api-keys` no longer admits requests.
2. **Native-client gate** (`request.intercept_before` + `request.intercept_after`).
   After credential selection, requests whose target format is `claude` must be
   native Anthropic Messages requests confirmed as Claude Code by upstream's detector
   (`helps.DetectClaudeCodeRequest`: `x-app: cli`, Claude Code User-Agent and betas,
   structured `metadata.user_id`, native entrypoint `cli`, `sdk-cli`, `sdk-ts` or
   `claude-vscode`). Requests targeting `codex` must be Responses/WebSocket requests
   from an official Codex client (`multiagentv2.IsCodexClientUserAgent` **and** an
   `Originator` of `codex_cli_rs`, `codex-tui`, `Codex Desktop` or `codex_exec`).
   Translated requests (for example Chat Completions to a Claude model) and keys used
   outside their providers get a JSON `403` naming the reason; callers without a fleet
   key are denied gated providers by default.
3. **Quota tracking** (`usage.handle`, `websocket.response_event`). Per credential it
   records Anthropic `Anthropic-Ratelimit-Unified-{5h,7d,7d_*}-{Status,Reset,Utilization}`
   windows (model-specific `7d_*` claims are attached to the model that returned them)
   and Codex `X-Codex-[<limit>-]{Primary,Secondary}-{Used-Percent,Window-Minutes,
   Reset-After-Seconds,Reset-At}` windows, classified by window length. Codex
   WebSocket `codex.rate_limits` events are converted with upstream's
   `helps.ParseCodexQuotaEventHeaders`. Windows past their reset are treated as fresh;
   early resets (quota restored or reset time moved later before it was due) are counted.
4. **Weekly-reset-first scheduler** (`scheduler.pick`) for `claude` and `codex`:
   skip accounts whose 5-hour or weekly window is exhausted, then pick the soonest
   weekly reset (Claude: the model's own `7d_*` window when observed, otherwise `7d`;
   Codex: the model's named limit, otherwise the shared weekly window). Ties prefer more
   weekly quota left; accounts without data come after known ones. A session keeps its
   account while its prompt cache is warm: Claude 5 minutes, or 1 hour when the session's
   requests used `cache_control` `ttl: "1h"`; Codex 1 hour (configurable). An exhausted
   bound account or an idle session is re-placed by the rule. If every candidate is
   excluded the pick is left to the host.
5. **Status** at `GET /v0/management/fleet/status` (management key required): windows,
   per-model views, recent picks with hashed session IDs and gate counters. No digests.

## Build

From the repository root, with cgo. The host binary must also be built with cgo for
plugin loading (`internal/pluginhost/loader_unix.go`). For Linux x86_64 with glibc 2.28
(Rocky 8) from macOS, use zig as the C compiler:

```sh
export CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
  CC="zig cc -target x86_64-linux-gnu.2.28" CXX="zig c++ -target x86_64-linux-gnu.2.28"
go build -trimpath -ldflags "-s -w" -o cli-proxy-api ./cmd/server
go build -trimpath -buildmode=c-shared -ldflags "-s -w" -o fleet.so ./cmd/fleet-plugin
rm -f fleet.h
```

The library file name sets the plugin ID: install it as `<plugins.dir>/fleet.so`. Keep the
directory and file root-owned and read-only to the proxy account; the host loads a
content-addressed copy from `$TMPDIR/cliproxy-pluginhost/`.

## Configuration

```yaml
upstream:
  claude:
    disable-claude-cloak-mode: false  # auto (default): native Claude Code passes through; others are cloaked
  codex:
    cloak-mode: auto                  # fleet default: official Codex clients keep their headers; others are cloaked
plugins:
  enabled: true
  dir: "/opt/cliproxyapi/current/plugins"   # root-owned; never writable by the service user
  configs:
    fleet:
      enabled: true
      priority: 10
      keys:
        - name: claude-code
          sha256: "<sha256 hex of the Claude Code client key>"
          providers: [claude]
        - name: codex
          sha256: "<sha256 hex of the Codex client key>"
          providers: [codex]
      # exclusive: true                # default true when keys are configured
      gate:
        # providers: [claude, codex]
        # claude-entrypoints: [cli, sdk-cli, sdk-ts, claude-vscode]
        # codex-originators: [codex_cli_rs, codex-tui, codex desktop, codex_exec]
        # deny-unknown-callers: true
      scheduler:
        # claude-cache-ttl: 5m
        # claude-extended-cache-ttl: 1h
        # codex-idle-ttl: 1h
```

Generate a key and its digest without echoing it to logs, for example
`openssl rand -hex 32 | tee key.txt | tr -d '\n' | shasum -a 256`.

## Limits

- Client identity is self-reported. The gate stops other tools and accidental
  configuration; a client that reproduces every Claude Code or Codex signal can pass.
  The tailnet-only listener and the per-tool keys are the access boundary.
- The gate applies to the target formats `claude` and `codex` regardless of whether the
  selected credential is OAuth or an API key.
- `scheduler.pick` runs before the after-selection gate, so a request that is later
  denied still refreshes its session binding.
- State is in memory; a restart forgets quota windows until the next responses.

Tests: `go test ./internal/fleet/` (unit and ABI-level) and the end-to-end smoke
procedure recorded in the fleet repository's `VIBEPROXY.md`.
