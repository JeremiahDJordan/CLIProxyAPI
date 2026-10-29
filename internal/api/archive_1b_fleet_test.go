//go:build unix

package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/archive"
	proxyconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
)

// Review finding 1: a chunked body larger than half the queue is captured
// with each byte copied once (1a regrew one buffer and copied the whole body
// on every exact-size step: 67 MiB copied for this 900 KiB body).
func TestArchiveChunkedBodyCopiesEachByteOnce(t *testing.T) {
	server, spool := newArchiveServerWithOverrides(t, func(o *archive.TestOverrides) { o.QueueBytes = 1000 << 10 }, nil)
	classifyForTest(t, http.MethodPost, "/archive-test/copies")
	var copied, consumed int64
	server.engine.POST("/archive-test/copies", func(c *gin.Context) {
		tee := archiveTee(t, c)
		buf := make([]byte, 16<<10) // a client body arrives in small reads
		for {
			_, err := c.Request.Body.Read(buf)
			if err != nil {
				break
			}
		}
		tee.mu.Lock()
		copied, consumed = tee.copied, tee.consumed
		tee.mu.Unlock()
		c.Status(http.StatusOK)
	})
	payload := bytes.Repeat([]byte("0123456789abcdef"), (900<<10)/16)
	req := httptest.NewRequest(http.MethodPost, "/archive-test/copies", io.MultiReader(bytes.NewReader(payload)))
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if consumed != int64(len(payload)) || copied != consumed {
		t.Fatalf("copied %d bytes for a %d-byte body (consumed %d)", copied, len(payload), consumed)
	}
	bodies := eventsFor(spoolEvents(t, spool), archive.TypeClientBody, "/archive-test/copies")
	if len(bodies) != 1 || bodies[0]["capture"] != archive.CaptureFull || !bytes.Equal(spoolBody(t, spool, bodies[0]), payload) {
		t.Fatalf("client_body = %v", bodies)
	}
	if queued := archiveStopQueueBytes(t, spool); queued != 0 {
		t.Fatalf("%v queue bytes still reserved", queued)
	}
}

// Review finding 2: a request's observer can finish after its handler (and
// so after the drain counters) is done. Stop waits for it, so its
// ingress_end is written before the shutdown event instead of being lost.
func TestArchiveStopWaitsForAnObserverStillFinishing(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodGet, "/archive-test/late-finish")
	handlerDone := make(chan struct{})
	server.engine.GET("/archive-test/late-finish", func(c *gin.Context) {
		c.Next()
		// The handler has returned (a WebSocket's socket count has ended);
		// the observer has not finished yet.
		close(handlerDone)
		time.Sleep(300 * time.Millisecond)
	}, func(c *gin.Context) { c.Status(http.StatusNoContent) })
	go server.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/archive-test/late-finish", nil))
	<-handlerDone
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := archive.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	events := spoolEvents(t, spool)
	ends := eventsFor(events, archive.TypeIngressEnd, "/archive-test/late-finish")
	if len(ends) != 1 || ends[0]["ended"] != "request_end" || ends[0]["status"] != float64(http.StatusNoContent) {
		t.Fatalf("ingress_end = %v", ends)
	}
	assertBeforeShutdown(t, events, ends[0])
}

func assertBeforeShutdown(t *testing.T, events []spoolEvent, ev spoolEvent) {
	t.Helper()
	for _, other := range events {
		if other["type"] == archive.TypeShutdown {
			if ev["seq"].(float64) > other["seq"].(float64) {
				t.Fatalf("%v follows the shutdown event", ev["type"])
			}
			return
		}
	}
	t.Fatal("no shutdown event")
}

// Review finding 2: HTTP shutdown ignores hijacked connections, so a
// WebSocket still open when Stop's wait ends is finalized explicitly: its
// ingress_end (ended shutdown) precedes the shutdown event, and the
// handler's own finish later adds nothing. Round-2 finding 2: what the
// connection does afterwards is not recorded, so it counts a drop.
func TestArchiveStopFinalizesAnOpenWebSocket(t *testing.T) {
	server, spool := newArchiveServerWithOverrides(t, func(o *archive.TestOverrides) { o.StopObserverWait = 100 * time.Millisecond }, nil)
	classifyForTest(t, http.MethodGet, "/archive-test/ws-open")
	handlerDone := make(chan struct{})
	server.engine.GET("/archive-test/ws-open", func(c *gin.Context) {
		defer close(handlerDone)
		conn, err := (&websocket.Upgrader{}).Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		for {
			if _, _, err = conn.ReadMessage(); err != nil {
				return
			}
		}
	})
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ts.URL, "http")+"/archive-test/ws-open", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = archive.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	<-handlerDone
	events := spoolEvents(t, spool)
	starts := eventsFor(events, archive.TypeIngressStart, "/archive-test/ws-open")
	ends := eventsFor(events, archive.TypeIngressEnd, "/archive-test/ws-open")
	if len(starts) != 1 || starts[0]["kind"] != archive.KindWSConnection || starts[0]["connection_id"] != starts[0]["ingress_id"] {
		t.Fatalf("ingress_start = %v", starts)
	}
	if len(ends) != 1 || ends[0]["ended"] != "shutdown" || ends[0]["hijacked"] != true ||
		ends[0]["status"] != float64(http.StatusSwitchingProtocols) || ends[0]["kind"] != archive.KindWSConnection ||
		ends[0]["capture_drops"] != float64(1) {
		t.Fatalf("ingress_end = %v", ends)
	}
	assertBeforeShutdown(t, events, ends[0])
}

// archiveUpstreamCtx is the context executors get: a background context
// carrying the gin context (BaseAPIHandler.GetContextWithCancel).
func archiveUpstreamCtx(c *gin.Context) context.Context {
	return context.WithValue(context.Background(), "gin", c)
}

// The executor taps record the outbound request, the upstream response, its
// events, errors and upstream WebSocket traffic with request logging off,
// before the helpers' own request-log checks.
func TestArchiveExecutorTapsRecordTheUpstreamExchange(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodPost, "/archive-test/upstream")
	outbound := []byte(`{"model":"claude-test","messages":[{"role":"user","content":"é  "}]}`)
	sse := [][]byte{
		[]byte("event: message_start"),
		[]byte(`data: {"type":"message_start","message":{"id":"msg_01","model":"claude-test","usage":{"input_tokens":12}}}`),
		{},
		[]byte(`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01"}}`),
	}
	server.engine.POST("/archive-test/upstream", func(c *gin.Context) {
		ctx := archiveUpstreamCtx(c)
		helps.RecordAPIRequest(ctx, server.cfg, helps.UpstreamRequestLog{URL: "https://api.anthropic.example/v1/messages?beta=true", Method: http.MethodPost, Body: outbound, Provider: "claude", AuthID: "claude-auth-1", AuthType: "oauth"})
		helps.RecordAPIResponseMetadata(ctx, server.cfg, http.StatusOK, http.Header{"Content-Type": {"text/event-stream"}})
		for _, chunk := range sse {
			helps.AppendAPIResponseChunk(ctx, server.cfg, chunk)
		}
		helps.RecordAPIResponseError(ctx, server.cfg, io.ErrUnexpectedEOF)
		helps.RecordAPIWebsocketRequest(ctx, server.cfg, helps.UpstreamRequestLog{URL: "wss://chatgpt.example/backend-api/codex/responses", Body: []byte(`{"type":"response.create"}`), Provider: "codex"})
		helps.RecordAPIWebsocketHandshake(ctx, server.cfg, http.StatusSwitchingProtocols, http.Header{"X-Codex-Primary-Used-Percent": {"12"}})
		helps.AppendCodexAPIWebsocketResponse(ctx, server.cfg, []byte(`{"type":"response.completed","response":{"id":"resp_9","usage":{"input_tokens":1}}}`))
		helps.RecordAPIWebsocketUpgradeRejection(ctx, server.cfg, helps.UpstreamRequestLog{URL: "wss://chatgpt.example/backend-api/codex/responses"}, http.StatusForbidden, nil, []byte(`{"error":"denied"}`))
		helps.RecordAPIWebsocketError(ctx, server.cfg, "read", errors.New("websocket: close 1011"))
		c.Status(http.StatusOK)
	})
	server.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/archive-test/upstream", strings.NewReader(`{}`)))
	events := spoolEvents(t, spool)
	requests := eventsFor(events, archive.TypeUpstreamRequest, "/archive-test/upstream")
	if len(requests) != 1 || requests[0]["attempt_seq"] != float64(1) || requests[0]["sub_attempt"] != float64(0) ||
		requests[0]["url"] != "https://api.anthropic.example/v1/messages?beta=true" || requests[0]["auth_id"] != "claude-auth-1" {
		t.Fatalf("upstream_request = %v", requests)
	}
	if got := spoolBody(t, spool, requests[0]); !bytes.Equal(got, outbound) {
		t.Fatalf("outbound body %q", got)
	}
	upstream := eventsFor(events, archive.TypeUpstreamEvent, "/archive-test/upstream")
	if len(upstream) != 3 || !bytes.Equal(spoolBody(t, spool, upstream[1]), sse[1]) || upstream[2]["chunk_seq"] != float64(4) {
		t.Fatalf("upstream_event = %v", upstream)
	}
	if meta := eventsFor(events, archive.TypeUpstreamResponseMeta, "/archive-test/upstream"); len(meta) != 1 || meta[0]["status"] != float64(200) {
		t.Fatalf("upstream_response_meta = %v", meta)
	}
	if errs := eventsFor(events, archive.TypeUpstreamError, "/archive-test/upstream"); len(errs) != 1 || errs[0]["class"] != "eof_unexpected" {
		t.Fatalf("upstream_error = %v", errs)
	}
	var wsEvents []string
	for _, ev := range eventsFor(events, archive.TypeUpstreamWS, "/archive-test/upstream") {
		wsEvents = append(wsEvents, ev["ws_event"].(string))
	}
	if strings.Join(wsEvents, ",") != "request,handshake,response,upgrade_rejection,error" {
		t.Fatalf("upstream_ws = %v", wsEvents)
	}
	if usage := eventsFor(events, archive.TypeUsage, "/archive-test/upstream"); len(usage) != 2 {
		t.Fatalf("usage = %v", usage)
	}
	ends := eventsFor(events, archive.TypeIngressEnd, "/archive-test/upstream")
	if len(ends) != 1 || ends[0]["attempts"] != float64(1) || ends[0]["output_item_ids"] == nil {
		t.Fatalf("ingress_end = %v", ends)
	}
	if ids := ends[0]["upstream_response_ids"].([]any); len(ids) != 2 || ids[0] != "msg_01" || ids[1] != "resp_9" {
		t.Fatalf("upstream_response_ids = %v", ids)
	}
	attemptEnds := eventsFor(events, archive.TypeAttemptEnd, "/archive-test/upstream")
	if len(attemptEnds) != 1 || attemptEnds[0]["ended"] != archive.AttemptEndedRequestEnd || attemptEnds[0]["requests"] != float64(2) {
		t.Fatalf("attempt_end = %v", attemptEnds)
	}
}

// Design section 10.3: the observer captures the X-Z6-* tags and removes
// them before any handler, so an executor forwarding client headers cannot
// send them upstream.
func TestArchiveZ6TagsAreCapturedAndRemoved(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodPost, "/archive-test/z6")
	var seen http.Header
	server.engine.POST("/archive-test/z6", func(c *gin.Context) {
		seen = c.Request.Header.Clone()
		// An executor that forwards every client header.
		helps.RecordAPIRequest(archiveUpstreamCtx(c), server.cfg, helps.UpstreamRequestLog{URL: "https://api.example/v1/messages", Headers: c.Request.Header.Clone()})
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/archive-test/z6", strings.NewReader(`{}`))
	req.Header.Set("X-Z6-Environment-Id", "env-7")
	req.Header.Set("X-Z6-Thread-Id", "thread-9")
	req.Header.Set("x-z6-extra", "other")
	req.Header.Set("X-Claude-Code-Session-Id", "claude-session-1")
	server.Handler().ServeHTTP(httptest.NewRecorder(), req)
	for name := range seen {
		if strings.HasPrefix(strings.ToLower(name), "x-z6-") {
			t.Fatalf("the handler saw %s", name)
		}
	}
	events := spoolEvents(t, spool)
	starts := eventsFor(events, archive.TypeIngressStart, "/archive-test/z6")
	z6, _ := starts[0]["z6"].(map[string]any)
	if z6["z6_environment_id"] != "env-7" || z6["z6_thread_id"] != "thread-9" || z6["z6_other"] == nil {
		t.Fatalf("z6 tags = %v", starts[0]["z6"])
	}
	if sessions, _ := starts[0]["sessions"].(map[string]any); sessions["claude_session_id"] != "claude-session-1" {
		t.Fatalf("sessions = %v", starts[0]["sessions"])
	}
	for _, ev := range eventsFor(events, archive.TypeUpstreamRequest, "/archive-test/z6") {
		for name := range ev["headers"].(map[string]any) {
			if strings.HasPrefix(strings.ToLower(name), "x-z6-") {
				t.Fatalf("an outbound request carries %s", name)
			}
		}
	}
	if headers := starts[0]["headers"].(map[string]any); headers["X-Z6-Environment-Id"] != nil {
		t.Fatal("ingress_start keeps the Z6 header among the headers")
	}
}

// ingress_end reports the client key's configured name and the gate code,
// whether the gate denied at authentication or after credential selection.
func TestArchiveGateCodeAndClientKey(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodPost, "/archive-test/gated")
	server.engine.POST("/archive-test/gated", func(c *gin.Context) {
		c.Set("accessMetadata", map[string]string{"fleet_key": "mac-mini-claude"})
		switch c.Query("denied") {
		case "auth":
			archiveNoteAuthDenial(c, "fleet_route_denied: client key mac-mini-claude may not use POST /archive-test/gated")
			c.AbortWithStatus(http.StatusForbidden)
		case "interceptor":
			ctx := archive.WithAttempt(archiveUpstreamCtx(c))
			archive.NoteGate(ctx, archive.GateDeny, "fleet_claude_client")
			c.AbortWithStatus(http.StatusForbidden)
		default:
			c.Status(http.StatusOK)
		}
	})
	for _, q := range []string{"", "?denied=auth", "?denied=interceptor"} {
		server.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/archive-test/gated"+q, strings.NewReader(`{}`)))
	}
	ends := eventsFor(spoolEvents(t, spool), archive.TypeIngressEnd, "/archive-test/gated")
	if len(ends) != 3 {
		t.Fatalf("ingress_end = %v", ends)
	}
	for i, want := range []string{"", "fleet_route_denied", "fleet_claude_client"} {
		if ends[i]["client_key"] != "mac-mini-claude" {
			t.Fatalf("client_key = %v", ends[i]["client_key"])
		}
		if got, _ := ends[i]["gate_code"].(string); got != want {
			t.Fatalf("request %d gate_code = %q, want %q", i, got, want)
		}
	}
}

// Downstream content is recorded before response compression, write by
// write with offsets, and the first content-bearing write sets first_token_at.
func TestArchiveDownstreamEventsAreUncompressed(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodGet, "/archive-test/sse")
	first := "event: message_start\ndata: {\"type\":\"message_start\"}\n\n" + strings.Repeat(": padding\n", 200)
	second := "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n"
	server.engine.GET("/archive-test/sse", func(c *gin.Context) {
		c.Header("Content-Type", "text/event-stream")
		c.Status(http.StatusOK)
		_, _ = c.Writer.WriteString(first)
		c.Writer.Flush()
		_, _ = c.Writer.Write([]byte(second))
	})
	req := httptest.NewRequest(http.MethodGet, "/archive-test/sse", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Skipf("the stream was not compressed (%v); nothing to compare", rec.Header())
	}
	zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(zr)
	events := spoolEvents(t, spool)
	downstream := eventsFor(events, archive.TypeDownstreamEvent, "/archive-test/sse")
	var joined []byte
	for i, ev := range downstream {
		if ev["offset"] != float64(len(joined)) {
			t.Fatalf("event %d offset %v, want %d", i, ev["offset"], len(joined))
		}
		joined = append(joined, spoolBody(t, spool, ev)...)
	}
	if !bytes.Equal(joined, plain) || len(downstream) != 2 {
		t.Fatalf("downstream events (%d) = %q, client got %q", len(downstream), joined, plain)
	}
	ends := eventsFor(events, archive.TypeIngressEnd, "/archive-test/sse")
	if len(ends) != 1 || ends[0]["bytes_written"] != float64(rec.Body.Len()) || ends[0]["first_token_at"] == nil {
		t.Fatalf("ingress_end = %v", ends)
	}
	if ends[0]["first_token_at"].(string) < downstream[1]["ts"].(string) {
		t.Fatalf("first_token_at %v precedes the content-bearing event %v", ends[0]["first_token_at"], downstream[1]["ts"])
	}
}

// The content tap is not installed when capture is off (covered by
// TestArchiveDisabledInstallsNothing through the handler names), and it
// keeps the writer chain's Flush and Hijack (TestArchiveWriterPreservesFlush,
// TestArchiveWriterPreservesHijack run with it installed).
func TestArchiveContentTapIsInstalledBelowCompression(t *testing.T) {
	server, _ := newArchiveServer(t, func(cfg *proxyconfig.Config) {})
	compression, content := -1, -1
	for i, h := range server.engine.Handlers {
		name := handlerName(h)
		switch {
		case strings.Contains(name, "responseCompressionMiddleware"):
			compression = i
		case strings.Contains(name, "archiveContentMiddleware"):
			content = i
		}
	}
	if compression < 0 || content != compression+1 {
		t.Fatalf("compression at %d, content tap at %d", compression, content)
	}
}

// Round-2 finding 2: Stop clears Current before it waits for the requests
// in flight, but their executor taps still record through the request's own
// ingress (bodies as dropped_body, counted), so the request is recorded as
// capture-incomplete instead of complete with its upstream exchange missing.
func TestArchiveTapsDuringStopAreRecordedOrCounted(t *testing.T) {
	server, spool := newArchiveServerWithOverrides(t, func(o *archive.TestOverrides) { o.StopObserverWait = 5 * time.Second }, nil)
	const path = "/archive-test/stop-window"
	classifyForTest(t, http.MethodPost, path)
	entered := make(chan struct{})
	server.engine.POST(path, func(c *gin.Context) {
		ctx := archive.WithAttempt(archiveUpstreamCtx(c))
		helps.RecordAPIRequest(ctx, server.cfg, helps.UpstreamRequestLog{URL: "https://api.example/v1/messages", Method: http.MethodPost, Body: []byte(`{}`)})
		close(entered)
		for archive.Current() != nil { // until Stop has begun
			time.Sleep(time.Millisecond)
		}
		helps.RecordAPIResponseMetadata(ctx, server.cfg, http.StatusOK, http.Header{"Content-Type": {"text/event-stream"}})
		helps.AppendAPIResponseChunk(ctx, server.cfg, []byte(`data: {"type":"message_delta","usage":{"output_tokens":7}}`))
		archive.EndAttempt(ctx, archive.AttemptEnd{Success: true})
		c.Status(http.StatusOK)
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, path, nil))
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := archive.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	<-done
	events := spoolEvents(t, spool)
	if meta := eventsFor(events, archive.TypeUpstreamResponseMeta, path); len(meta) != 1 || meta[0]["status"] != float64(http.StatusOK) {
		t.Fatalf("upstream_response_meta = %v", meta)
	}
	chunks := eventsFor(events, archive.TypeUpstreamEvent, path)
	if len(chunks) != 1 || chunks[0]["capture"] != archive.CaptureDroppedBody || chunks[0]["body_dropped"] != archive.DropStopped {
		t.Fatalf("upstream_event = %v", chunks)
	}
	if usage, attempts := eventsFor(events, archive.TypeUsage, path), eventsFor(events, archive.TypeAttemptEnd, path); len(usage) != 1 || len(attempts) != 1 || attempts[0]["ended"] != archive.AttemptEndedResult {
		t.Fatalf("usage %v, attempt_end %v", usage, attempts)
	}
	ends := eventsFor(events, archive.TypeIngressEnd, path)
	if len(ends) != 1 || ends[0]["ended"] != "request_end" || ends[0]["capture_drops"] != float64(1) {
		t.Fatalf("ingress_end = %v", ends)
	}
	assertBeforeShutdown(t, events, ends[0])
}

// archiveDiscardWriter keeps nothing, so a test can measure what the
// content tap itself allocates.
type archiveDiscardWriter struct{ header http.Header }

func (w *archiveDiscardWriter) Header() http.Header               { return w.header }
func (w *archiveDiscardWriter) Write(p []byte) (int, error)       { return len(p), nil }
func (w *archiveDiscardWriter) WriteString(s string) (int, error) { return len(s), nil }
func (w *archiveDiscardWriter) WriteHeader(int)                   {}

// Round-2 finding 1: the downstream content tap copies a write only once
// its event is admitted; Write and WriteString refused by a full queue
// allocate nothing.
func TestArchiveContentTapDoesNotCopyRefusedWrites(t *testing.T) {
	newArchiveServerWithOverrides(t, func(o *archive.TestOverrides) { o.QueueBytes = 1 << 20 }, nil)
	rec := archive.Current()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := archive.FlushForTest(ctx); err != nil {
		t.Fatal(err)
	}
	in := rec.BeginIngress(archive.RouteInference, time.Now())
	c, _ := gin.CreateTestContext(&archiveDiscardWriter{header: http.Header{}})
	c.Set(archiveIngressContextKey, in)
	w := newArchiveContentWriter(c)
	if w == nil {
		t.Fatal("no content writer")
	}
	text := strings.Repeat("x", 16<<20)
	data := []byte(text)
	if !rec.ReserveBody(1 << 20) {
		t.Fatal("cannot fill the queue")
	}
	defer rec.ReleaseBody(1 << 20)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 2 {
		_, _ = w.WriteString(text)
		_, _ = w.Write(data)
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= 1<<20 {
		t.Fatalf("four refused 16 MiB writes allocated %d bytes", allocated)
	}
	if in.Drops() != 4 {
		t.Fatalf("request drops = %d", in.Drops())
	}
}

// Round-3 finding 4: a panic recovered while recording a response write
// loses that downstream_event, so the request counts a drop and its
// ingress_end reports it; the response itself is unaffected.
func TestArchiveContentTapPanicCountsAgainstItsRequest(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodGet, "/archive-test/content-panic")
	server.engine.GET("/archive-test/content-panic", func(c *gin.Context) {
		c.String(http.StatusOK, "answer")
	})
	archiveTapFault = func(where string) {
		if where == "content.write" {
			panic("injected tap panic in " + where)
		}
	}
	t.Cleanup(func() { archiveTapFault = nil })
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/archive-test/content-panic", nil))
	archiveTapFault = nil
	if rec.Code != http.StatusOK || rec.Body.String() != "answer" {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	events := spoolEvents(t, spool)
	ends := eventsFor(events, archive.TypeIngressEnd, "/archive-test/content-panic")
	if len(ends) != 1 || ends[0]["capture_drops"] != float64(1) {
		t.Fatalf("ingress_end = %v", ends)
	}
	if got := eventsFor(events, archive.TypeDownstreamEvent, "/archive-test/content-panic"); len(got) != 0 {
		t.Fatalf("downstream_event = %v", got)
	}
}
