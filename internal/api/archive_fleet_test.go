//go:build unix

package api

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/klauspost/compress/zstd"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/archive"
	proxyconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

func archiveTestSpool(tb testing.TB) string {
	tb.Helper()
	spool := tb.TempDir()
	if err := os.WriteFile(filepath.Join(spool, archive.SentinelName), nil, 0o640); err != nil {
		tb.Fatal(err)
	}
	blobs := filepath.Join(spool, archive.BlobDirName)
	if err := os.Mkdir(blobs, 0o770); err != nil {
		tb.Fatal(err)
	}
	if err := os.Chmod(blobs, os.ModeSetgid|0o770); err != nil {
		tb.Fatal(err)
	}
	return spool
}

func archiveTestOverrides(tb testing.TB, mutate func(*archive.TestOverrides)) {
	tb.Helper()
	o := archive.TestOverrides{
		StateDir:           filepath.Join(tb.TempDir(), "archive-state"),
		FreeBytes:          func() uint64 { return 1 << 50 },
		FsyncInterval:      20 * time.Millisecond,
		HeartbeatInterval:  time.Hour,
		SpaceCheckInterval: time.Hour,
	}
	if mutate != nil {
		mutate(&o)
	}
	tb.Cleanup(archive.SetTestOverrides(o))
}

// newArchiveServer builds a server like the production one with the recorder on.
func newArchiveServer(tb testing.TB, mutate func(*proxyconfig.Config), opts ...ServerOption) (*Server, string) {
	tb.Helper()
	return newArchiveServerWithOverrides(tb, nil, mutate, opts...)
}

func newArchiveServerWithOverrides(tb testing.TB, overrides func(*archive.TestOverrides), mutate func(*proxyconfig.Config), opts ...ServerOption) (*Server, string) {
	tb.Helper()
	gin.SetMode(gin.TestMode)
	archiveTestOverrides(tb, overrides)
	spool := archiveTestSpool(tb)
	tmp := tb.TempDir()
	cfg := &proxyconfig.Config{}
	cfg.AuthDir = filepath.Join(tmp, "auth")
	cfg.Archive = proxyconfig.ArchiveConfig{Enabled: true, SpoolDir: spool}
	if mutate != nil {
		mutate(cfg)
	}
	server := NewServer(cfg, auth.NewManager(nil, nil, nil), sdkaccess.NewManager(), filepath.Join(tmp, "config.yaml"), opts...)
	tb.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Stop(ctx)
	})
	if archive.Current() == nil {
		tb.Fatal("recorder did not start")
	}
	return server, spool
}

// classifyForTest registers a test route pattern as an inference route.
func classifyForTest(tb testing.TB, method, pattern string) {
	tb.Helper()
	key := method + " " + pattern
	archiveInferenceRoutes[key] = nil
	tb.Cleanup(func() { delete(archiveInferenceRoutes, key) })
}

type spoolEvent map[string]any

func spoolEvents(tb testing.TB, spool string) []spoolEvent {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := archive.FlushForTest(ctx); err != nil {
		tb.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(spool, "*.jsonl"))
	sort.Strings(files)
	var out []spoolEvent
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			tb.Fatal(err)
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 1<<20), 64<<20)
		for scanner.Scan() {
			var ev spoolEvent
			if err = json.Unmarshal(scanner.Bytes(), &ev); err != nil {
				tb.Fatalf("bad spool line %q: %v", scanner.Text(), err)
			}
			out = append(out, ev)
		}
	}
	return out
}

func eventsFor(events []spoolEvent, typ, path string) []spoolEvent {
	ids := map[string]bool{}
	for _, ev := range events {
		if (ev["type"] == archive.TypeIngressStart || ev["type"] == archive.TypeMetadataOnly) && ev["path"] == path {
			ids[ev["ingress_id"].(string)] = true
		}
	}
	var out []spoolEvent
	for _, ev := range events {
		if id, _ := ev["ingress_id"].(string); ids[id] && ev["type"] == typ {
			out = append(out, ev)
		}
	}
	return out
}

func spoolBody(tb testing.TB, spool string, ev spoolEvent) []byte {
	tb.Helper()
	body := ev["body"].(map[string]any)
	var data []byte
	switch body["form"] {
	case archive.FormText:
		data = []byte(body["value"].(string))
	case archive.FormBase64:
		decoded, err := base64.StdEncoding.DecodeString(body["value"].(string))
		if err != nil {
			tb.Fatal(err)
		}
		data = decoded
	case archive.FormBlob:
		stored, err := os.ReadFile(filepath.Join(spool, archive.BlobDirName, body["sha256"].(string)))
		if err != nil {
			tb.Fatal(err)
		}
		data = stored
	default:
		tb.Fatalf("unknown body form %v", body["form"])
	}
	sum := sha256.Sum256(data)
	if body["sha256"] != hex.EncodeToString(sum[:]) {
		tb.Fatalf("sha256 mismatch for %v", body)
	}
	return data
}

func handlerName(h gin.HandlerFunc) string {
	return runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
}

func echoBody(c *gin.Context) {
	data, err := io.ReadAll(c.Request.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			c.String(http.StatusRequestEntityTooLarge, "too large after %d", len(data))
			return
		}
		c.String(http.StatusBadRequest, "read error")
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", data)
}

func TestArchiveDisabledInstallsNothing(t *testing.T) {
	archiveTestOverrides(t, nil)
	spool := archiveTestSpool(t)
	cfg := &proxyconfig.Config{}
	cfg.Archive = proxyconfig.ArchiveConfig{Enabled: false, SpoolDir: spool}
	server := newTestServerWithConfig(t, cfg)
	for _, h := range server.engine.Handlers {
		if strings.Contains(handlerName(h), "archive") {
			t.Fatalf("disabled archive installed %s", handlerName(h))
		}
	}
	var wrapped, teed, carried bool
	server.engine.POST("/archive-test/inspect", func(c *gin.Context) {
		for w := http.ResponseWriter(c.Writer); w != nil; {
			if _, ok := w.(*archiveResponseWriter); ok {
				wrapped = true
			}
			if cw, ok := w.(*unconsumedBodyCloseWriter); ok {
				_, teed = cw.tracker.ReadCloser.(*archiveBodyTee)
			}
			u, ok := w.(interface{ Unwrap() http.ResponseWriter })
			if !ok {
				break
			}
			w = u.Unwrap()
		}
		carried = archive.IngressFromContext(c.Request.Context()) != nil
		echoBody(c)
	})
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/archive-test/inspect", strings.NewReader("hello")))
	if rec.Code != http.StatusOK || rec.Body.String() != "hello" {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	if wrapped || teed || carried {
		t.Fatalf("disabled archive wrapped the writer=%v body=%v context=%v", wrapped, teed, carried)
	}
	if archive.Current() != nil {
		t.Fatal("recorder running while disabled")
	}
	entries, _ := os.ReadDir(spool)
	if len(entries) != 2 {
		t.Fatalf("disabled archive wrote to the spool: %v", entries)
	}
}

func TestArchiveObserverIsOutermostMiddleware(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		server, _ := newArchiveServer(t, nil)
		if name := handlerName(server.engine.Handlers[0]); !strings.Contains(name, "archiveObserverMiddleware") {
			t.Fatalf("first middleware is %s", name)
		}
		if name := handlerName(server.engine.Handlers[1]); !strings.Contains(name, "GinLogrusLogger") {
			t.Fatalf("second middleware is %s", name)
		}
	})
	t.Run("engine configurator added middleware", func(t *testing.T) {
		configured := func(c *gin.Context) { c.Next() }
		server, _ := newArchiveServer(t, nil, WithEngineConfigurator(func(e *gin.Engine) { e.Use(configured) }))
		if name := handlerName(server.engine.Handlers[0]); !strings.Contains(name, "archiveObserverMiddleware") {
			t.Fatalf("first middleware is %s", name)
		}
	})
}

func TestArchiveRedactsCredentials(t *testing.T) {
	server, spool := newArchiveServer(t, func(cfg *proxyconfig.Config) {
		cfg.RemoteManagement.SecretKey = "fake-management-secret-0000"
	})
	classifyForTest(t, http.MethodGet, "/archive-test/cookie")
	server.engine.GET("/archive-test/cookie", func(c *gin.Context) {
		c.Header("Set-Cookie", "sid=fake-set-cookie-0014; Path=/")
		c.String(http.StatusOK, "ok")
	})
	secrets := []string{
		"sk-fake-bearer-0001", "fake-proxy-auth-0002", "sk-ant-fake-xapikey-0003", "AIzaFAKEgoogkey0004",
		"fake-cookie-0005", "sk-fake-wsproto-0006", "AIzaFAKEquerykey0007", "fake-value-0008",
		"fake-code-0009", "fake-state-0010", "fake-password-0011", "fake-oauth-code-0012",
		"fake-oauth-state-0013", "fake-set-cookie-0014", "fake-management-key-0015",
	}
	credentialHeaders := http.Header{
		"Authorization":          {"Bearer sk-fake-bearer-0001"},
		"Proxy-Authorization":    {"Basic fake-proxy-auth-0002"},
		"X-Api-Key":              {"sk-ant-fake-xapikey-0003"},
		"X-Goog-Api-Key":         {"AIzaFAKEgoogkey0004"},
		"Cookie":                 {"session=fake-cookie-0005"},
		"Sec-Websocket-Protocol": {"realtime, openai-insecure-api-key.sk-fake-wsproto-0006"},
		"X-Management-Key":       {"fake-management-key-0015"},
	}
	requests := []struct{ method, target string }{
		{http.MethodPost, "/v1/messages?beta=true&key=AIzaFAKEquerykey0007"},
		{http.MethodPost, "/v1/chat/completions?value=fake-value-0008&password=fake-password-0011"},
		{http.MethodGet, "/v1beta/models/gemini-pro:streamGenerateContent?alt=sse&key=AIzaFAKEquerykey0007"},
		{http.MethodGet, "/v1/responses?code=fake-code-0009&state=fake-state-0010"},
		{http.MethodGet, "/v1/realtime?model=gpt-realtime&key=AIzaFAKEquerykey0007"},
		{http.MethodGet, "/v0/management/config?value=fake-value-0008&password=fake-password-0011"},
		{http.MethodGet, "/v0/management/oauth-callback?code=fake-oauth-code-0012&state=fake-oauth-state-0013"},
		{http.MethodGet, "/v8/management/oauth/callback?code=fake-oauth-code-0012&state=fake-oauth-state-0013"},
		{http.MethodGet, "/anthropic/callback?code=fake-oauth-code-0012&state=fake-oauth-state-0013"},
		{http.MethodGet, "/codex/callback?code=fake-oauth-code-0012&state=fake-oauth-state-0013"},
		{http.MethodGet, "/callback?code=fake-oauth-code-0012&state=fake-oauth-state-0013"},
		{http.MethodGet, "/no-such-route?password=fake-password-0011&fake-code-0009"},
		{http.MethodGet, "/archive-test/cookie?key=AIzaFAKEquerykey0007"},
	}
	for _, r := range requests {
		req := httptest.NewRequest(r.method, r.target, strings.NewReader(`{"model":"x"}`))
		for name, values := range credentialHeaders {
			req.Header[name] = values
		}
		server.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
	events := spoolEvents(t, spool)
	if err := archive.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	err := filepath.Walk(spool, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, errRead := os.ReadFile(path)
		if errRead != nil {
			return errRead
		}
		for _, secret := range secrets {
			if bytes.Contains(data, []byte(secret)) {
				t.Errorf("%s contains %s", filepath.Base(path), secret)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	start := eventsFor(events, archive.TypeIngressStart, "/v1/messages")
	if len(start) != 1 || start[0]["query"] != "beta=true&key=[redacted]" {
		t.Fatalf("messages ingress_start = %v", start)
	}
	headers := start[0]["headers"].(map[string]any)
	if got := headers["Authorization"].([]any)[0]; got != archive.Redacted {
		t.Fatalf("Authorization = %v", got)
	}
	gemini := eventsFor(events, archive.TypeIngressStart, "/v1beta/models/gemini-pro:streamGenerateContent")
	if len(gemini) != 1 || gemini[0]["query"] != "alt=sse&key=[redacted]" {
		t.Fatalf("gemini ingress_start = %v", gemini)
	}
	callback := eventsFor(events, archive.TypeMetadataOnly, "/anthropic/callback")
	if len(callback) != 1 || !reflect.DeepEqual(callback[0]["query_names"], []any{"code", "state"}) {
		t.Fatalf("callback metadata_only = %v", callback)
	}
	if _, ok := callback[0]["headers"]; ok {
		t.Fatal("metadata-only event carries headers")
	}
	cookie := eventsFor(events, archive.TypeIngressEnd, "/archive-test/cookie")
	if len(cookie) != 1 {
		t.Fatalf("cookie ingress_end = %v", cookie)
	}
	if got := cookie[0]["headers"].(map[string]any)["Set-Cookie"].([]any)[0]; got != archive.Redacted {
		t.Fatalf("Set-Cookie = %v", got)
	}
	for _, path := range []string{"/v0/management/config", "/v8/management/oauth/callback", "/no-such-route", "/v1/realtime"} {
		if got := eventsFor(events, archive.TypeMetadataOnly, path); len(got) != 1 {
			t.Fatalf("%s: metadata_only events = %v", path, got)
		}
	}
	if got := eventsFor(events, archive.TypeClientBody, "/v0/management/config"); len(got) != 0 {
		t.Fatalf("metadata-only route captured a body: %v", got)
	}
}

func compressBody(t *testing.T, encoding string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	switch encoding {
	case "gzip":
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(data)
		_ = zw.Close()
	case "zstd":
		zw, err := zstd.NewWriter(&buf)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = zw.Write(data)
		_ = zw.Close()
	}
	return buf.Bytes()
}

func TestArchiveClientBodyRoundTrip(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodPost, "/archive-test/echo")
	server.engine.POST("/archive-test/echo", echoBody)
	jsonish := []byte(`{"a":"x","a":1E5,"p":"\/x","name":"é","s":"` + "  " + `","html":"<b>&amp;</b>"}`)
	cases := []struct {
		name     string
		body     []byte
		encoding string
		chunked  bool
	}{
		{name: "u2028", body: []byte("before after ")},
		{name: "invalid-utf8", body: []byte{'{', 0xff, 0xfe, '}', 0xc3}},
		{name: "e-acute", body: []byte("café café")},
		{name: "duplicate-keys", body: jsonish},
		{name: "gzip", body: compressBody(t, "gzip", jsonish), encoding: "gzip"},
		{name: "zstd", body: compressBody(t, "zstd", jsonish), encoding: "zstd"},
		{name: "chunked", body: jsonish, chunked: true},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, "/archive-test/echo?case="+tc.name, bytes.NewReader(tc.body))
		if tc.encoding != "" {
			req.Header.Set("Content-Encoding", tc.encoding)
		}
		if tc.chunked {
			req.ContentLength = -1
			req.TransferEncoding = []string{"chunked"}
		}
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), tc.body) {
			t.Fatalf("%s: handler saw a different body", tc.name)
		}
	}
	bodies := eventsFor(spoolEvents(t, spool), archive.TypeClientBody, "/archive-test/echo")
	if len(bodies) != len(cases) {
		t.Fatalf("got %d client_body events, want %d", len(bodies), len(cases))
	}
	for i, tc := range cases {
		ev := bodies[i]
		if ev["capture"] != archive.CaptureFull || ev["eof"] != true || ev["wire_bytes"] != float64(len(tc.body)) {
			t.Fatalf("%s: client_body = %v", tc.name, ev)
		}
		if got := spoolBody(t, spool, ev); !bytes.Equal(got, tc.body) {
			t.Fatalf("%s: spool body differs", tc.name)
		}
		if ce, _ := ev["body"].(map[string]any)["content_encoding"].(string); ce != tc.encoding {
			t.Fatalf("%s: content_encoding = %q", tc.name, ce)
		}
	}
}

func TestArchiveLargeBodyBecomesBlob(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodPost, "/archive-test/echo")
	server.engine.POST("/archive-test/echo", echoBody)
	threshold := archive.Current().BlobThreshold()
	payload := bytes.Repeat([]byte("0123456789abcdef"), int(threshold/16)+1)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/archive-test/echo", bytes.NewReader(payload)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	bodies := eventsFor(spoolEvents(t, spool), archive.TypeClientBody, "/archive-test/echo")
	if len(bodies) != 1 || bodies[0]["body"].(map[string]any)["form"] != archive.FormBlob {
		t.Fatalf("client_body = %v", bodies)
	}
	if !bytes.Equal(spoolBody(t, spool, bodies[0]), payload) {
		t.Fatal("blob differs from the body")
	}
}

// findCloseWriter walks the writer chain to the body-limit middleware's writer.
func findCloseWriter(w http.ResponseWriter) *unconsumedBodyCloseWriter {
	for i := 0; i < 16 && w != nil; i++ {
		if cw, ok := w.(*unconsumedBodyCloseWriter); ok {
			return cw
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return nil
		}
		w = u.Unwrap()
	}
	return nil
}

func TestArchiveTeeUnderMaxBytesReader(t *testing.T) {
	server, spool := newArchiveServer(t, func(cfg *proxyconfig.Config) { cfg.MaxRequestBodyBytes = 64 })
	classifyForTest(t, http.MethodPost, "/archive-test/limited")
	trackerMatched := false
	server.engine.POST("/archive-test/limited", func(c *gin.Context) {
		// The limit middleware found the tracker the tee wraps, so its type
		// check still matched and MaxBytesReader sits above the tee.
		if cw := findCloseWriter(c.Writer); cw != nil {
			_, trackerMatched = cw.tracker.ReadCloser.(*archiveBodyTee)
		}
		echoBody(c)
	})
	payload := bytes.Repeat([]byte("x"), 100)

	t.Run("streamed past the limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/archive-test/limited?case=streamed", bytes.NewReader(payload))
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge || rec.Body.String() != "too large after 64" {
			t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
		}
		if !trackerMatched {
			t.Fatal("the body limit middleware did not find the tracker the tee wraps")
		}
	})
	t.Run("declared over the limit", func(t *testing.T) {
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/archive-test/limited?case=declared", bytes.NewReader(payload)))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status %d", rec.Code)
		}
	})

	events := spoolEvents(t, spool)
	bodies := eventsFor(events, archive.TypeClientBody, "/archive-test/limited")
	if len(bodies) != 2 {
		t.Fatalf("client_body events = %v", bodies)
	}
	streamed := bodies[0]
	if streamed["wire_bytes"] != float64(65) || streamed["delivered_bytes"] != float64(64) || streamed["truncated"] != true {
		t.Fatalf("streamed client_body = %v", streamed)
	}
	if got := spoolBody(t, spool, streamed); !bytes.Equal(got, payload[:65]) {
		t.Fatalf("captured %d bytes, want the 65 consumed", len(got))
	}
	declared := bodies[1]
	if declared["capture"] != archive.CaptureBodyUnread || declared["wire_bytes"] != float64(0) {
		t.Fatalf("declared client_body = %v", declared)
	}
	ends := eventsFor(events, archive.TypeIngressEnd, "/archive-test/limited")
	if len(ends) != 2 || ends[1]["status"] != float64(http.StatusRequestEntityTooLarge) || ends[1]["gin_aborted"] != true {
		t.Fatalf("ingress_end = %v", ends)
	}
}

type archiveTestPanic struct{ id int }

func TestArchiveObserverRepanicsWithTheSameValue(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	engine := gin.New()
	engine.Use(server.archiveObserverMiddleware())
	value := &archiveTestPanic{id: 7}
	engine.GET("/archive-test/panic", func(*gin.Context) { panic(value) })
	recovered := func() (rv any) {
		defer func() { rv = recover() }()
		engine.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/archive-test/panic", nil))
		return nil
	}()
	if recovered != value {
		t.Fatalf("observer re-panicked with %v, want the original value", recovered)
	}
	got := eventsFor(spoolEvents(t, spool), archive.TypeMetadataOnly, "/archive-test/panic")
	if len(got) != 1 || got[0]["abort"] != "panic" || got[0]["panic_type"] != "*api.archiveTestPanic" {
		t.Fatalf("metadata_only = %v", got)
	}
}

func TestArchiveAbortHandlerStillAborts(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodGet, "/archive-test/abort")
	server.engine.GET("/archive-test/abort", func(c *gin.Context) {
		c.Writer.WriteHeader(http.StatusOK)
		_, _ = c.Writer.Write([]byte("partial"))
		c.Writer.Flush()
		panic(http.ErrAbortHandler)
	})
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/archive-test/abort")
	if err == nil {
		_, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("the stream completed; http.ErrAbortHandler did not abort the connection")
	}
	ends := eventsFor(spoolEvents(t, spool), archive.TypeIngressEnd, "/archive-test/abort")
	if len(ends) != 1 || ends[0]["abort"] != "abort_handler" || ends[0]["bytes_written"] != float64(len("partial")) {
		t.Fatalf("ingress_end = %v", ends)
	}
}

func TestArchiveWriterPreservesFlush(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodGet, "/archive-test/stream")
	proceed := make(chan struct{})
	flushErr := make(chan error, 1)
	server.engine.GET("/archive-test/stream", func(c *gin.Context) {
		if _, ok := c.Writer.(interface{ FlushError() error }); !ok {
			flushErr <- errors.New("writer chain lost FlushError")
			return
		}
		c.Header("Content-Type", "text/event-stream")
		c.Status(http.StatusOK)
		_, _ = c.Writer.WriteString("data: first\n\n")
		flushErr <- http.NewResponseController(c.Writer).Flush()
		select {
		case <-proceed:
		case <-time.After(5 * time.Second):
		}
		_, _ = c.Writer.WriteString("data: second\n\n")
	})
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	for _, encoding := range []string{"identity", "gzip"} {
		t.Run(encoding, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, ts.URL+"/archive-test/stream", nil)
			if encoding == "identity" {
				req.Header.Set("Accept-Encoding", "identity")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if err = <-flushErr; err != nil {
				t.Fatalf("flush through the wrapper: %v", err)
			}
			line, err := bufio.NewReader(resp.Body).ReadString('\n')
			if err != nil || line != "data: first\n" {
				t.Fatalf("first event %q, %v; the flush did not reach the client", line, err)
			}
			proceed <- struct{}{}
			_, _ = io.ReadAll(resp.Body)
		})
	}
	ends := eventsFor(spoolEvents(t, spool), archive.TypeIngressEnd, "/archive-test/stream")
	if len(ends) != 2 {
		t.Fatalf("ingress_end = %v", ends)
	}
	if ends[0]["first_byte_at"] == nil || ends[0]["content_encoding"] != nil {
		t.Fatalf("identity ingress_end = %v", ends[0])
	}
	if ends[1]["content_encoding"] != "gzip" {
		t.Fatalf("gzip ingress_end = %v", ends[1])
	}
}

func TestArchiveWireBytesAreCompressedBytes(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodGet, "/archive-test/big")
	server.engine.GET("/archive-test/big", func(c *gin.Context) {
		c.String(http.StatusOK, strings.Repeat("compressible text ", 2000))
	})
	req := httptest.NewRequest(http.MethodGet, "/archive-test/big", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("response not compressed: %v", rec.Header())
	}
	ends := eventsFor(spoolEvents(t, spool), archive.TypeIngressEnd, "/archive-test/big")
	if len(ends) != 1 || ends[0]["bytes_written"] != float64(rec.Body.Len()) || ends[0]["content_encoding"] != "gzip" {
		t.Fatalf("ingress_end = %v (client got %d bytes)", ends, rec.Body.Len())
	}
}

func TestArchiveWriterPreservesHijack(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodGet, "/archive-test/ws")
	server.engine.GET("/archive-test/ws", func(c *gin.Context) {
		conn, err := (&websocket.Upgrader{}).Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		kind, msg, err := conn.ReadMessage()
		if err == nil {
			_ = conn.WriteMessage(kind, append([]byte("echo:"), msg...))
		}
	})
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ts.URL, "http")+"/archive-test/ws", nil)
	if err != nil {
		t.Fatalf("websocket upgrade through the wrapper: %v", err)
	}
	if err = conn.WriteMessage(websocket.TextMessage, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	_, msg, err := conn.ReadMessage()
	_ = conn.Close()
	if err != nil || string(msg) != "echo:hi" {
		t.Fatalf("echo %q, %v", msg, err)
	}
	var ends []spoolEvent
	deadline := time.Now().Add(5 * time.Second)
	for len(ends) == 0 && time.Now().Before(deadline) {
		ends = eventsFor(spoolEvents(t, spool), archive.TypeIngressEnd, "/archive-test/ws")
	}
	if len(ends) != 1 || ends[0]["hijacked"] != true || ends[0]["status"] != float64(http.StatusSwitchingProtocols) {
		t.Fatalf("ingress_end = %v", ends)
	}
}

func TestArchiveTapPanicDoesNotAffectRequest(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodPost, "/archive-test/echo")
	server.engine.POST("/archive-test/echo", func(c *gin.Context) {
		c.Writer.Flush()
		echoBody(c)
	})
	stages := []string{"observer.start", "observer.finish", "writer.commit", "writer.write", "body.read", "body.emit"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			archiveTapFault = func(where string) {
				if where == stage {
					panic("injected tap panic in " + where)
				}
			}
			defer func() { archiveTapFault = nil }()
			payload := []byte(`{"stage":"` + stage + `"}`)
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/archive-test/echo", bytes.NewReader(payload)))
			if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), payload) {
				t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
			}
		})
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range spoolEvents(t, spool) {
			if drops, ok := ev["drops"].(map[string]any); ok && ev["type"] == archive.TypeGap && drops[archive.DropTapPanic] != nil {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("tap panics were not reported as a gap")
}

func TestArchiveRouteClassificationIsExhaustive(t *testing.T) {
	cfg := &proxyconfig.Config{}
	cfg.RemoteManagement.SecretKey = "fake-management-secret-0000"
	server := newTestServerWithConfig(t, cfg,
		WithPluginHost(pluginhost.New()),
		WithKeepAliveEndpoint(time.Minute, func() {}),
		WithLocalManagementPassword("fake-local-password-0000"),
	)
	// The production service attaches the AI Studio relay at /v1/ws.
	server.AttachWebsocketRoute("/v1/ws", http.NotFoundHandler())
	server.AttachWebsocketRoute("/custom/relay", http.NotFoundHandler())

	registered := map[string]bool{}
	var missing []string
	for _, route := range server.engine.Routes() {
		key := route.Method + " " + route.Path
		registered[key] = true
		if _, _, known := server.classifyArchiveRoute(route.Method, route.Path); !known {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("routes without an archive class:\n%s", strings.Join(missing, "\n"))
	}
	// Explicit entries must name real routes, and the classes are disjoint.
	for key := range archiveInferenceRoutes {
		if !registered[key] {
			t.Errorf("inference entry %q is not a registered route", key)
		}
		if _, ok := archiveMetadataRoutes[key]; ok {
			t.Errorf("%q is in both classes", key)
		}
	}
	for key := range archiveMetadataRoutes {
		if !registered[key] {
			t.Errorf("metadata-only entry %q is not a registered route", key)
		}
	}
	for _, key := range []string{"GET /v1/ws", "GET /custom/relay", "GET /v1/realtime", "POST /v1/realtime/client_secrets", "POST /v1/realtime/sessions", "GET /anthropic/callback"} {
		method, pattern, _ := strings.Cut(key, " ")
		if class, _, _ := server.classifyArchiveRoute(method, pattern); class != archive.RouteMetadataOnly {
			t.Errorf("%s is %s, want metadata_only", key, class)
		}
	}
	if class, _, known := server.classifyArchiveRoute(http.MethodGet, ""); !known || class != archive.RouteMetadataOnly {
		t.Error("NoRoute dispatch is not metadata-only")
	}
	// A route nobody classified is reported, so the check above can fail.
	if class, _, known := server.classifyArchiveRoute(http.MethodPost, "/v1/embeddings"); known || class != archive.RouteMetadataOnly {
		t.Error("an unclassified route was not reported, or not kept metadata-only")
	}
}

// BenchmarkArchiveObserver compares a small inference request with the
// recorder off (not installed) and on (observer, writer wrapper and tee).
// With -cpu 1 the writer goroutine shares the core, so ns/op then includes
// the asynchronous encoding and disk work as well.
func BenchmarkArchiveObserver(b *testing.B) {
	payload := []byte(`{"model":"claude-test","messages":[{"role":"user","content":"` + strings.Repeat("hello ", 150) + `"}]}`)
	run := func(b *testing.B, enabled bool) {
		gin.SetMode(gin.ReleaseMode)
		// Per-request access logging would dominate both cases.
		level, out := log.GetLevel(), log.StandardLogger().Out
		log.SetLevel(log.ErrorLevel)
		log.SetOutput(io.Discard)
		b.Cleanup(func() {
			log.SetLevel(level)
			log.SetOutput(out)
		})
		var server *Server
		if enabled {
			// Production writer cadence: fsync every second.
			server, _ = newArchiveServerWithOverrides(b, func(o *archive.TestOverrides) { o.FsyncInterval = time.Second }, nil)
		} else {
			tmp := b.TempDir()
			cfg := &proxyconfig.Config{}
			cfg.AuthDir = filepath.Join(tmp, "auth")
			server = NewServer(cfg, auth.NewManager(nil, nil, nil), sdkaccess.NewManager(), filepath.Join(tmp, "config.yaml"))
		}
		classifyForTest(b, http.MethodPost, "/archive-bench/echo")
		server.engine.POST("/archive-bench/echo", echoBody)
		handler := server.Handler()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/archive-bench/echo?beta=true", bytes.NewReader(payload))
			req.Header.Set("Authorization", "Bearer sk-fake-bench")
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				b.Fatalf("status %d", rec.Code)
			}
		}
	}
	b.Run("off", func(b *testing.B) { run(b, false) })
	b.Run("on", func(b *testing.B) { run(b, true) })
}
