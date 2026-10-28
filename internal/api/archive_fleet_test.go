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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
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

// archiveTestSpool provisions a spool: root and blobs/ 2770, owned by the
// process's effective group, which archiveTestOverrides names.
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
	for _, dir := range []string{spool, blobs} {
		if err := os.Chown(dir, -1, os.Getegid()); err != nil {
			tb.Fatal(err)
		}
		if err := os.Chmod(dir, os.ModeSetgid|0o770); err != nil {
			tb.Fatal(err)
		}
	}
	return spool
}

func archiveTestOverrides(tb testing.TB, mutate func(*archive.TestOverrides)) {
	tb.Helper()
	group, err := user.LookupGroupId(strconv.Itoa(os.Getegid()))
	if err != nil {
		tb.Skipf("cannot name the effective group: %v", err)
	}
	o := archive.TestOverrides{
		StateDir:           filepath.Join(tb.TempDir(), "archive-state"),
		SpoolGroup:         group.Name,
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

// archiveStopQueueBytes stops the recorder and returns the queue bytes its
// shutdown event reports: anything above zero is a stranded reservation.
func archiveStopQueueBytes(tb testing.TB, spool string) float64 {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := archive.Stop(ctx); err != nil {
		tb.Fatal(err)
	}
	for _, ev := range spoolEvents(tb, spool) {
		if ev["type"] == archive.TypeShutdown {
			return ev["queue_bytes"].(float64)
		}
	}
	tb.Fatal("no shutdown event")
	return 0
}

// archiveTee returns the body tee of the request c is handling.
func archiveTee(tb testing.TB, c *gin.Context) *archiveBodyTee {
	tb.Helper()
	cw := findCloseWriter(c.Writer)
	if cw == nil {
		tb.Fatal("no body tracker")
	}
	tee, ok := cw.tracker.ReadCloser.(*archiveBodyTee)
	if !ok {
		tb.Fatal("no body tee")
	}
	return tee
}

func waitUntil(tb testing.TB, what string, cond func() bool) {
	tb.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			tb.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
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

	// The first configuration wins: a later enabled server in the same
	// process starts no recorder and installs nothing.
	enabled := &proxyconfig.Config{}
	enabled.Archive = proxyconfig.ArchiveConfig{Enabled: true, SpoolDir: spool}
	later := newTestServerWithConfig(t, enabled)
	if archive.Current() != nil {
		t.Fatal("an enabled server after a disabled one started the recorder")
	}
	for _, h := range later.engine.Handlers {
		if strings.Contains(handlerName(h), "archive") {
			t.Fatalf("an enabled server after a disabled one installed %s", handlerName(h))
		}
	}
	if entries, _ = os.ReadDir(spool); len(entries) != 2 {
		t.Fatalf("an enabled server after a disabled one wrote to the spool: %v", entries)
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
		c.Header("Location", "https://app.example/cb?code=fake-location-code-0019#access_token=fake-fragment-token-0020")
		c.String(http.StatusOK, "ok")
	})
	secrets := []string{
		"sk-fake-bearer-0001", "fake-proxy-auth-0002", "sk-ant-fake-xapikey-0003", "AIzaFAKEgoogkey0004",
		"fake-cookie-0005", "sk-fake-wsproto-0006", "AIzaFAKEquerykey0007", "fake-value-0008",
		"fake-code-0009", "fake-state-0010", "fake-password-0011", "fake-oauth-code-0012",
		"fake-oauth-state-0013", "fake-set-cookie-0014", "fake-management-key-0015",
		"fake-referer-code-0016", "fake-referer-state-0017", "fake-custom-token-0018",
		"fake-location-code-0019", "fake-fragment-token-0020",
	}
	credentialHeaders := http.Header{
		"Authorization":          {"Bearer sk-fake-bearer-0001"},
		"Proxy-Authorization":    {"Basic fake-proxy-auth-0002"},
		"X-Api-Key":              {"sk-ant-fake-xapikey-0003"},
		"X-Goog-Api-Key":         {"AIzaFAKEgoogkey0004"},
		"Cookie":                 {"session=fake-cookie-0005"},
		"Sec-Websocket-Protocol": {"realtime, openai-insecure-api-key.sk-fake-wsproto-0006"},
		"X-Management-Key":       {"fake-management-key-0015"},
		"Referer":                {"https://app.example/oauth/cb?code=fake-referer-code-0016&state=fake-referer-state-0017"},
		"X-Custom-Token":         {"fake-custom-token-0018"},
		"Session_id":             {"019a0000-session"},
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
	if got := headers["Referer"].([]any)[0]; got != "https://app.example/oauth/cb?code=[redacted]&state=[redacted]" {
		t.Fatalf("Referer = %v", got)
	}
	if got := headers["Session_id"].([]any)[0]; got != "019a0000-session" {
		t.Fatalf("Session_id = %v; session IDs are kept for joins", got)
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
	const threshold = 64 << 10
	server, spool := newArchiveServerWithOverrides(t, func(o *archive.TestOverrides) { o.BlobThresholdBytes = threshold }, nil)
	classifyForTest(t, http.MethodPost, "/archive-test/echo")
	server.engine.POST("/archive-test/echo", echoBody)
	payload := bytes.Repeat([]byte("0123456789abcdef"), threshold/16+1)
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

//go:noinline
func archiveTestPanicSite(value *archiveTestPanic) { panic(value) }

func TestArchiveObserverRepanicsWithTheSameValue(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	engine := gin.New()
	engine.Use(server.archiveObserverMiddleware())
	value := &archiveTestPanic{id: 7}
	engine.GET("/archive-test/panic", func(*gin.Context) { archiveTestPanicSite(value) })
	var logged bytes.Buffer
	out := log.StandardLogger().Out
	log.SetOutput(&logged)
	recovered := func() (rv any) {
		defer func() { rv = recover() }()
		engine.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/archive-test/panic", nil))
		return nil
	}()
	log.SetOutput(out)
	if recovered != value {
		t.Fatalf("observer re-panicked with %v, want the original value", recovered)
	}
	// The re-panic's trace starts in the observer; the log keeps the original.
	if !strings.Contains(logged.String(), "archiveTestPanicSite") {
		t.Fatalf("the original panic stack was not logged:\n%s", logged.String())
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
	// Reads part of the body, so the tee ends with the request, not at EOF.
	classifyForTest(t, http.MethodPost, "/archive-test/partial")
	server.engine.POST("/archive-test/partial", func(c *gin.Context) {
		head := make([]byte, 4)
		_, _ = io.ReadFull(c.Request.Body, head)
		c.Data(http.StatusOK, "application/octet-stream", head)
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
			rec = httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/archive-test/partial", bytes.NewReader(payload)))
			if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), payload[:4]) {
				t.Fatalf("partial: status %d body %q", rec.Code, rec.Body.String())
			}
		})
	}
	reported := false
	deadline := time.Now().Add(5 * time.Second)
	for !reported && time.Now().Before(deadline) {
		for _, ev := range spoolEvents(t, spool) {
			if drops, ok := ev["drops"].(map[string]any); ok && ev["type"] == archive.TypeGap && drops[archive.DropTapPanic] != nil {
				reported = true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !reported {
		t.Fatal("tap panics were not reported as a gap")
	}
	if queued := archiveStopQueueBytes(t, spool); queued != 0 {
		t.Fatalf("tap panics stranded %v reserved queue bytes", queued)
	}
}

func TestArchiveBodyTeeReservesItsBuffer(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodPost, "/archive-test/peek")
	payload := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB, declared
	type state struct{ cap, reserved int64 }
	var afterHead, beforeEOF state
	server.engine.POST("/archive-test/peek", func(c *gin.Context) {
		tee := archiveTee(t, c)
		snapshot := func() state {
			tee.mu.Lock()
			defer tee.mu.Unlock()
			return state{int64(cap(tee.buf)), tee.reserved}
		}
		head := make([]byte, 1024)
		_, _ = io.ReadFull(c.Request.Body, head)
		afterHead = snapshot()
		rest := make([]byte, len(payload)-len(head))
		_, _ = io.ReadFull(c.Request.Body, rest)
		beforeEOF = snapshot()
		_, _ = io.ReadAll(c.Request.Body)
		c.Status(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/archive-test/peek", bytes.NewReader(payload)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	// The buffer grows with what was read, and is always reserved.
	if afterHead.cap > afterHead.reserved || afterHead.reserved >= int64(len(payload)) {
		t.Fatalf("after 1 KiB: buffer %d bytes, reserved %d", afterHead.cap, afterHead.reserved)
	}
	if beforeEOF.cap != int64(len(payload)) || beforeEOF.reserved != beforeEOF.cap {
		t.Fatalf("whole body: buffer %d bytes, reserved %d, want %d", beforeEOF.cap, beforeEOF.reserved, len(payload))
	}
	bodies := eventsFor(spoolEvents(t, spool), archive.TypeClientBody, "/archive-test/peek")
	if len(bodies) != 1 || !bytes.Equal(spoolBody(t, spool, bodies[0]), payload) {
		t.Fatalf("client_body = %v", bodies)
	}
	if queued := archiveStopQueueBytes(t, spool); queued != 0 {
		t.Fatalf("%v queue bytes still reserved", queued)
	}
}

func TestArchiveMetadataReservationCountsQueryNames(t *testing.T) {
	server, spool := newArchiveServerWithOverrides(t, func(o *archive.TestOverrides) { o.QueueBytes = 64 << 10 }, nil)
	names := make([]string, 0, 50000)
	for i := 0; i < cap(names); i++ {
		names = append(names, "name"+strconv.Itoa(i)+"=x")
	}
	big := "/archive-test/unrouted?" + strings.Join(names, "&") // about 750 KB of names
	small := "/archive-test/unrouted-small?a=1"
	for _, target := range []string{big, small} {
		server.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, target, nil))
	}
	events := spoolEvents(t, spool)
	if got := eventsFor(events, archive.TypeMetadataOnly, "/archive-test/unrouted"); len(got) != 0 {
		t.Fatal("a metadata_only event larger than the queue was accepted")
	}
	if got := eventsFor(events, archive.TypeMetadataOnly, "/archive-test/unrouted-small"); len(got) != 1 {
		t.Fatalf("small metadata_only events = %v", got)
	}
	waitUntil(t, "a queue_full gap", func() bool {
		for _, ev := range spoolEvents(t, spool) {
			if drops, ok := ev["drops"].(map[string]any); ok && ev["type"] == archive.TypeGap && drops[archive.DropQueueFull] != nil {
				return true
			}
		}
		return false
	})
}

func TestArchiveBodyReadInFlightAtRequestEnd(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodPost, "/archive-test/background")
	readDone := make(chan []byte, 1)
	server.engine.POST("/archive-test/background", func(c *gin.Context) {
		tee := archiveTee(t, c)
		body := c.Request.Body
		go func() {
			data := make([]byte, 64)
			n, _ := body.Read(data)
			readDone <- data[:n]
		}()
		// Return while that read waits for the client.
		waitUntil(t, "the read to start", func() bool {
			tee.mu.Lock()
			defer tee.mu.Unlock()
			return tee.reading > 0
		})
		c.Status(http.StatusAccepted)
	})
	pr, pw := io.Pipe()
	req := httptest.NewRequest(http.MethodPost, "/archive-test/background", pr)
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d", rec.Code)
	}
	_, _ = pw.Write([]byte("late body"))
	if got := <-readDone; string(got) != "late body" {
		t.Fatalf("the read returned %q", got)
	}
	_ = pw.Close()
	bodies := eventsFor(spoolEvents(t, spool), archive.TypeClientBody, "/archive-test/background")
	if len(bodies) != 1 || bodies[0]["capture"] != archive.CaptureFull || bodies[0]["wire_bytes"] != float64(9) || bodies[0]["ended"] != "request_end" {
		t.Fatalf("client_body = %v; the read in flight at request end was lost", bodies)
	}
	if got := spoolBody(t, spool, bodies[0]); string(got) != "late body" {
		t.Fatalf("captured %q", got)
	}
}

type archiveFailingReader struct{}

// The error text carries what a transport error can: URL user information,
// a key in a query and an OAuth code.
func (archiveFailingReader) Read([]byte) (int, error) {
	return 0, errors.New(`read "https://user:fake-pass-0001@upstream.example/v1?key=fake-key-0002&code=fake-code-0003": failed`)
}

func TestArchiveBodyReadErrorIsNotUnread(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodPost, "/archive-test/echo")
	server.engine.POST("/archive-test/echo", echoBody)
	req := httptest.NewRequest(http.MethodPost, "/archive-test/echo", archiveFailingReader{})
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
	bodies := eventsFor(spoolEvents(t, spool), archive.TypeClientBody, "/archive-test/echo")
	if len(bodies) != 1 || bodies[0]["capture"] == archive.CaptureBodyUnread || bodies[0]["read_error"] != "other" {
		t.Fatalf("client_body = %v", bodies)
	}
	files, _ := filepath.Glob(filepath.Join(spool, "*.jsonl"))
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("fake-")) {
			t.Fatalf("%s keeps the read error's text", filepath.Base(path))
		}
	}
}

func TestArchiveReadErrorClass(t *testing.T) {
	timeout := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	cases := map[string]error{
		"eof_unexpected": fmt.Errorf("chunked: %w", io.ErrUnexpectedEOF),
		"max_bytes":      &http.MaxBytesError{Limit: 64},
		"canceled":       fmt.Errorf("body: %w", context.Canceled),
		"timeout":        timeout,
		"closed":         http.ErrBodyReadAfterClose,
		"other":          errors.New("https://user:fake-pass-0001@example.test/?key=fake-key-0002"),
	}
	for want, err := range cases {
		if got := archiveReadErrorClass(err); got != want {
			t.Errorf("archiveReadErrorClass(%v) = %q, want %q", err, got, want)
		}
	}
	if got := archiveReadErrorClass(context.DeadlineExceeded); got != "timeout" {
		t.Errorf("context.DeadlineExceeded = %q", got)
	}
}

// A body read still in progress when the request ends may be dropped later;
// ingress_end waits for that body, so its capture_drops counts the drop.
func TestArchiveIngressEndCountsALateBodyDrop(t *testing.T) {
	var free atomic.Uint64
	free.Store(1 << 50)
	server, spool := newArchiveServerWithOverrides(t,
		func(o *archive.TestOverrides) {
			o.FreeBytes = free.Load
			o.SpaceCheckInterval = 5 * time.Millisecond
		},
		func(cfg *proxyconfig.Config) {
			cfg.Archive.BodyFreeGB = 2
			cfg.Archive.HardFreeGB = 1
		})
	classifyForTest(t, http.MethodPost, "/archive-test/late-drop")
	readDone := make(chan []byte, 1)
	server.engine.POST("/archive-test/late-drop", func(c *gin.Context) {
		tee := archiveTee(t, c)
		body := c.Request.Body
		go func() {
			data, _ := io.ReadAll(body)
			readDone <- data
		}()
		waitUntil(t, "the read to start", func() bool {
			tee.mu.Lock()
			defer tee.mu.Unlock()
			return tee.reading > 0
		})
		c.Status(http.StatusAccepted)
	})
	pr, pw := io.Pipe()
	req := httptest.NewRequest(http.MethodPost, "/archive-test/late-drop", pr)
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d", rec.Code)
	}
	// Space runs low after the request ended, before its body arrives.
	free.Store(3 << 29)
	waitUntil(t, "bodies to stop", func() bool { return !archive.Current().CaptureBodies() })
	_, _ = pw.Write([]byte("late body"))
	_ = pw.Close()
	if got := <-readDone; string(got) != "late body" {
		t.Fatalf("the read returned %q", got)
	}
	events := spoolEvents(t, spool)
	bodies := eventsFor(events, archive.TypeClientBody, "/archive-test/late-drop")
	ends := eventsFor(events, archive.TypeIngressEnd, "/archive-test/late-drop")
	if len(bodies) != 1 || bodies[0]["capture"] != archive.CaptureDroppedBody || bodies[0]["drop_reason"] != archive.DropLowSpaceBody {
		t.Fatalf("client_body = %v", bodies)
	}
	if len(ends) != 1 || ends[0]["capture_drops"] != float64(1) {
		t.Fatalf("ingress_end = %v, want capture_drops 1 for the late body", ends)
	}
	if ends[0]["seq"].(float64) < bodies[0]["seq"].(float64) {
		t.Fatal("ingress_end was written before the late client_body")
	}
}

// When doubling the buffer does not fit in the queue, the exact size is
// tried, so a chunked body larger than half the queue is still captured.
func TestArchiveChunkedBodyFallsBackToExactReservation(t *testing.T) {
	server, spool := newArchiveServerWithOverrides(t, func(o *archive.TestOverrides) { o.QueueBytes = 1000 << 10 }, nil)
	classifyForTest(t, http.MethodPost, "/archive-test/echo")
	server.engine.POST("/archive-test/echo", echoBody)
	payload := bytes.Repeat([]byte("0123456789abcdef"), (528<<10)/16)
	req := httptest.NewRequest(http.MethodPost, "/archive-test/echo", bytes.NewReader(payload))
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	bodies := eventsFor(spoolEvents(t, spool), archive.TypeClientBody, "/archive-test/echo")
	if len(bodies) != 1 || bodies[0]["capture"] != archive.CaptureFull {
		t.Fatalf("client_body = %v; a 528 KiB chunked body was dropped from a 1000 KiB queue", bodies)
	}
	if got := spoolBody(t, spool, bodies[0]); !bytes.Equal(got, payload) {
		t.Fatalf("captured %d bytes, want %d", len(got), len(payload))
	}
	if queued := archiveStopQueueBytes(t, spool); queued != 0 {
		t.Fatalf("%v queue bytes still reserved", queued)
	}
}

// Two concurrent reads: one sees EOF while the other is still returning
// data. client_body waits for the last read, so the data is not lost.
func TestArchiveConcurrentEOFWaitsForOtherReads(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	classifyForTest(t, http.MethodPost, "/archive-test/racing")
	body := &archiveRacingReader{release: make(chan struct{})}
	server.engine.POST("/archive-test/racing", func(c *gin.Context) {
		// Read the tee itself: the tracker and MaxBytesReader above it are
		// not safe for concurrent reads.
		tee := archiveTee(t, c)
		delivered := make(chan int, 1)
		go func() {
			n, _ := tee.Read(make([]byte, 64))
			delivered <- n
		}()
		waitUntil(t, "the first read to start", func() bool { return body.calls.Load() == 1 })
		if n, err := tee.Read(make([]byte, 64)); n != 0 || !errors.Is(err, io.EOF) {
			t.Errorf("second read = %d, %v; want EOF", n, err)
		}
		close(body.release)
		if n := <-delivered; n != 9 {
			t.Errorf("first read delivered %d bytes", n)
		}
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/archive-test/racing", body)
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	bodies := eventsFor(spoolEvents(t, spool), archive.TypeClientBody, "/archive-test/racing")
	if len(bodies) != 1 || bodies[0]["capture"] != archive.CaptureFull || bodies[0]["wire_bytes"] != float64(9) || bodies[0]["eof"] != true || bodies[0]["ended"] != "eof" {
		t.Fatalf("client_body = %v; the bytes of the read still in progress at EOF were lost", bodies)
	}
	if got := spoolBody(t, spool, bodies[0]); string(got) != "late body" {
		t.Fatalf("captured %q", got)
	}
}

// archiveRacingReader's first Read waits for release and returns data; every
// later Read returns EOF at once.
type archiveRacingReader struct {
	calls   atomic.Int32
	release chan struct{}
}

func (r *archiveRacingReader) Read(p []byte) (int, error) {
	if r.calls.Add(1) == 1 {
		<-r.release
		return copy(p, "late body"), nil
	}
	return 0, io.EOF
}

func (r *archiveRacingReader) Close() error { return nil }

func TestArchiveBodyStopsWhenSpaceRunsLow(t *testing.T) {
	var free atomic.Uint64
	free.Store(1 << 50)
	server, spool := newArchiveServerWithOverrides(t,
		func(o *archive.TestOverrides) {
			o.FreeBytes = free.Load
			o.SpaceCheckInterval = 5 * time.Millisecond
		},
		func(cfg *proxyconfig.Config) {
			cfg.Archive.BodyFreeGB = 2
			cfg.Archive.HardFreeGB = 1
		})
	classifyForTest(t, http.MethodPost, "/archive-test/space")
	server.engine.POST("/archive-test/space", func(c *gin.Context) {
		head := make([]byte, 5)
		_, _ = io.ReadFull(c.Request.Body, head)
		free.Store(3 << 29) // 1.5 GiB: below body_free_gb
		waitUntil(t, "bodies to stop", func() bool { return !archive.Current().CaptureBodies() })
		if c.Query("rest") == "1" {
			_, _ = io.ReadAll(c.Request.Body)
		}
		c.Status(http.StatusOK)
	})
	for _, tc := range []struct {
		target string
		body   []byte
	}{
		// Ends with the request, after the last reservation.
		{"/archive-test/space?case=ended", []byte("0123456789")},
		// Keeps reading, past its first buffer.
		{"/archive-test/space?rest=1", bytes.Repeat([]byte("x"), 64<<10)},
	} {
		free.Store(1 << 50)
		waitUntil(t, "bodies to resume", archive.Current().CaptureBodies)
		req := httptest.NewRequest(http.MethodPost, tc.target, bytes.NewReader(tc.body))
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", tc.target, rec.Code)
		}
	}
	bodies := eventsFor(spoolEvents(t, spool), archive.TypeClientBody, "/archive-test/space")
	if len(bodies) != 2 {
		t.Fatalf("client_body events = %v", bodies)
	}
	for _, ev := range bodies {
		if ev["capture"] != archive.CaptureDroppedBody || ev["drop_reason"] != archive.DropLowSpaceBody || ev["body"] != nil {
			t.Fatalf("client_body = %v, want dropped_body for low space", ev)
		}
	}
	if queued := archiveStopQueueBytes(t, spool); queued != 0 {
		t.Fatalf("%v queue bytes still reserved", queued)
	}
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
