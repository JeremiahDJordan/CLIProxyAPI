package api

// Fleet fork: request archive transport observer and client body tee.
// See internal/archive and the fleet repository's
// docs/PROXY-REQUEST-ARCHIVE-DESIGN.md (sections 1-4).

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/archive"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/httpwire"
	log "github.com/sirupsen/logrus"
)

// archiveIngressContextKey carries the *archive.Ingress on the gin context.
// The request context carries it too (archive.IngressFromContext).
const archiveIngressContextKey = "fleet.archive.ingress"

// archiveRecorderOwner is the server that started the process recorder; only
// it stops the recorder.
var archiveRecorderOwner atomic.Pointer[Server]

// archiveTapFault lets tests inject a panic into a tap. Nil in production.
var archiveTapFault func(where string)

// installArchiveObserver starts the recorder once per process and installs
// the transport observer as the outermost middleware, outside logging,
// recovery, the body limit, CORS and response compression. With
// archive.enabled false it installs nothing.
func (s *Server) installArchiveObserver(engine *gin.Engine, cfg *config.Config) {
	if s == nil || engine == nil || cfg == nil || !cfg.Archive.Enabled {
		return
	}
	rec := archive.Start(archive.StartParams{Config: cfg.Archive, ResponseSteering: cfg.Codex.ResponseSteering})
	if rec == nil {
		return
	}
	archiveRecorderOwner.CompareAndSwap(nil, s)
	observer := s.archiveObserverMiddleware()
	if len(engine.Handlers) == 0 {
		engine.Use(observer)
		return
	}
	// An engine configurator added middleware first; stay outermost. The
	// Use calls that follow in NewServer rebuild the 404/405 chains.
	engine.Handlers = append(gin.HandlersChain{observer}, engine.Handlers...)
}

// stopArchiveRecorder writes the shutdown event when this server owns the recorder.
func (s *Server) stopArchiveRecorder(ctx context.Context) {
	if s == nil || !archiveRecorderOwner.CompareAndSwap(s, nil) {
		return
	}
	if errStop := archive.Stop(ctx); errStop != nil {
		log.WithError(errStop).Warn("request archive: stop did not finish")
	}
}

func recoverArchiveTap(where string) {
	if recovered := recover(); recovered != nil {
		archive.NoteTapPanic(where, recovered)
	}
}

func archiveFault(where string) {
	if archiveTapFault != nil {
		archiveTapFault(where)
	}
}

func (s *Server) archiveObserverMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		rec := archive.Current()
		if rec == nil {
			c.Next()
			return
		}
		obs := s.beginArchiveObservation(rec, c)
		if obs == nil {
			c.Next()
			return
		}
		completed := false
		defer func() {
			if completed {
				obs.finish(c, nil, false)
				return
			}
			// Record the abort, then re-panic with the same value: the
			// observer never swallows a panic (http.ErrAbortHandler must
			// still reach net/http). A nil value here is runtime.Goexit.
			recovered := recover()
			obs.finish(c, recovered, true)
			if recovered != nil {
				panic(recovered)
			}
		}()
		c.Next()
		completed = true
	}
}

type archiveObservation struct {
	in       *archive.Ingress
	class    archive.RouteClass
	route    string
	method   string
	path     string
	clientIP string
	rawQuery string
	upgrade  bool
	resp     *archiveResponseState
	writer   *archiveResponseWriter
	tee      *archiveBodyTee
}

func (s *Server) beginArchiveObservation(rec *archive.Recorder, c *gin.Context) (obs *archiveObservation) {
	defer recoverArchiveTap("observer.start")
	archiveFault("observer.start")
	req := c.Request
	if req == nil || req.URL == nil {
		return nil
	}
	if !rec.CaptureEvents() {
		// Low space or a failed writer: count the request, skip the work.
		rec.CountDrop(rec.BodyDropReason(), archive.DropCount{Events: 1})
		return nil
	}
	start := time.Now()
	route := c.FullPath()
	class, allow, _ := s.classifyArchiveRoute(req.Method, route)
	in := rec.BeginIngress(class, start)
	inference := class == archive.RouteInference
	o := &archiveObservation{
		in:       in,
		class:    class,
		route:    route,
		method:   req.Method,
		path:     req.URL.Path,
		clientIP: c.ClientIP(),
		rawQuery: req.URL.RawQuery,
		upgrade:  strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket"),
		resp:     &archiveResponseState{inference: inference},
	}
	var startEvent *archive.Event
	if inference {
		data := archiveIngressStartData{
			Method:           o.method,
			Path:             o.path,
			Route:            route,
			RouteClass:       string(class),
			Query:            archive.RedactQuery(req.URL.RawQuery, allow),
			ClientIP:         o.clientIP,
			Proto:            req.Proto,
			Host:             req.Host,
			ContentLength:    req.ContentLength,
			TransferEncoding: req.TransferEncoding,
			Headers:          archive.RedactHeaders(req.Header),
		}
		startEvent = &archive.Event{Type: archive.TypeIngressStart, Time: start, Capture: archive.CaptureFull, Data: data, SizeHint: data.sizeHint()}
		o.tee = s.installArchiveBodyTee(req, in)
	}
	o.writer = &archiveResponseWriter{ResponseWriter: c.Writer, state: o.resp}
	c.Writer = o.writer
	// From here on finish must run, even if the rest of this tap panics.
	obs = o
	c.Request = req.WithContext(archive.WithIngress(req.Context(), in))
	c.Set(archiveIngressContextKey, in)
	if startEvent != nil {
		in.Emit(startEvent)
	}
	return o
}

// finish emits ingress_end (inference) or metadata_only. It runs in the
// observer's deferred function, also while a panic or Goexit unwinds.
func (o *archiveObservation) finish(c *gin.Context, recovered any, aborted bool) {
	defer recoverArchiveTap("observer.finish")
	archiveFault("observer.finish")
	end := time.Now()
	if o.tee != nil {
		o.tee.finish("request_end")
	}
	summary := archiveResponseSummary{DurationUS: end.Sub(o.in.Started()).Microseconds()}
	switch {
	case aborted && recovered == nil:
		summary.Abort = "goexit"
	case aborted:
		summary.PanicType = fmt.Sprintf("%T", recovered)
		summary.Abort = "panic"
		if err, ok := recovered.(error); ok && errors.Is(err, http.ErrAbortHandler) {
			summary.Abort = "abort_handler"
		}
	}
	// Later middleware may leave its own writer on c.Writer; read ours.
	inner := o.writer.ResponseWriter
	summary.Status = inner.Status()
	summary.HeaderWritten = inner.Written()
	snap := o.resp.snapshotFinal(inner)
	summary.ContentEncoding = snap.contentEncoding
	headers := snap.headers
	summary.BytesWritten = o.resp.bytes.Load()
	if first := o.resp.firstByte.Load(); first != 0 {
		summary.FirstByteAt = archiveTime(time.Unix(0, first))
	}
	if o.resp.hijacked.Load() {
		summary.Hijacked = true
		if o.upgrade {
			summary.Status = http.StatusSwitchingProtocols
		}
	}
	summary.GinAborted = c.IsAborted()
	summary.AuthDecision, summary.AuthProvider = archiveAuthDecision(c, summary.Status)

	if o.class == archive.RouteInference {
		summary.CaptureDrops = o.in.Drops()
		data := archiveIngressEndData{archiveResponseSummary: summary, Headers: headers}
		o.in.Emit(&archive.Event{Type: archive.TypeIngressEnd, Time: end, Capture: archive.CaptureFull, Data: data, SizeHint: archiveHeaderSize(headers)})
		return
	}
	data := archiveMetadataOnlyData{
		StartedAt:              archiveTime(o.in.Started()),
		Method:                 o.method,
		Path:                   o.path,
		Route:                  o.route,
		RouteClass:             string(o.class),
		QueryNames:             archive.QueryNames(o.rawQuery),
		ClientIP:               o.clientIP,
		archiveResponseSummary: summary,
	}
	o.in.Emit(&archive.Event{Type: archive.TypeMetadataOnly, Time: end, Capture: archive.CaptureMetadataOnly, Data: data, SizeHint: int64(len(o.path))})
}

func archiveTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}

// archiveAuthDecision reports what the access middleware decided. Fleet gate
// fields come with the executor taps.
func archiveAuthDecision(c *gin.Context, status int) (string, string) {
	if value, ok := c.Get("accessProvider"); ok {
		provider, _ := value.(string)
		return "authenticated", provider
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return "rejected", ""
	}
	return "unknown", ""
}

type archiveIngressStartData struct {
	Method           string              `json:"method"`
	Path             string              `json:"path"`
	Route            string              `json:"route"`
	RouteClass       string              `json:"route_class"`
	Query            string              `json:"query,omitempty"`
	ClientIP         string              `json:"client_ip"`
	Proto            string              `json:"proto"`
	Host             string              `json:"host,omitempty"`
	ContentLength    int64               `json:"content_length"`
	TransferEncoding []string            `json:"transfer_encoding,omitempty"`
	Headers          map[string][]string `json:"headers,omitempty"`
}

func (d archiveIngressStartData) sizeHint() int64 {
	return int64(len(d.Path)+len(d.Query)+len(d.Host)) + archiveHeaderSize(d.Headers)
}

func archiveHeaderSize(h map[string][]string) int64 {
	var n int64
	for name, values := range h {
		n += int64(len(name)) + 8
		for _, value := range values {
			n += int64(len(value)) + 4
		}
	}
	return n
}

type archiveResponseSummary struct {
	Status          int    `json:"status"`
	HeaderWritten   bool   `json:"header_written"`
	BytesWritten    int64  `json:"bytes_written"`
	ContentEncoding string `json:"content_encoding,omitempty"`
	FirstByteAt     string `json:"first_byte_at,omitempty"`
	DurationUS      int64  `json:"duration_us"`
	Hijacked        bool   `json:"hijacked,omitempty"`
	GinAborted      bool   `json:"gin_aborted,omitempty"`
	Abort           string `json:"abort,omitempty"`
	PanicType       string `json:"panic_type,omitempty"`
	AuthDecision    string `json:"auth_decision"`
	AuthProvider    string `json:"auth_provider,omitempty"`
	CaptureDrops    int64  `json:"capture_drops,omitempty"`
}

type archiveIngressEndData struct {
	archiveResponseSummary
	Headers map[string][]string `json:"headers,omitempty"`
}

type archiveMetadataOnlyData struct {
	StartedAt  string   `json:"started_at"`
	Method     string   `json:"method"`
	Path       string   `json:"path"`
	Route      string   `json:"route"`
	RouteClass string   `json:"route_class"`
	QueryNames []string `json:"query_names,omitempty"`
	ClientIP   string   `json:"client_ip"`
	archiveResponseSummary
}

// archiveResponseState is what the writer wrapper observes. Handlers may
// write from their own goroutines, so it is updated atomically.
type archiveResponseState struct {
	inference bool
	bytes     atomic.Int64
	firstByte atomic.Int64
	hijacked  atomic.Bool
	headers   atomic.Pointer[archiveHeaderSnapshot]
}

type archiveHeaderSnapshot struct {
	contentEncoding string
	headers         map[string][]string
}

// noteCommit captures the response headers as they are about to be sent.
func (st *archiveResponseState) noteCommit(w gin.ResponseWriter) {
	defer recoverArchiveTap("writer.commit")
	if st == nil || st.headers.Load() != nil || w.Written() {
		return
	}
	archiveFault("writer.commit")
	st.headers.CompareAndSwap(nil, st.snapshot(w.Header()))
}

// snapshotFinal returns the committed headers, or the current ones when the
// response was committed outside the wrapper (gin's final WriteHeaderNow).
func (st *archiveResponseState) snapshotFinal(w gin.ResponseWriter) *archiveHeaderSnapshot {
	if snap := st.headers.Load(); snap != nil {
		return snap
	}
	snap := st.snapshot(w.Header())
	st.headers.CompareAndSwap(nil, snap)
	return st.headers.Load()
}

func (st *archiveResponseState) snapshot(h http.Header) *archiveHeaderSnapshot {
	snap := &archiveHeaderSnapshot{contentEncoding: h.Get("Content-Encoding")}
	if st.inference {
		snap.headers = archive.RedactHeaders(h)
	}
	return snap
}

func (st *archiveResponseState) noteWrite(n int) {
	defer recoverArchiveTap("writer.write")
	if st == nil || n <= 0 {
		return
	}
	archiveFault("writer.write")
	st.bytes.Add(int64(n))
	if st.firstByte.Load() == 0 {
		st.firstByte.CompareAndSwap(0, time.Now().UnixNano())
	}
}

func (st *archiveResponseState) noteHijack() {
	defer recoverArchiveTap("writer.hijack")
	if st != nil {
		st.hijacked.Store(true)
	}
}

// archiveResponseWriter counts the bytes actually written below response
// compression and preserves Flush, FlushError, Unwrap and Hijack.
type archiveResponseWriter struct {
	gin.ResponseWriter
	state *archiveResponseState
}

func (w *archiveResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *archiveResponseWriter) WriteHeaderNow() {
	w.state.noteCommit(w.ResponseWriter)
	w.ResponseWriter.WriteHeaderNow()
}

func (w *archiveResponseWriter) Write(data []byte) (int, error) {
	w.state.noteCommit(w.ResponseWriter)
	n, errWrite := w.ResponseWriter.Write(data)
	w.state.noteWrite(n)
	return n, errWrite
}

func (w *archiveResponseWriter) WriteString(data string) (int, error) {
	w.state.noteCommit(w.ResponseWriter)
	n, errWrite := w.ResponseWriter.WriteString(data)
	w.state.noteWrite(n)
	return n, errWrite
}

func (w *archiveResponseWriter) Flush() {
	_ = w.FlushError()
}

func (w *archiveResponseWriter) FlushError() error {
	w.state.noteCommit(w.ResponseWriter)
	return httpwire.FlushResponse(w.ResponseWriter)
}

func (w *archiveResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, errHijack := w.ResponseWriter.Hijack()
	if errHijack == nil {
		w.state.noteHijack()
	}
	return conn, rw, errHijack
}

// installArchiveBodyTee wraps the request body tracker's inner reader, below
// MaxBytesReader, so the tracker type checks in server_middleware.go match.
func (s *Server) installArchiveBodyTee(req *http.Request, in *archive.Ingress) *archiveBodyTee {
	if req.Body == nil || req.Body == http.NoBody || (req.ContentLength == 0 && len(req.TransferEncoding) == 0) {
		return nil
	}
	tracker, ok := req.Body.(*requestBodyTracker)
	if !ok {
		tracker = &requestBodyTracker{ReadCloser: req.Body, contentLength: req.ContentLength}
		req.Body = tracker
	}
	if tracker.ReadCloser == nil {
		return nil
	}
	rec := in.Recorder()
	tee := &archiveBodyTee{
		inner:         tracker.ReadCloser,
		in:            in,
		rec:           rec,
		encoding:      req.Header.Get("Content-Encoding"),
		contentLength: req.ContentLength,
		limit:         s.maxRequestBodyBytes(),
		capturing:     rec.CaptureBodies(),
	}
	if !tee.capturing {
		tee.dropReason = rec.BodyDropReason()
	}
	tracker.ReadCloser = tee
	return tee
}

// archiveBodyTee copies the wire bytes the handler consumes. It reserves
// queue bytes as it reads and emits client_body once, at EOF, Close or the
// end of the request, whichever comes first; later reads pass through.
type archiveBodyTee struct {
	inner         io.ReadCloser
	in            *archive.Ingress
	rec           *archive.Recorder
	encoding      string
	contentLength int64
	limit         int64

	mu         sync.Mutex
	buf        []byte
	reserved   int64
	consumed   int64
	capturing  bool
	dropReason string
	sawEOF     bool
	done       bool
}

func (t *archiveBodyTee) Read(p []byte) (int, error) {
	n, errRead := t.inner.Read(p)
	t.observe(p, n, errRead)
	return n, errRead
}

func (t *archiveBodyTee) Close() error {
	errClose := t.inner.Close()
	t.finish("close")
	return errClose
}

func (t *archiveBodyTee) observe(p []byte, n int, errRead error) {
	defer recoverArchiveTap("body.read")
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return
	}
	archiveFault("body.read")
	if n > 0 {
		t.consumed += int64(n)
		if t.capturing {
			if t.rec.ReserveBody(int64(n)) {
				if t.buf == nil && t.contentLength > 0 && t.contentLength <= t.rec.BlobThreshold() {
					t.buf = make([]byte, 0, t.contentLength+1)
				}
				t.buf = append(t.buf, p[:n]...)
				t.reserved += int64(n)
			} else {
				t.dropLocked(archive.DropQueueFull)
			}
		}
	}
	if errors.Is(errRead, io.EOF) {
		t.sawEOF = true
		t.emitLocked("eof")
	}
}

func (t *archiveBodyTee) finish(ended string) {
	defer recoverArchiveTap("body.finish")
	t.mu.Lock()
	defer t.mu.Unlock()
	t.emitLocked(ended)
}

func (t *archiveBodyTee) dropLocked(reason string) {
	t.rec.ReleaseBody(t.reserved)
	t.reserved = 0
	t.buf = nil
	t.capturing = false
	t.dropReason = reason
}

type archiveClientBodyData struct {
	WireBytes       int64  `json:"wire_bytes"`
	DeliveredBytes  int64  `json:"delivered_bytes"`
	Truncated       bool   `json:"truncated,omitempty"`
	EOF             bool   `json:"eof"`
	Ended           string `json:"ended"`
	ContentLength   int64  `json:"content_length"`
	ContentEncoding string `json:"content_encoding,omitempty"`
	DropReason      string `json:"drop_reason,omitempty"`
}

func (t *archiveBodyTee) emitLocked(ended string) {
	if t.done {
		return
	}
	t.done = true
	archiveFault("body.emit")
	data := archiveClientBodyData{
		WireBytes:       t.consumed,
		DeliveredBytes:  t.consumed,
		EOF:             t.sawEOF,
		Ended:           ended,
		ContentLength:   t.contentLength,
		ContentEncoding: t.encoding,
	}
	// MaxBytesReader reads one byte past its limit before failing.
	if t.limit > 0 && t.consumed > t.limit {
		data.DeliveredBytes = t.limit
		data.Truncated = true
	}
	if t.consumed == 0 && !t.sawEOF {
		// Never read by the handler, so not read by the recorder either.
		t.rec.ReleaseBody(t.reserved)
		t.reserved = 0
		t.in.Emit(&archive.Event{Type: archive.TypeClientBody, Capture: archive.CaptureBodyUnread, Data: data})
		return
	}
	if !t.capturing {
		data.DropReason = t.dropReason
		t.in.NoteDrop()
		t.rec.CountDrop(t.dropReason, archive.DropCount{Bodies: 1, Bytes: t.consumed})
		t.in.Emit(&archive.Event{Type: archive.TypeClientBody, Capture: archive.CaptureDroppedBody, Data: data})
		return
	}
	body := &archive.BodyData{Bytes: t.buf, ContentEncoding: t.encoding}
	reserved := t.reserved
	t.buf = nil
	t.reserved = 0
	t.in.EmitReserved(&archive.Event{Type: archive.TypeClientBody, Capture: archive.CaptureFull, Body: body, Data: data}, reserved)
}
