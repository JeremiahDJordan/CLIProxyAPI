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
	"runtime/debug"
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
// recovery, the body limit, CORS and response compression. A disabled
// configuration also goes through Start's once-per-process guard, so the
// first configuration wins: with archive.enabled false Start does nothing (no
// goroutine, no file), a later enabled server starts nothing either, and
// nothing is installed.
func (s *Server) installArchiveObserver(engine *gin.Engine, cfg *config.Config) {
	if s == nil || engine == nil || cfg == nil {
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
				if !isArchiveAbortHandler(recovered) {
					// The re-panic's own trace starts here; keep the original.
					log.WithField("panic", fmt.Sprintf("%T: %v", recovered, recovered)).
						Errorf("request archive: recorded a handler panic; re-panicking\n%s", debug.Stack())
				}
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

func isArchiveAbortHandler(recovered any) bool {
	err, ok := recovered.(error)
	return ok && errors.Is(err, http.ErrAbortHandler)
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
	o.writer = &archiveResponseWriter{ResponseWriter: c.Writer, state: o.resp}
	c.Writer = o.writer
	// From here on finish must run, even if the rest of this tap panics.
	obs = o
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
	if o.tee != nil {
		// Also when the rest of finish panics, so the tee never strands its
		// reservation. Ending the tee twice is harmless.
		defer o.tee.end("request_end")
	}
	archiveFault("observer.finish")
	end := time.Now()
	summary := archiveResponseSummary{DurationUS: end.Sub(o.in.Started()).Microseconds()}
	switch {
	case aborted && recovered == nil:
		summary.Abort = "goexit"
	case aborted:
		summary.PanicType = fmt.Sprintf("%T", recovered)
		summary.Abort = "panic"
		if isArchiveAbortHandler(recovered) {
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
		summary.FirstByteAt = archive.FormatTime(time.Unix(0, first))
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
		data := archiveIngressEndData{archiveResponseSummary: summary, Headers: headers}
		// The writer fills in capture_drops when it writes the event.
		ev := &archive.Event{Type: archive.TypeIngressEnd, Time: end, Capture: archive.CaptureFull, Data: data, SizeHint: data.sizeHint(), ReportDrops: true}
		if o.tee == nil {
			o.in.Emit(ev)
			return
		}
		// ingress_end follows client_body so its capture_drops counts a
		// body drop. When a read is still in progress both wait for that
		// read (on its goroutine, never on this one), or for Stop; ts stays
		// the request end. The held event's bytes are reserved first; a
		// failed reservation drops it (counted) and the deferred end still
		// ends the body.
		reserved, ok := o.in.ReserveEvent(ev)
		if !ok {
			return
		}
		o.tee.endThen("request_end", func() {
			defer recoverArchiveTap("observer.finish")
			o.in.EmitReserved(ev, reserved)
		})
		return
	}
	data := archiveMetadataOnlyData{
		StartedAt:              archive.FormatTime(o.in.Started()),
		Method:                 o.method,
		Path:                   o.path,
		Route:                  o.route,
		RouteClass:             string(o.class),
		QueryNames:             archive.QueryNames(o.rawQuery),
		ClientIP:               o.clientIP,
		archiveResponseSummary: summary,
	}
	o.in.Emit(&archive.Event{Type: archive.TypeMetadataOnly, Time: end, Capture: archive.CaptureMetadataOnly, Data: data, SizeHint: data.sizeHint()})
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

// The sizeHint methods count every variable-size field, so an event's queue
// reservation covers what it holds; fixed fields fit in the event overhead.
func (d archiveIngressStartData) sizeHint() int64 {
	return archiveStringsSize(d.Method, d.Path, d.Route, d.RouteClass, d.Query, d.ClientIP, d.Proto, d.Host) +
		archiveStringsSize(d.TransferEncoding...) + archiveHeaderSize(d.Headers)
}

func (d archiveIngressEndData) sizeHint() int64 {
	return d.archiveResponseSummary.sizeHint() + archiveHeaderSize(d.Headers)
}

func (d archiveMetadataOnlyData) sizeHint() int64 {
	return archiveStringsSize(d.StartedAt, d.Method, d.Path, d.Route, d.RouteClass, d.ClientIP) +
		archiveStringsSize(d.QueryNames...) + d.archiveResponseSummary.sizeHint()
}

func (s archiveResponseSummary) sizeHint() int64 {
	return archiveStringsSize(s.ContentEncoding, s.FirstByteAt, s.Abort, s.PanicType, s.AuthDecision, s.AuthProvider)
}

func (d archiveClientBodyData) sizeHint() int64 {
	return archiveStringsSize(d.Ended, d.ContentEncoding, d.DropReason, d.ReadError)
}

// archiveStringsSize is the length of values plus quotes and a separator each.
func archiveStringsSize(values ...string) int64 {
	var n int64
	for _, value := range values {
		n += int64(len(value)) + 4
	}
	return n
}

func archiveHeaderSize(h map[string][]string) int64 {
	var n int64
	for name, values := range h {
		n += int64(len(name)) + 8 + archiveStringsSize(values...)
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
	}
	// Tracked until client_body is emitted, so Stop can finalize it. Once
	// Stop has begun the tee is not tracked and captures nothing.
	tee.capturing = rec.TrackCapture(tee) && rec.CaptureBodies()
	if !tee.capturing {
		tee.dropReason = rec.BodyDropReason()
	}
	tracker.ReadCloser = tee
	return tee
}

// archiveBodyMinBuffer is the first buffer for a body of unknown length.
const archiveBodyMinBuffer = 4 << 10

// archiveEndedShutdown is client_body's ended when Stop finalized the tee.
const archiveEndedShutdown = "shutdown"

// archiveBodyTee copies the wire bytes the handler consumes. Its queue
// reservation always covers its buffer's capacity. It emits client_body
// once, at EOF or Close, or at the end of the request, but never while
// another read is in progress: the last read to return then emits it, unless
// Stop finalizes the tee first. Later reads pass through. net/http request
// bodies are not safe for concurrent reads, so the order of bytes from
// concurrent reads is not meaningful; the tee only makes sure none of them is
// lost and the reservation is returned.
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
	readErr    string
	reading    int
	endPending string
	// afterEnd runs once client_body has been emitted (ingress_end).
	afterEnd  func()
	done      bool
	handedOff bool
}

func (t *archiveBodyTee) Read(p []byte) (n int, errRead error) {
	t.beginRead()
	defer func() {
		t.observe(p, n, errRead)
		t.endRead()
	}()
	return t.inner.Read(p)
}

func (t *archiveBodyTee) Close() error {
	errClose := t.inner.Close()
	t.end("close")
	return errClose
}

func (t *archiveBodyTee) beginRead() {
	t.mu.Lock()
	t.reading++
	t.mu.Unlock()
}

func (t *archiveBodyTee) observe(p []byte, n int, errRead error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	defer t.recoverLocked("body.read")
	if t.done {
		return
	}
	archiveFault("body.read")
	if n > 0 {
		t.consumed += int64(n)
		if t.capturing {
			t.captureLocked(p[:n])
		}
	}
	switch {
	case errors.Is(errRead, io.EOF):
		t.sawEOF = true
		if t.reading > 1 {
			// Another read is still in progress; the last to return emits,
			// with whatever it delivered.
			if t.endPending == "" {
				t.endPending = "eof"
			}
			return
		}
		t.emitLocked("eof")
	case errRead != nil && t.readErr == "":
		t.readErr = archiveReadErrorClass(errRead)
	}
}

// archiveReadErrorClass names a body read error by category. Its text is
// never kept: it can carry URLs with credentials, keys or OAuth codes.
func archiveReadErrorClass(err error) string {
	var maxErr *http.MaxBytesError
	var netErr net.Error
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "eof_unexpected"
	case errors.As(err, &maxErr):
		return "max_bytes"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.Is(err, http.ErrBodyReadAfterClose):
		return "closed"
	default:
		return "other"
	}
}

// endRead finishes a read; the last read in progress emits the event when
// the request ended during it.
func (t *archiveBodyTee) endRead() {
	t.mu.Lock()
	defer t.mu.Unlock()
	defer t.runAfterEndLocked()
	defer t.recoverLocked("body.read")
	t.reading--
	if t.reading == 0 && t.endPending != "" {
		t.emitLocked(t.endPending)
	}
}

// end emits the event now, or leaves it to the read in progress. It never
// waits and is idempotent.
func (t *archiveBodyTee) end(ended string) {
	t.endThen(ended, nil)
}

// endThen is end, and then runs afterEnd once the event has been emitted:
// now, or when the last read in progress returns.
func (t *archiveBodyTee) endThen(ended string, afterEnd func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	defer t.runAfterEndLocked()
	defer t.recoverLocked("body.finish")
	if t.afterEnd == nil {
		t.afterEnd = afterEnd
	}
	if t.done {
		return
	}
	if t.reading > 0 {
		if t.endPending == "" {
			t.endPending = ended
		}
		return
	}
	t.emitLocked(ended)
}

// FinalizeAtStop is called by Stop, before the writer's final drain. It does
// not wait for a read in progress: client_body records the body as dropped
// (reason stopped, ended shutdown; wire_bytes counts what was read so far),
// the deferred ingress_end follows, and every reservation is returned. A read returning
// later finds the tee done and emits nothing.
func (t *archiveBodyTee) FinalizeAtStop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	defer t.runAfterEndLocked()
	defer t.recoverLocked("body.stop")
	t.emitLocked(archiveEndedShutdown)
}

// runAfterEndLocked runs afterEnd once, after client_body was emitted (or
// lost to a tap panic, which recoverLocked has counted by then).
func (t *archiveBodyTee) runAfterEndLocked() {
	if !t.done || t.afterEnd == nil {
		return
	}
	afterEnd := t.afterEnd
	t.afterEnd = nil
	afterEnd()
}

// recoverLocked is the deferred guard of every tee step: after a tap panic
// it returns the reservation and stops capturing, so nothing is stranded.
func (t *archiveBodyTee) recoverLocked(where string) {
	recovered := recover()
	if recovered == nil {
		return
	}
	archive.NoteTapPanic(where, recovered)
	if t.capturing {
		// Returns the reservation; only a capturing tee holds one.
		t.dropLocked(archive.DropTapPanic)
	}
	if t.done && !t.handedOff {
		// The panic came while emitting: the event is lost.
		t.handedOff = true
		t.in.NoteDrop()
	}
}

// captureLocked appends data, first reserving any growth of the buffer.
func (t *archiveBodyTee) captureLocked(data []byte) {
	need := int64(len(t.buf)) + int64(len(data))
	if have := int64(cap(t.buf)); need > have {
		size := max(need, 2*have, archiveBodyMinBuffer)
		if t.contentLength >= need {
			size = min(size, t.contentLength)
		}
		if !t.rec.ReserveBody(size - have) {
			// A doubled buffer may not fit where the exact size does.
			if size == need || !t.rec.ReserveBody(need-have) {
				t.dropLocked(t.rec.BodyDropReason())
				return
			}
			size = need
		}
		t.reserved += size - have
		grown := make([]byte, len(t.buf), size)
		copy(grown, t.buf)
		t.buf = grown
	}
	t.buf = append(t.buf, data...)
}

func (t *archiveBodyTee) releaseLocked() {
	t.rec.ReleaseBody(t.reserved)
	t.reserved = 0
	t.buf = nil
}

func (t *archiveBodyTee) dropLocked(reason string) {
	t.releaseLocked()
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
	ReadError       string `json:"read_error,omitempty"`
}

func (t *archiveBodyTee) emitLocked(ended string) {
	if t.done {
		return
	}
	t.done = true
	t.rec.UntrackCapture(t)
	archiveFault("body.emit")
	data := archiveClientBodyData{
		WireBytes:       t.consumed,
		DeliveredBytes:  t.consumed,
		EOF:             t.sawEOF,
		Ended:           ended,
		ContentLength:   t.contentLength,
		ContentEncoding: t.encoding,
		ReadError:       t.readErr,
	}
	// MaxBytesReader reads one byte past its limit before failing.
	if t.limit > 0 && t.consumed > t.limit {
		data.DeliveredBytes = t.limit
		data.Truncated = true
	}
	if t.consumed == 0 && !t.sawEOF && t.readErr == "" && ended != archiveEndedShutdown {
		// Never read by the handler, so not read by the recorder either.
		t.releaseLocked()
		t.handedOff = true
		t.in.Emit(&archive.Event{Type: archive.TypeClientBody, Capture: archive.CaptureBodyUnread, Data: data, SizeHint: data.sizeHint()})
		return
	}
	if t.capturing && !t.rec.CaptureBodies() {
		// Space ran low (or capture stopped) after the last read.
		t.dropLocked(t.rec.BodyDropReason())
	}
	if !t.capturing {
		data.DropReason = t.dropReason
		t.handedOff = true
		t.in.NoteDrop()
		t.rec.CountDrop(t.dropReason, archive.DropCount{Bodies: 1, Bytes: t.consumed})
		t.in.Emit(&archive.Event{Type: archive.TypeClientBody, Capture: archive.CaptureDroppedBody, Data: data, SizeHint: data.sizeHint()})
		return
	}
	body := &archive.BodyData{Bytes: t.buf, ContentEncoding: t.encoding}
	reserved := t.reserved
	t.buf = nil
	t.reserved = 0
	t.handedOff = true
	t.in.EmitReserved(&archive.Event{Type: archive.TypeClientBody, Capture: archive.CaptureFull, Body: body, Data: data, SizeHint: data.sizeHint()}, reserved)
}
