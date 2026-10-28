package api

// Fleet fork: request archive transport observer and client body tee.
// See internal/archive and the fleet repository's
// docs/PROXY-REQUEST-ARCHIVE-DESIGN.md (sections 1-4).

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
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
	"github.com/tidwall/gjson"
)

// archiveIngressContextKey carries the *archive.Ingress on the gin context.
// The request context carries it too (archive.IngressFromContext).
const archiveIngressContextKey = archive.GinIngressKey

// archiveZ6HeaderPrefix marks the Z6 tags (design section 10.3). The observer
// captures them and removes them from the request before any handler runs,
// so no executor or custom-header rule can forward them upstream.
const archiveZ6HeaderPrefix = "X-Z6-"

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
		z6 := takeArchiveZ6Tags(c.Request)
		obs := s.beginArchiveObservation(rec, c, z6)
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
	rec      *archive.Recorder
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

	// mu orders the request's own finish against Stop's FinalizeAtStop;
	// whichever runs first queues the final event.
	mu       sync.Mutex
	finished bool
	tracked  bool
}

// takeArchiveZ6Tags removes every X-Z6-* header from the request and returns
// their values (the first of each).
func takeArchiveZ6Tags(req *http.Request) map[string]string {
	defer recoverArchiveTap("observer.z6")
	if req == nil {
		return nil
	}
	var tags map[string]string
	for name, values := range req.Header {
		if len(name) < len(archiveZ6HeaderPrefix) || !strings.EqualFold(name[:len(archiveZ6HeaderPrefix)], archiveZ6HeaderPrefix) {
			continue
		}
		if tags == nil {
			tags = map[string]string{}
		}
		if len(values) > 0 {
			tags[strings.ToLower(name)] = values[0]
		}
		delete(req.Header, name)
	}
	return tags
}

func isArchiveAbortHandler(recovered any) bool {
	err, ok := recovered.(error)
	return ok && errors.Is(err, http.ErrAbortHandler)
}

func (s *Server) beginArchiveObservation(rec *archive.Recorder, c *gin.Context, z6 map[string]string) (obs *archiveObservation) {
	defer recoverArchiveTap("observer.start")
	archiveFault("observer.start")
	req := c.Request
	if req == nil || req.URL == nil {
		return nil
	}
	if !rec.CaptureEvents() {
		// Low space, a failed writer or Stop: count the request, skip the work.
		rec.CountDrop(rec.BodyDropReason(), archive.DropCount{Events: 1})
		return nil
	}
	start := time.Now()
	route := c.FullPath()
	class, allow, _ := s.classifyArchiveRoute(req.Method, route)
	upgrade := strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket")
	var in *archive.Ingress
	if upgrade {
		in = rec.BeginConnection(class, start)
	} else {
		in = rec.BeginIngress(class, start)
	}
	inference := class == archive.RouteInference
	o := &archiveObservation{
		in:       in,
		rec:      rec,
		class:    class,
		route:    route,
		method:   req.Method,
		path:     req.URL.Path,
		clientIP: c.ClientIP(),
		rawQuery: req.URL.RawQuery,
		upgrade:  upgrade,
		resp:     &archiveResponseState{inference: inference},
	}
	o.writer = &archiveResponseWriter{ResponseWriter: c.Writer, state: o.resp}
	c.Writer = o.writer
	// From here on finish must run, even if the rest of this tap panics.
	obs = o
	var startEvent *archive.Event
	if inference {
		data := archiveIngressStartData{
			Kind:             in.Kind(),
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
			Sessions:         archiveSessionIDs(req.Header),
			Z6:               newArchiveZ6Tags(z6),
		}
		startEvent = &archive.Event{Type: archive.TypeIngressStart, Time: start, Capture: archive.CaptureFull, Data: data, SizeHint: data.sizeHint()}
		o.tee = s.installArchiveBodyTee(req, in)
	}
	c.Request = req.WithContext(archive.WithIngress(req.Context(), in))
	c.Set(archiveIngressContextKey, in)
	if startEvent != nil {
		in.Emit(startEvent)
	}
	// Tracked until its final event is queued, so Stop waits for it (or
	// finalizes it) instead of losing it.
	o.mu.Lock()
	o.tracked = rec.TrackObserver(o)
	o.mu.Unlock()
	return o
}

// finish emits ingress_end (inference) or metadata_only. It runs in the
// observer's deferred function, also while a panic or Goexit unwinds. When
// Stop finalized the observation first, it only ends the tee.
func (o *archiveObservation) finish(c *gin.Context, recovered any, aborted bool) {
	defer recoverArchiveTap("observer.finish")
	if o.tee != nil {
		// Also when the rest of finish panics, so the tee never strands its
		// reservation. Ending the tee twice is harmless.
		defer o.tee.end("request_end")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	defer o.untrackLocked()
	if o.finished {
		return
	}
	o.finished = true
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
	if value, ok := c.Get("accessMetadata"); ok {
		if meta, okMeta := value.(map[string]string); okMeta {
			o.in.SetClientKey(meta["fleet_key"])
		}
	}

	if o.class == archive.RouteInference {
		o.emitIngressEndLocked(end, summary, headers, "request_end")
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

// emitIngressEndLocked queues ingress_end after closing the request's open
// attempts. ingress_end follows client_body so its capture_drops counts a
// body drop: when a read is still in progress both wait for that read (on its
// goroutine, never on this one), or for Stop; ts stays the request end. The
// held event's bytes are reserved first; a failed reservation drops it
// (counted) and the deferred end still ends the body.
func (o *archiveObservation) emitIngressEndLocked(end time.Time, summary archiveResponseSummary, headers map[string][]string, ended string) {
	attemptsEnded := archive.AttemptEndedRequestEnd
	if ended == archiveEndedShutdown {
		attemptsEnded = archive.AttemptEndedShutdown
	}
	o.in.CloseAttempts(attemptsEnded)
	data := archiveIngressEndData{
		Kind:                   o.in.Kind(),
		Ended:                  ended,
		archiveResponseSummary: summary,
		Headers:                headers,
		Summary:                o.in.Summary(),
	}
	// The writer fills in capture_drops when it writes the event.
	ev := &archive.Event{Type: archive.TypeIngressEnd, Time: end, Capture: archive.CaptureFull, Data: data, SizeHint: data.sizeHint(), ReportDrops: true}
	if o.tee == nil {
		o.in.Emit(ev)
		return
	}
	reserved, ok := o.in.ReserveEvent(ev)
	if !ok {
		return
	}
	o.tee.endThen(ended, func() {
		defer recoverArchiveTap("observer.finish")
		o.in.EmitReserved(ev, reserved)
	})
}

// untrackLocked ends the observation's tracking once its final event is
// queued or handed to the tee (itself a tracked capture).
func (o *archiveObservation) untrackLocked() {
	if o.tracked {
		o.tracked = false
		o.rec.UntrackObserver(o)
	}
}

// FinalizeAtStop queues the final event of a request still running when
// Stop's wait ends: a hijacked WebSocket, say, which HTTP shutdown does not
// wait for. It reads only what the writer wrapper recorded atomically; the
// request's own finish, if it comes later, queues nothing.
func (o *archiveObservation) FinalizeAtStop() {
	defer recoverArchiveTap("observer.stop")
	o.mu.Lock()
	defer o.mu.Unlock()
	defer o.untrackLocked()
	if o.finished {
		return
	}
	o.finished = true
	end := time.Now()
	summary := archiveResponseSummary{DurationUS: end.Sub(o.in.Started()).Microseconds(), Abort: "shutdown", AuthDecision: "unknown"}
	var headers map[string][]string
	if snap := o.resp.headers.Load(); snap != nil {
		summary.Status = snap.status
		summary.HeaderWritten = true
		summary.ContentEncoding = snap.contentEncoding
		headers = snap.headers
	}
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
	if o.class == archive.RouteInference {
		o.emitIngressEndLocked(end, summary, headers, archiveEndedShutdown)
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

// archiveNoteAuthDenial records the gate code of a request the access
// middleware refused with a fleet code (fleet_route_denied: ...).
func archiveNoteAuthDenial(c *gin.Context, message string) {
	defer recoverArchiveTap("observer.auth")
	if archive.Current() == nil || c == nil || c.Request == nil {
		return
	}
	code, _, found := strings.Cut(message, ":")
	if !found || !archiveGateCode.MatchString(code) {
		return
	}
	archive.IngressFromContext(c.Request.Context()).NoteGate(code)
}

var archiveGateCode = regexp.MustCompile(`^fleet_[a-z_]{1,48}$`)

// archiveSessionIDs reads the session identities of design section 5 from
// the request headers (they are also kept in the redacted headers).
func archiveSessionIDs(h http.Header) *archiveSessions {
	ids := archiveSessions{
		SessionID:       strings.TrimSpace(h.Get("Session_id")),
		ClaudeSessionID: strings.TrimSpace(h.Get("X-Claude-Code-Session-Id")),
		ClaudeAgentID:   strings.TrimSpace(h.Get("X-Claude-Code-Agent-Id")),
	}
	if ids.SessionID == "" {
		ids.SessionID = strings.TrimSpace(h.Get("Session-Id"))
	}
	if metadata := h.Get("X-Codex-Turn-Metadata"); metadata != "" {
		ids.CodexTurnID = archiveCodexTurnID(metadata)
	}
	if ids.CodexTurnID != "" || strings.Contains(strings.ToLower(h.Get("Originator")), "codex") {
		ids.CodexSessionID = ids.SessionID
	}
	if ids == (archiveSessions{}) {
		return nil
	}
	return &ids
}

// archiveCodexTurnID reads turn_id from Codex's x-codex-turn-metadata JSON.
func archiveCodexTurnID(metadata string) string {
	if !gjson.Valid(metadata) {
		return ""
	}
	return gjson.Get(metadata, "turn_id").String()
}

type archiveSessions struct {
	SessionID       string `json:"session_id,omitempty"`
	ClaudeSessionID string `json:"claude_session_id,omitempty"`
	ClaudeAgentID   string `json:"claude_agent_id,omitempty"`
	CodexSessionID  string `json:"codex_session_id,omitempty"`
	CodexTurnID     string `json:"codex_turn_id,omitempty"`
}

func (s *archiveSessions) sizeHint() int64 {
	if s == nil {
		return 0
	}
	return archiveStringsSize(s.SessionID, s.ClaudeSessionID, s.ClaudeAgentID, s.CodexSessionID, s.CodexTurnID)
}

// archiveZ6 is the Z6 tags, removed from the request (design section 10.3).
type archiveZ6 struct {
	EnvironmentID string            `json:"z6_environment_id,omitempty"`
	ThreadID      string            `json:"z6_thread_id,omitempty"`
	Other         map[string]string `json:"z6_other,omitempty"`
}

func newArchiveZ6Tags(tags map[string]string) *archiveZ6 {
	if len(tags) == 0 {
		return nil
	}
	z6 := &archiveZ6{}
	for name, value := range tags {
		switch name {
		case "x-z6-environment-id":
			z6.EnvironmentID = value
		case "x-z6-thread-id":
			z6.ThreadID = value
		default:
			// Any other X-Z6-* header is kept by name, redacted like a header.
			if z6.Other == nil {
				z6.Other = map[string]string{}
			}
			z6.Other[name] = archive.RedactHeaders(http.Header{name: {value}})[name][0]
		}
	}
	return z6
}

func (z *archiveZ6) sizeHint() int64 {
	if z == nil {
		return 0
	}
	n := archiveStringsSize(z.EnvironmentID, z.ThreadID)
	for name, value := range z.Other {
		n += archiveStringsSize(name, value)
	}
	return n
}

// archiveAuthDecision reports what the access middleware decided.
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
	Kind             string              `json:"kind"`
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
	Sessions         *archiveSessions    `json:"sessions,omitempty"`
	Z6               *archiveZ6          `json:"z6,omitempty"`
}

// The sizeHint methods count every variable-size field, so an event's queue
// reservation covers what it holds; fixed fields fit in the event overhead.
func (d archiveIngressStartData) sizeHint() int64 {
	return archiveStringsSize(d.Kind, d.Method, d.Path, d.Route, d.RouteClass, d.Query, d.ClientIP, d.Proto, d.Host) +
		archiveStringsSize(d.TransferEncoding...) + archiveHeaderSize(d.Headers) + d.Sessions.sizeHint() + d.Z6.sizeHint()
}

func (d archiveIngressEndData) sizeHint() int64 {
	return archiveStringsSize(d.Kind, d.Ended) + d.archiveResponseSummary.sizeHint() + archiveHeaderSize(d.Headers) + d.Summary.SizeHint()
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
	Kind  string `json:"kind"`
	Ended string `json:"ended"`
	archiveResponseSummary
	Headers map[string][]string `json:"headers,omitempty"`
	archive.Summary
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
	status          int
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
	snap := st.snapshot(w.Header())
	snap.status = w.Status()
	st.headers.CompareAndSwap(nil, snap)
}

// snapshotFinal returns the committed headers, or the current ones when the
// response was committed outside the wrapper (gin's final WriteHeaderNow).
func (st *archiveResponseState) snapshotFinal(w gin.ResponseWriter) *archiveHeaderSnapshot {
	if snap := st.headers.Load(); snap != nil {
		return snap
	}
	snap := st.snapshot(w.Header())
	snap.status = w.Status()
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
	// Tracked until client_body and the deferred ingress_end are emitted, so
	// Stop can finalize it. Once Stop has begun the tee is not tracked and
	// captures nothing. The tee's lock covers its initialization, because
	// Stop can finalize it as soon as it is tracked.
	tee.mu.Lock()
	tee.capturing = rec.TrackCapture(tee) && rec.CaptureBodies()
	if !tee.capturing {
		tee.dropReason = rec.BodyDropReason()
	}
	tee.mu.Unlock()
	tracker.ReadCloser = tee
	return tee
}

// The tee holds a body in chunks. Each new chunk is as large as what is held
// so far (the total doubles), between archiveBodyMinBuffer and
// archiveBodyMaxChunk, so growing never copies what was read and the unused
// space charged to the queue stays under 1 MiB.
const (
	archiveBodyMinBuffer = 4 << 10
	archiveBodyMaxChunk  = 1 << 20
)

// archiveEndedShutdown is client_body's ended when Stop finalized the tee.
const archiveEndedShutdown = "shutdown"

// archiveBodyTee copies the wire bytes the handler consumes. Its queue
// reservation always covers its buffers' capacity. It emits client_body
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
	chunks     [][]byte
	captured   int64 // bytes held in chunks
	copied     int64 // bytes ever copied into chunks (equals captured: no regrowth copies)
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
// lost to a tap panic, which recoverLocked has counted by then), and then
// stops tracking the tee. Until then Stop's FinalizeAtStop waits on the tee's
// lock (never on a read), so an emission in progress is queued before the
// writer's final drain.
func (t *archiveBodyTee) runAfterEndLocked() {
	if !t.done {
		return
	}
	if afterEnd := t.afterEnd; afterEnd != nil {
		t.afterEnd = nil
		afterEnd()
	}
	t.rec.UntrackCapture(t)
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

// captureLocked appends data to the last chunk and, when it is full, to a
// new chunk whose queue bytes are reserved first. Each byte is copied once.
func (t *archiveBodyTee) captureLocked(data []byte) {
	for len(data) > 0 {
		if n := len(t.chunks); n > 0 {
			last := t.chunks[n-1]
			if free := cap(last) - len(last); free > 0 {
				k := min(free, len(data))
				t.chunks[n-1] = append(last, data[:k]...)
				t.captured += int64(k)
				t.copied += int64(k)
				data = data[k:]
				continue
			}
		}
		need := int64(len(data))
		size := max(min(max(t.captured, archiveBodyMinBuffer), archiveBodyMaxChunk), need)
		if left := t.contentLength - t.captured; t.contentLength > 0 && left >= need {
			size = min(size, left)
		}
		if !t.rec.ReserveBody(size) {
			// A full step may not fit where this read's bytes do.
			if size == need || !t.rec.ReserveBody(need) {
				t.dropLocked(t.rec.BodyDropReason())
				return
			}
			size = need
		}
		t.reserved += size
		t.chunks = append(t.chunks, make([]byte, 0, size))
	}
}

// bufferCapLocked is the capacity of the tee's chunks.
func (t *archiveBodyTee) bufferCapLocked() int64 {
	var n int64
	for _, chunk := range t.chunks {
		n += int64(cap(chunk))
	}
	return n
}

func (t *archiveBodyTee) releaseLocked() {
	t.rec.ReleaseBody(t.reserved)
	t.reserved = 0
	t.chunks = nil
	t.captured = 0
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
	body := &archive.BodyData{Chunks: t.chunks, ContentEncoding: t.encoding}
	if len(t.chunks) == 0 {
		body.Bytes = []byte{}
	}
	reserved := t.reserved
	t.chunks = nil
	t.captured = 0
	t.reserved = 0
	t.handedOff = true
	t.in.EmitReserved(&archive.Event{Type: archive.TypeClientBody, Capture: archive.CaptureFull, Body: body, Data: data, SizeHint: data.sizeHint()}, reserved)
}

// installArchiveContentTap installs the downstream content tap right after
// response compression, so it records what handlers write before it is
// compressed (design section 3, "Downstream content"). Like the observer it
// is installed only while the recorder runs.
func (s *Server) installArchiveContentTap(engine *gin.Engine) {
	if engine == nil || archive.Current() == nil {
		return
	}
	engine.Use(archiveContentMiddleware)
}

func archiveContentMiddleware(c *gin.Context) {
	if w := newArchiveContentWriter(c); w != nil {
		c.Writer = w
	}
	c.Next()
}

func newArchiveContentWriter(c *gin.Context) (w *archiveContentWriter) {
	defer recoverArchiveTap("content.start")
	value, ok := c.Get(archiveIngressContextKey)
	if !ok {
		return nil
	}
	in, _ := value.(*archive.Ingress)
	// A WebSocket's frames are recorded by its handler.
	if in == nil || in.Class() != archive.RouteInference || in.Kind() != archive.KindHTTP {
		return nil
	}
	return &archiveContentWriter{ResponseWriter: c.Writer, in: in}
}

// archiveContentWriter records each write of the response body as a
// downstream_event with its offset, and the first content-bearing write as
// first_token_at. It preserves Flush, FlushError, Unwrap and Hijack.
type archiveContentWriter struct {
	gin.ResponseWriter
	in     *archive.Ingress
	offset atomic.Int64
	token  atomic.Bool
}

type archiveDownstreamData struct {
	Offset int64 `json:"offset"`
}

func (w *archiveContentWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *archiveContentWriter) Write(data []byte) (int, error) {
	n, errWrite := w.ResponseWriter.Write(data)
	w.record(data[:max(n, 0)])
	return n, errWrite
}

func (w *archiveContentWriter) WriteString(data string) (int, error) {
	n, errWrite := w.ResponseWriter.WriteString(data)
	if n > 0 {
		w.record([]byte(data[:n]))
	}
	return n, errWrite
}

func (w *archiveContentWriter) Flush() {
	_ = w.FlushError()
}

func (w *archiveContentWriter) FlushError() error {
	return httpwire.FlushResponse(w.ResponseWriter)
}

func (w *archiveContentWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.ResponseWriter.Hijack()
}

func (w *archiveContentWriter) record(data []byte) {
	defer recoverArchiveTap("content.write")
	if len(data) == 0 {
		return
	}
	archiveFault("content.write")
	now := time.Now()
	offset := w.offset.Add(int64(len(data))) - int64(len(data))
	if !w.token.Load() && archiveContentBearing(w.Header().Get("Content-Type"), data) {
		w.token.Store(true)
		w.in.NoteFirstToken(now)
	}
	archive.EmitDownstream(w.in, now, archiveDownstreamData{Offset: offset}, data)
}

// archiveContentBearing is a best-effort test for the first token: a
// non-streamed body's first write, or a streamed event carrying a text,
// reasoning or tool-argument delta. The shipper can recompute it from the
// downstream events.
func archiveContentBearing(contentType string, data []byte) bool {
	if !strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		return true
	}
	for _, marker := range archiveTokenMarkers {
		if bytes.Contains(data, marker) {
			return true
		}
	}
	return false
}

var archiveTokenMarkers = [][]byte{
	[]byte(`"text_delta"`), []byte(`"thinking_delta"`), []byte(`"input_json_delta"`), // Anthropic
	[]byte(`.delta"`),                                                                                  // Responses: response.output_text.delta, reasoning and argument deltas
	[]byte(`"delta":{"content":"`), []byte(`"delta":{"reasoning_content":"`), []byte(`"tool_calls":[`), // Chat Completions
	[]byte(`"parts":[{"text":"`), // Gemini
}
