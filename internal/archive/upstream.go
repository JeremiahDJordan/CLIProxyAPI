package archive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unsafe"

	"github.com/tidwall/gjson"
)

// Executor taps (design section 3, "Outbound request and upstream response"
// and "Upstream WebSocket"). The executor helpers call them before their own
// request-log checks, so capture never depends on request logging. Each
// starts with one nil check (Installed); they capture only for inference
// requests, record through the request's own ingress and never wait on the
// disk.

// UpstreamRequest is an outbound request as the executor sends it, after
// translation, cloaking and signing.
type UpstreamRequest struct {
	URL     string
	Method  string
	Headers http.Header
	Body    []byte
	// BodyNotCaptured records the body as not captured (DropNotCaptured)
	// instead of recording Body: the executor does not have the bytes it sent
	// at the tap, or they carry a credential.
	BodyNotCaptured bool
	// GetBody, when set, supplies the body recorded instead of Body (which
	// is still read for previous_response_id): an http.Request's own, for
	// bytes only the request holds (Codex's zstd encoding of Body). Its
	// ContentLength bytes are reserved before they are read; a body that
	// cannot be read in full is recorded as not captured.
	GetBody       func() (io.ReadCloser, error)
	ContentLength int64
	// Resend names why the executor sent the attempt's request again itself
	// (ResendCompressionRejected); it is recorded as the new sub-attempt's
	// resend, and empty provider and credential fields repeat those of the
	// attempt's previous request.
	Resend    string
	Provider  string
	AuthID    string
	AuthLabel string
	AuthType  string
}

// Resend reasons (upstream_request's resend).
const (
	// ResendCompressionRejected is Codex's uncompressed resend after the
	// upstream rejected a zstd request body (HTTP 400 or 415).
	ResendCompressionRejected = "compression_rejected"
)

// recoverTap contains a panic in a tap; it must be deferred directly, since
// recover works only there. When the tap had found its request (*in is
// set), the request counts a drop too: what the tap was recording is lost,
// so its ingress_end must not look complete. The tap's own deferred cleanup,
// which returns its reservation, runs first.
func recoverTap(where string, in **Ingress) {
	if rv := recover(); rv != nil {
		NoteTapPanic(where, rv)
		if in != nil {
			(*in).NoteDrop()
		}
	}
}

// Recorded reports whether taps given ctx record anything: capture was
// started and ctx carries an inference request. Executors check it before
// work done only for the archive (reading a response they discard).
func Recorded(ctx context.Context) bool {
	if !Installed() {
		return false
	}
	in, _ := tapTarget(ctx)
	return in != nil
}

// tapTarget finds the inference request and attempt a tap belongs to. It
// does not consult Current: a request in flight while Stop runs is recorded
// through its own ingress.
func tapTarget(ctx context.Context) (*Ingress, *Attempt) {
	if ctx == nil {
		return nil, nil
	}
	in := IngressFromContext(ctx)
	if in == nil || in.rec == nil || in.class != RouteInference {
		return nil, nil
	}
	a := AttemptFromContext(ctx)
	if a == nil || a.in != in {
		a = in.implicitAttempt()
	}
	return in, a
}

type upstreamRequestData struct {
	Transport string              `json:"transport"`
	URL       string              `json:"url"`
	Method    string              `json:"method,omitempty"`
	Headers   map[string][]string `json:"headers,omitempty"`
	Resend    string              `json:"resend,omitempty"`
	Provider  string              `json:"provider,omitempty"`
	AuthID    string              `json:"auth_id,omitempty"`
	AuthLabel string              `json:"auth_label,omitempty"`
	AuthType  string              `json:"auth_type,omitempty"`
}

func (d upstreamRequestData) sizeHint() int64 {
	return stringsSize(d.Transport, d.URL, d.Method, d.Resend, d.Provider, d.AuthID, d.AuthLabel, d.AuthType) + headersSize(d.Headers)
}

func newUpstreamRequestData(transport string, req UpstreamRequest) upstreamRequestData {
	return upstreamRequestData{
		Transport: transport,
		URL:       RedactUpstreamURL(req.URL),
		Method:    req.Method,
		Headers:   RedactHeaders(req.Headers),
		Resend:    req.Resend,
		Provider:  req.Provider,
		AuthID:    req.AuthID,
		AuthLabel: req.AuthLabel,
		AuthType:  req.AuthType,
	}
}

// TapUpstreamRequest records an outbound HTTP request as a new sub-attempt.
func TapUpstreamRequest(ctx context.Context, req UpstreamRequest) {
	if !Installed() {
		return
	}
	var in *Ingress
	defer recoverTap("upstream.request", &in)
	in, a := tapTarget(ctx)
	if a == nil {
		return
	}
	now := time.Now()
	seq, sub := a.nextRequest(now, &req)
	a.notePrevious(req.Body)
	data := newUpstreamRequestData("http", req)
	ev := &Event{Type: TypeUpstreamRequest, Time: now, AttemptSeq: seq, SubAttempt: &sub, Data: data, SizeHint: data.sizeHint()}
	switch {
	case req.BodyNotCaptured:
		in.emitNotCaptured(ev)
	case req.GetBody != nil:
		// The bytes as sent, encoded as the request says (body.content_encoding).
		emitBodyFill(in, ev, req.ContentLength, req.Headers.Get("Content-Encoding"), func(dst []byte) bool { return readBody(req.GetBody, dst) })
	default:
		emitBody(in, ev, req.Body)
	}
}

// readBody reads exactly len(dst) bytes, the whole body, into dst.
func readBody(getBody func() (io.ReadCloser, error), dst []byte) bool {
	body, err := getBody()
	if err != nil || body == nil {
		return false
	}
	defer func() { _ = body.Close() }()
	if _, err = io.ReadFull(body, dst); err != nil {
		return false
	}
	var more [1]byte
	n, _ := body.Read(more[:])
	return n == 0
}

type upstreamResponseMetaData struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers,omitempty"`
}

// TapUpstreamResponse records the upstream status and headers.
func TapUpstreamResponse(ctx context.Context, status int, headers http.Header) {
	if !Installed() {
		return
	}
	var in *Ingress
	defer recoverTap("upstream.response", &in)
	in, a := tapTarget(ctx)
	if a == nil {
		return
	}
	now := time.Now()
	seq, sub := a.current(now)
	a.setStatus(status)
	data := upstreamResponseMetaData{Status: status, Headers: RedactHeaders(headers)}
	in.Emit(&Event{Type: TypeUpstreamResponseMeta, Time: now, AttemptSeq: seq, SubAttempt: &sub, Capture: CaptureFull, Data: data, SizeHint: headersSize(data.Headers)})
}

type upstreamEventData struct {
	ChunkSeq uint32 `json:"chunk_seq"`
	// NotCapturedReason says why a body the archive did not read was not
	// captured (TapUpstreamBodyNotCaptured).
	NotCapturedReason string `json:"not_captured_reason,omitempty"`
}

// TapUpstreamChunk records one decompressed upstream event, or a whole
// non-streamed (or error) response body, exactly as the executor read it.
// Chunks are numbered per sub-attempt from 1; empty chunks (blank SSE lines)
// are numbered but not written.
func TapUpstreamChunk(ctx context.Context, chunk []byte) {
	if !Installed() {
		return
	}
	var in *Ingress
	defer recoverTap("upstream.event", &in)
	in, a := tapTarget(ctx)
	if a == nil {
		return
	}
	now := time.Now()
	seq, sub, n := a.nextChunk(now)
	if len(chunk) == 0 {
		return
	}
	emitBody(in, &Event{Type: TypeUpstreamEvent, Time: now, AttemptSeq: seq, SubAttempt: &sub, Data: upstreamEventData{ChunkSeq: n}}, chunk)
	a.inspect(chunk, now, seq, sub)
}

// Why an upstream body was not captured (upstream_event's
// not_captured_reason).
const (
	// NotCapturedRejectedBeforeResend is the body of the response rejecting
	// Codex's zstd request body (HTTP 400 or 415), which the executor closes
	// unread before its uncompressed resend.
	NotCapturedRejectedBeforeResend = "rejected_before_resend"
)

// TapUpstreamBodyNotCaptured records, as the current sub-attempt's next
// upstream_event, a response body the executor discards without the
// archive reading it, for reason (NotCapturedRejectedBeforeResend): the
// event has no body (body_dropped: not_captured) and counts against the
// request like every body not captured. The body is the executor's alone:
// it is closed as it is without capture, so recording cannot delay what
// the executor does next.
func TapUpstreamBodyNotCaptured(ctx context.Context, reason string) {
	if !Installed() {
		return
	}
	var in *Ingress
	defer recoverTap("upstream.event", &in)
	in, a := tapTarget(ctx)
	if a == nil {
		return
	}
	now := time.Now()
	seq, sub, n := a.nextChunk(now)
	data := upstreamEventData{ChunkSeq: n, NotCapturedReason: reason}
	in.emitNotCaptured(&Event{Type: TypeUpstreamEvent, Time: now, AttemptSeq: seq, SubAttempt: &sub, Data: data, SizeHint: int64(len(reason))})
}

type upstreamErrorData struct {
	Class string `json:"class"`
	Error string `json:"error,omitempty"`
}

// TapUpstreamError records an error with no HTTP response (a transport
// error, or a failure reading the body). Its text is redacted.
func TapUpstreamError(ctx context.Context, err error) {
	if !Installed() || err == nil {
		return
	}
	var in *Ingress
	defer recoverTap("upstream.error", &in)
	in, a := tapTarget(ctx)
	if a == nil {
		return
	}
	now := time.Now()
	seq, sub := a.current(now)
	data := upstreamErrorData{Class: ErrorClass(err), Error: RedactText(err.Error())}
	in.Emit(&Event{Type: TypeUpstreamError, Time: now, AttemptSeq: seq, SubAttempt: &sub, Capture: CaptureFull, Data: data, SizeHint: stringsSize(data.Class, data.Error)})
}

// ErrorClass names an error by category, never by its text.
func ErrorClass(err error) string {
	var netErr net.Error
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return "eof_unexpected"
	default:
		return "other"
	}
}

// Upstream WebSocket event kinds (upstream_ws's ws_event).
const (
	WSEventRequest   = "request"
	WSEventHandshake = "handshake"
	WSEventRejection = "upgrade_rejection"
	WSEventError     = "error"
	WSEventResponse  = "response"
)

type upstreamWSData struct {
	WSEvent         string              `json:"ws_event"`
	URL             string              `json:"url,omitempty"`
	Headers         map[string][]string `json:"headers,omitempty"`
	Status          int                 `json:"status,omitempty"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	Stage           string              `json:"stage,omitempty"`
	Class           string              `json:"class,omitempty"`
	Error           string              `json:"error,omitempty"`
	FrameSeq        uint32              `json:"frame_seq,omitempty"`
	Trimmed         bool                `json:"trimmed,omitempty"`
	Provider        string              `json:"provider,omitempty"`
	AuthID          string              `json:"auth_id,omitempty"`
	AuthLabel       string              `json:"auth_label,omitempty"`
	AuthType        string              `json:"auth_type,omitempty"`
}

func (d upstreamWSData) sizeHint() int64 {
	return stringsSize(d.WSEvent, d.URL, d.Stage, d.Class, d.Error, d.Provider, d.AuthID, d.AuthLabel, d.AuthType) +
		headersSize(d.Headers) + headersSize(d.ResponseHeaders)
}

// TapUpstreamWSRequest records a frame sent on an upstream WebSocket (with
// the connection's URL and handshake headers) as a new sub-attempt.
func TapUpstreamWSRequest(ctx context.Context, req UpstreamRequest) {
	if !Installed() {
		return
	}
	var in *Ingress
	defer recoverTap("upstream.ws.request", &in)
	in, a := tapTarget(ctx)
	if a == nil {
		return
	}
	now := time.Now()
	seq, sub := a.nextRequest(now, &req)
	a.notePrevious(req.Body)
	data := upstreamWSData{
		WSEvent: WSEventRequest, URL: RedactUpstreamURL(req.URL), Headers: RedactHeaders(req.Headers),
		Provider: req.Provider, AuthID: req.AuthID, AuthLabel: req.AuthLabel, AuthType: req.AuthType,
	}
	ev := &Event{Type: TypeUpstreamWS, Time: now, AttemptSeq: seq, SubAttempt: &sub, Data: data, SizeHint: data.sizeHint()}
	if req.BodyNotCaptured {
		in.emitNotCaptured(ev)
		return
	}
	emitBody(in, ev, req.Body)
}

// TapUpstreamWSHandshake records the upstream handshake's status and headers.
func TapUpstreamWSHandshake(ctx context.Context, status int, headers http.Header) {
	if !Installed() {
		return
	}
	var in *Ingress
	defer recoverTap("upstream.ws.handshake", &in)
	in, a := tapTarget(ctx)
	if a == nil {
		return
	}
	now := time.Now()
	seq, sub := a.current(now)
	a.setStatus(status)
	data := upstreamWSData{WSEvent: WSEventHandshake, Status: status, ResponseHeaders: RedactHeaders(headers)}
	in.Emit(&Event{Type: TypeUpstreamWS, Time: now, AttemptSeq: seq, SubAttempt: &sub, Capture: CaptureFull, Data: data, SizeHint: data.sizeHint()})
}

// TapUpstreamWSRejection records a refused upgrade with its response body.
func TapUpstreamWSRejection(ctx context.Context, req UpstreamRequest, status int, headers http.Header, body []byte) {
	if !Installed() {
		return
	}
	var in *Ingress
	defer recoverTap("upstream.ws.rejection", &in)
	in, a := tapTarget(ctx)
	if a == nil {
		return
	}
	now := time.Now()
	seq, sub := a.current(now)
	a.setStatus(status)
	data := upstreamWSData{
		WSEvent: WSEventRejection, URL: RedactUpstreamURL(req.URL), Headers: RedactHeaders(req.Headers),
		Status: status, ResponseHeaders: RedactHeaders(headers),
		Provider: req.Provider, AuthID: req.AuthID, AuthLabel: req.AuthLabel, AuthType: req.AuthType,
	}
	emitBody(in, &Event{Type: TypeUpstreamWS, Time: now, AttemptSeq: seq, SubAttempt: &sub, Data: data, SizeHint: data.sizeHint()}, body)
}

// TapUpstreamWSError records an upstream WebSocket error at a stage (dial,
// send, read, ...). Its text is redacted.
func TapUpstreamWSError(ctx context.Context, stage string, err error) {
	if !Installed() || err == nil {
		return
	}
	var in *Ingress
	defer recoverTap("upstream.ws.error", &in)
	in, a := tapTarget(ctx)
	if a == nil {
		return
	}
	now := time.Now()
	seq, sub := a.current(now)
	data := upstreamWSData{WSEvent: WSEventError, Stage: stage, Class: ErrorClass(err), Error: RedactText(err.Error())}
	in.Emit(&Event{Type: TypeUpstreamWS, Time: now, AttemptSeq: seq, SubAttempt: &sub, Capture: CaptureFull, Data: data, SizeHint: data.sizeHint()})
}

// TapUpstreamWSFrame records a frame received from an upstream WebSocket,
// before the executor restores it. trimmed says the caller removed
// surrounding whitespace first (Codex frames).
func TapUpstreamWSFrame(ctx context.Context, payload []byte, trimmed bool) {
	if !Installed() {
		return
	}
	var in *Ingress
	defer recoverTap("upstream.ws.frame", &in)
	in, a := tapTarget(ctx)
	if a == nil {
		return
	}
	now := time.Now()
	seq, sub, n := a.nextFrame(now)
	data := upstreamWSData{WSEvent: WSEventResponse, FrameSeq: n, Trimmed: trimmed}
	emitBody(in, &Event{Type: TypeUpstreamWS, Time: now, AttemptSeq: seq, SubAttempt: &sub, Data: data, SizeHint: data.sizeHint()}, payload)
	a.inspect(payload, now, seq, sub)
}

// UsageSourceReporter marks usage events built from the usage reporter's
// record rather than read from an upstream event.
const UsageSourceReporter = "reporter"

type usageData struct {
	Source string          `json:"source"`
	Event  string          `json:"event,omitempty"`
	Model  string          `json:"model,omitempty"`
	Usage  json.RawMessage `json:"usage"`
}

// TapUsage records usage for the attempt in ctx from another source than an
// upstream event (the usage reporter's token breakdown). raw must be a JSON
// object; anything else is ignored. Its copy is redacted (RedactJSON).
func TapUsage(ctx context.Context, source, model string, raw []byte) {
	if !Installed() {
		return
	}
	var in *Ingress
	defer recoverTap("usage", &in)
	in, a := tapTarget(ctx)
	if a == nil || !isJSONObject(raw) {
		return
	}
	now := time.Now()
	seq, sub := a.current(now)
	emitUsage(in, &Event{Type: TypeUsage, Time: now, AttemptSeq: seq, SubAttempt: &sub}, usageData{Source: source, Model: model}, raw)
}

// isJSONObject reports whether raw is one valid JSON object, without copying
// it (gjson.ParseBytes copies its whole input).
func isJSONObject(raw []byte) bool {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{' && gjson.ValidBytes(raw)
}

// BytesView returns b as a string without copying it, for gjson.Parse and
// gjson.Get, which then copy nothing either: their results are substrings
// of b (gjson.ParseBytes and GetBytes copy), except strings, which gjson
// unescapes into a copy as large as the string: read a view with JSONText
// where a string can be large or many are read. b must not change while
// the view is in use, and nothing that outlives the caller may refer to the
// view or a result read from it: copy what is kept (OwnedString), after the
// event that keeps it is reserved where it can be large.
func BytesView(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// maxOwnedLen bounds identities and other short fields read from upstream
// or client JSON (IDs, model names, event types). A longer value is not one
// of them and is dropped without being copied.
const maxOwnedLen = 256

// OwnedString copies s, a value read from a view (BytesView), so it does not
// keep the view's input alive; a value longer than maxOwnedLen is dropped.
func OwnedString(s string) string {
	if len(s) > maxOwnedLen {
		return ""
	}
	return strings.Clone(s)
}

// idAt is the identity-sized string at the object path keys in obj
// (jsonText): a view of obj, or of scratch when it is written with escapes
// (escaped). Nothing is copied until it is kept: identities.add* copy an
// escaped one they keep, and noteIDs copies the identities it keeps.
func idAt(obj string, scratch *JSONScratch, keys ...string) (id string, escaped bool) {
	return jsonText(jsonGet(obj, keys...), maxOwnedLen, scratch)
}

// notePrevious records previous_response_id from an outbound body.
func (a *Attempt) notePrevious(body []byte) {
	if !bytes.Contains(body, []byte(`"previous_response_id"`)) {
		return
	}
	var scratch JSONScratch
	if prev, _ := idAt(BytesView(body), &scratch, "previous_response_id"); prev != "" {
		a.noteIDs(identities{PreviousResponseID: prev})
	}
}

// inspect reads raw usage and identities from an upstream event or body:
// Anthropic message_start/message_delta/content_block_start, Responses
// response.* and output items, and non-streamed JSON bodies. It parses only
// chunks that can carry them, through raw views of the chunk (BytesView,
// jsonGet), so a large event is never copied outside the queue's
// reservations: identities are collected as views, of the chunk or, when
// written with escapes, of a reused scratch buffer, and copied only once
// they pass the limits and duplicate checks of the event's identities and
// then the attempt's (noteIDs); the model and the event type are copied
// bounded, and the usage object only once its event is reserved
// (emitUsage).
func (a *Attempt) inspect(chunk []byte, now time.Time, seq, sub uint16) {
	data := bytes.TrimSpace(chunk)
	if rest, ok := bytes.CutPrefix(data, []byte("data:")); ok {
		data = bytes.TrimSpace(rest)
	}
	if len(data) == 0 || data[0] != '{' {
		return
	}
	if !bytes.Contains(data, []byte(`"usage`)) && !bytes.Contains(data, []byte(`"id"`)) &&
		!bytes.Contains(data, []byte(`"responseId"`)) && !bytes.Contains(data, []byte(`"previous_response_id"`)) {
		return
	}
	if !gjson.ValidBytes(data) {
		return
	}
	root := BytesView(data)
	// Escaped strings are unescaped into these: the event type and
	// previous_response_id, kept to the end, into their own; each ID in turn
	// into scratch, overwritten by the next (found copies those it keeps).
	var typeScratch, prevScratch, scratch JSONScratch
	var found identities // views of root, or copies of escaped IDs
	var usage, model string
	event, _ := idAt(root, &typeScratch, "type")
	switch event {
	case "message_start":
		message := jsonGet(root, "message")
		found.addResponse(idAt(message, &scratch, "id"))
		usage, model = jsonGet(message, "usage"), jsonGet(message, "model")
	case "message_delta":
		usage = jsonGet(root, "usage")
	case "content_block_start":
		found.addItem(idAt(root, &scratch, "content_block", "id"))
	case "response.created", "response.in_progress", "response.completed", "response.done",
		"response.failed", "response.incomplete":
		response := jsonGet(root, "response")
		found.addResponse(idAt(response, &scratch, "id"))
		found.PreviousResponseID, _ = idAt(response, &prevScratch, "previous_response_id")
		usage, model = jsonGet(response, "usage"), jsonGet(response, "model")
	case "response.output_item.added", "response.output_item.done":
		item := jsonGet(root, "item")
		found.addItem(idAt(item, &scratch, "id"))
		found.addItem(idAt(item, &scratch, "call_id"))
	case "message":
		// A non-streamed Anthropic Messages body.
		found.addResponse(idAt(root, &scratch, "id"))
		usage, model = jsonGet(root, "usage"), jsonGet(root, "model")
		jsonEach(jsonGet(root, "content"), func(block string) bool {
			found.addItem(idAt(block, &scratch, "id"))
			return true
		})
		event = "body"
	default:
		switch object, _ := idAt(root, &scratch, "object"); {
		case object == "response":
			// A non-streamed Responses body.
			found.addResponse(idAt(root, &scratch, "id"))
			found.PreviousResponseID, _ = idAt(root, &prevScratch, "previous_response_id")
			usage, model = jsonGet(root, "usage"), jsonGet(root, "model")
			jsonEach(jsonGet(root, "output"), func(item string) bool {
				found.addItem(idAt(item, &scratch, "id"))
				found.addItem(idAt(item, &scratch, "call_id"))
				return true
			})
			event = "body"
		case jsonIsObject(jsonGet(root, "usageMetadata")):
			// Gemini.
			found.addResponse(idAt(root, &scratch, "responseId"))
			usage, model = jsonGet(root, "usageMetadata"), jsonGet(root, "modelVersion")
			if event == "" {
				event = "usageMetadata"
			}
		case jsonIsObject(jsonGet(root, "usage")):
			// Chat Completions and other bodies or chunks with top-level usage.
			found.addResponse(idAt(root, &scratch, "id"))
			usage, model = jsonGet(root, "usage"), jsonGet(root, "model")
			if event == "" {
				event = "body"
			}
		}
	}
	a.noteIDs(found)
	if !jsonIsObject(usage) {
		return
	}
	model, _ = jsonText(model, maxOwnedLen, &scratch)
	emitUsage(a.in, &Event{Type: TypeUsage, Time: now, AttemptSeq: seq, SubAttempt: &sub},
		usageData{Source: "upstream", Event: OwnedString(event), Model: OwnedString(model)}, usage)
}

// emitUsage queues a usage event carrying a redacted copy (RedactJSON) of
// the usage object raw (a view, from inspect). Like emitBody it reserves
// before it copies; the copy's growth from redaction, if any, is reserved
// when it is queued.
func emitUsage[R []byte | string](in *Ingress, ev *Event, data usageData, raw R) {
	ev.Capture = CaptureFull
	ev.SizeHint = int64(len(raw)) + stringsSize(data.Source, data.Event, data.Model)
	in.EmitCopying(ev, func(ev *Event) {
		data.Usage = RedactJSON(raw)
		ev.SizeHint = int64(len(data.Usage)) + stringsSize(data.Source, data.Event, data.Model)
		ev.Data = data
	})
}

// EmitDownstream records one write of a response body to the client (what
// the client receives, before compression) as a downstream_event. body is
// the written []byte or string; it is copied only once the event is admitted.
func EmitDownstream[B []byte | string](in *Ingress, now time.Time, data any, body B) {
	if in == nil {
		return
	}
	emitBody(in, &Event{Type: TypeDownstreamEvent, Time: now, Data: data, SizeHint: 32}, body)
}

// EmitClientFrame records a WebSocket frame between the client and the proxy
// (a client_ws_frame); data carries its direction and message type.
func EmitClientFrame(in *Ingress, now time.Time, data any, sizeHint int64, payload []byte) {
	if in == nil {
		return
	}
	emitBody(in, &Event{Type: TypeClientWSFrame, Time: now, Data: data, SizeHint: sizeHint}, payload)
}

// emitBody queues ev carrying a copy of body. The event's whole size, body
// included, is reserved before anything is copied, so a body the queue
// refuses is dropped (and counted) without being allocated; the reservation
// is returned if the copy panics. While bodies are not captured (low space,
// or the recorder is stopping), the event is still queued, without its
// body, as dropped_body, and the drop counts against the request.
func emitBody[B []byte | string](in *Ingress, ev *Event, body B) {
	emitBodyFill(in, ev, int64(len(body)), "", func(dst []byte) bool {
		copy(dst, body)
		return true
	})
}

// emitBodyFill is emitBody for a body of size bytes, in content encoding
// encoding (empty for none), that fill copies into the event's buffer once
// it is reserved. When fill fails the event is queued without its body, as
// not captured (emitNotCaptured).
func emitBodyFill(in *Ingress, ev *Event, size int64, encoding string, fill func(dst []byte) bool) {
	rec := in.rec
	if !rec.CaptureBodies() {
		if rec.acceptsEvents() {
			reason := rec.BodyDropReason()
			rec.CountDrop(reason, DropCount{Bodies: 1, Bytes: max(size, 0)})
			in.NoteDrop()
			ev.Capture = CaptureDroppedBody
			ev.BodyDropped = reason
		}
		// When events are refused too, Emit drops and counts the event.
		in.Emit(ev)
		return
	}
	if size < 0 {
		in.emitNotCaptured(ev)
		return
	}
	// The copy's capacity is exactly size, so this is the event's
	// reservation (Event.reservation) once the body is attached.
	reserved, ok := in.reserve(int64(eventOverhead)+ev.SizeHint+size,
		DropCount{Events: 1, Bodies: 1, Bytes: size})
	if !ok {
		return
	}
	defer func() {
		// Returned if the copy panics; queued events own their reservation.
		rec.q.release(reserved)
	}()
	_ = fault("tap.copy") // tests panic here
	data := make([]byte, size)
	if !fill(data) {
		rec.q.release(reserved)
		reserved = 0
		in.emitNotCaptured(ev)
		return
	}
	ev.Capture = CaptureFull
	ev.Body = &BodyData{Bytes: data, ContentEncoding: encoding}
	n := reserved
	reserved = 0
	in.EmitReserved(ev, n)
}

// emitNotCaptured queues a body-carrying event whose body the tap does not
// have (or must not keep) as dropped_body with DropNotCaptured, and counts
// the drop against the request only: it is a known limit of an executor,
// not a capture failure, so it is not a gap.
func (in *Ingress) emitNotCaptured(ev *Event) {
	ev.Capture = CaptureDroppedBody
	ev.BodyDropped = DropNotCaptured
	in.NoteDrop()
	in.Emit(ev)
}

func headersSize(h map[string][]string) int64 {
	var n int64
	for name, values := range h {
		n += int64(len(name)) + 8 + stringsSize(values...)
	}
	return n
}
