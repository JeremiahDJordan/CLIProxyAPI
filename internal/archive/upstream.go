package archive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/tidwall/gjson"
)

// Executor taps (design section 3, "Outbound request and upstream response"
// and "Upstream WebSocket"). The executor helpers call them before their own
// request-log checks, so capture never depends on request logging. Each
// starts with one nil check on Current(); they capture only for inference
// requests and never wait on the disk.

// UpstreamRequest is an outbound request as the executor sends it, after
// translation, cloaking and signing.
type UpstreamRequest struct {
	URL       string
	Method    string
	Headers   http.Header
	Body      []byte
	Provider  string
	AuthID    string
	AuthLabel string
	AuthType  string
}

func recoverTap(where string) {
	if rv := recover(); rv != nil {
		NoteTapPanic(where, rv)
	}
}

// tapTarget finds the inference request and attempt a tap belongs to.
func tapTarget(ctx context.Context) (*Ingress, *Attempt) {
	rec := Current()
	if rec == nil || ctx == nil {
		return nil, nil
	}
	in := IngressFromContext(ctx)
	if in == nil || in.rec != rec || in.class != RouteInference {
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
	Provider  string              `json:"provider,omitempty"`
	AuthID    string              `json:"auth_id,omitempty"`
	AuthLabel string              `json:"auth_label,omitempty"`
	AuthType  string              `json:"auth_type,omitempty"`
}

func (d upstreamRequestData) sizeHint() int64 {
	return stringsSize(d.Transport, d.URL, d.Method, d.Provider, d.AuthID, d.AuthLabel, d.AuthType) + headersSize(d.Headers)
}

func newUpstreamRequestData(transport string, req UpstreamRequest) upstreamRequestData {
	return upstreamRequestData{
		Transport: transport,
		URL:       RedactUpstreamURL(req.URL),
		Method:    req.Method,
		Headers:   RedactHeaders(req.Headers),
		Provider:  req.Provider,
		AuthID:    req.AuthID,
		AuthLabel: req.AuthLabel,
		AuthType:  req.AuthType,
	}
}

// TapUpstreamRequest records an outbound HTTP request as a new sub-attempt.
func TapUpstreamRequest(ctx context.Context, req UpstreamRequest) {
	if Current() == nil {
		return
	}
	defer recoverTap("upstream.request")
	in, a := tapTarget(ctx)
	if a == nil {
		return
	}
	now := time.Now()
	seq, sub := a.nextRequest(now, AttemptInfo{AuthID: req.AuthID, Provider: req.Provider})
	a.notePrevious(req.Body)
	data := newUpstreamRequestData("http", req)
	in.emitBody(&Event{Type: TypeUpstreamRequest, Time: now, AttemptSeq: seq, SubAttempt: &sub, Data: data, SizeHint: data.sizeHint()}, req.Body, true)
}

type upstreamResponseMetaData struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers,omitempty"`
}

// TapUpstreamResponse records the upstream status and headers.
func TapUpstreamResponse(ctx context.Context, status int, headers http.Header) {
	if Current() == nil {
		return
	}
	defer recoverTap("upstream.response")
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
}

// TapUpstreamChunk records one decompressed upstream event, or a whole
// non-streamed (or error) response body, exactly as the executor read it.
// Chunks are numbered per sub-attempt from 1; empty chunks (blank SSE lines)
// are numbered but not written.
func TapUpstreamChunk(ctx context.Context, chunk []byte) {
	if Current() == nil {
		return
	}
	defer recoverTap("upstream.event")
	in, a := tapTarget(ctx)
	if a == nil {
		return
	}
	now := time.Now()
	seq, sub, n := a.nextChunk(now)
	if len(chunk) == 0 {
		return
	}
	in.emitBody(&Event{Type: TypeUpstreamEvent, Time: now, AttemptSeq: seq, SubAttempt: &sub, Data: upstreamEventData{ChunkSeq: n}}, chunk, true)
	a.inspect(chunk, now, seq, sub)
}

type upstreamErrorData struct {
	Class string `json:"class"`
	Error string `json:"error,omitempty"`
}

// TapUpstreamError records an error with no HTTP response (a transport
// error, or a failure reading the body). Its text is redacted.
func TapUpstreamError(ctx context.Context, err error) {
	if Current() == nil || err == nil {
		return
	}
	defer recoverTap("upstream.error")
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
	if Current() == nil {
		return
	}
	defer recoverTap("upstream.ws.request")
	in, a := tapTarget(ctx)
	if a == nil {
		return
	}
	now := time.Now()
	seq, sub := a.nextRequest(now, AttemptInfo{AuthID: req.AuthID, Provider: req.Provider})
	a.notePrevious(req.Body)
	data := upstreamWSData{
		WSEvent: WSEventRequest, URL: RedactUpstreamURL(req.URL), Headers: RedactHeaders(req.Headers),
		Provider: req.Provider, AuthID: req.AuthID, AuthLabel: req.AuthLabel, AuthType: req.AuthType,
	}
	in.emitBody(&Event{Type: TypeUpstreamWS, Time: now, AttemptSeq: seq, SubAttempt: &sub, Data: data, SizeHint: data.sizeHint()}, req.Body, true)
}

// TapUpstreamWSHandshake records the upstream handshake's status and headers.
func TapUpstreamWSHandshake(ctx context.Context, status int, headers http.Header) {
	if Current() == nil {
		return
	}
	defer recoverTap("upstream.ws.handshake")
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
	if Current() == nil {
		return
	}
	defer recoverTap("upstream.ws.rejection")
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
	in.emitBody(&Event{Type: TypeUpstreamWS, Time: now, AttemptSeq: seq, SubAttempt: &sub, Data: data, SizeHint: data.sizeHint()}, body, true)
}

// TapUpstreamWSError records an upstream WebSocket error at a stage (dial,
// send, read, ...). Its text is redacted.
func TapUpstreamWSError(ctx context.Context, stage string, err error) {
	if Current() == nil || err == nil {
		return
	}
	defer recoverTap("upstream.ws.error")
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
	if Current() == nil {
		return
	}
	defer recoverTap("upstream.ws.frame")
	in, a := tapTarget(ctx)
	if a == nil {
		return
	}
	now := time.Now()
	seq, sub, n := a.nextFrame(now)
	data := upstreamWSData{WSEvent: WSEventResponse, FrameSeq: n, Trimmed: trimmed}
	in.emitBody(&Event{Type: TypeUpstreamWS, Time: now, AttemptSeq: seq, SubAttempt: &sub, Data: data, SizeHint: data.sizeHint()}, payload, true)
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
// object; anything else is ignored.
func TapUsage(ctx context.Context, source, model string, raw []byte) {
	if Current() == nil {
		return
	}
	defer recoverTap("usage")
	in, a := tapTarget(ctx)
	if a == nil || !gjson.ValidBytes(raw) || !gjson.ParseBytes(raw).IsObject() {
		return
	}
	now := time.Now()
	seq, sub := a.current(now)
	data := usageData{Source: source, Model: model, Usage: bytes.Clone(raw)}
	in.Emit(&Event{Type: TypeUsage, Time: now, AttemptSeq: seq, SubAttempt: &sub, Capture: CaptureFull, Data: data, SizeHint: int64(len(raw)) + stringsSize(source, model)})
}

// notePrevious records previous_response_id from an outbound body.
func (a *Attempt) notePrevious(body []byte) {
	if !bytes.Contains(body, []byte(`"previous_response_id"`)) {
		return
	}
	if prev := gjson.GetBytes(body, "previous_response_id"); prev.Type == gjson.String {
		a.noteIDs(identities{PreviousResponseID: prev.String()})
	}
}

// inspect reads raw usage and identities from an upstream event or body:
// Anthropic message_start/message_delta/content_block_start, Responses
// response.* and output items, and non-streamed JSON bodies. It parses only
// chunks that can carry them.
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
	root := gjson.ParseBytes(data)
	var found identities
	var usage gjson.Result
	var model string
	event := root.Get("type").String()
	switch event {
	case "message_start":
		message := root.Get("message")
		found.addResponse(message.Get("id").String())
		usage, model = message.Get("usage"), message.Get("model").String()
	case "message_delta":
		usage = root.Get("usage")
	case "content_block_start":
		found.addItem(root.Get("content_block.id").String())
	case "response.created", "response.in_progress", "response.completed", "response.done",
		"response.failed", "response.incomplete":
		response := root.Get("response")
		found.addResponse(response.Get("id").String())
		found.PreviousResponseID = response.Get("previous_response_id").String()
		usage, model = response.Get("usage"), response.Get("model").String()
	case "response.output_item.added", "response.output_item.done":
		item := root.Get("item")
		found.addItem(item.Get("id").String())
		found.addItem(item.Get("call_id").String())
	case "message":
		// A non-streamed Anthropic Messages body.
		found.addResponse(root.Get("id").String())
		usage, model = root.Get("usage"), root.Get("model").String()
		root.Get("content").ForEach(func(_, block gjson.Result) bool {
			found.addItem(block.Get("id").String())
			return true
		})
		event = "body"
	default:
		switch {
		case root.Get("object").String() == "response":
			// A non-streamed Responses body.
			found.addResponse(root.Get("id").String())
			found.PreviousResponseID = root.Get("previous_response_id").String()
			usage, model = root.Get("usage"), root.Get("model").String()
			root.Get("output").ForEach(func(_, item gjson.Result) bool {
				found.addItem(item.Get("id").String())
				found.addItem(item.Get("call_id").String())
				return true
			})
			event = "body"
		case root.Get("usageMetadata").IsObject():
			// Gemini.
			found.addResponse(root.Get("responseId").String())
			usage, model = root.Get("usageMetadata"), root.Get("modelVersion").String()
			if event == "" {
				event = "usageMetadata"
			}
		case root.Get("usage").IsObject():
			// Chat Completions and other bodies or chunks with top-level usage.
			found.addResponse(root.Get("id").String())
			usage, model = root.Get("usage"), root.Get("model").String()
			if event == "" {
				event = "body"
			}
		}
	}
	a.noteIDs(found)
	if !usage.IsObject() {
		return
	}
	raw := []byte(usage.Raw)
	payload := usageData{Source: "upstream", Event: event, Model: model, Usage: raw}
	a.in.Emit(&Event{Type: TypeUsage, Time: now, AttemptSeq: seq, SubAttempt: &sub, Capture: CaptureFull, Data: payload,
		SizeHint: int64(len(raw)) + stringsSize(payload.Source, payload.Event, payload.Model)})
}

// EmitDownstream records one write of a response body to the client (what
// the client receives, before compression) as a downstream_event.
func EmitDownstream(in *Ingress, now time.Time, data any, body []byte) {
	if in == nil {
		return
	}
	in.emitBody(&Event{Type: TypeDownstreamEvent, Time: now, Data: data, SizeHint: 32}, body, true)
}

// EmitClientFrame records a WebSocket frame between the client and the proxy
// (a client_ws_frame); data carries its direction and message type.
func EmitClientFrame(in *Ingress, now time.Time, data any, sizeHint int64, payload []byte) {
	if in == nil {
		return
	}
	in.emitBody(&Event{Type: TypeClientWSFrame, Time: now, Data: data, SizeHint: sizeHint}, payload, true)
}

// emitBody queues ev carrying a copy of body. While bodies are not captured
// (low space, or the recorder is stopping), the event is still queued,
// without its body, as dropped_body, and the drop counts against the request.
func (in *Ingress) emitBody(ev *Event, body []byte, hasBody bool) {
	if !hasBody {
		ev.Capture = CaptureFull
		in.Emit(ev)
		return
	}
	rec := in.rec
	if !rec.CaptureBodies() {
		if rec.acceptsEvents() {
			reason := rec.BodyDropReason()
			rec.CountDrop(reason, DropCount{Bodies: 1, Bytes: int64(len(body))})
			in.NoteDrop()
			ev.Capture = CaptureDroppedBody
			ev.BodyDropped = reason
		}
		// When events are refused too, Emit drops and counts the event.
		in.Emit(ev)
		return
	}
	data := bytes.Clone(body)
	if data == nil {
		data = []byte{}
	}
	ev.Capture = CaptureFull
	ev.Body = &BodyData{Bytes: data}
	in.Emit(ev)
}

func headersSize(h map[string][]string) int64 {
	var n int64
	for name, values := range h {
		n += int64(len(name)) + 8 + stringsSize(values...)
	}
	return n
}
