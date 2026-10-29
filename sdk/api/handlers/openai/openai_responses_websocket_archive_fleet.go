package openai

// Fleet fork: request archive capture of Responses WebSockets (design
// sections 3 and 5 in the fleet repository's PROXY-REQUEST-ARCHIVE-DESIGN.md).
// The upgrade request is the ws_connection ingress, recorded by the transport
// observer; every frame the client sends is a ws_turn with its own ingress_id
// and turn_seq, allocated by the reader as the frame arrives, before any check,
// so turns answered locally (interrupts, stale epochs, denials, prewarms) are
// recorded too. The turn travels in WebsocketInput and is attached to that
// turn's execution context, never to the gin context shared by every turn.

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/archive"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// Turn outcomes recorded in a ws_turn's ingress_end.
const (
	wsTurnCompleted        = "completed"
	wsTurnUpstreamError    = "upstream_error"
	wsTurnForwardError     = "forward_error"
	wsTurnRequestError     = "request_error"
	wsTurnAuthDenied       = "auth_denied"
	wsTurnStaleEpoch       = "stale_epoch"
	wsTurnPrewarm          = "prewarm_local"
	wsTurnInterruptPrefix  = "interrupt_"
	wsTurnDrainDropped     = "drain_dropped"
	wsTurnNotAdmitted      = "not_admitted"
	wsTurnConnectionClosed = "connection_closed"
	wsTurnReplayRequired   = "replay_required"
)

// responsesWebsocketArchive records one connection's turns and frames. It is
// nil when capture is off or when the upgrade request was not recorded as an
// inference connection. With response steering on for the connection it
// records nothing (steering): it only detaches each turn's execution from
// the connection's ingress, so no turn traffic is recorded on the connection.
type responsesWebsocketArchive struct {
	rec          *archive.Recorder
	conn         *archive.Ingress
	steering     bool
	sessionID    string // the handler's session id, as logged
	headerTurnID string // x-codex-turn-metadata of the upgrade request: a fallback only

	current   atomic.Pointer[responsesWebsocketTurn] // the turn being answered
	interrupt atomic.Pointer[responsesWebsocketTurn] // the interrupt being forwarded

	mu   sync.Mutex
	open map[*responsesWebsocketTurn]struct{}
}

var steeringCaptureWarned atomic.Bool

func newResponsesWebsocketArchive(c *gin.Context, sessionID string, steering bool) (a *responsesWebsocketArchive) {
	if !archive.Installed() || c == nil || c.Request == nil {
		return nil
	}
	var conn *archive.Ingress
	defer recoverWebsocketArchiveFor("ws.open", &conn)
	conn = archive.IngressFromContext(c.Request.Context())
	if conn == nil || conn.Kind() != archive.KindWSConnection || conn.Class() != archive.RouteInference {
		return nil
	}
	if steering {
		// The steering guard: the duplex executor reads later frames itself
		// and its events are not tagged per turn yet, so this connection's
		// turns are not recorded (counted as a gap, and against the
		// connection, whose ingress_end must not look complete). Capture
		// refuses to start with steering on; this covers it being turned on
		// by a reload.
		conn.Recorder().CountDrop(archive.DropSteeringTurns, archive.DropCount{Events: 1})
		conn.NoteDrop()
		if steeringCaptureWarned.CompareAndSwap(false, true) {
			log.Warn("request archive: codex.response-steering is on; WebSocket turns of steering connections are not recorded")
		}
		return &responsesWebsocketArchive{conn: conn, steering: true}
	}
	var scratch archive.JSONScratch
	return &responsesWebsocketArchive{
		rec:          conn.Recorder(),
		conn:         conn,
		sessionID:    sessionID,
		headerTurnID: strings.Clone(boundedWSTurnField(archiveCodexTurnIDFromMetadata(c.Request.Header.Get("X-Codex-Turn-Metadata"), &scratch))),
		open:         map[*responsesWebsocketTurn]struct{}{},
	}
}

// recoverWebsocketArchiveFor contains a panic in a step recording on *in
// (nil until the step has found it): a recovered panic loses what it was
// recording, so *in counts a drop too.
func recoverWebsocketArchiveFor(where string, in **archive.Ingress) {
	if recovered := recover(); recovered != nil {
		archive.NoteTapPanic(where, recovered)
		if in != nil {
			(*in).NoteDrop()
		}
	}
}

// responsesWebsocketTurn is one client frame and what answered it.
type responsesWebsocketTurn struct {
	a  *responsesWebsocketArchive
	in *archive.Ingress

	mu        sync.Mutex
	ended     bool
	tracked   bool
	outcome   string
	status    int
	framesOut int64
	bytesOut  int64
}

type wsTurnStartData struct {
	Kind               string `json:"kind"`
	MessageType        string `json:"message_type"`
	FrameType          string `json:"frame_type,omitempty"`
	Model              string `json:"model,omitempty"`
	PreviousResponseID string `json:"previous_response_id,omitempty"`
	CodexTurnID        string `json:"codex_turn_id,omitempty"`
	CodexTurnIDSource  string `json:"codex_turn_id_source,omitempty"`
	WSSessionID        string `json:"ws_session_id,omitempty"`
}

type wsFrameData struct {
	Direction   string `json:"direction"`
	MessageType string `json:"message_type"`
	WriteError  string `json:"write_error,omitempty"`
}

type wsTurnEndData struct {
	Kind       string `json:"kind"`
	Ended      string `json:"ended"`
	Outcome    string `json:"outcome,omitempty"`
	Status     int    `json:"status,omitempty"`
	FramesOut  int64  `json:"frames_out"`
	BytesOut   int64  `json:"bytes_out"`
	DurationUS int64  `json:"duration_us"`
	archive.Summary
}

func websocketMessageTypeName(kind int) string {
	if kind == websocket.BinaryMessage {
		return "binary"
	}
	return "text"
}

// Longest frame_type, model, previous_response_id and codex_turn_id a
// turn's ingress_start keeps; longer values are dropped (the frame itself is
// recorded byte for byte).
const wsTurnFieldMax = 256

// wsTurnMetadataMax bounds the client_metadata x-codex-turn-metadata string
// a frame's turn ID is read from (a longer one is ignored); it is JSON in a
// JSON string, so it is read unescaped into a scratch buffer.
const wsTurnMetadataMax = 8 << 10

// beginTurn allocates a turn for a frame read from the client and records
// its ingress_start and the frame itself (before tool-call repair or any
// other rewriting). The frame's fields are read through a view of it, not a
// copy, and copied only once the ingress_start is reserved, so a frame the
// queue refuses costs nothing of its size.
func (a *responsesWebsocketArchive) beginTurn(kind int, payload []byte) (t *responsesWebsocketTurn) {
	if a == nil || a.steering {
		return nil
	}
	var in *archive.Ingress
	defer recoverWebsocketArchiveFor("ws.turn", &in)
	if !a.rec.CaptureEvents() {
		// Low space, a failed writer or Stop: the turn is not recorded,
		// which counts against its connection too.
		a.rec.CountDrop(a.rec.BodyDropReason(), archive.DropCount{Events: 1})
		a.conn.NoteDrop()
		return nil
	}
	now := time.Now()
	in = a.rec.BeginTurn(a.conn, now)
	t = &responsesWebsocketTurn{a: a, in: in}
	data := wsTurnStartData{Kind: archive.KindWSTurn, MessageType: websocketMessageTypeName(kind), WSSessionID: a.sessionID}
	if gjson.ValidBytes(payload) {
		// Views of payload, or of a scratch each for escaped values, until
		// copied below: JSONText copies nothing (gjson would unescape a
		// large string in full).
		var typeScratch, modelScratch, prevScratch, metadataScratch, turnScratch archive.JSONScratch
		frame := archive.BytesView(payload)
		data.FrameType = archive.JSONText(frame, wsTurnFieldMax, &typeScratch, "type")
		data.Model = archive.JSONText(frame, wsTurnFieldMax, &modelScratch, "model")
		data.PreviousResponseID = archive.JSONText(frame, wsTurnFieldMax, &prevScratch, "previous_response_id")
		// The turn ID comes from the frame's client_metadata; the upgrade
		// header is set once per connection and is only a fallback.
		metadata := archive.JSONText(frame, wsTurnMetadataMax, &metadataScratch, "client_metadata", "x-codex-turn-metadata")
		data.CodexTurnID = archiveCodexTurnIDFromMetadata(metadata, &turnScratch)
		if data.CodexTurnID != "" {
			data.CodexTurnIDSource = "frame"
		}
	}
	if data.CodexTurnID == "" && a.headerTurnID != "" {
		data.CodexTurnID, data.CodexTurnIDSource = a.headerTurnID, "header"
	}
	ev := &archive.Event{Type: archive.TypeIngressStart, Time: now, Capture: archive.CaptureFull,
		SizeHint: int64(len(data.FrameType)+len(data.Model)+len(data.PreviousResponseID)+len(data.CodexTurnID)+len(data.WSSessionID)) + 64}
	in.EmitCopying(ev, func(ev *archive.Event) {
		data.FrameType = strings.Clone(data.FrameType)
		data.Model = strings.Clone(data.Model)
		data.PreviousResponseID = strings.Clone(data.PreviousResponseID)
		data.CodexTurnID = strings.Clone(data.CodexTurnID)
		ev.Data = data
	})
	archive.EmitClientFrame(in, now, wsFrameData{Direction: "in", MessageType: data.MessageType}, 16, payload)
	a.mu.Lock()
	a.open[t] = struct{}{}
	a.mu.Unlock()
	t.mu.Lock()
	t.tracked = a.rec.TrackObserver(t)
	t.mu.Unlock()
	return t
}

// boundedWSTurnField drops a value longer than wsTurnFieldMax.
func boundedWSTurnField(value string) string {
	if len(value) > wsTurnFieldMax {
		return ""
	}
	return value
}

// note records the turn's outcome; the last one noted wins.
func (t *responsesWebsocketTurn) note(outcome string, status int) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.outcome = outcome
	if status != 0 {
		t.status = status
	}
	t.mu.Unlock()
}

// noteError records an error answer and, for a fleet denial, its gate code.
func (t *responsesWebsocketTurn) noteError(outcome string, errMsg *interfaces.ErrorMessage) {
	if t == nil {
		return
	}
	in := t.in
	defer recoverWebsocketArchiveFor("ws.note", &in)
	status := http.StatusInternalServerError
	if errMsg != nil && errMsg.StatusCode > 0 {
		status = errMsg.StatusCode
	}
	t.note(outcome, status)
	if errMsg != nil && errMsg.Error != nil {
		if code, _, found := strings.Cut(errMsg.Error.Error(), ":"); found && wsArchiveGateCode.MatchString(code) {
			t.in.NoteGate(code)
		}
	}
}

var wsArchiveGateCode = regexp.MustCompile(`^fleet_[a-z_]{1,48}$`)

// noteClientKey records the configured name of the key the turn's
// authentication accepted.
func (t *responsesWebsocketTurn) noteClientKey(c *gin.Context) {
	if t == nil || c == nil {
		return
	}
	in := t.in
	defer recoverWebsocketArchiveFor("ws.note", &in)
	if value, ok := c.Get("accessMetadata"); ok {
		if meta, okMeta := value.(map[string]string); okMeta {
			t.in.SetClientKey(meta["fleet_key"])
		}
	}
}

// turnContext attaches turn to its execution context. A turn that is not
// recorded (nil, and every turn of a steering connection) is detached from
// its connection, whose ingress the context also carries, so its traffic is
// not recorded there.
func (a *responsesWebsocketArchive) turnContext(t *responsesWebsocketTurn, ctx context.Context) context.Context {
	if a == nil {
		return ctx
	}
	if t == nil {
		return archive.WithoutIngress(ctx)
	}
	return archive.WithIngress(ctx, t.in)
}

// end queues the turn's ingress_end, once, after closing its open attempts.
// A turn ended by Stop (ended shutdown) counts a drop: what it does
// afterwards is not recorded.
func (t *responsesWebsocketTurn) end(ended string) {
	if t == nil {
		return
	}
	in := t.in
	defer recoverWebsocketArchiveFor("ws.turn.end", &in)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ended {
		return
	}
	t.ended = true
	now := time.Now()
	attempts := archive.AttemptEndedRequestEnd
	if ended == archiveTurnEndedShutdown {
		attempts = archive.AttemptEndedShutdown
		t.in.NoteDrop()
	}
	t.in.CloseAttempts(attempts)
	data := wsTurnEndData{
		Kind: archive.KindWSTurn, Ended: ended, Outcome: t.outcome, Status: t.status,
		FramesOut: t.framesOut, BytesOut: t.bytesOut, DurationUS: now.Sub(t.in.Started()).Microseconds(),
		Summary: t.in.Summary(),
	}
	t.in.Emit(&archive.Event{Type: archive.TypeIngressEnd, Time: now, Capture: archive.CaptureFull, Data: data, ReportDrops: true,
		SizeHint: int64(len(data.Outcome)+len(data.Ended)) + data.Summary.SizeHint() + 64})
	t.a.mu.Lock()
	delete(t.a.open, t)
	t.a.mu.Unlock()
	if t.tracked {
		t.tracked = false
		t.a.rec.UntrackObserver(t)
	}
}

// Turn end reasons (ingress_end's ended).
const (
	archiveTurnEnded         = "turn_end"
	archiveTurnEndedShutdown = "shutdown"
)

// FinalizeAtStop ends a turn still open when Stop's wait ends.
func (t *responsesWebsocketTurn) FinalizeAtStop() {
	t.end(archiveTurnEndedShutdown)
}

// take makes t the turn being answered and returns the function that ends
// it with the admission's own end.
func (a *responsesWebsocketArchive) take(t *responsesWebsocketTurn, endAdmission func()) func() {
	if a == nil || t == nil {
		return endAdmission
	}
	a.current.Store(t)
	return func() {
		if endAdmission != nil {
			endAdmission()
		}
		a.current.CompareAndSwap(t, nil)
		t.end(archiveTurnEnded)
	}
}

// closeTurns ends the turns the handler never took (still queued when the
// connection closed). The reader has stopped by then.
func (a *responsesWebsocketArchive) closeTurns() {
	if a == nil || a.steering {
		return
	}
	a.mu.Lock()
	open := make([]*responsesWebsocketTurn, 0, len(a.open))
	for t := range a.open {
		open = append(open, t)
	}
	a.mu.Unlock()
	for _, t := range open {
		t.mu.Lock()
		if t.outcome == "" {
			t.outcome = wsTurnConnectionClosed
		}
		t.mu.Unlock()
		t.end(archiveTurnEnded)
	}
}

// downstream records a frame written to the client, after restoration, on
// the turn being answered (or the connection between turns).
func (a *responsesWebsocketArchive) downstream(kind int, payload []byte, errWrite error) {
	a.downstreamFor(nil, kind, payload, errWrite)
}

// downstreamFor records a frame written to the client on turn, or, when turn
// is nil, as downstream does.
func (a *responsesWebsocketArchive) downstreamFor(turn *responsesWebsocketTurn, kind int, payload []byte, errWrite error) {
	if a == nil || a.steering {
		return
	}
	var target *archive.Ingress
	defer recoverWebsocketArchiveFor("ws.downstream", &target)
	target = a.conn
	t := turn
	if t == nil {
		t = a.current.Load()
	}
	if t != nil {
		target = t.in
		t.mu.Lock()
		t.framesOut++
		t.bytesOut += int64(len(payload))
		t.mu.Unlock()
	}
	data := wsFrameData{Direction: "out", MessageType: websocketMessageTypeName(kind)}
	if errWrite != nil {
		data.WriteError = archive.ErrorClass(errWrite)
	}
	archive.EmitClientFrame(target, time.Now(), data, 48, payload)
}

// interruptContext attaches the interrupt being forwarded, so its upstream
// frames are recorded on its own turn.
func (a *responsesWebsocketArchive) interruptContext(ctx context.Context) context.Context {
	if a == nil {
		return ctx
	}
	return a.turnContext(a.interrupt.Load(), ctx)
}

// forwardingInterrupt marks t as the interrupt being forwarded until done.
func (a *responsesWebsocketArchive) forwardingInterrupt(t *responsesWebsocketTurn) (done func()) {
	if a == nil || t == nil {
		return func() {}
	}
	a.interrupt.Store(t)
	return func() { a.interrupt.CompareAndSwap(t, nil) }
}

// writeResponsesWebsocketErrorForTurn writes an error frame answering turn
// (a frame the reader answers itself, such as a rejected interrupt) and
// records it on that turn rather than on the turn being answered.
func writeResponsesWebsocketErrorForTurn(writer *responsesWebsocketWriter, errMsg *interfaces.ErrorMessage, turn *responsesWebsocketTurn) ([]byte, error) {
	payload, errBuild := buildResponsesWebsocketErrorPayload(errMsg)
	if errBuild != nil {
		return nil, errBuild
	}
	return payload, writeResponsesWebsocketPayloadForTurn(writer, nil, payload, time.Now(), turn)
}

// turnFromInput returns the turn a queued frame carries.
func turnFromInput(message cliproxyexecutor.WebsocketInput) *responsesWebsocketTurn {
	t, _ := message.Archive.(*responsesWebsocketTurn)
	return t
}

// archiveCodexTurnIDFromMetadata reads turn_id from Codex's
// x-codex-turn-metadata JSON string: a view of metadata, or of scratch when
// it is escaped (archive.JSONText).
func archiveCodexTurnIDFromMetadata(metadata string, scratch *archive.JSONScratch) string {
	if metadata == "" || !gjson.Valid(metadata) {
		return ""
	}
	return archive.JSONText(metadata, wsTurnFieldMax, scratch, "turn_id")
}
