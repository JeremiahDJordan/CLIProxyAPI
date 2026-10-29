package archive

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// GinIngressKey carries the *Ingress on the gin context too, so taps given
// a context built from context.Background() plus "gin" (most handlers) find
// it. A WebSocket turn's ingress is carried in its own execution context.
const GinIngressKey = "fleet.archive.ingress"

// RouteClass decides what is captured for a route (design section 1).
type RouteClass string

const (
	// RouteInference routes are captured in full: headers and bodies.
	RouteInference RouteClass = "inference"
	// RouteMetadataOnly routes keep time, method, path, query parameter
	// names, status, client address and auth decision; no headers or bodies.
	RouteMetadataOnly RouteClass = "metadata_only"
)

// Ingress is one client request, or one WebSocket turn. It travels in the
// request context so later taps (outbound requests, attempts, usage) attach
// their events to the same ingress_id.
type Ingress struct {
	rec     *Recorder
	id      string
	class   RouteClass
	started time.Time
	drops   atomic.Int64

	// Set when the ingress is created; immutable afterwards.
	kind         string
	connectionID string
	turnSeq      uint32

	turns      atomic.Uint32 // turn_seq of the connection's last turn
	attempts   atomic.Uint32 // attempt_seq of the last attempt
	firstToken atomic.Int64  // first content-bearing downstream write (Unix ns)

	mu        sync.Mutex
	open      []*Attempt // attempts that have begun and not ended
	implicit  *Attempt   // for taps outside any conductor attempt
	gateCode  string
	clientKey string
	ids       identities
}

// BeginIngress allocates an HTTP ingress with a fresh UUIDv7.
func (r *Recorder) BeginIngress(class RouteClass, started time.Time) *Ingress {
	if r == nil {
		return nil
	}
	return &Ingress{rec: r, id: NewID(), class: class, started: started, kind: KindHTTP}
}

// BeginConnection allocates the ingress of a WebSocket upgrade request. Its
// ingress_id is also the connection_id of the connection's turns.
func (r *Recorder) BeginConnection(class RouteClass, started time.Time) *Ingress {
	in := r.BeginIngress(class, started)
	if in != nil {
		in.kind = KindWSConnection
		in.connectionID = in.id
	}
	return in
}

// BeginTurn allocates a WebSocket turn on conn and assigns its turn_seq, in
// the order turns are received.
func (r *Recorder) BeginTurn(conn *Ingress, started time.Time) *Ingress {
	if r == nil || conn == nil {
		return nil
	}
	return &Ingress{
		rec:          r,
		id:           NewID(),
		class:        RouteInference,
		started:      started,
		kind:         KindWSTurn,
		connectionID: conn.id,
		turnSeq:      conn.turns.Add(1),
	}
}

// Kind is http, ws_connection or ws_turn.
func (in *Ingress) Kind() string {
	if in == nil {
		return ""
	}
	return in.kind
}

// ConnectionID is the WebSocket connection's ingress_id, empty for HTTP.
func (in *Ingress) ConnectionID() string {
	if in == nil {
		return ""
	}
	return in.connectionID
}

// TurnSeq is the turn's order on its connection, zero for other kinds.
func (in *Ingress) TurnSeq() uint32 {
	if in == nil {
		return 0
	}
	return in.turnSeq
}

// ID is the ingress_id.
func (in *Ingress) ID() string {
	if in == nil {
		return ""
	}
	return in.id
}

// Class is the route class decided at ingress.
func (in *Ingress) Class() RouteClass {
	if in == nil {
		return RouteMetadataOnly
	}
	return in.class
}

// Started is when the request reached the proxy.
func (in *Ingress) Started() time.Time {
	if in == nil {
		return time.Time{}
	}
	return in.started
}

// Recorder returns the recorder that allocated the ingress.
func (in *Ingress) Recorder() *Recorder {
	if in == nil {
		return nil
	}
	return in.rec
}

// Emit queues an event for this ingress. A drop counts against the request.
func (in *Ingress) Emit(ev *Event) bool {
	return in.EmitReserved(ev, 0)
}

// EmitReserved queues an event whose body bytes were already reserved.
func (in *Ingress) EmitReserved(ev *Event, reserved int64) bool {
	if in == nil || in.rec == nil || ev == nil {
		return false
	}
	ev.IngressID = in.id
	if ev.ConnectionID == "" {
		ev.ConnectionID = in.connectionID
	}
	if ev.TurnSeq == 0 {
		ev.TurnSeq = in.turnSeq
	}
	ev.ingress = in
	if !in.rec.emit(ev, reserved) {
		in.drops.Add(1)
		return false
	}
	return true
}

// ReserveEvent claims ev's queue bytes now, for an event held until later
// (an ingress_end waiting for its client_body); EmitReserved then charges
// them to it. A failure drops the event and counts it against the request,
// as emit does. Like emit it still succeeds while Stop is finalizing: the
// held event is a request's final event, not a new capture.
func (in *Ingress) ReserveEvent(ev *Event) (int64, bool) {
	if in == nil || in.rec == nil || ev == nil {
		return 0, false
	}
	return in.reserve(ev.reservation(), DropCount{Events: 1})
}

// EmitCopying queues ev, reserving its size (ev.SizeHint, estimated from
// views of the input: BytesView) before copyData copies its fields into it,
// so an event the queue refuses copies nothing. Growth beyond the
// reservation is reserved when the event is queued; the reservation is
// returned if copyData panics.
func (in *Ingress) EmitCopying(ev *Event, copyData func(*Event)) bool {
	if in == nil || in.rec == nil || ev == nil {
		return false
	}
	reserved, ok := in.reserve(ev.reservation(), DropCount{Events: 1})
	if !ok {
		return false
	}
	defer func() {
		// Returned if the copy panics; queued events own their reservation.
		in.rec.q.release(reserved)
	}()
	_ = fault("tap.copy") // tests panic here
	copyData(ev)
	n := reserved
	reserved = 0
	return in.EmitReserved(ev, n)
}

// reserve claims n queue bytes for an event of this request before its
// contents are copied. A failure counts d as dropped, against the request
// too, as emit does.
func (in *Ingress) reserve(n int64, d DropCount) (int64, bool) {
	r := in.rec
	acceptsEvents := r.acceptsEvents()
	if acceptsEvents && r.q.reserve(n) {
		return n, true
	}
	reason := DropQueueFull
	if !acceptsEvents {
		reason = r.BodyDropReason()
	}
	r.ledger.add(reason, d)
	in.drops.Add(1)
	return 0, false
}

// NoteDrop counts a body or event of this request that was not captured.
func (in *Ingress) NoteDrop() {
	if in != nil {
		in.drops.Add(1)
	}
}

// Drops is the number of this request's events or bodies not captured so far.
func (in *Ingress) Drops() int64 {
	if in == nil {
		return 0
	}
	return in.drops.Load()
}

type ingressContextKey struct{}

// WithIngress returns ctx carrying in.
func WithIngress(ctx context.Context, in *Ingress) context.Context {
	if in == nil {
		return ctx
	}
	return context.WithValue(ctx, ingressContextKey{}, in)
}

// WithoutIngress returns ctx carrying no ingress, also when a parent context
// (or its gin context) carries one: a WebSocket turn that is not recorded
// must not have its traffic recorded on its connection.
func WithoutIngress(ctx context.Context) context.Context {
	return context.WithValue(ctx, ingressContextKey{}, (*Ingress)(nil))
}

// IngressFromContext returns the ingress carried by ctx, or else by the gin
// context ctx carries under "gin", or nil.
func IngressFromContext(ctx context.Context) *Ingress {
	if ctx == nil {
		return nil
	}
	if in, ok := ctx.Value(ingressContextKey{}).(*Ingress); ok {
		return in
	}
	if g, ok := ctx.Value("gin").(*gin.Context); ok && g != nil {
		if value, found := g.Get(GinIngressKey); found {
			in, _ := value.(*Ingress)
			return in
		}
	}
	return nil
}

// NoteGate records the fleet gate's decision code for the request.
func (in *Ingress) NoteGate(code string) {
	if in == nil || code == "" {
		return
	}
	in.mu.Lock()
	in.gateCode = code
	in.mu.Unlock()
}

// SetClientKey records the configured name of the client key that
// authenticated the request (never the key or a digest of it).
func (in *Ingress) SetClientKey(name string) {
	if in == nil || name == "" {
		return
	}
	in.mu.Lock()
	in.clientKey = name
	in.mu.Unlock()
}

// NoteFirstToken records the first content-bearing downstream write.
func (in *Ingress) NoteFirstToken(at time.Time) {
	if in != nil {
		in.firstToken.CompareAndSwap(0, at.UnixNano())
	}
}

// Summary is what an ingress_end reports beyond the transport: gate and
// client key, identities from the upstream exchange, first token time and
// the number of attempts.
type Summary struct {
	GateCode     string `json:"gate_code,omitempty"`
	ClientKey    string `json:"client_key,omitempty"`
	Attempts     uint32 `json:"attempts"`
	FirstTokenAt string `json:"first_token_at,omitempty"`
	identities
}

// Summary snapshots the request's summary.
func (in *Ingress) Summary() Summary {
	if in == nil {
		return Summary{}
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	sum := Summary{GateCode: in.gateCode, ClientKey: in.clientKey, Attempts: in.attempts.Load(), identities: in.ids.clone()}
	if first := in.firstToken.Load(); first != 0 {
		sum.FirstTokenAt = FormatTime(time.Unix(0, first))
	}
	return sum
}

// SizeHint estimates the summary's encoded size for queue reservations.
func (s Summary) SizeHint() int64 {
	return stringsSize(s.GateCode, s.ClientKey, s.FirstTokenAt) + s.identities.sizeHint()
}

func stringsSize(values ...string) int64 {
	var n int64
	for _, value := range values {
		n += int64(len(value)) + 4
	}
	return n
}
