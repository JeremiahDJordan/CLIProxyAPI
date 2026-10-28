package archive

import (
	"context"
	"sync/atomic"
	"time"
)

// RouteClass decides what is captured for a route (design section 1).
type RouteClass string

const (
	// RouteInference routes are captured in full: headers and bodies.
	RouteInference RouteClass = "inference"
	// RouteMetadataOnly routes keep time, method, path, query parameter
	// names, status, client address and auth decision; no headers or bodies.
	RouteMetadataOnly RouteClass = "metadata_only"
)

// Ingress is one client request. It travels in the request context so later
// taps (outbound requests, attempts, usage) attach their events to the same
// ingress_id.
type Ingress struct {
	rec     *Recorder
	id      string
	class   RouteClass
	started time.Time
	drops   atomic.Int64
}

// BeginIngress allocates an ingress with a fresh UUIDv7.
func (r *Recorder) BeginIngress(class RouteClass, started time.Time) *Ingress {
	if r == nil {
		return nil
	}
	return &Ingress{rec: r, id: NewID(), class: class, started: started}
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
// as emit does. It fails once Stop has begun.
func (in *Ingress) ReserveEvent(ev *Event) (int64, bool) {
	if in == nil || in.rec == nil || ev == nil {
		return 0, false
	}
	r := in.rec
	n := ev.reservation()
	if r.CaptureEvents() && r.q.reserve(n) {
		return n, true
	}
	reason := DropQueueFull
	if !r.CaptureEvents() {
		reason = r.BodyDropReason()
	}
	r.ledger.add(reason, DropCount{Events: 1})
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

// IngressFromContext returns the ingress carried by ctx, or nil.
func IngressFromContext(ctx context.Context) *Ingress {
	if ctx == nil {
		return nil
	}
	in, _ := ctx.Value(ingressContextKey{}).(*Ingress)
	return in
}
