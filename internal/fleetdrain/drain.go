// Package fleetdrain counts the proxy work in flight so a restart can wait for
// a quiet moment, and lets the server drain that work when it stops (fleet fork).
//
// A Tracker belongs to one API server. It travels in each request's context so
// the Responses WebSocket handler can count its turns and close when draining.
// Every method is safe on a nil Tracker: nothing is counted and it never drains.
package fleetdrain

import (
	"context"
	"sync"
)

// Activity is a snapshot of the work in flight.
type Activity struct {
	// Requests counts HTTP requests being served, excluding WebSocket upgrades
	// and the activity route itself.
	Requests int `json:"requests"`
	// WebSockets counts open Responses WebSocket connections.
	WebSockets int `json:"websockets"`
	// WebSocketTurns counts Responses WebSocket requests being answered.
	WebSocketTurns int `json:"websocket_turns"`
	// Draining reports that the server has stopped accepting work.
	Draining bool `json:"draining"`
	// Quiet means no request or WebSocket turn is in flight; idle WebSockets
	// may remain open, and clients reconnect them on their next turn.
	Quiet bool `json:"quiet"`
}

// Tracker counts work in flight for one server.
type Tracker struct {
	mu       sync.Mutex
	requests int
	sockets  int
	turns    int
	draining bool
	drain    chan struct{}
	// changed is closed and replaced whenever work finishes, waking Wait.
	changed chan struct{}
}

// New returns an empty Tracker.
func New() *Tracker {
	return &Tracker{drain: make(chan struct{}), changed: make(chan struct{})}
}

type contextKey struct{}

// WithTracker returns ctx carrying t.
func WithTracker(ctx context.Context, t *Tracker) context.Context {
	return context.WithValue(ctx, contextKey{}, t)
}

// FromContext returns the Tracker in ctx, or nil.
func FromContext(ctx context.Context) *Tracker {
	if ctx == nil {
		return nil
	}
	t, _ := ctx.Value(contextKey{}).(*Tracker)
	return t
}

// BeginRequest counts one HTTP request until the returned function is called.
func (t *Tracker) BeginRequest() func() {
	if t == nil {
		return func() {}
	}
	return t.begin(&t.requests)
}

// BeginWebSocket counts one open Responses WebSocket until the returned function is called.
func (t *Tracker) BeginWebSocket() func() {
	if t == nil {
		return func() {}
	}
	return t.begin(&t.sockets)
}

// BeginTurn counts one Responses WebSocket turn until the returned function is called.
func (t *Tracker) BeginTurn() func() {
	if t == nil {
		return func() {}
	}
	return t.begin(&t.turns)
}

func (t *Tracker) begin(counter *int) func() {
	t.mu.Lock()
	*counter++
	t.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			*counter--
			close(t.changed)
			t.changed = make(chan struct{})
			t.mu.Unlock()
		})
	}
}

// Draining returns a channel closed once draining starts; nil for a nil Tracker.
func (t *Tracker) Draining() <-chan struct{} {
	if t == nil {
		return nil
	}
	return t.drain
}

// IsDraining reports whether draining has started.
func (t *Tracker) IsDraining() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.draining
}

// StartDrain marks the server as draining; idle WebSockets close and busy ones
// close after their current turn. It is idempotent.
func (t *Tracker) StartDrain() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.draining {
		t.draining = true
		close(t.drain)
	}
}

// Snapshot returns the current activity.
func (t *Tracker) Snapshot() Activity {
	if t == nil {
		return Activity{Quiet: true}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return Activity{
		Requests:       t.requests,
		WebSockets:     t.sockets,
		WebSocketTurns: t.turns,
		Draining:       t.draining,
		Quiet:          t.requests == 0 && t.turns == 0,
	}
}

// Wait blocks until no request, WebSocket turn or WebSocket remains, or ctx ends.
func (t *Tracker) Wait(ctx context.Context) error {
	if t == nil {
		return nil
	}
	for {
		t.mu.Lock()
		idle := t.requests == 0 && t.turns == 0 && t.sockets == 0
		changed := t.changed
		t.mu.Unlock()
		if idle {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
