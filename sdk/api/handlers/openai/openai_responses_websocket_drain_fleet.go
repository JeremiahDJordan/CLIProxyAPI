package openai

// Fleet fork: Responses WebSockets during a server drain (internal/api/drain_fleet.go).
// An idle socket closes at once and a busy one after its current turn, with 1012
// (service restart). Codex checks its cached socket before each turn and reconnects
// when it is closed, so the next turn reaches the next server process.

import (
	"context"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/fleetdrain"
)

const responsesWebsocketDrainCloseTimeout = time.Second

// responsesWebsocketReadHookForTest runs after the reader admits a frame.
var responsesWebsocketReadHookForTest func()

// responsesWebsocketAdmission coordinates the socket's reader with a drain. The
// reader admits every data frame the moment it is read, so a frame being parsed
// or queued is never mistaken for an idle socket. Frames read before the drain
// began are answered; a turn read after it is dropped (the client gets the 1012
// close and resends to the next process), while interrupts are still handled.
// The handler closes only while nothing admitted waits, and is woken whenever the
// reader finishes a frame itself. Each admitted frame counts as a turn until it
// is finished. Nil-safe.
type responsesWebsocketAdmission struct {
	mu      sync.Mutex
	tracker *fleetdrain.Tracker // nil when turns are not counted (steering mode)
	closing bool
	pending int      // admitted frames not yet taken by the handler or finished by the reader
	ends    []func() // their turn counts, in reader order
	changed chan struct{}
}

func newResponsesWebsocketAdmission(tracker *fleetdrain.Tracker) *responsesWebsocketAdmission {
	return &responsesWebsocketAdmission{tracker: tracker, changed: make(chan struct{}, 1)}
}

// admit counts a frame the reader has just read. ok is false once the socket is
// closing; afterDrain reports that the drain had already begun.
func (a *responsesWebsocketAdmission) admit() (afterDrain, ok bool) {
	if a == nil {
		return false, true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing {
		return false, false
	}
	a.pending++
	if a.tracker != nil {
		a.ends = append(a.ends, a.tracker.BeginTurn())
	}
	return a.tracker.IsDraining(), true
}

// changes wakes the handler when the reader has finished a frame itself.
func (a *responsesWebsocketAdmission) changes() <-chan struct{} {
	if a == nil {
		return nil
	}
	return a.changed
}

// unadmit ends the count of the frame the reader holds once it has finished it
// itself (an interrupt, or a turn dropped during a drain), and wakes the handler.
func (a *responsesWebsocketAdmission) unadmit() {
	if a == nil {
		return
	}
	a.mu.Lock()
	var end func()
	if a.pending > 0 {
		a.pending--
		if n := len(a.ends); n > 0 {
			end, a.ends = a.ends[n-1], a.ends[:n-1]
		}
	}
	a.mu.Unlock()
	if end != nil {
		end()
	}
	select {
	case a.changed <- struct{}{}:
	default:
	}
}

// take hands the oldest admitted frame's count to the handler, which ends it when
// the turn is done.
func (a *responsesWebsocketAdmission) take() func() {
	if a == nil {
		return func() {}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending > 0 {
		a.pending--
	}
	if len(a.ends) == 0 {
		return func() {}
	}
	end := a.ends[0]
	a.ends = a.ends[1:]
	return end
}

// closeIfIdle marks the socket closing when no admitted frame waits.
func (a *responsesWebsocketAdmission) closeIfIdle() bool {
	if a == nil {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending > 0 {
		return false
	}
	a.closing = true
	return true
}

// release ends every count still held, once the reader has stopped.
func (a *responsesWebsocketAdmission) release() {
	if a == nil {
		return
	}
	a.mu.Lock()
	ends := a.ends
	a.ends, a.pending, a.closing = nil, 0, true
	a.mu.Unlock()
	for _, end := range ends {
		end()
	}
}

// closeForDrain sends a best-effort 1012 close frame and closes the connection.
func (w *responsesWebsocketWriter) closeForDrain() error {
	if w == nil || w.conn == nil || !w.closing.CompareAndSwap(false, true) {
		return nil
	}
	if !w.writeMu.TryLock() {
		return w.conn.Close()
	}
	defer w.writeMu.Unlock()
	payload := websocket.FormatCloseMessage(websocket.CloseServiceRestart, "service restart")
	errWrite := w.conn.WriteControl(websocket.CloseMessage, payload, time.Now().Add(responsesWebsocketDrainCloseTimeout))
	errClose := w.conn.Close()
	if errWrite != nil {
		return errWrite
	}
	return errClose
}

type responsesWebsocketAdmissionKey struct{}

func withResponsesWebsocketAdmission(ctx context.Context, a *responsesWebsocketAdmission) context.Context {
	return context.WithValue(ctx, responsesWebsocketAdmissionKey{}, a)
}

// responsesWebsocketAdmissionFrom returns the socket's admission, or nil (admit everything).
func responsesWebsocketAdmissionFrom(ctx context.Context) *responsesWebsocketAdmission {
	a, _ := ctx.Value(responsesWebsocketAdmissionKey{}).(*responsesWebsocketAdmission)
	return a
}
