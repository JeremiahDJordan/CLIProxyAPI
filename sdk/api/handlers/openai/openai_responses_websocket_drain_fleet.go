package openai

// Fleet fork: Responses WebSockets during a server drain (internal/api/drain_fleet.go).
// An idle socket closes at once and a busy one after its current turn, with 1012
// (service restart). Codex checks its cached socket before each turn and reconnects
// when it is closed, so the next turn reaches the next server process.

import (
	"time"

	"github.com/gorilla/websocket"
)

const responsesWebsocketDrainCloseTimeout = time.Second

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
