package openai

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/fleetdrain"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/tidwall/gjson"
)

// drainGatedExecutor holds each turn open until the test releases it.
type drainGatedExecutor struct {
	started chan struct{}
	release chan struct{}
}

func (*drainGatedExecutor) Identifier() string { return "codex" }

func (*drainGatedExecutor) Execute(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, errors.New("not implemented")
}

func (e *drainGatedExecutor) ExecuteStream(ctx context.Context, _ *coreauth.Auth, _ coreexecutor.Request, _ coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	chunks := make(chan coreexecutor.StreamChunk, 1)
	e.started <- struct{}{}
	go func() {
		defer close(chunks)
		select {
		case <-e.release:
		case <-ctx.Done():
			return
		}
		chunks <- coreexecutor.StreamChunk{Payload: []byte(`{"type":"response.completed","response":{"id":"resp-drain","output":[]}}`)}
	}()
	return &coreexecutor.StreamResult{Chunks: chunks}, nil
}

func (*drainGatedExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	return auth, nil
}

func (*drainGatedExecutor) CountTokens(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, errors.New("not implemented")
}

func (*drainGatedExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("not implemented")
}

// newDrainWebsocket serves the Responses WebSocket with a tracker in the request
// context, as the API server's drain middleware provides it, and dials it.
func newDrainWebsocket(t *testing.T) (*fleetdrain.Tracker, *drainGatedExecutor, *websocket.Conn) {
	return newDrainWebsocketWithConfig(t, &sdkconfig.SDKConfig{})
}

func newDrainWebsocketWithConfig(t *testing.T, cfg *sdkconfig.SDKConfig) (*fleetdrain.Tracker, *drainGatedExecutor, *websocket.Conn) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	executor := &drainGatedExecutor{started: make(chan struct{}, 4), release: make(chan struct{})}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	auth := &coreauth.Auth{ID: "auth-drain", Provider: "codex", Status: coreauth.StatusActive}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register auth: %v", err)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "drain-model"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })

	tracker := fleetdrain.New()
	h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(cfg, manager))
	router := gin.New()
	router.Use(func(c *gin.Context) { // as the API server's drain middleware does
		end := tracker.BeginRequest()
		defer end()
		var once sync.Once
		handoff := func() {
			// The upgraded socket must already be counted when the request stops counting.
			once.Do(func() { drainHandoffSockets.Store(int64(tracker.Snapshot().WebSockets)) })
			end()
		}
		c.Request = c.Request.WithContext(fleetdrain.WithRequest(fleetdrain.WithTracker(c.Request.Context(), tracker), handoff))
		c.Next()
	})
	router.GET("/v1/responses/ws", h.ResponsesWebsocket)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses/ws", nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	// Once upgraded, the connection is counted instead of the request.
	waitDrainActivity(t, tracker, func(a fleetdrain.Activity) bool { return a.WebSockets == 1 && a.Requests == 0 })
	return tracker, executor, conn
}

// drainHandoffSockets records the open-socket count seen when the request count ended.
var drainHandoffSockets atomic.Int64

func waitDrainActivity(t *testing.T, tracker *fleetdrain.Tracker, ok func(fleetdrain.Activity) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok(tracker.Snapshot()) {
		if time.Now().After(deadline) {
			t.Fatalf("activity never reached the expected state: %+v", tracker.Snapshot())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func expectServiceRestartClose(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, payload, err := conn.ReadMessage()
	if !websocket.IsCloseError(err, websocket.CloseServiceRestart) {
		t.Fatalf("read = %q, %v; want close 1012 (service restart)", payload, err)
	}
}

func TestResponsesWebsocketDrainClosesIdleSocket(t *testing.T) {
	tracker, _, conn := newDrainWebsocket(t)
	if got := tracker.Snapshot(); !got.Quiet || got.WebSocketTurns != 0 {
		t.Fatalf("an idle socket should be quiet: %+v", got)
	}
	tracker.StartDrain()
	expectServiceRestartClose(t, conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tracker.Wait(ctx); err != nil {
		t.Fatalf("drain did not finish after the idle socket closed: %v (%+v)", err, tracker.Snapshot())
	}
}

func TestResponsesWebsocketDrainFinishesTurnBeforeClosing(t *testing.T) {
	tracker, executor, conn := newDrainWebsocket(t)
	request := `{"type":"response.create","model":"drain-model","input":[{"type":"message","role":"user","content":"hi"}]}`
	if err := conn.WriteMessage(websocket.TextMessage, []byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	select {
	case <-executor.started:
	case <-time.After(5 * time.Second):
		t.Fatal("turn never reached the executor")
	}
	if got := tracker.Snapshot(); got.WebSocketTurns != 1 || got.Quiet {
		t.Fatalf("a turn in flight should not be quiet: %+v", got)
	}

	tracker.StartDrain()
	waited := make(chan error, 1)
	go func() { waited <- tracker.Wait(context.Background()) }()
	select {
	case err := <-waited:
		t.Fatalf("drain finished with a turn in flight: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(executor.release)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("turn in flight was cut off: %v", err)
	}
	if got := gjson.GetBytes(payload, "type").String(); got != wsEventTypeCompleted {
		t.Fatalf("response type = %q, want %q: %s", got, wsEventTypeCompleted, payload)
	}
	expectServiceRestartClose(t, conn)
	select {
	case err := <-waited:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("drain did not finish after the turn: %+v", tracker.Snapshot())
	}
}

func TestResponsesWebsocketDrainAnswersAFrameAlreadyRead(t *testing.T) {
	reached := make(chan struct{}, 1)
	resume := make(chan struct{})
	responsesWebsocketReadHookForTest = func() {
		reached <- struct{}{}
		<-resume
	}
	t.Cleanup(func() { responsesWebsocketReadHookForTest = nil })
	tracker, executor, conn := newDrainWebsocket(t)
	close(executor.release)

	request := `{"type":"response.create","model":"drain-model","input":[{"type":"message","role":"user","content":"hi"}]}`
	if err := conn.WriteMessage(websocket.TextMessage, []byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	select {
	case <-reached: // read, not yet parsed or queued
	case <-time.After(5 * time.Second):
		t.Fatal("reader never read the frame")
	}
	if got := tracker.Snapshot(); got.WebSocketTurns != 1 || got.Quiet {
		t.Fatalf("a frame being read is a turn in flight: %+v", got)
	}
	tracker.StartDrain()
	time.Sleep(100 * time.Millisecond)
	if got := tracker.Snapshot(); got.WebSockets != 1 || got.WebSocketTurns != 1 {
		t.Fatalf("socket closed while its frame was held: %+v", got)
	}
	close(resume)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("the held frame was dropped: %v", err)
	}
	if got := gjson.GetBytes(payload, "type").String(); got != wsEventTypeCompleted {
		t.Fatalf("response type = %q, want %q: %s", got, wsEventTypeCompleted, payload)
	}
	expectServiceRestartClose(t, conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tracker.Wait(ctx); err != nil {
		t.Fatalf("drain did not finish after the held frame: %v (%+v)", err, tracker.Snapshot())
	}
}

func TestResponsesWebsocketSteeringSessionCountsAsBusy(t *testing.T) {
	tracker, _, _ := newDrainWebsocketWithConfig(t, &sdkconfig.SDKConfig{CodexResponseSteering: true})
	if got := tracker.Snapshot(); got.SteeringWebSockets != 1 || got.Quiet {
		t.Fatalf("a steering session must not look quiet: %+v", got)
	}
}

func TestResponsesWebsocketUpgradeCountsSocketBeforeEndingRequest(t *testing.T) {
	drainHandoffSockets.Store(-1)
	newDrainWebsocket(t)
	if got := drainHandoffSockets.Load(); got != 1 {
		t.Fatalf("open sockets when the request stopped counting = %d, want 1 (no uncounted window)", got)
	}
}

func TestResponsesWebsocketDrainRefusesTurnsSentAfterIt(t *testing.T) {
	tracker, executor, conn := newDrainWebsocket(t)
	request := `{"type":"response.create","model":"drain-model","input":[{"type":"message","role":"user","content":"hi"}]}`
	if err := conn.WriteMessage(websocket.TextMessage, []byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	select {
	case <-executor.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first turn never reached the executor")
	}
	tracker.StartDrain()
	// A new turn sent after the drain began is left for the next process.
	if err := conn.WriteMessage(websocket.TextMessage, []byte(request)); err != nil {
		t.Fatalf("write second request: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	waitDrainActivity(t, tracker, func(a fleetdrain.Activity) bool { return a.WebSocketTurns == 1 })
	close(executor.release)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, payload, err := conn.ReadMessage()
	if err != nil || gjson.GetBytes(payload, "type").String() != wsEventTypeCompleted {
		t.Fatalf("first turn = %q, %v; want %s", payload, err, wsEventTypeCompleted)
	}
	expectServiceRestartClose(t, conn)
	select {
	case <-executor.started:
		t.Fatal("a turn sent after the drain began was executed")
	default:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tracker.Wait(ctx); err != nil {
		t.Fatalf("drain did not finish: %v (%+v)", err, tracker.Snapshot())
	}
}

func TestResponsesWebsocketDrainClosesAfterAnInterruptItHeld(t *testing.T) {
	reached := make(chan struct{}, 1)
	resume := make(chan struct{})
	var once sync.Once
	responsesWebsocketReadHookForTest = func() {
		once.Do(func() {
			reached <- struct{}{}
			<-resume
		})
	}
	t.Cleanup(func() { responsesWebsocketReadHookForTest = nil })
	tracker, _, conn := newDrainWebsocket(t)

	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.interrupt","response_id":"resp-none"}`)); err != nil {
		t.Fatalf("write interrupt: %v", err)
	}
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("reader never read the interrupt")
	}
	tracker.StartDrain()
	time.Sleep(50 * time.Millisecond)
	if got := tracker.Snapshot(); got.WebSockets != 1 {
		t.Fatalf("socket closed while its interrupt was held: %+v", got)
	}
	close(resume)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, payload, err := conn.ReadMessage()
	if err != nil || gjson.GetBytes(payload, "type").String() != "error" {
		t.Fatalf("interrupt reply = %q, %v; want an error event", payload, err)
	}
	expectServiceRestartClose(t, conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tracker.Wait(ctx); err != nil {
		t.Fatalf("drain did not finish after the interrupt: %v (%+v)", err, tracker.Snapshot())
	}
}
