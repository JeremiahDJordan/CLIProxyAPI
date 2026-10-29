//go:build unix

package openai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/archive"
	proxyconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

const archiveWSCompleted = `{"type":"response.completed","response":{"id":"resp_ws_1","output":[],"usage":{"input_tokens":3,"output_tokens":1}}}`

// archiveWSExecutor stands in for the Codex executor: it records the
// outbound request and the upstream event through the archive taps, as the
// executor helpers do, and can hold a turn open.
type archiveWSExecutor struct {
	started chan struct{}
	release chan struct{}
}

func (*archiveWSExecutor) Identifier() string { return "codex" }

func (*archiveWSExecutor) Execute(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, errors.New("not implemented")
}

func (e *archiveWSExecutor) ExecuteStream(ctx context.Context, _ *coreauth.Auth, req coreexecutor.Request, _ coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	archive.TapUpstreamRequest(ctx, archive.UpstreamRequest{URL: "https://chatgpt.example/backend-api/codex/responses", Method: http.MethodPost, Body: req.Payload, Provider: "codex"})
	chunks := make(chan coreexecutor.StreamChunk, 1)
	select {
	case e.started <- struct{}{}:
	default:
	}
	go func() {
		defer close(chunks)
		if e.release != nil {
			select {
			case <-e.release:
			case <-ctx.Done():
				return
			}
		}
		archive.TapUpstreamChunk(ctx, []byte(archiveWSCompleted))
		chunks <- coreexecutor.StreamChunk{Payload: []byte(archiveWSCompleted)}
	}()
	return &coreexecutor.StreamResult{Chunks: chunks}, nil
}

func (*archiveWSExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	return auth, nil
}

func (*archiveWSExecutor) CountTokens(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, errors.New("not implemented")
}

func (*archiveWSExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("not implemented")
}

// startArchiveForWebsocket starts a recorder on a temporary spool, like
// internal/api's tests do.
func startArchiveForWebsocket(t *testing.T, mutate func(*archive.TestOverrides)) string {
	t.Helper()
	group, err := user.LookupGroupId(strconv.Itoa(os.Getegid()))
	if err != nil {
		t.Skipf("cannot name the effective group: %v", err)
	}
	spool := t.TempDir()
	if err = os.WriteFile(filepath.Join(spool, archive.SentinelName), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(spool, archive.BlobDirName), 0o770); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{spool, filepath.Join(spool, archive.BlobDirName)} {
		if err = os.Chmod(dir, os.ModeSetgid|0o770); err != nil {
			t.Fatal(err)
		}
	}
	o := archive.TestOverrides{
		StateDir:           filepath.Join(t.TempDir(), "state"),
		SpoolGroup:         group.Name,
		FreeBytes:          func() uint64 { return 1 << 50 },
		FsyncInterval:      20 * time.Millisecond,
		HeartbeatInterval:  time.Hour,
		SpaceCheckInterval: time.Hour,
	}
	if mutate != nil {
		mutate(&o)
	}
	t.Cleanup(archive.SetTestOverrides(o))
	if archive.Start(archive.StartParams{Config: proxyconfig.ArchiveConfig{Enabled: true, SpoolDir: spool}}) == nil {
		t.Fatal("recorder did not start")
	}
	return spool
}

type archiveWSEvent map[string]any

func archiveWSEvents(t *testing.T, spool string) []archiveWSEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := archive.FlushForTest(ctx); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(spool, "*.jsonl"))
	sort.Strings(files)
	var out []archiveWSEvent
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 1<<20), 64<<20)
		for scanner.Scan() {
			var ev archiveWSEvent
			if err = json.Unmarshal(scanner.Bytes(), &ev); err != nil {
				t.Fatal(err)
			}
			out = append(out, ev)
		}
	}
	return out
}

func archiveWSBody(t *testing.T, ev archiveWSEvent) []byte {
	t.Helper()
	body := ev["body"].(map[string]any)
	switch body["form"] {
	case archive.FormText:
		return []byte(body["value"].(string))
	case archive.FormBase64:
		data, err := base64.StdEncoding.DecodeString(body["value"].(string))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	t.Fatalf("form %v", body["form"])
	return nil
}

// serveArchivedWebsocket serves the Responses WebSocket behind a middleware
// that, as the transport observer does for an upgrade request, records the
// connection ingress, and dials it.
func serveArchivedWebsocket(t *testing.T, cfg *sdkconfig.SDKConfig, exec *archiveWSExecutor, header http.Header) (*websocket.Conn, *archive.Ingress, chan struct{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := coreauth.NewManager(nil, nil, nil)
	manager.RegisterExecutor(exec)
	auth := &coreauth.Auth{ID: "auth-archive-ws", Provider: "codex", Status: coreauth.StatusActive}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "archive-model"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(cfg, manager))
	connIngress := make(chan *archive.Ingress, 1)
	done := make(chan struct{})
	router := gin.New()
	router.Use(func(c *gin.Context) {
		defer close(done)
		in := archive.Current().BeginConnection(archive.RouteInference, time.Now())
		c.Request = c.Request.WithContext(archive.WithIngress(c.Request.Context(), in))
		c.Set(archive.GinIngressKey, in)
		connIngress <- in
		c.Next()
	})
	router.GET("/v1/responses", h.ResponsesWebsocket)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", header)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, <-connIngress, done
}

func readWebsocketUntil(t *testing.T, conn *websocket.Conn, eventType string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("reading for %s: %v", eventType, err)
		}
		if strings.Contains(string(payload), `"type":"`+eventType+`"`) {
			return
		}
	}
}

// Every client frame, whatever its type, is a ws_turn with its own
// ingress_id and turn_seq in arrival order, its exact bytes, and an
// ingress_end saying how it was answered. A turn's upstream traffic and the
// frames written while answering it attach to that turn, not to the
// connection.
func TestArchiveWebsocketTurnsForEveryFrameType(t *testing.T) {
	spool := startArchiveForWebsocket(t, nil)
	exec := &archiveWSExecutor{started: make(chan struct{}, 4)}
	header := http.Header{"X-Codex-Turn-Metadata": {`{"turn_id":"turn-header"}`}}
	conn, connIn, done := serveArchivedWebsocket(t, &sdkconfig.SDKConfig{}, exec, header)

	frames := []struct {
		kind    int
		payload string
		answer  string
	}{
		{websocket.TextMessage, `{"type":"response.create","model":"archive-model","input":[{"type":"message","role":"user","content":"hi"}],"client_metadata":{"x-codex-turn-metadata":"{\"turn_id\":\"turn-frame\"}"}}`, "response.completed"},
		{websocket.TextMessage, `{"type":"response.interrupt","response_id":"resp_ws_1"}`, "error"},
		{websocket.TextMessage, `not json at all`, "error"},
		{websocket.BinaryMessage, `{"type":"response.create","model":"archive-model","input":[{"type":"message","role":"user","content":"again"}]}`, ""},
	}
	for _, f := range frames {
		if err := conn.WriteMessage(f.kind, []byte(f.payload)); err != nil {
			t.Fatal(err)
		}
		if f.answer != "" {
			readWebsocketUntil(t, conn, f.answer)
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, _ = conn.ReadMessage() // the binary turn's answer
	_ = conn.Close()
	<-done

	events := archiveWSEvents(t, spool)
	var turns []archiveWSEvent
	byTurn := map[string][]archiveWSEvent{}
	for _, ev := range events {
		id, _ := ev["ingress_id"].(string)
		byTurn[id] = append(byTurn[id], ev)
		if ev["type"] == archive.TypeIngressStart && ev["kind"] == archive.KindWSTurn {
			turns = append(turns, ev)
		}
	}
	if len(turns) != len(frames) {
		t.Fatalf("%d ws_turn ingress_start events for %d frames", len(turns), len(frames))
	}
	wantOutcome := []string{wsTurnCompleted, wsTurnInterruptPrefix + "rejected", wsTurnRequestError, ""}
	for i, turn := range turns {
		if turn["turn_seq"] != float64(i+1) || turn["connection_id"] != connIn.ID() {
			t.Fatalf("turn %d: turn_seq %v connection_id %v (connection %s)", i, turn["turn_seq"], turn["connection_id"], connIn.ID())
		}
		evs := byTurn[turn["ingress_id"].(string)]
		var in, end archiveWSEvent
		for _, ev := range evs {
			switch {
			case ev["type"] == archive.TypeClientWSFrame && ev["direction"] == "in":
				in = ev
			case ev["type"] == archive.TypeIngressEnd:
				end = ev
			}
		}
		if in == nil || !bytes.Equal(archiveWSBody(t, in), []byte(frames[i].payload)) {
			t.Fatalf("turn %d: client frame %v", i, in)
		}
		if end == nil || end["kind"] != archive.KindWSTurn || end["turn_seq"] != float64(i+1) {
			t.Fatalf("turn %d: ingress_end %v", i, end)
		}
		if wantOutcome[i] != "" && end["outcome"] != wantOutcome[i] {
			t.Fatalf("turn %d: outcome %v, want %s", i, end["outcome"], wantOutcome[i])
		}
	}
	if turns[0]["codex_turn_id"] != "turn-frame" || turns[0]["codex_turn_id_source"] != "frame" ||
		turns[1]["codex_turn_id"] != "turn-header" || turns[1]["codex_turn_id_source"] != "header" {
		t.Fatalf("codex turn ids: %v / %v", turns[0], turns[1])
	}
	if turns[0]["frame_type"] != "response.create" || turns[1]["frame_type"] != "response.interrupt" || turns[3]["message_type"] != "binary" {
		t.Fatalf("frame types: %v %v %v", turns[0]["frame_type"], turns[1]["frame_type"], turns[3]["message_type"])
	}
	first := byTurn[turns[0]["ingress_id"].(string)]
	var upstream, out, usage int
	for _, ev := range first {
		switch {
		case ev["type"] == archive.TypeUpstreamRequest:
			upstream++
		case ev["type"] == archive.TypeClientWSFrame && ev["direction"] == "out":
			out++
		case ev["type"] == archive.TypeUsage:
			usage++
		}
	}
	if upstream != 1 || out == 0 || usage != 1 {
		t.Fatalf("first turn: %d upstream requests, %d frames out, %d usage events", upstream, out, usage)
	}
	for _, ev := range byTurn[connIn.ID()] {
		if ev["type"] == archive.TypeUpstreamRequest {
			t.Fatal("a turn's upstream request was recorded on the connection")
		}
	}
}

// The steering guard: with response steering on for a connection its turns
// are not recorded, and that is counted as a gap.
func TestArchiveWebsocketSteeringGuard(t *testing.T) {
	spool := startArchiveForWebsocket(t, nil)
	conn, _, done := serveArchivedWebsocket(t, &sdkconfig.SDKConfig{CodexResponseSteering: true}, &archiveWSExecutor{started: make(chan struct{}, 1)}, nil)
	_ = conn.Close()
	<-done
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := archive.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	counted := false
	for _, ev := range archiveWSEvents(t, spool) {
		if ev["kind"] == archive.KindWSTurn {
			t.Fatalf("a steering connection's turn was recorded: %v", ev)
		}
		if drops, ok := ev["drops"].(map[string]any); ok && ev["type"] == archive.TypeGap && drops[archive.DropSteeringTurns] != nil {
			counted = true
		}
	}
	if !counted {
		t.Fatal("the unrecorded steering connection was not counted as a gap")
	}
}

// A turn still being answered when Stop's wait ends is finalized: its
// ingress_end (ended shutdown) precedes the shutdown event. Round-2 finding
// 2: what the turn does afterwards is not recorded, so it counts a drop.
func TestArchiveStopFinalizesAnOpenWebsocketTurn(t *testing.T) {
	spool := startArchiveForWebsocket(t, func(o *archive.TestOverrides) { o.StopObserverWait = 100 * time.Millisecond })
	exec := &archiveWSExecutor{started: make(chan struct{}, 1), release: make(chan struct{})}
	conn, _, done := serveArchivedWebsocket(t, &sdkconfig.SDKConfig{}, exec, nil)
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"archive-model","input":[]}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exec.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the turn never reached the executor")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := archive.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	close(exec.release)
	_ = conn.Close()
	<-done
	var end, shutdown archiveWSEvent
	for _, ev := range archiveWSEvents(t, spool) {
		switch {
		case ev["type"] == archive.TypeIngressEnd && ev["kind"] == archive.KindWSTurn:
			if end != nil {
				t.Fatal("two ingress_end events for one turn")
			}
			end = ev
		case ev["type"] == archive.TypeShutdown:
			shutdown = ev
		}
	}
	if end == nil || end["ended"] != archiveTurnEndedShutdown || shutdown == nil || end["seq"].(float64) > shutdown["seq"].(float64) ||
		end["capture_drops"] != float64(1) {
		t.Fatalf("turn ingress_end %v, shutdown %v", end, shutdown)
	}
}

// Round-2 finding 6: the reader answers a rejected response.interrupt
// itself; its error frame is recorded on the interrupt's own turn, before
// that turn's ingress_end, not on the connection or another turn.
func TestArchiveRejectedInterruptAnswersItsOwnTurn(t *testing.T) {
	spool := startArchiveForWebsocket(t, nil)
	conn, connIn, done := serveArchivedWebsocket(t, &sdkconfig.SDKConfig{}, &archiveWSExecutor{started: make(chan struct{}, 1)}, nil)
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.interrupt","response_id":"resp_ws_1"}`)); err != nil {
		t.Fatal(err)
	}
	readWebsocketUntil(t, conn, "error")
	_ = conn.Close()
	<-done
	var turn string
	var out, end archiveWSEvent
	for _, ev := range archiveWSEvents(t, spool) {
		switch {
		case ev["type"] == archive.TypeIngressStart && ev["kind"] == archive.KindWSTurn:
			turn = ev["ingress_id"].(string)
		case ev["type"] == archive.TypeClientWSFrame && ev["direction"] == "out":
			if ev["ingress_id"] == connIn.ID() || out != nil {
				t.Fatalf("frame out recorded on %v (turn %s)", ev["ingress_id"], turn)
			}
			out = ev
		case ev["type"] == archive.TypeIngressEnd && ev["kind"] == archive.KindWSTurn:
			end = ev
		}
	}
	if out == nil || out["ingress_id"] != turn || !strings.Contains(string(archiveWSBody(t, out)), `"type":"error"`) {
		t.Fatalf("error frame = %v", out)
	}
	if end == nil || end["outcome"] != wsTurnInterruptPrefix+"rejected" || end["frames_out"] != float64(1) ||
		end["bytes_out"] != float64(len(archiveWSBody(t, out))) || out["seq"].(float64) > end["seq"].(float64) {
		t.Fatalf("interrupt turn ingress_end = %v, frame seq %v", end, out["seq"])
	}
}

// Round-2 finding 2: a frame that arrives while Stop waits for the turns in
// flight is not recorded as a turn. That counts against its connection, and
// the refused turn's upstream traffic is not recorded on the connection.
func TestArchiveTurnRefusedDuringStopCountsAgainstItsConnection(t *testing.T) {
	spool := startArchiveForWebsocket(t, func(o *archive.TestOverrides) { o.StopObserverWait = 5 * time.Second })
	exec := &archiveWSExecutor{started: make(chan struct{}, 2), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(exec.release) })
	defer release()
	conn, connIn, done := serveArchivedWebsocket(t, &sdkconfig.SDKConfig{}, exec, nil)
	frame := []byte(`{"type":"response.create","model":"archive-model","input":[]}`)
	if err := conn.WriteMessage(websocket.TextMessage, frame); err != nil {
		t.Fatal(err)
	}
	<-exec.started
	stopped := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		stopped <- archive.Stop(ctx)
	}()
	for archive.Current() != nil {
		time.Sleep(time.Millisecond)
	}
	if err := conn.WriteMessage(websocket.TextMessage, frame); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for connIn.Drops() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	// The first turn still holds the handler: nothing answers the refused one yet.
	if got := connIn.Drops(); got != 1 {
		t.Fatalf("connection drops after the refused frame = %d", got)
	}
	release()
	readWebsocketUntil(t, conn, "response.completed")
	readWebsocketUntil(t, conn, "response.completed")
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	<-done
	turns := 0
	for _, ev := range archiveWSEvents(t, spool) {
		if ev["type"] == archive.TypeIngressStart && ev["kind"] == archive.KindWSTurn {
			turns++
		}
		if ev["ingress_id"] == connIn.ID() && ev["type"] == archive.TypeUpstreamRequest {
			t.Fatalf("the refused turn's upstream request was recorded on the connection: %v", ev)
		}
	}
	if turns != 1 {
		t.Fatalf("%d turns recorded", turns)
	}
}
