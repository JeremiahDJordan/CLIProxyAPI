//go:build unix

package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// Review finding 4: an event's body is collectable once the event is
// written, not only once its whole batch is.
func TestWrittenEventsAreReleasedBeforeTheBatchEnds(t *testing.T) {
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	flush(t)
	first, third := make(chan struct{}), make(chan struct{})
	var writes atomic.Int32
	hook := func(op string) error {
		if op != "segment.write" {
			return nil
		}
		switch writes.Add(1) {
		case 1:
			<-first
		case 3:
			<-third
		}
		return nil
	}
	faultHook.Store(&hook)
	t.Cleanup(func() {
		select {
		case <-third:
		default:
			close(third)
		}
	})
	rec.Emit(&Event{Type: TypeGap, Data: map[string]any{"reason": "blocks the writer"}})
	waitFor(t, "the writer to block", func() bool { return writes.Load() == 1 })
	// Queued while the writer is blocked, so both land in one batch.
	var body weak.Pointer[BodyData]
	func() {
		data := &BodyData{Bytes: bytes.Repeat([]byte("x"), 1<<20)}
		body = weak.Make(data)
		rec.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: data})
	}()
	rec.Emit(&Event{Type: TypeGap, Data: map[string]any{"reason": "blocked behind the body"}})
	close(first)
	waitFor(t, "the event after the body to block", func() bool { return writes.Load() == 3 })
	waitFor(t, "the written body to be collected", func() bool {
		runtime.GC()
		return body.Value() == nil
	})
}

// Review finding 5: the periodic check runs the start-up spool checks, so a
// spool that becomes unsafe stops capture, and recovery waits until it is
// safe again.
func TestPeriodicCheckRerunsSpoolSafetyChecks(t *testing.T) {
	shortBackoff(t, 10*time.Millisecond)
	cases := map[string]struct {
		break_, fix func(t *testing.T, spool string)
	}{
		"sentinel removed": {
			break_: func(t *testing.T, spool string) { mustDo(t, os.Remove(filepath.Join(spool, SentinelName))) },
			fix: func(t *testing.T, spool string) {
				mustDo(t, os.WriteFile(filepath.Join(spool, SentinelName), nil, 0o640))
			},
		},
		"blobs mode changed": {
			break_: func(t *testing.T, spool string) { mustDo(t, os.Chmod(filepath.Join(spool, BlobDirName), 0o770)) },
			fix: func(t *testing.T, spool string) {
				mustDo(t, os.Chmod(filepath.Join(spool, BlobDirName), os.ModeSetgid|0o770))
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			env := setup(t, "", func(o *TestOverrides) { o.SpaceCheckInterval = 10 * time.Millisecond })
			rec := mustStart(t, env)
			flush(t)
			tc.break_(t, env.spool)
			waitFor(t, "capture to stop", func() bool { return !rec.CaptureEvents() })
			// Recovery keeps failing while the spool is unsafe.
			time.Sleep(100 * time.Millisecond)
			if rec.CaptureEvents() {
				t.Fatal("capture resumed on an unsafe spool")
			}
			tc.fix(t, env.spool)
			waitFor(t, "capture to resume", rec.CaptureEvents)
			stop(t)
			var gap event
			for _, ev := range ofType(readEvents(t, env.spool), TypeGap) {
				if ev["reason"] == DropWriterError {
					gap = ev
				}
			}
			if errText, _ := gap["error"].(string); !strings.Contains(errText, "spool check") {
				t.Fatalf("writer_error gap = %v", gap)
			}
		})
	}
}

// Review finding 6: a segment whose close fails is closed by recovery
// instead of staying .open.jsonl for the life of the process.
func TestFailedSegmentCloseIsRetriedByRecovery(t *testing.T) {
	for _, op := range []string{"segment.close", "segment.rename"} {
		t.Run(op, func(t *testing.T) {
			shortBackoff(t, 10*time.Millisecond)
			env := setup(t, "", func(o *TestOverrides) { o.SegmentMaxBytes = 2048 })
			rec := mustStart(t, env)
			var failed atomic.Bool
			hook := func(name string) error {
				if name == op && failed.CompareAndSwap(false, true) {
					return errors.New("injected close failure")
				}
				return nil
			}
			faultHook.Store(&hook)
			for i := 0; i < 20; i++ {
				rec.Emit(&Event{Type: TypeGap, Data: map[string]any{"reason": "rotate", "pad": strings.Repeat("x", 300), "i": i}})
			}
			waitFor(t, "the failure and recovery", func() bool { return failed.Load() && rec.CaptureEvents() })
			// Recovery closes the stranded segment before writing anything new.
			waitFor(t, "no open segment but the current one", func() bool {
				open := 0
				for _, path := range segmentFiles(t, env.spool) {
					if strings.HasSuffix(path, ".open.jsonl") {
						open++
					}
				}
				return open <= 1
			})
			stop(t)
			files := segmentFiles(t, env.spool)
			for i, path := range files {
				m := segmentName.FindStringSubmatch(filepath.Base(path))
				if m == nil || m[4] != "closed" || m[3] != fmt.Sprintf("%06d", i+1) {
					t.Fatalf("segment %d is %s; all %v", i, filepath.Base(path), files)
				}
			}
		})
	}
}

// Review finding 7: the shipper may delete a reused blob before the event
// referencing it is written; the writer then writes the blob again, so the
// blob is in the spool once its event is.
func TestReusedBlobDeletedMeanwhileIsWrittenAgain(t *testing.T) {
	env := setup(t, "", func(o *TestOverrides) { o.BlobThresholdBytes = 64 })
	rec := mustStart(t, env)
	payload := bytes.Repeat([]byte("archived by the shipper "), 10)
	sum := sha256.Sum256(payload)
	blob := filepath.Join(env.spool, BlobDirName, hex.EncodeToString(sum[:]))
	rec.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: &BodyData{Bytes: payload}})
	flush(t)
	ops := traceOps(t, "blob.reuse", "blob.rewrite", "blob.rename", "segment.write")
	// The shipper archives the first segment and unlinks the blob just
	// after the writer chose to reuse it.
	var removed atomic.Bool
	hook := func(op, path string) {
		if op == "blob.reuse" && removed.CompareAndSwap(false, true) {
			_ = os.Remove(path)
		}
	}
	recordOps := traceHook.Load()
	both := func(op, path string) { (*recordOps)(op, path); hook(op, path) }
	traceHook.Store(&both)
	rec.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: &BodyData{Bytes: payload}})
	flush(t)
	if got := ops(); !slices.Equal(got, []string{"blob.reuse", "segment.write", "blob.rewrite", "blob.rename"}) {
		t.Fatalf("steps = %v", got)
	}
	stored, err := os.ReadFile(blob)
	if err != nil || !bytes.Equal(stored, payload) {
		t.Fatalf("blob after the event: %v", err)
	}
	assertMode(t, blob, 0o640)
	if got := rec.w.blobsRewritten.Load(); got != 1 {
		t.Fatalf("blobs_rewritten = %d", got)
	}
	// A blob still in place is not written again.
	traceHook.Store(nil)
	rec.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: &BodyData{Bytes: payload}})
	flush(t)
	if got := rec.w.blobsRewritten.Load(); got != 1 {
		t.Fatalf("an unchanged reused blob was rewritten (%d)", got)
	}
}

// Review finding 3: Start runs the disk work on its own goroutine with a
// deadline. A start that misses it leaves capture off; when it finishes
// later it counts start_timeout and stops.
func TestStartThatHangsLeavesCaptureOff(t *testing.T) {
	env := setup(t, "", func(o *TestOverrides) { o.StartTimeout = 100 * time.Millisecond })
	release := make(chan struct{})
	hook := func(op string) error {
		if op == "start.check" {
			<-release
		}
		return nil
	}
	faultHook.Store(&hook)
	abandoned := make(chan struct{})
	traced := func(op, _ string) {
		if op == "start.abandoned" {
			close(abandoned)
		}
	}
	traceHook.Store(&traced)
	started := time.Now()
	if rec := Start(StartParams{Config: enabledConfig(env.spool)}); rec != nil {
		t.Fatal("a hung start returned a recorder")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("Start waited %v", elapsed)
	}
	if Current() != nil {
		t.Fatal("capture is on after a hung start")
	}
	close(release)
	select {
	case <-abandoned:
	case <-time.After(10 * time.Second):
		t.Fatal("the late start was never stopped")
	}
	if Current() != nil {
		t.Fatal("the late start was installed")
	}
	events := readEvents(t, env.spool)
	found := false
	for _, gap := range ofType(events, TypeGap) {
		if drops, ok := gap["drops"].(map[string]any); ok && drops[DropStartTimeout] != nil {
			found = true
		}
	}
	if !found {
		t.Fatalf("no start_timeout gap: %v", events)
	}
	for _, path := range segmentFiles(t, env.spool) {
		if !strings.HasSuffix(path, ".closed.jsonl") {
			t.Fatalf("segment left open: %s", path)
		}
	}
}

// Review finding 3: Stop never waits on a hung writer beyond its bound,
// also with a context that has no deadline.
func TestStopIsBoundedWhenTheWriterHangs(t *testing.T) {
	env := setup(t, "", func(o *TestOverrides) {
		o.StopWriterWait = 200 * time.Millisecond
		o.StopObserverWait = 50 * time.Millisecond
	})
	rec := mustStart(t, env)
	flush(t)
	release := make(chan struct{})
	t.Cleanup(func() {
		// Let the writer finish before the spool is removed.
		close(release)
		select {
		case <-rec.done:
		case <-time.After(10 * time.Second):
			t.Error("the writer never finished")
		}
	})
	var blocked atomic.Bool
	hook := func(op string) error {
		if op == "segment.write" && blocked.CompareAndSwap(false, true) {
			<-release
		}
		return nil
	}
	faultHook.Store(&hook)
	rec.Emit(&Event{Type: TypeGap, Data: map[string]any{"reason": "hangs"}})
	waitFor(t, "the writer to hang", blocked.Load)
	started := time.Now()
	if err := Stop(context.Background()); err == nil {
		t.Fatal("Stop reported success with a hung writer")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("Stop waited %v on a hung writer", elapsed)
	}
}

// stopObserver is a request observer that queues its final event when the
// test lets it, or when Stop finalizes it.
type stopObserver struct {
	rec       *Recorder
	in        *Ingress
	once      sync.Once
	finalized atomic.Bool
}

func (o *stopObserver) finish(ended string) {
	o.once.Do(func() {
		o.in.Emit(&Event{Type: TypeIngressEnd, ReportDrops: true, Data: map[string]any{"ended": ended}})
		o.rec.UntrackObserver(o)
	})
}

func (o *stopObserver) FinalizeAtStop() {
	o.finalized.Store(true)
	o.finish("shutdown")
}

// Review finding 2: Stop waits (bounded) for observers to queue their final
// event, and finalizes the ones still open at the deadline; either way the
// event precedes the shutdown event.
func TestStopWaitsForObserversAndFinalizesTheRest(t *testing.T) {
	env := setup(t, "", func(o *TestOverrides) { o.StopObserverWait = 300 * time.Millisecond })
	rec := mustStart(t, env)
	late := &stopObserver{rec: rec, in: rec.BeginIngress(RouteInference, time.Now())}
	stuck := &stopObserver{rec: rec, in: rec.BeginIngress(RouteInference, time.Now())}
	if !rec.TrackObserver(late) || !rec.TrackObserver(stuck) {
		t.Fatal("cannot track observers")
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		late.finish("request_end")
	}()
	stop(t)
	if late.finalized.Load() || !stuck.finalized.Load() {
		t.Fatalf("finalized: late %v, stuck %v", late.finalized.Load(), stuck.finalized.Load())
	}
	if rec.TrackObserver(&stopObserver{rec: rec}) {
		t.Fatal("an observer was tracked after Stop")
	}
	events := readEvents(t, env.spool)
	shutdown := ofType(events, TypeShutdown)[0]["seq"].(float64)
	ends := map[string]string{}
	for _, ev := range ofType(events, TypeIngressEnd) {
		if ev["seq"].(float64) > shutdown {
			t.Fatalf("ingress_end after shutdown: %v", ev)
		}
		ends[ev["ingress_id"].(string)] = ev["ended"].(string)
	}
	if ends[late.in.ID()] != "request_end" || ends[stuck.in.ID()] != "shutdown" {
		t.Fatalf("ingress_end events = %v", ends)
	}
}

// Chunked bodies (the client body tee's form) round-trip like single buffers.
func TestChunkedBodiesRoundTrip(t *testing.T) {
	env := setup(t, "", func(o *TestOverrides) { o.BlobThresholdBytes = 64 })
	rec := mustStart(t, env)
	cases := map[string]*BodyData{
		"text":   {Chunks: [][]byte{[]byte("caf"), []byte("\xc3"), []byte("\xa9 au lait")}},
		"binary": {Chunks: [][]byte{{0xff, 0x00}, {0xfe}}, ContentEncoding: "gzip"},
		"blob":   {Chunks: [][]byte{bytes.Repeat([]byte("a"), 50), bytes.Repeat([]byte("b"), 50)}},
	}
	for name, body := range cases {
		rec.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: body, Data: map[string]any{"case": name}})
	}
	flush(t)
	for _, ev := range ofType(readEvents(t, env.spool), TypeClientBody) {
		want := cases[ev["case"].(string)]
		if got := decodeBody(t, env.spool, ev["body"].(map[string]any)); !bytes.Equal(got, want.flat()) {
			t.Fatalf("%s: %q != %q", ev["case"], got, want.flat())
		}
	}
}

func mustDo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func attemptEvents(events []event, typ string) []event {
	return ofType(events, typ)
}

// Attempts take their attempt_seq when first used, so attempt contexts that
// are never used leave no gap; each outbound request is a sub-attempt;
// attempts left open close with their request.
func TestAttemptsAndSubAttempts(t *testing.T) {
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	in := rec.BeginIngress(RouteInference, time.Now())
	ctx := WithIngress(context.Background(), in)
	unused := WithAttempt(ctx)
	first := WithAttempt(unused)
	DescribeAttempt(first, AttemptInfo{AuthID: "auth-1", Provider: "claude", Model: "claude-test", PickReason: "affinity"})
	TapUpstreamRequest(first, UpstreamRequest{URL: "https://api.example/v1/messages", Method: "POST", Body: []byte(`{"a":1}`)})
	TapUpstreamResponse(first, 529, http.Header{"Retry-After": {"1"}})
	TapUpstreamRequest(first, UpstreamRequest{URL: "https://api.example/v1/messages", Method: "POST", Body: []byte(`{"a":1}`)})
	TapUpstreamResponse(first, 200, nil)
	TapUpstreamChunk(first, []byte("event: message_start"))
	TapUpstreamChunk(first, []byte{})
	TapUpstreamChunk(first, []byte(`data: {"type":"message_start","message":{"id":"msg_01","model":"claude-test","usage":{"input_tokens":3,"cache_creation":{"ephemeral_5m_input_tokens":2}}}}`))
	EndAttempt(first, AttemptEnd{Success: true})
	// A resend after a refresh inherits the description.
	second := WithAttempt(first)
	NoteGate(second, GateDeny, "fleet_claude_client")
	in.CloseAttempts(AttemptEndedRequestEnd)
	stop(t)

	events := readEvents(t, env.spool)
	starts := attemptEvents(events, TypeAttemptStart)
	ends := attemptEvents(events, TypeAttemptEnd)
	if len(starts) != 2 || starts[0]["attempt_seq"] != float64(1) || starts[1]["attempt_seq"] != float64(2) {
		t.Fatalf("attempt_start = %v", starts)
	}
	if starts[0]["auth_id"] != "auth-1" || starts[0]["pick_reason"] != "affinity" || starts[1]["auth_id"] != "auth-1" {
		t.Fatalf("attempt descriptions = %v", starts)
	}
	if len(ends) != 2 || ends[0]["success"] != true || ends[0]["requests"] != float64(2) || ends[0]["status"] != float64(200) {
		t.Fatalf("first attempt_end = %v", ends)
	}
	if ends[1]["ended"] != AttemptEndedRequestEnd || ends[1]["gate"] != GateDeny || ends[1]["gate_code"] != "fleet_claude_client" {
		t.Fatalf("second attempt_end = %v", ends[1])
	}
	if ids, _ := ends[0]["upstream_response_ids"].([]any); len(ids) != 1 || ids[0] != "msg_01" {
		t.Fatalf("identities = %v", ends[0])
	}
	requests := ofType(events, TypeUpstreamRequest)
	if len(requests) != 2 || requests[0]["sub_attempt"] != float64(0) || requests[1]["sub_attempt"] != float64(1) {
		t.Fatalf("upstream_request sub_attempts = %v", requests)
	}
	chunks := ofType(events, TypeUpstreamEvent)
	if len(chunks) != 2 || chunks[0]["chunk_seq"] != float64(1) || chunks[1]["chunk_seq"] != float64(3) || chunks[1]["sub_attempt"] != float64(1) {
		t.Fatalf("upstream_event = %v", chunks)
	}
	usage := ofType(events, TypeUsage)
	if len(usage) != 1 || usage[0]["event"] != "message_start" || usage[0]["attempt_seq"] != float64(1) || usage[0]["model"] != "claude-test" {
		t.Fatalf("usage = %v", usage)
	}
	if raw := usage[0]["usage"].(map[string]any); raw["input_tokens"] != float64(3) || raw["cache_creation"] == nil {
		t.Fatalf("usage_raw = %v", raw)
	}
}

// Usage and identities from every upstream shape the design names.
func TestUpstreamUsageAndIdentityShapes(t *testing.T) {
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	in := rec.BeginIngress(RouteInference, time.Now())
	ctx := WithAttempt(WithIngress(context.Background(), in))
	TapUpstreamRequest(ctx, UpstreamRequest{URL: "https://chatgpt.example/backend-api/codex/responses", Body: []byte(`{"previous_response_id":"resp_prev"}`)})
	for _, chunk := range []string{
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01"}}`,
		`data: {"type":"message_delta","usage":{"output_tokens":9}}`,
		`data: {"type":"response.output_item.added","item":{"id":"fc_1","call_id":"call_1"}}`,
		`data: {"type":"response.completed","response":{"id":"resp_2","model":"gpt-test","usage":{"input_tokens":5,"output_tokens":1}}}`,
		`{"id":"msg_02","type":"message","model":"claude-haiku","content":[{"type":"tool_use","id":"toolu_02"}],"usage":{"input_tokens":1}}`,
		`{"id":"chatcmpl-1","object":"chat.completion","usage":{"prompt_tokens":2}}`,
		`{"responseId":"g-1","modelVersion":"gemini-test","usageMetadata":{"promptTokenCount":4}}`,
	} {
		TapUpstreamChunk(ctx, []byte(chunk))
	}
	TapUpstreamWSFrame(ctx, []byte(`{"type":"response.output_item.done","item":{"id":"rs_1"}}`), true)
	EndAttempt(ctx, AttemptEnd{Success: true})
	stop(t)
	events := readEvents(t, env.spool)
	var sources []string
	for _, ev := range ofType(events, TypeUsage) {
		sources = append(sources, ev["event"].(string))
	}
	if want := []string{"message_delta", "response.completed", "body", "body", "usageMetadata"}; !slices.Equal(sources, want) {
		t.Fatalf("usage events = %v, want %v", sources, want)
	}
	end := ofType(events, TypeAttemptEnd)[0]
	if end["previous_response_id"] != "resp_prev" {
		t.Fatalf("previous_response_id = %v", end["previous_response_id"])
	}
	if got := fmt.Sprint(end["upstream_response_ids"]); got != "[resp_2 msg_02 chatcmpl-1 g-1]" {
		t.Fatalf("upstream_response_ids = %v", got)
	}
	if got := fmt.Sprint(end["output_item_ids"]); got != "[toolu_01 fc_1 call_1 toolu_02 rs_1]" {
		t.Fatalf("output_item_ids = %v", got)
	}
	frames := ofType(events, TypeUpstreamWS)
	if len(frames) != 1 || frames[0]["ws_event"] != WSEventResponse || frames[0]["trimmed"] != true || frames[0]["frame_seq"] != float64(1) {
		t.Fatalf("upstream_ws = %v", frames)
	}
}

// Disabled means not installed: with no recorder every tap returns at once
// and attempt contexts are not created.
func TestTapsAreNoOpsWithoutARecorder(t *testing.T) {
	setup(t, "", nil)
	ctx := context.Background()
	if WithAttempt(ctx) != ctx {
		t.Fatal("WithAttempt changed the context with capture off")
	}
	TapUpstreamRequest(ctx, UpstreamRequest{})
	TapUpstreamResponse(ctx, 200, nil)
	TapUpstreamChunk(ctx, []byte("x"))
	TapUpstreamError(ctx, errors.New("x"))
	TapUpstreamWSRequest(ctx, UpstreamRequest{})
	TapUpstreamWSHandshake(ctx, 101, nil)
	TapUpstreamWSRejection(ctx, UpstreamRequest{}, 403, nil, nil)
	TapUpstreamWSError(ctx, "dial", errors.New("x"))
	TapUpstreamWSFrame(ctx, []byte("x"), false)
	TapUsage(ctx, UsageSourceReporter, "m", []byte(`{}`))
	NoteGate(ctx, GateDeny, "x")
	EndAttempt(ctx, AttemptEnd{})
}

// While bodies are off (low space), body-carrying taps still record their
// metadata, as dropped_body, and count the drop against the request.
func TestTapBodiesDropWhenSpaceIsLow(t *testing.T) {
	env := setup(t, "", func(o *TestOverrides) { o.SpaceCheckInterval = 10 * time.Millisecond })
	rec := Start(StartParams{Config: enabledConfigWithThresholds(env.spool)})
	if rec == nil {
		t.Fatal("Start returned nil")
	}
	env.free.Store(uint64(gib) + uint64(gib)/2)
	waitFor(t, "bodies to stop", func() bool { return !rec.CaptureBodies() })
	in := rec.BeginIngress(RouteInference, time.Now())
	ctx := WithAttempt(WithIngress(context.Background(), in))
	TapUpstreamRequest(ctx, UpstreamRequest{URL: "https://api.example/v1", Body: []byte("outbound")})
	flush(t)
	requests := ofType(readEvents(t, env.spool), TypeUpstreamRequest)
	if len(requests) != 1 || requests[0]["capture"] != CaptureDroppedBody || requests[0]["body_dropped"] != DropLowSpaceBody || requests[0]["body"] != nil {
		t.Fatalf("upstream_request = %v", requests)
	}
	if in.Drops() != 1 {
		t.Fatalf("request drops = %d", in.Drops())
	}
}

func enabledConfigWithThresholds(spool string) (cfg config.ArchiveConfig) {
	cfg = enabledConfig(spool)
	cfg.BodyFreeGB, cfg.HardFreeGB = 2, 1
	return cfg
}
