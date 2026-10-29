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
	"syscall"
	"testing"
	"time"
	"weak"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/buildinfo"
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

// Round-2 finding 1: a tap reserves an event's whole size, body included,
// before it copies the body, so bodies the queue refuses are counted and
// never allocated; a panic during the copy returns the reservation.
func TestRefusedTapBodiesAreNeverCopied(t *testing.T) {
	env := setup(t, "", func(o *TestOverrides) { o.QueueBytes = 1 << 20 })
	rec := mustStart(t, env)
	flush(t)
	in := rec.BeginIngress(RouteInference, time.Now())
	ctx := WithAttempt(WithIngress(context.Background(), in))
	body := bytes.Repeat([]byte("x"), 16<<20)
	text := string(body)
	if !rec.q.reserve(rec.q.limit) {
		t.Fatal("cannot fill the queue")
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	TapUpstreamRequest(ctx, UpstreamRequest{URL: "https://api.example/v1/messages", Body: body})
	TapUpstreamChunk(ctx, body)
	TapUpstreamWSFrame(ctx, body, false)
	EmitDownstream(in, time.Now(), nil, body)
	EmitDownstream(in, time.Now(), nil, text)
	EmitClientFrame(in, time.Now(), nil, 16, body)
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= 1<<20 {
		t.Fatalf("six refused 16 MiB bodies allocated %d bytes", allocated)
	}
	if got := rec.ledger.totals()[DropQueueFull]; got.Bodies != 6 || got.Bytes != 6*int64(len(body)) {
		t.Fatalf("queue_full drops = %+v", got)
	}
	rec.q.release(rec.q.limit)

	panicking := func(op string) error {
		if op == "tap.copy" {
			panic("copy failed")
		}
		return nil
	}
	faultHook.Store(&panicking)
	TapUpstreamChunk(ctx, []byte("chunk"))
	TapUsage(ctx, UsageSourceReporter, "m", []byte(`{"input_tokens":1}`))
	faultHook.Store(nil)
	flush(t)
	if used := rec.q.used.Load(); used != 0 {
		t.Fatalf("%d queue bytes stranded by a panicking copy", used)
	}
	if got := rec.ledger.totals()[DropTapPanic].Events; got != 2 {
		t.Fatalf("tap panics counted = %d", got)
	}
}

// Round-2 finding 2: Stop clears Current first, but the taps of a request
// still in flight record through its own ingress. While Stop waits for
// observers their events are queued (bodies as dropped_body, counted), and
// once the writer has closed the queue they are dropped and counted.
func TestTapsDuringStopReachTheirIngress(t *testing.T) {
	env := setup(t, "", func(o *TestOverrides) { o.StopObserverWait = 5 * time.Second })
	rec := mustStart(t, env)
	obs := &stopObserver{rec: rec, in: rec.BeginIngress(RouteInference, time.Now())}
	if !rec.TrackObserver(obs) {
		t.Fatal("cannot track the observer")
	}
	ctx := WithAttempt(WithIngress(context.Background(), obs.in))
	TapUpstreamRequest(ctx, UpstreamRequest{URL: "https://api.example/v1/messages", Body: []byte(`{}`)})
	stopped := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		stopped <- Stop(ctx)
	}()
	waitFor(t, "Stop to begin", func() bool { return Current() == nil && rec.stopping.Load() })
	TapUpstreamResponse(ctx, http.StatusOK, http.Header{"Content-Type": {"text/event-stream"}})
	TapUpstreamChunk(ctx, []byte(`data: {"type":"message_delta","usage":{"output_tokens":7}}`))
	EndAttempt(ctx, AttemptEnd{Success: true})
	obs.finish("request_end")
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	drops := obs.in.Drops()
	TapUpstreamError(ctx, errors.New("read after the final drain"))
	if obs.in.Drops() != drops+1 {
		t.Fatal("a tap after the queue closed was not counted against its request")
	}
	byType := map[string]event{}
	for _, ev := range readEvents(t, env.spool) {
		if ev["ingress_id"] == obs.in.ID() {
			byType[ev["type"].(string)] = ev
		}
	}
	meta, chunk, end := byType[TypeUpstreamResponseMeta], byType[TypeUpstreamEvent], byType[TypeIngressEnd]
	if meta == nil || meta["capture"] != CaptureFull || meta["status"] != float64(http.StatusOK) {
		t.Fatalf("upstream_response_meta = %v", meta)
	}
	if chunk == nil || chunk["capture"] != CaptureDroppedBody || chunk["body_dropped"] != DropStopped {
		t.Fatalf("upstream_event = %v", chunk)
	}
	if byType[TypeUsage] == nil || byType[TypeAttemptEnd] == nil {
		t.Fatalf("usage %v, attempt_end %v", byType[TypeUsage], byType[TypeAttemptEnd])
	}
	if end == nil || end["capture_drops"] != float64(1) {
		t.Fatalf("ingress_end = %v", end)
	}
}

func readStateFile(t *testing.T, dir string) stateFile {
	t.Helper()
	st, err := readState(dir)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// suspectGap returns the gap events' suspect ranges.
func suspectGaps(events []event) []map[string]any {
	var out []map[string]any
	for _, gap := range ofType(events, TypeGap) {
		ranges, _ := gap["suspect"].([]any)
		for _, r := range ranges {
			out = append(out, r.(map[string]any))
		}
	}
	return out
}

// Round-2 finding 3: when an fsync fails, the events written since the last
// successful one are recorded as a suspect range (boot, segment, seq range)
// by a durable writer_error gap, although the close retried during the
// failure then succeeds.
func TestFsyncFailureRecordsASuspectRange(t *testing.T) {
	shortBackoff(t, 10*time.Millisecond)
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	var failed atomic.Bool
	hook := func(op string) error {
		if op == "segment.sync" && failed.CompareAndSwap(false, true) {
			return syscall.EIO
		}
		return nil
	}
	faultHook.Store(&hook)
	in := rec.BeginIngress(RouteInference, time.Now())
	in.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: &BodyData{Bytes: []byte("written, then its fsync failed")}})
	waitFor(t, "the failed fsync and the recovery", func() bool {
		return failed.Load() && rec.w.writerErrors.Load() > 0 && rec.CaptureEvents()
	})
	flush(t)
	events := readEvents(t, env.spool)
	body := ofType(events, TypeClientBody)[0]
	seq := uint64(body["seq"].(float64))
	ranges := suspectGaps(events)
	if len(ranges) != 1 {
		t.Fatalf("suspect ranges = %v", ranges)
	}
	r := ranges[0]
	first, last := uint64(r["first_seq"].(float64)), uint64(r["last_seq"].(float64))
	if r["boot_id"] != rec.bootID || first > seq || last < seq {
		t.Fatalf("suspect range %v does not cover the body (seq %d)", r, seq)
	}
	// The retried close succeeded: the segment holding the range is closed,
	// and holds every event of the range.
	closed := filepath.Join(env.spool, r["segment"].(string)+".closed.jsonl")
	data, err := os.ReadFile(closed)
	if err != nil {
		t.Fatalf("segment of the suspect range: %v", err)
	}
	for n := first; n <= last; n++ {
		if !bytes.Contains(data, fmt.Appendf(nil, `"seq":%d,`, n)) {
			t.Fatalf("seq %d is not in %s", n, filepath.Base(closed))
		}
	}
	gap := ofType(events, TypeGap)[0]
	if gap["reason"] != DropWriterError || !strings.Contains(gap["error"].(string), "input/output error") {
		t.Fatalf("gap = %v", gap)
	}
	if st := readStateFile(t, env.state); len(st.Suspect) != 0 {
		t.Fatalf("a reported suspect range is still pending: %v", st.Suspect)
	}
}

// Round-2 finding 3: a suspect range not reported yet (the writer never
// recovered before Stop) is persisted, and the next boot's carried_over gap
// reports it with the boot that wrote it.
func TestSuspectRangeSurvivesARestart(t *testing.T) {
	shortBackoff(t, 10*time.Millisecond)
	state := filepath.Join(t.TempDir(), "state")
	env := setup(t, state, nil)
	rec := mustStart(t, env)
	failing := func(op string) error {
		if op == "segment.sync" || op == "segment.close" {
			return syscall.EIO
		}
		return nil
	}
	faultHook.Store(&failing)
	rec.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: &BodyData{Bytes: []byte("never durable")}})
	waitFor(t, "the writer to fail", func() bool { return rec.w.writerErrors.Load() > 0 })
	stop(t)
	st := readStateFile(t, state)
	if len(st.Suspect) != 1 || st.Suspect[0].BootID != rec.bootID {
		t.Fatalf("persisted suspect ranges = %v", st.Suspect)
	}
	want := st.Suspect[0]

	faultHook.Store(nil)
	next := setup(t, state, nil)
	mustStart(t, next)
	flush(t)
	ranges := suspectGaps(readEvents(t, next.spool))
	if len(ranges) != 1 || ranges[0]["boot_id"] != want.BootID || ranges[0]["segment"] != want.Segment ||
		uint64(ranges[0]["first_seq"].(float64)) != want.FirstSeq || uint64(ranges[0]["last_seq"].(float64)) != want.LastSeq {
		t.Fatalf("carried-over suspect ranges = %v, want %+v", ranges, want)
	}
	if gap := ofType(readEvents(t, next.spool), TypeGap)[0]; gap["reason"] != "carried_over" {
		t.Fatalf("gap = %v", gap)
	}
}

// An event whose reused blob was deleted and could not be written again is
// in the segment: its seq stays used (no later event repeats it) and it is
// suspect, since its blob may be missing.
func TestFailedBlobRewriteKeepsSeqsAndIsSuspect(t *testing.T) {
	shortBackoff(t, 10*time.Millisecond)
	env := setup(t, "", func(o *TestOverrides) { o.BlobThresholdBytes = 64 })
	rec := mustStart(t, env)
	payload := bytes.Repeat([]byte("archived by the shipper "), 10)
	rec.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: &BodyData{Bytes: payload}})
	flush(t)
	var rewriting, failed atomic.Bool
	trace := func(op, path string) {
		switch op {
		case "blob.reuse":
			_ = os.Remove(path)
		case "blob.rewrite":
			rewriting.Store(true)
		}
	}
	traceHook.Store(&trace)
	hook := func(op string) error {
		if op == "blob.dirsync" && rewriting.Load() && failed.CompareAndSwap(false, true) {
			return syscall.EIO
		}
		return nil
	}
	faultHook.Store(&hook)
	rec.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: &BodyData{Bytes: payload}})
	waitFor(t, "the failed rewrite and the recovery", func() bool {
		return failed.Load() && rec.w.writerErrors.Load() > 0 && rec.CaptureEvents()
	})
	traceHook.Store(nil)
	rec.Emit(&Event{Type: TypeHeartbeat, Data: map[string]any{"after": true}})
	flush(t)
	events := readEvents(t, env.spool)
	seen := map[float64]bool{}
	for _, ev := range events {
		if seen[ev["seq"].(float64)] {
			t.Fatalf("seq %v written twice", ev["seq"])
		}
		seen[ev["seq"].(float64)] = true
	}
	bodies := ofType(events, TypeClientBody)
	ranges := suspectGaps(events)
	if len(bodies) != 2 || len(ranges) != 1 || ranges[0]["first_seq"] != bodies[1]["seq"] || ranges[0]["last_seq"] != bodies[1]["seq"] {
		t.Fatalf("bodies %v, suspect ranges %v", bodies, ranges)
	}
}

type panickingContext struct{ context.Context }

func (panickingContext) Value(any) any { panic("context lookup failed") }

// Round-2 finding 5: a tap panic inside WithAttempt returns the caller's
// context, never nil (which the conductor would replace with Background,
// losing cancellation, deadline and values).
func TestWithAttemptKeepsTheContextAfterAPanic(t *testing.T) {
	env := setup(t, "", nil)
	mustStart(t, env)
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	ctx := panickingContext{parent}
	got := WithAttempt(ctx)
	if got != ctx || got.Err() != context.Canceled {
		t.Fatalf("WithAttempt returned %v (err %v)", got, got.Err())
	}
}

// Round-2 finding 7: an outbound body an executor cannot record as sent is
// dropped_body with not_captured, counted against its request, never a
// complete empty body; it is not a gap.
func TestUncapturedOutboundBodyIsNeverFull(t *testing.T) {
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	in := rec.BeginIngress(RouteInference, time.Now())
	ctx := WithAttempt(WithIngress(context.Background(), in))
	TapUpstreamRequest(ctx, UpstreamRequest{URL: "https://devin.example/chat", Body: []byte("rendering"), BodyNotCaptured: true})
	TapUpstreamWSRequest(ctx, UpstreamRequest{URL: "wss://devin.example/ws", BodyNotCaptured: true})
	flush(t)
	events := readEvents(t, env.spool)
	for _, ev := range append(ofType(events, TypeUpstreamRequest), ofType(events, TypeUpstreamWS)...) {
		if ev["capture"] != CaptureDroppedBody || ev["body_dropped"] != DropNotCaptured || ev["body"] != nil {
			t.Fatalf("%v", ev)
		}
	}
	if in.Drops() != 2 {
		t.Fatalf("request drops = %d", in.Drops())
	}
	if _, counted := rec.ledger.totals()[DropNotCaptured]; counted || len(ofType(events, TypeGap)) != 0 {
		t.Fatal("not_captured was reported as a gap")
	}
}

// Round-2 precondition: the boot event carries the build version, commit and
// date main sets from the release ldflags (-X main.Version, main.Commit,
// main.BuildDate, copied into buildinfo by main's init before any server
// starts the recorder), read when capture starts.
func TestBootEventCarriesTheBuildInfo(t *testing.T) {
	version, commit, date := buildinfo.Version, buildinfo.Commit, buildinfo.BuildDate
	t.Cleanup(func() { buildinfo.Version, buildinfo.Commit, buildinfo.BuildDate = version, commit, date })
	buildinfo.Version, buildinfo.Commit, buildinfo.BuildDate = "v8.9.9-fleet.6", "0123456789abcdef0123456789abcdef01234567", "2026-10-28T00:00:00Z"
	env := setup(t, "", nil)
	mustStart(t, env)
	flush(t)
	boot := ofType(readEvents(t, env.spool), TypeBoot)[0]
	if boot["build_version"] != "v8.9.9-fleet.6" || boot["build_commit"] != "0123456789abcdef0123456789abcdef01234567" || boot["build_date"] != "2026-10-28T00:00:00Z" {
		t.Fatalf("boot event = %v", boot)
	}
}
