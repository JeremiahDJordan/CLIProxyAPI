//go:build unix

package archive

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// largeCompletedEvent is a Responses response.completed SSE event (or, with
// prefix "", a WebSocket frame) whose output text is n bytes, with a
// response ID, a model and usage, as an upstream sends a long answer.
func largeCompletedEvent(prefix string, n int) []byte {
	var b bytes.Buffer
	b.WriteString(prefix)
	b.WriteString(`{"type":"response.completed","response":{"id":"resp_large","model":"gpt-large","output":[{"id":"msg_large","type":"message","content":[{"type":"output_text","text":"`)
	b.Write(bytes.Repeat([]byte("x"), n))
	b.WriteString(`"}]}],"usage":{"input_tokens":3,"output_tokens":5}}}`)
	return b.Bytes()
}

// Round-3 finding 1: inspecting upstream JSON and usage objects must not
// copy the whole input outside the queue's reservations. With the queue
// full, each refused 16 MiB JSON event allocates nothing of its size: the
// upstream SSE event, the upstream WebSocket frame and a usage object.
func TestRefusedJSONIsNotCopied(t *testing.T) {
	env := setup(t, "", func(o *TestOverrides) { o.QueueBytes = 1 << 20; o.FsyncInterval = time.Hour })
	rec := mustStart(t, env)
	in := rec.BeginIngress(RouteInference, time.Now())
	ctx := WithAttempt(WithIngress(context.Background(), in))
	TapUpstreamResponse(ctx, 200, nil)
	flush(t)
	sse := largeCompletedEvent("data: ", 16<<20)
	frame := largeCompletedEvent("", 16<<20)
	usage := []byte(`{"input_tokens":1,"note":"` + strings.Repeat("y", 16<<20) + `"}`)
	if !rec.q.reserve(rec.q.limit) {
		t.Fatal("cannot fill the queue")
	}
	defer rec.q.release(rec.q.limit)
	cases := []struct {
		name string
		tap  func()
	}{
		{"upstream_event", func() { TapUpstreamChunk(ctx, sse) }},
		{"upstream_ws", func() { TapUpstreamWSFrame(ctx, frame, false) }},
		{"usage", func() { TapUsage(ctx, UsageSourceReporter, "m", usage) }},
	}
	for _, c := range cases {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		c.tap()
		runtime.ReadMemStats(&after)
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= 1<<20 {
			t.Errorf("%s: a refused 16 MiB JSON input allocated %d bytes", c.name, allocated)
		}
	}
	// The events were refused, and the identities still read.
	if got := rec.ledger.totals()[DropQueueFull].Events; got < 4 {
		t.Fatalf("queue_full events = %d", got)
	}
	if sum := in.Summary(); len(sum.ResponseIDs) != 1 || sum.ResponseIDs[0] != "resp_large" {
		t.Fatalf("identities = %+v", sum.identities)
	}
	runtime.KeepAlive(sse)
	runtime.KeepAlive(frame)
	runtime.KeepAlive(usage)
}

// Round-3 finding 1: an identity kept from a large event (the response ID
// on the attempt and the request) is a copy of its own, so it does not keep
// the event's bytes alive once the tap returns.
func TestKeptIdentitiesDoNotPinTheirEvent(t *testing.T) {
	env := setup(t, "", func(o *TestOverrides) { o.QueueBytes = 1 << 20; o.FsyncInterval = time.Hour })
	rec := mustStart(t, env)
	in := rec.BeginIngress(RouteInference, time.Now())
	ctx := WithAttempt(WithIngress(context.Background(), in))
	TapUpstreamResponse(ctx, 200, nil)
	flush(t)
	if !rec.q.reserve(rec.q.limit) {
		t.Fatal("cannot fill the queue")
	}
	defer rec.q.release(rec.q.limit)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	func() {
		// The executor's buffer, released once the tap returns.
		chunk := largeCompletedEvent("data: ", 16<<20)
		TapUpstreamChunk(ctx, chunk)
	}()
	runtime.GC()
	runtime.ReadMemStats(&after)
	if retained := int64(after.HeapAlloc) - int64(before.HeapAlloc); retained > 1<<20 {
		t.Fatalf("a kept response ID retained %d heap bytes after GC", retained)
	}
	if sum := in.Summary(); len(sum.ResponseIDs) != 1 || sum.ResponseIDs[0] != "resp_large" {
		t.Fatalf("identities = %+v", sum.identities)
	}
}

// Round-3 finding 1: with room in the queue the usage copy is still made,
// redacted, and identities over the length bound are dropped.
func TestInspectStillRecordsUsageAndBoundsIdentities(t *testing.T) {
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	in := rec.BeginIngress(RouteInference, time.Now())
	ctx := WithAttempt(WithIngress(context.Background(), in))
	TapUpstreamResponse(ctx, 200, nil)
	long := strings.Repeat("r", maxOwnedLen+1)
	TapUpstreamChunk(ctx, []byte(`data: {"type":"response.completed","response":{"id":"`+long+`","model":"gpt-x","usage":{"input_tokens":2,"access_token":"fake-usage-token"}}}`))
	TapUpstreamChunk(ctx, []byte(`data: {"type":"response.created","response":{"id":"resp_ok","previous_response_id":"resp_prev"}}`))
	flush(t)
	usage := ofType(readEvents(t, env.spool), TypeUsage)
	if len(usage) != 1 || usage[0]["model"] != "gpt-x" || usage[0]["event"] != "response.completed" {
		t.Fatalf("usage events = %v", usage)
	}
	raw := usage[0]["usage"].(map[string]any)
	if raw["input_tokens"] != float64(2) || raw["access_token"] != Redacted {
		t.Fatalf("usage = %v", raw)
	}
	sum := in.Summary()
	if len(sum.ResponseIDs) != 1 || sum.ResponseIDs[0] != "resp_ok" || sum.PreviousResponseID != "resp_prev" {
		t.Fatalf("identities = %+v", sum.identities)
	}
	if in.rec.q.used.Load() != 0 {
		t.Fatalf("queue bytes left: %d", in.rec.q.used.Load())
	}
}

// Round-3 finding 4: a panic recovered in a tap that had found its request
// loses what the tap was recording, so the request counts a drop (its
// ingress_end must not look complete); the reservation is still returned.
func TestRecoveredTapPanicCountsAgainstItsRequest(t *testing.T) {
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	in := rec.BeginIngress(RouteInference, time.Now())
	ctx := WithAttempt(WithIngress(context.Background(), in))
	TapUpstreamResponse(ctx, 200, nil)
	flush(t)
	panicking := func(op string) error {
		if op == "tap.copy" {
			panic("copy failed")
		}
		return nil
	}
	faultHook.Store(&panicking)
	TapUpstreamChunk(ctx, []byte("lost chunk"))
	TapUsage(ctx, UsageSourceReporter, "m", []byte(`{"input_tokens":1}`))
	TapUpstreamRequest(ctx, UpstreamRequest{URL: "https://api.example/v1/messages", Body: []byte(`{}`)})
	faultHook.Store(nil)
	if got := in.Drops(); got != 3 {
		t.Fatalf("request drops after three recovered tap panics = %d", got)
	}
	in.Emit(&Event{Type: TypeIngressEnd, Capture: CaptureFull, ReportDrops: true})
	flush(t)
	ends := ofType(readEvents(t, env.spool), TypeIngressEnd)
	if len(ends) != 1 || ends[0]["capture_drops"] != float64(3) {
		t.Fatalf("ingress_end = %v", ends)
	}
	if used := rec.q.used.Load(); used != 0 {
		t.Fatalf("%d queue bytes stranded by a panicking copy", used)
	}
}

// Round-3 finding 2: a range made suspect by a failed fsync is persisted
// before the failure handling retries the segment's close, which can hang
// on a suspended pool: here the close blocks, and the state directory
// already holds the range a next boot would report.
func TestSuspectRangePersistedBeforeCloseRetry(t *testing.T) {
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	entered, release := make(chan struct{}), make(chan struct{})
	var failed, blocked atomic.Bool
	hook := func(op string) error {
		if op == "segment.sync" && failed.CompareAndSwap(false, true) {
			return syscall.EIO
		}
		if op == "segment.close" && blocked.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		return nil
	}
	// Installed before the event is written, so its first fsync fails.
	faultHook.Store(&hook)
	in := rec.BeginIngress(RouteInference, time.Now())
	in.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: &BodyData{Bytes: []byte("not synced yet")}})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the close retry never ran")
	}
	persisted := readStateFile(t, env.state).Suspect
	close(release)
	faultHook.Store(nil)
	if len(persisted) != 1 || persisted[0].BootID != rec.bootID || persisted[0].FirstSeq == 0 {
		t.Fatalf("suspect ranges persisted while the close retry hung = %+v", persisted)
	}
}

// Round-3 finding 2, with a real process exit: the recorder runs in a
// child process that exits inside the close retry after a failed fsync.
// The range survives in the state directory, and the next boot reports it.
func TestSuspectRangeSurvivesExitDuringCloseRetry(t *testing.T) {
	if root := os.Getenv("ARCHIVE_TEST_EXIT_ROOT"); root != "" {
		env := setup(t, filepath.Join(root, "state"), nil)
		rec := mustStart(t, env)
		var failed atomic.Bool
		hook := func(op string) error {
			if op == "segment.sync" && failed.CompareAndSwap(false, true) {
				return syscall.EIO
			}
			if op == "segment.close" {
				os.Exit(77)
			}
			return nil
		}
		// Installed before the event is written, so its first fsync fails.
		faultHook.Store(&hook)
		in := rec.BeginIngress(RouteInference, time.Now())
		in.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: &BodyData{Bytes: []byte("exit sample")}})
		select {
		case <-rec.done:
		case <-time.After(30 * time.Second):
		}
		t.Fatal("the close retry did not run")
	}
	root := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestSuspectRangeSurvivesExitDuringCloseRetry$")
	// TMPDIR keeps the child's spool under root: its exit skips cleanup.
	cmd.Env = append(os.Environ(), "ARCHIVE_TEST_EXIT_ROOT="+root, "TMPDIR="+root)
	out, err := cmd.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 77 {
		t.Fatalf("child: %v\n%s", err, out)
	}
	state := filepath.Join(root, "state")
	st := readStateFile(t, state)
	if len(st.Suspect) != 1 {
		t.Fatalf("suspect ranges after the exit = %+v", st.Suspect)
	}
	// The next boot reports the range in a gap.
	env := setup(t, state, nil)
	mustStart(t, env)
	flush(t)
	gaps := suspectGaps(readEvents(t, env.spool))
	if len(gaps) != 1 || gaps[0]["boot_id"] != st.Suspect[0].BootID || gaps[0]["first_seq"] != float64(st.Suspect[0].FirstSeq) {
		t.Fatalf("next boot's suspect ranges = %v (persisted %+v)", gaps, st.Suspect)
	}
}

// Round-3 finding 5: the usage reporter's record keeps its
// token_breakdown.quality (a breakdown is a count, not a credential), and
// "credential" is a credential name part.
func TestRedactJSONKeepsReporterShape(t *testing.T) {
	reporter := `{"input_tokens":3,"output_tokens":2,"reasoning_tokens":0,"cached_tokens":0,"cache_read_tokens":0,"cache_creation_tokens":0,"total_tokens":5,` +
		`"token_breakdown":{"schema_version":2,"quality":"complete","total_tokens":5,"input":{"total_tokens":3,"uncached_tokens":3,"cache_read_tokens":0,"cache_write_tokens":0},` +
		`"output":{"total_tokens":2,"non_reasoning_tokens":2,"reasoning_tokens":0},"unclassified_tokens":0},"response_service_tier":"default"}`
	if got := string(RedactJSON([]byte(reporter))); got != reporter {
		t.Fatalf("reporter record changed:\n got %s\nwant %s", got, reporter)
	}
	if got := string(RedactJSON(`{"client_credential":"opaque","tokenBreakdown":{"quality":"inconsistent"}}`)); got != `{"client_credential":"[redacted]","tokenBreakdown":{"quality":"inconsistent"}}` {
		t.Fatalf("got %s", got)
	}
	headers := RedactHeaders(map[string][]string{"X-Upstream-Credential": {"opaque"}, "Access-Control-Allow-Credentials": {"true"}})
	if headers["X-Upstream-Credential"][0] != Redacted || headers["Access-Control-Allow-Credentials"][0] != "true" {
		t.Fatalf("headers = %v", headers)
	}
}
