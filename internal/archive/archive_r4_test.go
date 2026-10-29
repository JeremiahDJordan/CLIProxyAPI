//go:build unix

package archive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stallingBody returns head, then blocks until it is closed (as a transport
// body does when the upstream stops sending), counting what it returned.
type stallingBody struct {
	head   []byte
	read   atomic.Int64
	once   sync.Once
	closed chan struct{}
}

func newStallingBody(head []byte) *stallingBody {
	return &stallingBody{head: head, closed: make(chan struct{})}
}

func (b *stallingBody) Read(p []byte) (int, error) {
	if off := int(b.read.Load()); off < len(b.head) {
		n := copy(p, b.head[off:])
		b.read.Add(int64(n))
		return n, nil
	}
	<-b.closed
	return 0, errors.New("read on closed body")
}

func (b *stallingBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

// discardedEvents returns the upstream_event events of discarded bodies.
func discardedEvents(events []event) []event {
	var out []event
	for _, ev := range ofType(events, TypeUpstreamEvent) {
		if ev["discarded"] == true {
			out = append(out, ev)
		}
	}
	return out
}

func discardedSetup(t *testing.T, mutate func(*TestOverrides)) (*testEnv, *Recorder, *Ingress, context.Context) {
	t.Helper()
	env := setup(t, "", mutate)
	rec := mustStart(t, env)
	in := rec.BeginIngress(RouteInference, time.Now())
	ctx := WithAttempt(WithIngress(context.Background(), in))
	TapUpstreamRequest(ctx, UpstreamRequest{URL: "https://api.example/v1/responses", Body: []byte(`{}`)})
	TapUpstreamResponse(ctx, 415, nil)
	return env, rec, in, ctx
}

// Round-4 finding 1: a discarded body is read on the archive's own
// goroutine. TapDiscardedBody returns at once even when the body stalls
// after its first bytes; the body is recorded as truncated when its time
// bound ends, as the attempt's first sub-attempt, and the request counts
// the drop, also in the ledger (so heartbeats and gaps show it).
func TestDiscardedBodyThatStallsNeverBlocks(t *testing.T) {
	env, rec, in, ctx := discardedSetup(t, func(o *TestOverrides) { o.DiscardedBodyWait = 100 * time.Millisecond })
	body := newStallingBody([]byte(`{"error":"zst`))
	started := time.Now()
	if !TapDiscardedBody(ctx, body, body.Close) {
		t.Fatal("the archive did not take the body")
	}
	if took := time.Since(started); took > 50*time.Millisecond {
		t.Fatalf("TapDiscardedBody took %v", took)
	}
	// The resend is a new sub-attempt meanwhile.
	TapUpstreamRequest(ctx, UpstreamRequest{URL: "https://api.example/v1/responses", Body: []byte(`{}`), Resend: ResendCompressionRejected})
	waitFor(t, "the stalled body's event", func() bool {
		flush(t)
		return len(discardedEvents(readEvents(t, env.spool))) == 1
	})
	ev := discardedEvents(readEvents(t, env.spool))[0]
	if ev["sub_attempt"] != float64(0) || ev["chunk_seq"] != float64(1) || ev["capture"] != CaptureDroppedBody ||
		ev["body_dropped"] != DropTruncated || ev["stopped"] != discardedStoppedTimeout || ev["read_bytes"] != float64(13) || ev["body"] != nil {
		t.Fatalf("discarded upstream_event = %v", ev)
	}
	if in.Drops() != 1 || rec.ledger.totals()[DropTruncated].Bodies != 1 {
		t.Fatalf("request drops %d, ledger %v", in.Drops(), rec.ledger.totals())
	}
	waitFor(t, "the buffers' reservation", func() bool { return rec.q.used.Load() == 0 })
	select {
	case <-body.closed:
	default:
		t.Fatal("the stalled body was not closed")
	}
}

// Round-4 finding 1: a body still arriving when its attempt ends is
// finalized then, before attempt_end, without waiting for the read.
func TestDiscardedBodyEndsWithItsAttempt(t *testing.T) {
	env, _, in, ctx := discardedSetup(t, nil)
	body := newStallingBody([]byte(`{"error"`))
	if !TapDiscardedBody(ctx, body, body.Close) {
		t.Fatal("the archive did not take the body")
	}
	waitFor(t, "the first bytes", func() bool { return body.read.Load() == 8 })
	EndAttempt(ctx, AttemptEnd{StatusCode: 200, Success: true})
	flush(t)
	events := readEvents(t, env.spool)
	discarded := discardedEvents(events)
	if len(discarded) != 1 || discarded[0]["body_dropped"] != DropTruncated || discarded[0]["stopped"] != discardedStoppedAttemptEnd {
		t.Fatalf("discarded upstream_event = %v", discarded)
	}
	end := ofType(events, TypeAttemptEnd)
	if len(end) != 1 || end[0]["seq"].(float64) < discarded[0]["seq"].(float64) {
		t.Fatalf("attempt_end %v does not follow the discarded body %v", end, discarded[0])
	}
	if in.Drops() != 1 {
		t.Fatalf("request drops = %d", in.Drops())
	}
}

// Round-4 finding 1: a complete body is recorded byte for byte as the
// sub-attempt it answered, even when the resend's events are queued first;
// a body over the limit is truncated (stopped: limit) without being read
// past it, and counted in the ledger.
func TestDiscardedBodyRecordedOrTruncatedAtTheLimit(t *testing.T) {
	env, rec, in, ctx := discardedSetup(t, nil)
	small := bytes.Repeat([]byte("rejected "), 2000) // 18 000 bytes: several buffers
	if !TapDiscardedBody(ctx, io.NopCloser(bytes.NewReader(small)), func() error { return nil }) {
		t.Fatal("the archive did not take the body")
	}
	waitFor(t, "the small body", func() bool {
		flush(t)
		return len(discardedEvents(readEvents(t, env.spool))) == 1
	})
	ev := discardedEvents(readEvents(t, env.spool))[0]
	if ev["capture"] != CaptureFull || !bytes.Equal(decodeBody(t, env.spool, ev["body"].(map[string]any)), small) || ev["sub_attempt"] != float64(0) {
		t.Fatalf("discarded upstream_event = %v", ev)
	}
	if in.Drops() != 0 {
		t.Fatalf("a complete body counted %d drops", in.Drops())
	}
	large := &countingReader{r: bytes.NewReader(bytes.Repeat([]byte("x"), 3<<20))}
	if !TapDiscardedBody(ctx, io.NopCloser(large), func() error { return nil }) {
		t.Fatal("the archive did not take the large body")
	}
	waitFor(t, "the large body", func() bool {
		flush(t)
		return len(discardedEvents(readEvents(t, env.spool))) == 2
	})
	ev = discardedEvents(readEvents(t, env.spool))[1]
	if ev["body_dropped"] != DropTruncated || ev["stopped"] != discardedStoppedLimit || ev["read_bytes"] != float64(discardedBodyLimit) {
		t.Fatalf("large discarded upstream_event = %v", ev)
	}
	if got := large.n.Load(); got > discardedBodyLimit+1 {
		t.Fatalf("read %d bytes of a body over the %d-byte limit", got, discardedBodyLimit)
	}
	if in.Drops() != 1 || rec.ledger.totals()[DropTruncated].Bodies != 1 {
		t.Fatalf("request drops %d, ledger %v", in.Drops(), rec.ledger.totals())
	}
	waitFor(t, "the buffers' reservation", func() bool { return rec.q.used.Load() == 0 })
}

type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// failingBody returns head and then fails, as a reset connection does.
type failingBody struct {
	head []byte
	done bool
}

func (b *failingBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.ErrUnexpectedEOF
	}
	b.done = true
	return copy(p, b.head), nil
}

func (*failingBody) Close() error { return nil }

// Round-4 finding 1: a read that fails before the body's end leaves it
// incomplete: it is truncated (stopped: read_error, with the error's class),
// never recorded as a full body, and counted.
func TestDiscardedBodyReadErrorIsTruncated(t *testing.T) {
	env, rec, in, ctx := discardedSetup(t, nil)
	if !TapDiscardedBody(ctx, &failingBody{head: []byte(`{"err`)}, func() error { return nil }) {
		t.Fatal("the archive did not take the body")
	}
	waitFor(t, "the failed body's event", func() bool {
		flush(t)
		return len(discardedEvents(readEvents(t, env.spool))) == 1
	})
	ev := discardedEvents(readEvents(t, env.spool))[0]
	if ev["body_dropped"] != DropTruncated || ev["stopped"] != discardedStoppedReadError || ev["read_error"] != "eof_unexpected" ||
		ev["read_bytes"] != float64(5) || ev["body"] != nil {
		t.Fatalf("discarded upstream_event = %v", ev)
	}
	if in.Drops() != 1 || rec.ledger.totals()[DropTruncated].Bodies != 1 {
		t.Fatalf("request drops %d, ledger %v", in.Drops(), rec.ledger.totals())
	}
}

// Round-4 finding 1: a panic while reading a discarded body (here the
// archive's own, injected; a decoder's is the same) is contained on the
// reader goroutine: the event is queued without its body (tap_panic), the
// request counts the drop, the reservation is returned and the body closed.
func TestDiscardedBodyReadPanicIsContainedAndCounted(t *testing.T) {
	env, rec, in, ctx := discardedSetup(t, nil)
	panicking := func(op string) error {
		if op == "tap.discarded" {
			panic("read failed")
		}
		return nil
	}
	faultHook.Store(&panicking)
	defer faultHook.Store(nil)
	body := newStallingBody([]byte("never read"))
	before := tapPanics.Load()
	if !TapDiscardedBody(ctx, body, body.Close) {
		t.Fatal("the archive did not take the body")
	}
	waitFor(t, "the panicking read's event", func() bool {
		flush(t)
		return len(discardedEvents(readEvents(t, env.spool))) == 1
	})
	ev := discardedEvents(readEvents(t, env.spool))[0]
	if ev["body_dropped"] != DropTapPanic || ev["body"] != nil {
		t.Fatalf("discarded upstream_event = %v", ev)
	}
	if in.Drops() != 1 || tapPanics.Load() != before+1 {
		t.Fatalf("request drops %d, tap panics %d", in.Drops(), tapPanics.Load()-before)
	}
	waitFor(t, "the reservation", func() bool { return rec.q.used.Load() == 0 })
	waitFor(t, "the close", func() bool {
		select {
		case <-body.closed:
			return true
		default:
			return false
		}
	})
}

// Round-4 finding 2: with the queue full, a discarded body is not read and
// nothing of its size is allocated; the executor keeps it (and closes it,
// as without capture), and the drop is counted.
func TestDiscardedBodyRefusedByAFullQueueIsNotRead(t *testing.T) {
	_, rec, in, ctx := discardedSetup(t, func(o *TestOverrides) { o.QueueBytes = 1 << 20; o.FsyncInterval = time.Hour })
	flush(t)
	if !rec.q.reserve(rec.q.limit) {
		t.Fatal("cannot fill the queue")
	}
	defer rec.q.release(rec.q.limit)
	body := &countingReader{r: bytes.NewReader(bytes.Repeat([]byte("r"), 512<<10))}
	before := rec.ledger.totals()[DropQueueFull]
	runtime.GC()
	var ms0, ms1 runtime.MemStats
	runtime.ReadMemStats(&ms0)
	owned := TapDiscardedBody(ctx, io.NopCloser(body), func() error { return nil })
	runtime.ReadMemStats(&ms1)
	if owned || body.n.Load() != 0 {
		t.Fatalf("owned %v, read %d bytes with the queue full", owned, body.n.Load())
	}
	if allocated := ms1.TotalAlloc - ms0.TotalAlloc; allocated >= 64<<10 {
		t.Fatalf("a refused 512 KiB body allocated %d bytes", allocated)
	}
	if got := rec.ledger.totals()[DropQueueFull]; got.Events != before.Events+1 || in.Drops() != 1 {
		t.Fatalf("queue_full %+v (was %+v), request drops %d", got, before, in.Drops())
	}
}

// Round-4 finding 2: a body larger than the queue can hold is read only as
// far as its reservations reach; it is then queued without its body
// (queue_full), and every reservation is returned.
func TestDiscardedBodyStopsAtItsReservation(t *testing.T) {
	env, rec, in, ctx := discardedSetup(t, func(o *TestOverrides) { o.QueueBytes = 64 << 10; o.FsyncInterval = time.Hour })
	flush(t)
	body := &countingReader{r: bytes.NewReader(bytes.Repeat([]byte("r"), 512<<10))}
	if !TapDiscardedBody(ctx, io.NopCloser(body), func() error { return nil }) {
		t.Fatal("the archive did not take the body")
	}
	waitFor(t, "the refused body's event", func() bool {
		flush(t)
		return len(discardedEvents(readEvents(t, env.spool))) == 1
	})
	ev := discardedEvents(readEvents(t, env.spool))[0]
	if ev["body_dropped"] != DropQueueFull || ev["body"] != nil {
		t.Fatalf("discarded upstream_event = %v", ev)
	}
	if got := body.n.Load(); got > 64<<10 {
		t.Fatalf("read %d bytes with a 64 KiB queue", got)
	}
	if in.Drops() != 1 || rec.ledger.totals()[DropQueueFull].Bodies != 1 {
		t.Fatalf("request drops %d, ledger %v", in.Drops(), rec.ledger.totals())
	}
	waitFor(t, "the reservations", func() bool { return rec.q.used.Load() == 0 })
}

// Round-4 finding 2: once Stop has begun nothing is read, and Stop
// finalizes a body still being read (stopped) and unblocks its read.
func TestDiscardedBodyAndStop(t *testing.T) {
	env, rec, in, ctx := discardedSetup(t, nil)
	stalled := newStallingBody([]byte("partial"))
	if !TapDiscardedBody(ctx, stalled, stalled.Close) {
		t.Fatal("the archive did not take the body")
	}
	waitFor(t, "the first bytes", func() bool { return stalled.read.Load() == 7 })
	stop(t)
	select {
	case <-stalled.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not unblock the read")
	}
	events := readEvents(t, env.spool)
	discarded := discardedEvents(events)
	if len(discarded) != 1 || discarded[0]["body_dropped"] != DropStopped {
		t.Fatalf("discarded upstream_event at Stop = %v", discarded)
	}
	if in.Drops() != 1 {
		t.Fatalf("request drops = %d", in.Drops())
	}
	waitFor(t, "the reservations", func() bool { return rec.q.used.Load() == 0 })

	after := &countingReader{r: strings.NewReader("after stop")}
	if TapDiscardedBody(ctx, io.NopCloser(after), func() error { return nil }) || after.n.Load() != 0 {
		t.Fatalf("a body discarded after Stop was read (%d bytes)", after.n.Load())
	}
}

// jsonEscapes is n bytes of JSON escapes of the byte hex (two hex digits),
// six bytes each; it is built from 0x5c, so this source holds no escape.
func jsonEscapes(n int, hex string) string {
	return strings.Repeat(string([]byte{0x5c, 'u', '0', '0', hex[0], hex[1]}), n/6)
}

// largeEscapedID is a response.completed event whose response ID is n
// bytes of escapes.
func largeEscapedID(n int) []byte {
	return []byte(`data: {"type":"response.completed","response":{"id":"` + jsonEscapes(n, "61") +
		`","model":"gpt-x","usage":{"input_tokens":1}}}`)
}

// Round-4 finding 3: inspecting upstream JSON bounds every raw token before
// it is unescaped and checks the identity limits and duplicates before it
// copies. With the queue full, an 8 MiB escaped ID, an 8 MiB escaped member
// name, and a 10 MiB body of 50 000 identical 200-byte item IDs allocate
// nothing of their size, and only one ID is kept.
func TestInspectBoundsEscapedAndDuplicateIdentities(t *testing.T) {
	_, rec, in, ctx := discardedSetup(t, func(o *TestOverrides) { o.QueueBytes = 1 << 20; o.FsyncInterval = time.Hour })
	flush(t)
	if !rec.q.reserve(rec.q.limit) {
		t.Fatal("cannot fill the queue")
	}
	defer rec.q.release(rec.q.limit)
	escapedID := largeEscapedID(8 << 20)
	escapedName := []byte(`data: {"` + jsonEscapes(8<<20, "62") + `":1,"type":"response.completed","response":{"id":"resp_named","usage":{"input_tokens":1}}}`)
	id := strings.Repeat("i", 200)
	var dup bytes.Buffer
	dup.WriteString(`{"object":"response","id":"resp_dup","output":[`)
	for i := range 50000 {
		if i > 0 {
			dup.WriteByte(',')
		}
		dup.WriteString(`{"type":"message","id":"` + id + `"}`)
	}
	dup.WriteString(`],"usage":{"input_tokens":1}}`)
	escapedPrev := []byte(`{"model":"m","previous_response_id":"` + jsonEscapes(8<<20, "63") + `"}`)
	cases := []struct {
		name string
		tap  func()
	}{
		{"escaped id", func() { TapUpstreamChunk(ctx, escapedID) }},
		{"escaped member name", func() { TapUpstreamChunk(ctx, escapedName) }},
		{"duplicate ids", func() { TapUpstreamChunk(ctx, dup.Bytes()) }},
		{"escaped previous_response_id", func() {
			TapUpstreamRequest(ctx, UpstreamRequest{URL: "https://api.example/v1/responses", Body: escapedPrev})
		}},
	}
	for _, c := range cases {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		c.tap()
		runtime.ReadMemStats(&after)
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= 256<<10 {
			t.Errorf("%s: allocated %d bytes", c.name, allocated)
		}
	}
	sum := in.Summary()
	if len(sum.OutputItemIDs) != 1 || sum.OutputItemIDs[0] != id || sum.PreviousResponseID != "" ||
		!slicesEqual(sum.ResponseIDs, []string{"resp_named", "resp_dup"}) {
		t.Fatalf("identities = %+v", sum.identities)
	}
	runtime.KeepAlive(escapedID)
	runtime.KeepAlive(escapedName)
	runtime.KeepAlive(escapedPrev)
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Round-4 finding 3: short escaped strings are still read, unescaped.
func TestInspectStillReadsShortEscapedIdentities(t *testing.T) {
	_, _, in, ctx := discardedSetup(t, nil)
	TapUpstreamChunk(ctx, []byte(`data: {"type":"response.completed","response":{"id":"resp_`+jsonEscapes(6, "31")+`","previous_response_id":"resp_`+jsonEscapes(6, "30")+`"}}`))
	sum := in.Summary()
	if len(sum.ResponseIDs) != 1 || sum.ResponseIDs[0] != "resp_1" || sum.PreviousResponseID != "resp_0" {
		t.Fatalf("identities = %+v", sum.identities)
	}
	if got := JSONText(`{"a":{"b":"x\"y"},"c":[1,{"d":2}],"e":"`+strings.Repeat("z", 300)+`"}`, 256, "a", "b"); got != `x"y` {
		t.Fatalf("JSONText = %q", got)
	}
	if got := JSONText(`{"e":"`+strings.Repeat("z", 300)+`"}`, 256, "e"); got != "" {
		t.Fatalf("JSONText kept a 300-byte value: %q", got)
	}
}
