package archive

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// Discarded upstream bodies (design section 3, "Outbound request and
// upstream response"): the body of a response an executor discards unread
// before resending (Codex's rejection of a zstd request body). Without
// capture the executor closes it at once, so the archive reads it on its
// own goroutine and never holds up the resend: a body that stalls changes
// nothing for the request.

// Bounds on reading a discarded body.
const (
	// discardedBodyLimit is the longest discarded body recorded; a longer
	// one is recorded as truncated (stopped: limit), and the rest is not read.
	discardedBodyLimit = 1 << 20
	// discardedBodyWait bounds how long a discarded body is read.
	discardedBodyWait = time.Second
	// discardedBodyMinBuffer is the first buffer's size; each later buffer is
	// as large as what was read so far.
	discardedBodyMinBuffer = 4 << 10
)

// Why reading a discarded body stopped before its end (the stopped field of
// a truncated upstream_event).
const (
	discardedStoppedLimit      = "limit"
	discardedStoppedTimeout    = "timeout"
	discardedStoppedAttemptEnd = "attempt_end"
	discardedStoppedReadError  = "read_error"
)

type discardedEventData struct {
	ChunkSeq  uint32 `json:"chunk_seq"`
	Discarded bool   `json:"discarded"`
	Stopped   string `json:"stopped,omitempty"`
	ReadError string `json:"read_error,omitempty"`
	ReadBytes int64  `json:"read_bytes,omitempty"`
}

// discardedBody reads one discarded body into buffers whose queue bytes are
// reserved before they are allocated, and queues its upstream_event once:
// complete, at the body's end, or without its body, when reading stops
// first (the limit, discardedBodyWait, the attempt's end, a read error,
// Stop, a failed reservation or a panic). Its reservation always covers its
// buffers.
type discardedBody struct {
	in      *Ingress
	ev      *Event
	unblock func() error

	mu       sync.Mutex
	chunks   [][]byte
	size     int64 // bytes read into chunks
	overhead int64 // the event's own reservation
	reserved int64 // the buffers' reservation: their capacity
	owned    bool  // the reader goroutine owns the body
	reading  bool  // a read into the last buffer is in progress
	done     bool  // the event was queued (or lost to a panic)
}

// TapDiscardedBody records body, the body of an upstream response the
// executor discards unread (TapUpstreamResponse records its status and
// headers), as the upstream_event of the attempt's current sub-attempt,
// marked discarded, without delaying the executor. When it returns true
// the archive owns body: it reads it on its own goroutine, at most
// discardedBodyLimit bytes for at most discardedBodyWait and never past the
// attempt's end or Stop, and closes it; the executor must not use body
// again. unblock closes what lies under body's decoders (the transport
// body, which may be closed during a read; decoders may not), so a read in
// progress ends when reading must stop. When it returns false the executor
// closes body itself, as it does without capture, and nothing was read:
// capture is off or does not record the request, bodies are not captured
// (the event is queued without its body), or the queue cannot hold its
// first bytes (counted).
func TapDiscardedBody(ctx context.Context, body io.ReadCloser, unblock func() error) (owned bool) {
	if !Installed() || body == nil || unblock == nil {
		return false
	}
	var in *Ingress
	defer recoverTap("upstream.discarded", &in)
	in, a := tapTarget(ctx)
	if a == nil {
		return false
	}
	now := time.Now()
	seq, sub, n := a.nextChunk(now)
	data := discardedEventData{ChunkSeq: n, Discarded: true}
	ev := &Event{Type: TypeUpstreamEvent, Time: now, AttemptSeq: seq, SubAttempt: &sub, Data: data, SizeHint: 64}
	rec := in.rec
	if !rec.CaptureBodies() {
		in.emitBodyOff(ev, 0)
		return false
	}
	overhead, ok := in.reserve(int64(eventOverhead)+ev.SizeHint, DropCount{Events: 1, Bodies: 1})
	if !ok {
		return false
	}
	d := &discardedBody{in: in, ev: ev, unblock: unblock, overhead: overhead}
	if !rec.ReserveBody(discardedBodyMinBuffer) {
		d.mu.Lock()
		d.dropLocked(rec.BodyDropReason(), "")
		d.mu.Unlock()
		return false
	}
	d.reserved = discardedBodyMinBuffer
	d.chunks = [][]byte{make([]byte, 0, discardedBodyMinBuffer)}
	// Ended with its attempt, and by Stop: neither waits for a read.
	if !a.addDiscarded(d) {
		d.finalize(DropTruncated, discardedStoppedAttemptEnd)
		return false
	}
	if !rec.TrackCapture(d) {
		d.finalize(rec.BodyDropReason(), "")
		return false
	}
	d.mu.Lock()
	if d.done {
		// Finalized already: nothing was read, so the executor closes it.
		d.mu.Unlock()
		return false
	}
	d.owned = true
	d.mu.Unlock()
	go d.run(body)
	return true
}

// run reads the body until its end, the limit or a stop, and then closes
// it: only here, after the last read, since a decoder is not safe to close
// during one.
func (d *discardedBody) run(body io.ReadCloser) {
	defer func() {
		defer recoverTap("upstream.discarded.close", nil)
		_ = body.Close()
	}()
	defer d.recoverRead()
	timer := time.AfterFunc(discardedBodyWaitFor(), func() {
		d.finalize(DropTruncated, discardedStoppedTimeout)
	})
	defer timer.Stop()
	for {
		buf, probe := d.nextBuffer()
		if buf == nil {
			return
		}
		_ = fault("tap.discarded") // tests panic here
		n, errRead := body.Read(buf)
		if !d.readDone(n, errRead, probe) {
			return
		}
	}
}

// nextBuffer returns free space in the last buffer, reserving and adding a
// buffer first when it is full, or nil when reading must stop. At the limit
// it returns a one-byte probe instead: a byte read there makes the body
// truncated.
func (d *discardedBody) nextBuffer() (buf []byte, probe bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.done {
		return nil, false
	}
	if d.size >= discardedBodyLimit {
		d.reading = true
		return make([]byte, 1), true
	}
	last := d.chunks[len(d.chunks)-1]
	if len(last) == cap(last) {
		size := min(max(d.size, discardedBodyMinBuffer), discardedBodyLimit-d.size)
		rec := d.in.rec
		if !rec.ReserveBody(size) {
			d.dropLocked(rec.BodyDropReason(), "")
			return nil, false
		}
		d.reserved += size
		last = make([]byte, 0, size)
		d.chunks = append(d.chunks, last)
	}
	d.reading = true
	return last[len(last):cap(last)], false
}

// readDone takes a read's result and reports whether to read on. When the
// capture was finalized during the read, it returns the buffers'
// reservation, which the read was still using.
func (d *discardedBody) readDone(n int, errRead error, probe bool) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reading = false
	if d.done {
		d.releaseLocked()
		return false
	}
	if probe && n > 0 {
		d.dropLocked(DropTruncated, discardedStoppedLimit)
		return false
	}
	if !probe && n > 0 {
		last := len(d.chunks) - 1
		d.chunks[last] = d.chunks[last][:len(d.chunks[last])+n]
		d.size += int64(n)
	}
	switch {
	case errors.Is(errRead, io.EOF):
		d.emitLocked()
		return false
	case errRead != nil:
		// Not the whole body: a reset, or the request's context ending.
		d.dropReadLocked(DropTruncated, discardedStoppedReadError, errRead)
		return false
	}
	return true
}

// recoverRead contains a panic while reading (a decoder's, or the
// archive's): the event is queued without its body (tap_panic), and the
// request counts the drop.
func (d *discardedBody) recoverRead() {
	rv := recover()
	if rv == nil {
		return
	}
	NoteTapPanic("upstream.discarded", rv)
	defer recoverTap("upstream.discarded", &d.in)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reading = false
	if d.done {
		d.releaseLocked()
		return
	}
	d.dropLocked(DropTapPanic, "")
}

// finalize ends the capture without waiting for a read in progress: the
// event is queued without its body, as dropped for reason (stopped says
// why a truncated read stopped), and a read in progress is unblocked. It
// is idempotent, and a no-op once the event is queued.
func (d *discardedBody) finalize(reason, stopped string) {
	defer recoverTap("upstream.discarded", &d.in)
	d.mu.Lock()
	if d.done {
		d.mu.Unlock()
		return
	}
	d.dropLocked(reason, stopped)
	unblock := d.owned
	d.mu.Unlock()
	if unblock {
		_ = d.unblock()
	}
}

// FinalizeAtStop is called by Stop before the writer's final drain.
func (d *discardedBody) FinalizeAtStop() {
	d.finalize(DropStopped, "")
}

// emitLocked queues the event with the whole body, handing it the buffers
// and their reservation. An empty body is numbered but not written, like an
// empty chunk.
func (d *discardedBody) emitLocked() {
	d.done = true
	in := d.in
	in.rec.UntrackCapture(d)
	ev := d.ev
	if d.size == 0 {
		in.rec.q.release(d.overhead)
		d.overhead = 0
		d.releaseLocked()
	} else {
		ev.Capture = CaptureFull
		ev.Body = &BodyData{Chunks: d.chunks}
		reserved := d.overhead + d.reserved
		d.chunks, d.overhead, d.reserved = nil, 0, 0
		in.EmitReserved(ev, reserved)
	}
}

// dropLocked queues the event without its body, as dropped for reason, and
// counts the drop against the request and, except for a panic (which
// NoteTapPanic counts), in the drop ledger, so heartbeats and gaps show it.
// The buffers' reservation is returned now, or by the read using them.
func (d *discardedBody) dropLocked(reason, stopped string) {
	d.dropReadLocked(reason, stopped, nil)
}

// dropReadLocked is dropLocked for a read that failed with errRead, whose
// class (never its text) the event records.
func (d *discardedBody) dropReadLocked(reason, stopped string, errRead error) {
	d.done = true
	in := d.in
	in.rec.UntrackCapture(d)
	if reason != DropTapPanic {
		in.rec.CountDrop(reason, DropCount{Bodies: 1, Bytes: d.size})
	}
	in.NoteDrop()
	ev := d.ev
	ev.Capture = CaptureDroppedBody
	ev.BodyDropped = reason
	data := ev.Data.(discardedEventData)
	data.Stopped, data.ReadError, data.ReadBytes = stopped, ErrorClass(errRead), d.size
	ev.Data = data
	overhead := d.overhead
	d.overhead = 0
	if !d.reading {
		d.releaseLocked()
	}
	in.EmitReserved(ev, overhead)
}

// releaseLocked returns the buffers' reservation and drops them.
func (d *discardedBody) releaseLocked() {
	d.in.rec.q.release(d.reserved)
	d.reserved = 0
	d.chunks = nil
}

// emitBodyOff queues ev without its body while bodies are not captured
// (low space, or Stop), counting the drop against the request and in the
// drop ledger; size is what the body would have held, when known. While
// events are refused too, Emit drops and counts the event.
func (in *Ingress) emitBodyOff(ev *Event, size int64) {
	rec := in.rec
	if rec.acceptsEvents() {
		reason := rec.BodyDropReason()
		rec.CountDrop(reason, DropCount{Bodies: 1, Bytes: max(size, 0)})
		in.NoteDrop()
		ev.Capture = CaptureDroppedBody
		ev.BodyDropped = reason
	}
	in.Emit(ev)
}

// addDiscarded registers d to be finalized when the attempt ends, so its
// event precedes attempt_end and its drop is counted before ingress_end.
// It fails once the attempt has ended.
func (a *Attempt) addDiscarded(d *discardedBody) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ended {
		return false
	}
	a.discarded = append(a.discarded, d)
	return true
}

// RecoverTap contains a panic in a tap outside this package that records
// for in (nil when it has found none); it must be deferred directly, since
// recover works only there. Like the taps' own guard it counts the panic,
// and a drop against in: what the tap was recording is lost.
func RecoverTap(where string, in *Ingress) {
	if rv := recover(); rv != nil {
		NoteTapPanic(where, rv)
		in.NoteDrop()
	}
}
