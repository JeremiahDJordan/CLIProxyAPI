// Package archive records proxy traffic into an append-only spool for the
// fleet request archive (docs/PROXY-REQUEST-ARCHIVE-DESIGN.md in the fleet
// repository). It is part of the fleet fork.
//
// Disabled means not installed: with archive.enabled false nothing is started,
// no file is opened and every tap is a single nil check on Current(). Taps
// never wait on the disk. They copy what they need, reserve its size on a
// byte-bounded queue and enqueue; a failed reservation drops and counts. One
// writer goroutine drains the queue in order and alone writes segments and
// blobs.
package archive

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	log "github.com/sirupsen/logrus"
)

// SentinelName marks the spool dataset root.
const SentinelName = ".fleet-archive-spool"

// BlobDirName is the blob directory under the spool root.
const BlobDirName = "blobs"

const (
	spaceOK int32 = iota
	spaceNoBodies
	spaceStopped
)

// Bounds on the recorder's work outside its writer goroutine, so a spool
// that hangs (a suspended pool with ZFS failmode=wait) never holds up the
// proxy's start or shutdown.
const (
	// startTimeout bounds Start: the disk work runs on its own goroutine and
	// capture stays off when it does not finish in time.
	startTimeout = 5 * time.Second
	// stopObserverWait bounds how long Stop waits for requests and turns in
	// flight to queue their final events before it finalizes them itself.
	stopObserverWait = 2 * time.Second
	// stopWriterWait bounds how long Stop waits for the writer's final drain.
	stopWriterWait = 10 * time.Second
	// lateStopTimeout bounds stopping a recorder whose start finished late.
	lateStopTimeout = 30 * time.Second
)

var (
	current atomic.Pointer[Recorder]

	lifecycleMu    sync.Mutex
	startAttempted bool

	// heldLocks keeps every boot lock descriptor reachable (and therefore
	// open and locked) for the life of the process. Its own lock, because a
	// start that runs late appends to it while Start no longer waits.
	locksMu   sync.Mutex
	heldLocks []*os.File

	tapPanics    atomic.Int64
	lastPanicLog atomic.Int64
)

// Current returns the running recorder, or nil when capture is off.
func Current() *Recorder {
	return current.Load()
}

// StartParams carries the process-start configuration.
type StartParams struct {
	Config config.ArchiveConfig
	// ResponseSteering is codex.response-steering. Capture refuses to start
	// while it is on, until duplex turn tagging exists.
	ResponseSteering bool
}

// Start starts the recorder once per process. Later calls return the running
// recorder (or nil) without reading the configuration again, so a reload
// never turns capture on or off, whichever configuration came first. It
// returns nil when capture is disabled or refused; refusals are logged and
// counted as a gap.
//
// The start's disk work (statfs, the boot lock, the boot event) runs on its
// own goroutine. When it does not finish within startTimeout, Start returns
// nil and capture stays off for the process; a start that finishes later
// counts start_timeout as a gap and stops at once.
func Start(p StartParams) *Recorder {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	if startAttempted {
		return current.Load()
	}
	startAttempted = true
	if !p.Config.Enabled {
		return nil
	}
	type started struct {
		rec *Recorder
		err error
	}
	done := make(chan started, 1)
	go func() {
		var res started
		defer func() {
			if rv := recover(); rv != nil {
				res = started{err: fmt.Errorf("start panicked: %v", rv)}
			}
			done <- res
		}()
		res.rec, res.err = start(p)
	}()
	timer := time.NewTimer(startTimeoutFor())
	defer timer.Stop()
	select {
	case res := <-done:
		if res.err != nil {
			log.WithError(res.err).Warn("request archive: capture is off")
			return nil
		}
		current.Store(res.rec)
		log.WithFields(log.Fields{"boot_id": res.rec.bootID, "spool": res.rec.opts.SpoolDir}).Info("request archive: capture started")
		return res.rec
	case <-timer.C:
		log.WithField("timeout", startTimeoutFor().String()).Warn("request archive: start did not finish in time (is the spool pool suspended?); capture is off for this process")
		go func() {
			res := <-done
			if res.rec != nil {
				res.rec.abandonLateStart()
			}
		}()
		return nil
	}
}

// abandonLateStart stops a recorder whose start finished after Start gave
// up on it. It was never installed; its boot records the timeout as a gap.
func (r *Recorder) abandonLateStart() {
	r.ledger.add(DropStartTimeout, DropCount{Events: 1})
	ctx, cancel := context.WithTimeout(context.Background(), lateStopTimeout)
	defer cancel()
	if err := r.stop(ctx); err != nil {
		log.WithError(err).Warn("request archive: stopping the late start did not finish")
	}
	log.WithField("boot_id", r.bootID).Warn("request archive: a late start finished and was stopped; capture stays off")
	trace("start.abandoned", r.opts.SpoolDir)
}

// Stop finalizes what is in flight, drains the queue, writes the shutdown
// event and closes the open segment. Its waits are bounded (stopObserverWait,
// stopWriterWait, and ctx), so a hung spool never holds up shutdown. The boot
// lock stays held until the process exits.
func Stop(ctx context.Context) error {
	lifecycleMu.Lock()
	rec := current.Swap(nil)
	lifecycleMu.Unlock()
	if rec == nil {
		return nil
	}
	return rec.stop(ctx)
}

// Recorder is a running capture.
type Recorder struct {
	opts        Options
	bootID      string
	bootStarted time.Time
	q           *queue
	w           *writer
	ledger      *dropLedger

	spaceMode atomic.Int32
	writerOK  atomic.Bool
	stopping  atomic.Bool

	stopOnce sync.Once
	stopCh   chan struct{}
	done     chan struct{}

	// captures holds the pending captures Stop finalizes; nil once it has.
	capturesMu     sync.Mutex
	captures       map[PendingCapture]struct{}
	capturesClosed bool

	// observers holds requests and WebSocket turns that have not queued
	// their final event yet. Stop waits for them (bounded) and then
	// finalizes the rest; observersChanged is signalled on each untrack.
	observersMu      sync.Mutex
	observers        map[PendingCapture]struct{}
	observersClosed  bool
	observersChanged chan struct{}
}

type refusal struct {
	reason string
	err    error
}

func (r *refusal) Error() string { return r.err.Error() }
func (r *refusal) Unwrap() error { return r.err }

func start(p StartParams) (*Recorder, error) {
	opts, errOpts := optionsFromConfig(p.Config)
	opts = applyOverrides(opts)
	if errOpts != nil {
		return nil, refuse(opts.StateDir, DropStartRefusedConfig, errOpts)
	}
	if p.ResponseSteering {
		return nil, refuse(opts.StateDir, DropStartRefusedSteering,
			errors.New("codex.response-steering is on; capture refuses to start until duplex turn tagging exists"))
	}
	if err := fault("start.check"); err != nil {
		return nil, refuse(opts.StateDir, DropStartRefusedSpool, err)
	}
	fsInfo, errCheck := checkSpool(opts)
	if errCheck != nil {
		return nil, refuse(opts.StateDir, DropStartRefusedSpool, errCheck)
	}

	started := time.Now()
	id, errID := uuid.NewV7()
	if errID != nil {
		return nil, fmt.Errorf("generate boot id: %w", errID)
	}
	rec := &Recorder{
		opts:        opts,
		bootID:      id.String(),
		bootStarted: started,
		q:           newQueue(opts.QueueBytes),
		ledger:      newDropLedger(opts.StateDir),
		stopCh:      make(chan struct{}),
		done:        make(chan struct{}),
		captures:    map[PendingCapture]struct{}{},

		observers:        map[PendingCapture]struct{}{},
		observersChanged: make(chan struct{}, 1),
	}
	rec.spaceMode.Store(spaceModeFor(fsInfo.free, opts))

	// The lock exists, locked and 0640, before any segment does.
	lock, errLock := createBootLock(opts.SpoolDir, rec.bootID)
	if errLock != nil {
		return nil, refuse(opts.StateDir, DropStartRefusedSpool, fmt.Errorf("create boot lock: %w", errLock))
	}
	locksMu.Lock()
	heldLocks = append(heldLocks, lock)
	locksMu.Unlock()

	if errLoad := rec.ledger.load(); errLoad != nil {
		log.WithError(errLoad).Warn("request archive: cannot read persisted drop counters")
	}
	rec.w = newWriter(rec, fsInfo.free)
	rec.writerOK.Store(true)
	if errBoot := rec.w.begin(p); errBoot != nil {
		return nil, refuse(opts.StateDir, DropStartRefusedSpool, fmt.Errorf("write boot event: %w", errBoot))
	}
	go rec.w.run()
	return rec, nil
}

func refuse(stateDir, reason string, err error) error {
	if errRecord := recordRefusal(stateDir, reason); errRecord != nil {
		log.WithError(errRecord).Warn("request archive: cannot persist the refused start")
	}
	return &refusal{reason: reason, err: err}
}

func checkSpool(opts Options) (fsStat, error) {
	info, err := statFS(opts.SpoolDir)
	if err != nil {
		return info, fmt.Errorf("statfs %s: %w", opts.SpoolDir, err)
	}
	if !info.isZFS {
		return info, fmt.Errorf("spool %s is not on ZFS (filesystem %s)", opts.SpoolDir, info.fsType)
	}
	sentinel, err := os.Lstat(filepath.Join(opts.SpoolDir, SentinelName))
	if err != nil {
		return info, fmt.Errorf("spool sentinel: %w", err)
	}
	if !sentinel.Mode().IsRegular() {
		return info, fmt.Errorf("spool sentinel %s is not a regular file", SentinelName)
	}
	if err = checkSpoolDirs(opts.SpoolDir, filepath.Join(opts.SpoolDir, BlobDirName), opts.SpoolGroup); err != nil {
		return info, fmt.Errorf("spool permissions: %w", err)
	}
	return info, nil
}

func spaceModeFor(free uint64, opts Options) int32 {
	switch {
	case free < opts.HardFreeBytes:
		return spaceStopped
	case free < opts.BodyFreeBytes:
		return spaceNoBodies
	default:
		return spaceOK
	}
}

// createBootLock creates <boot_id>.lock.tmp, locks it, makes it 0640 and
// renames it into place, keeping the same descriptor.
func createBootLock(spool, bootID string) (*os.File, error) {
	tmp := filepath.Join(spool, bootID+".lock.tmp")
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return nil, err
	}
	trace("lock.create", tmp)
	fail := func(err error) (*os.File, error) {
		_ = f.Close()
		_ = os.Remove(tmp)
		return nil, err
	}
	if err = lockExclusive(f); err != nil {
		return fail(err)
	}
	trace("lock.flock", tmp)
	if err = f.Chmod(0o640); err != nil {
		return fail(err)
	}
	trace("lock.chmod", tmp)
	final := filepath.Join(spool, bootID+".lock")
	if err = os.Rename(tmp, final); err != nil {
		return fail(err)
	}
	trace("lock.rename", final)
	if err = syncDir(spool); err != nil {
		return nil, err
	}
	return f, nil
}

// CaptureEvents reports whether new events would be accepted.
func (r *Recorder) CaptureEvents() bool {
	return r != nil && !r.stopping.Load() && r.writerOK.Load() && r.spaceMode.Load() != spaceStopped
}

// acceptsEvents reports whether emit queues events at all. Unlike
// CaptureEvents it stays true while Stop finalizes what is in flight.
func (r *Recorder) acceptsEvents() bool {
	return r.writerOK.Load() && r.spaceMode.Load() != spaceStopped
}

// CaptureBodies reports whether bodies would be accepted.
func (r *Recorder) CaptureBodies() bool {
	return r.CaptureEvents() && r.spaceMode.Load() == spaceOK
}

// ReserveBody claims queue bytes for a body buffer. It fails while bodies
// are not being captured, so a body in progress stops when space runs low.
func (r *Recorder) ReserveBody(n int64) bool {
	return r != nil && r.CaptureBodies() && r.q.reserve(n)
}

// ReleaseBody returns bytes claimed by ReserveBody when the body is dropped.
func (r *Recorder) ReleaseBody(n int64) {
	if r != nil {
		r.q.release(n)
	}
}

// CountDrop records a drop that happened before an event reached the queue.
func (r *Recorder) CountDrop(reason string, d DropCount) {
	if r != nil {
		r.ledger.add(reason, d)
	}
}

// BodyDropReason explains why a body would not be captured right now.
func (r *Recorder) BodyDropReason() string {
	switch {
	case r.stopping.Load():
		return DropStopped
	case !r.writerOK.Load():
		return DropWriterError
	case r.spaceMode.Load() == spaceStopped:
		return DropLowSpaceHard
	case r.spaceMode.Load() == spaceNoBodies:
		return DropLowSpaceBody
	default:
		return DropQueueFull
	}
}

// emit queues ev. reserved bytes were claimed earlier (a body read so far)
// and are charged to the event; the rest of its size is reserved now. On
// failure every reservation is released and the drop is counted.
func (r *Recorder) emit(ev *Event, reserved int64) bool {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	drop := func(reason string) bool {
		r.q.release(reserved)
		d := DropCount{Events: 1}
		if ev.Body != nil {
			d.Bodies = 1
			d.Bytes = ev.Body.Len()
		}
		r.ledger.add(reason, d)
		return false
	}
	// Stopping refuses new captures and reservations, not events: Stop
	// finalizes the pending captures after it begins, and the writer's
	// close of the queue is the cut-off.
	if !r.acceptsEvents() || (ev.Body != nil && !r.CaptureBodies()) {
		return drop(r.BodyDropReason())
	}
	if extra := ev.reservation() - reserved; extra > 0 {
		if !r.q.reserve(extra) {
			return drop(DropQueueFull)
		}
		reserved += extra
	}
	if !r.q.push(&queued{ev: ev, reserved: reserved}) {
		return drop(DropStopped)
	}
	return true
}

// PendingCapture is a capture that can hold queue bytes or a deferred event
// until a read returns (the client body tee). Stop finalizes every one still
// tracked, without waiting for that read, before the writer's final drain.
type PendingCapture interface {
	// FinalizeAtStop emits what the capture holds and releases its
	// reservations. It must not wait, and must be idempotent.
	FinalizeAtStop()
}

// TrackCapture registers p until UntrackCapture. It fails once Stop has
// begun; reservations fail by then too, so an untracked capture holds none.
func (r *Recorder) TrackCapture(p PendingCapture) bool {
	if r == nil || p == nil {
		return false
	}
	r.capturesMu.Lock()
	defer r.capturesMu.Unlock()
	if r.capturesClosed {
		return false
	}
	r.captures[p] = struct{}{}
	return true
}

// UntrackCapture removes p once it holds nothing more.
func (r *Recorder) UntrackCapture(p PendingCapture) {
	if r == nil || p == nil {
		return
	}
	r.capturesMu.Lock()
	delete(r.captures, p)
	r.capturesMu.Unlock()
}

// TrackObserver registers a request or WebSocket turn whose final event is
// not queued yet. It fails once Stop has begun finalizing observers.
func (r *Recorder) TrackObserver(p PendingCapture) bool {
	if r == nil || p == nil {
		return false
	}
	r.observersMu.Lock()
	defer r.observersMu.Unlock()
	if r.observersClosed {
		return false
	}
	r.observers[p] = struct{}{}
	return true
}

// UntrackObserver removes p once its final event is queued (or handed to a
// tracked capture).
func (r *Recorder) UntrackObserver(p PendingCapture) {
	if r == nil || p == nil {
		return
	}
	r.observersMu.Lock()
	delete(r.observers, p)
	r.observersMu.Unlock()
	select {
	case r.observersChanged <- struct{}{}:
	default:
	}
}

// finalizeObservers waits until every tracked observer has queued its final
// event, at most until the earlier of stopObserverWait and half of ctx's
// remaining time (the writer's drain needs the rest), and then finalizes
// those still open. A WebSocket's handler finishes before its observer, and
// HTTP shutdown ignores hijacked connections, so without this wait a clean
// drain could lose the connection's ingress_end.
func (r *Recorder) finalizeObservers(ctx context.Context) {
	wait := stopObserverWaitFor()
	if deadline, ok := ctx.Deadline(); ok {
		wait = min(wait, time.Until(deadline)/2)
	}
	timer := time.NewTimer(max(wait, 0))
	defer timer.Stop()
	for waiting := true; waiting; {
		r.observersMu.Lock()
		left := len(r.observers)
		r.observersMu.Unlock()
		if left == 0 {
			break
		}
		select {
		case <-r.observersChanged:
		case <-timer.C:
			waiting = false
		case <-ctx.Done():
			waiting = false
		}
	}
	r.observersMu.Lock()
	pending := r.observers
	r.observers = nil
	r.observersClosed = true
	r.observersMu.Unlock()
	if len(pending) > 0 {
		log.WithField("open", len(pending)).Warn("request archive: finalizing requests still open at shutdown")
	}
	for p := range pending {
		p.FinalizeAtStop()
	}
}

// finalizeCaptures closes the registry and finalizes what it held. Captures
// lock themselves, so it runs without holding capturesMu.
func (r *Recorder) finalizeCaptures() {
	r.capturesMu.Lock()
	pending := r.captures
	r.captures = nil
	r.capturesClosed = true
	r.capturesMu.Unlock()
	for p := range pending {
		p.FinalizeAtStop()
	}
}

// Emit queues a recorder-level event (one without an ingress).
func (r *Recorder) Emit(ev *Event) bool {
	if r == nil || ev == nil {
		return false
	}
	return r.emit(ev, 0)
}

// flush waits until the writer has handled every event queued before it.
// Tests use it; it never runs on a request path.
func (r *Recorder) flush(ctx context.Context) error {
	ch := make(chan struct{})
	if !r.q.push(&queued{flushed: ch}) {
		return errors.New("archive: recorder stopped")
	}
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Recorder) stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	r.stopOnce.Do(func() {
		// Refuse new captures and observations, let those in flight queue
		// their final events (bounded), finalize the rest, then end the
		// pending body captures without waiting for their reads, so every
		// event is queued before the writer's final drain and no
		// reservation outlives it.
		r.stopping.Store(true)
		r.finalizeObservers(ctx)
		r.finalizeCaptures()
		close(r.stopCh)
	})
	timer := time.NewTimer(stopWriterWaitFor())
	defer timer.Stop()
	select {
	case <-r.done:
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("archive: the writer did not finish its final drain in time")
	}
	// Taps still finishing may have counted drops after the writer's last
	// write of the state file. Persist those (on another goroutine: it is
	// disk work); later ones, which nothing could persist, are not counted
	// (their requests have no ingress_end, so they show as incomplete).
	r.ledger.close()
	persisted := make(chan struct{})
	go func() {
		defer close(persisted)
		r.w.persistLedger()
	}()
	select {
	case <-persisted:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("archive: persisting the drop counters did not finish in time")
	}
}

// NewID returns a time-ordered UUIDv7 string.
func NewID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}

// NoteTapPanic counts a panic recovered inside a tap and logs at most one per
// minute. The request it happened in continues unaffected.
func NoteTapPanic(where string, recovered any) {
	tapPanics.Add(1)
	if rec := Current(); rec != nil {
		rec.ledger.add(DropTapPanic, DropCount{Events: 1})
	}
	now := time.Now().Unix()
	last := lastPanicLog.Load()
	if now-last < 60 || !lastPanicLog.CompareAndSwap(last, now) {
		return
	}
	log.WithFields(log.Fields{"tap": where, "panic": fmt.Sprintf("%T: %v", recovered, recovered)}).Error("request archive: recovered tap panic")
}
