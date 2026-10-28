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

var (
	current atomic.Pointer[Recorder]

	lifecycleMu    sync.Mutex
	startAttempted bool
	// heldLocks keeps every boot lock descriptor reachable (and therefore
	// open and locked) for the life of the process.
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
	rec, err := start(p)
	if err != nil {
		log.WithError(err).Warn("request archive: capture is off")
		return nil
	}
	current.Store(rec)
	log.WithFields(log.Fields{"boot_id": rec.bootID, "spool": rec.opts.SpoolDir}).Info("request archive: capture started")
	return rec
}

// Stop drains the queue, writes the shutdown event and closes the open
// segment. The boot lock stays held until the process exits.
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
	}
	rec.spaceMode.Store(spaceModeFor(fsInfo.free, opts))

	// The lock exists, locked and 0640, before any segment does.
	lock, errLock := createBootLock(opts.SpoolDir, rec.bootID)
	if errLock != nil {
		return nil, refuse(opts.StateDir, DropStartRefusedSpool, fmt.Errorf("create boot lock: %w", errLock))
	}
	heldLocks = append(heldLocks, lock)

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
			d.Bytes = int64(len(ev.Body.Bytes))
		}
		r.ledger.add(reason, d)
		return false
	}
	if !r.CaptureEvents() || (ev.Body != nil && !r.CaptureBodies()) {
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
		r.stopping.Store(true)
		close(r.stopCh)
	})
	select {
	case <-r.done:
		// Taps still finishing may have counted drops after the writer's
		// last write of the state file.
		r.w.persistLedger()
		return nil
	case <-ctx.Done():
		return ctx.Err()
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
