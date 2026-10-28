package archive

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/buildinfo"
	log "github.com/sirupsen/logrus"
)

const (
	maxWriterBackoff = time.Minute
	persistInterval  = 5 * time.Second
)

// writer is the single goroutine that writes segments and blobs. Only it
// touches w's unexported fields; the atomics are read by heartbeats.
type writer struct {
	r       *Recorder
	opts    Options
	spool   string
	blobDir string
	prefix  string

	seg  *segment
	segN int
	seq  uint64
	// unclosed holds segments whose close failed; recovery retries them, so
	// a failed close never strands an .open.jsonl for the life of the process.
	unclosed []*segment

	dirty         bool
	lastTick      time.Time
	lastHeartbeat time.Time
	lastSpace     time.Time
	lastPersist   time.Time
	// lastPersistWarn rate-limits warnings about an unwritable state directory.
	lastPersistWarn time.Time

	// inflight holds the batch being written, so a failure can drop the rest.
	inflight []*queued
	failure  error

	free           atomic.Uint64
	eventsWritten  atomic.Uint64
	bytesWritten   atomic.Uint64
	segmentsClosed atomic.Uint64
	blobsWritten   atomic.Uint64
	blobsReused    atomic.Uint64
	blobsRewritten atomic.Uint64
	writerErrors   atomic.Uint64
}

type segment struct {
	f      *os.File
	name   string
	path   string
	opened time.Time
	size   int64
	// Close progress, so a retry resumes where the failed close stopped.
	synced, fileClosed, renamed bool
}

func newWriter(r *Recorder, free uint64) *writer {
	w := &writer{
		r:       r,
		opts:    r.opts,
		spool:   r.opts.SpoolDir,
		blobDir: filepath.Join(r.opts.SpoolDir, BlobDirName),
		prefix:  r.bootStarted.UTC().Format("20060102T150405.000000Z") + "-" + r.bootID,
	}
	w.free.Store(free)
	now := time.Now()
	w.lastTick, w.lastHeartbeat, w.lastSpace, w.lastPersist = now, now, now, now
	return w
}

type bootData struct {
	RecorderVersion  string     `json:"recorder_version"`
	RedactionVersion int        `json:"redaction_version"`
	EnvelopeVersion  int        `json:"envelope_version"`
	BuildVersion     string     `json:"build_version"`
	BuildCommit      string     `json:"build_commit"`
	BuildDate        string     `json:"build_date"`
	BootStartedAt    string     `json:"boot_started_at"`
	PID              int        `json:"pid"`
	Hostname         string     `json:"hostname,omitempty"`
	FreeBytes        uint64     `json:"free_bytes"`
	CaptureState     string     `json:"capture_state"`
	ResponseSteering bool       `json:"response_steering"`
	Config           bootConfig `json:"config"`
}

type gapData struct {
	Reason      string               `json:"reason"`
	Since       string               `json:"since,omitempty"`
	Drops       map[string]DropCount `json:"drops,omitempty"`
	PriorBootID string               `json:"prior_boot_id,omitempty"`
	Error       string               `json:"error,omitempty"`
}

type statsData struct {
	Reason         string               `json:"reason,omitempty"`
	QueueBytes     int64                `json:"queue_bytes"`
	QueueLimit     int64                `json:"queue_limit"`
	EventsWritten  uint64               `json:"events_written"`
	BytesWritten   uint64               `json:"bytes_written"`
	SegmentsClosed uint64               `json:"segments_closed"`
	BlobsWritten   uint64               `json:"blobs_written"`
	BlobsReused    uint64               `json:"blobs_reused"`
	BlobsRewritten uint64               `json:"blobs_rewritten"`
	WriterErrors   uint64               `json:"writer_errors"`
	TapPanics      int64                `json:"tap_panics"`
	FreeBytes      uint64               `json:"free_bytes"`
	CaptureState   string               `json:"capture_state"`
	Drops          map[string]DropCount `json:"drops,omitempty"`
}

// begin writes the boot event, and a gap for drops persisted by earlier
// boots, before the writer goroutine starts.
func (w *writer) begin(p StartParams) error {
	host, _ := os.Hostname()
	boot := &Event{Type: TypeBoot, Time: w.r.bootStarted, Data: bootData{
		RecorderVersion:  RecorderVersion,
		RedactionVersion: RedactionVersion,
		EnvelopeVersion:  EnvelopeVersion,
		BuildVersion:     buildinfo.Version,
		BuildCommit:      buildinfo.Commit,
		BuildDate:        buildinfo.BuildDate,
		BootStartedAt:    FormatTime(w.r.bootStarted),
		PID:              os.Getpid(),
		Hostname:         host,
		FreeBytes:        w.free.Load(),
		CaptureState:     w.captureState(),
		ResponseSteering: p.ResponseSteering,
		Config:           w.opts.bootConfig(),
	}}
	if err := w.writeEvent(boot); err != nil {
		return err
	}
	if err := w.flushGap(time.Now()); err != nil {
		return err
	}
	return w.sync()
}

func (w *writer) run() {
	defer close(w.r.done)
	backoff := writerBackoff
	for {
		if w.serveSafely() {
			return
		}
		w.safely("failure", w.handleFailure)
		if !w.recoverFromFailure(&backoff) {
			return
		}
	}
}

func (w *writer) serveSafely() (stopped bool) {
	defer func() {
		if rv := recover(); rv != nil {
			w.failure = fmt.Errorf("writer panic: %v", rv)
			stopped = false
		}
	}()
	return w.serve()
}

func (w *writer) serve() bool {
	ticker := time.NewTicker(w.opts.FsyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-w.r.q.notify:
			if err := w.drain(w.r.q.take()); err != nil {
				w.failure = err
				return false
			}
		case now := <-ticker.C:
			if err := w.tick(now); err != nil {
				w.failure = err
				return false
			}
		case <-w.r.stopCh:
			if err := w.shutdown(); err != nil {
				w.failure = err
				return false
			}
			return true
		}
	}
}

func (w *writer) safely(stage string, fn func()) {
	defer func() {
		if rv := recover(); rv != nil {
			log.WithField("stage", stage).Errorf("request archive: writer panic: %v", rv)
		}
	}()
	fn()
}

func (w *writer) drain(items []*queued) error {
	w.inflight = items
	for len(w.inflight) > 0 {
		item := w.inflight[0]
		if item.flushed != nil {
			close(item.flushed)
			w.inflight[0] = nil
			w.inflight = w.inflight[1:]
			continue
		}
		if err := w.writeEvent(item.ev); err != nil {
			return err
		}
		w.r.q.release(item.reserved)
		// Drop the written item from the batch's backing array, so its body
		// can be collected before the rest of the batch is written.
		w.inflight[0] = nil
		w.inflight = w.inflight[1:]
		// A long batch must not hold off fsync, space checks or rotation.
		if now := time.Now(); now.Sub(w.lastTick) >= w.opts.FsyncInterval {
			if err := w.tick(now); err != nil {
				return err
			}
		}
	}
	w.inflight = nil
	return nil
}

// tick runs the time-based work. The ticker calls it every FsyncInterval,
// and drain calls it between events once that interval has passed.
func (w *writer) tick(now time.Time) error {
	w.lastTick = now
	if w.seg != nil && now.Sub(w.seg.opened) >= w.opts.SegmentDuration {
		if err := w.closeSegment(); err != nil {
			return err
		}
	}
	if now.Sub(w.lastSpace) >= w.opts.SpaceCheckInterval {
		if err := w.checkSpace(now); err != nil {
			return err
		}
	}
	if err := w.flushGap(now); err != nil {
		return err
	}
	if now.Sub(w.lastHeartbeat) >= w.opts.HeartbeatInterval {
		if err := w.writeEvent(&Event{Type: TypeHeartbeat, Time: now, Data: w.stats("")}); err != nil {
			return err
		}
		w.lastHeartbeat = now
	}
	// Ticks come every FsyncInterval (1 s), also during a long batch, so
	// data is synced within 2 s.
	if err := w.sync(); err != nil {
		return err
	}
	if now.Sub(w.lastPersist) >= persistInterval {
		w.persistLedger()
		w.lastPersist = now
	}
	return nil
}

// checkSpace re-runs the start-up spool checks (ZFS, sentinel, modes and
// group) and reads the free space. A spool that fails them (the pool was
// unmounted, say) is a writer failure: capture stops until recovery finds
// the spool safe again.
func (w *writer) checkSpace(now time.Time) error {
	w.lastSpace = now
	st, err := checkSpool(w.opts)
	if err != nil {
		return fmt.Errorf("spool check: %w", err)
	}
	w.free.Store(st.free)
	mode := spaceModeFor(st.free, w.opts)
	if old := w.r.spaceMode.Swap(mode); old != mode {
		log.WithFields(log.Fields{"free_bytes": st.free, "capture_state": w.captureState()}).Warn("request archive: spool free space changed capture")
	}
	return nil
}

// flushGap reports pending drops once capture is healthy. While space is low
// they stay pending and persisted, and become a gap when space returns.
func (w *writer) flushGap(now time.Time) error {
	if w.r.spaceMode.Load() != spaceOK {
		return nil
	}
	pending, since, prior, carried := w.r.ledger.pendingSnapshot()
	if len(pending) == 0 {
		return nil
	}
	gap := gapData{Reason: "dropped", Drops: pending, PriorBootID: prior}
	if carried {
		gap.Reason = "carried_over"
	}
	if !since.IsZero() {
		gap.Since = FormatTime(since)
	}
	if err := w.writeEvent(&Event{Type: TypeGap, Time: now, Data: gap}); err != nil {
		return err
	}
	// Clear the counters only once the gap reporting them is durable.
	if err := w.sync(); err != nil {
		return err
	}
	w.r.ledger.settle(pending)
	w.persistLedger()
	return nil
}

func (w *writer) captureState() string {
	switch {
	case !w.r.writerOK.Load():
		return "writer_failed"
	case w.r.spaceMode.Load() == spaceStopped:
		return "stopped_low_space"
	case w.r.spaceMode.Load() == spaceNoBodies:
		return "no_bodies_low_space"
	default:
		return "full"
	}
}

func (w *writer) stats(reason string) statsData {
	return statsData{
		Reason:         reason,
		QueueBytes:     w.r.q.used.Load(),
		QueueLimit:     w.r.q.limit,
		EventsWritten:  w.eventsWritten.Load(),
		BytesWritten:   w.bytesWritten.Load(),
		SegmentsClosed: w.segmentsClosed.Load(),
		BlobsWritten:   w.blobsWritten.Load(),
		BlobsReused:    w.blobsReused.Load(),
		BlobsRewritten: w.blobsRewritten.Load(),
		WriterErrors:   w.writerErrors.Load(),
		TapPanics:      tapPanics.Load(),
		FreeBytes:      w.free.Load(),
		CaptureState:   w.captureState(),
		Drops:          w.r.ledger.totals(),
	}
}

// writeEvent writes one event: its blob first (if any), then its line.
func (w *writer) writeEvent(ev *Event) error {
	env := &envelope{
		V:            EnvelopeVersion,
		BootID:       w.r.bootID,
		Seq:          w.seq + 1,
		TS:           FormatTime(ev.Time),
		Type:         ev.Type,
		IngressID:    ev.IngressID,
		ConnectionID: ev.ConnectionID,
		TurnSeq:      ev.TurnSeq,
		AttemptSeq:   ev.AttemptSeq,
		SubAttempt:   ev.SubAttempt,
		Capture:      ev.Capture,
		BodyDropped:  ev.BodyDropped,
	}
	if ev.ReportDrops {
		env.CaptureDrops = ev.ingress.Drops()
	}
	var blob []byte
	if ev.Body != nil {
		env.Body, blob = encodeBody(ev.Body, w.opts.BlobThresholdBytes)
	}
	line, errEncode := encodeLine(env, ev.Data)
	if errEncode != nil {
		log.WithError(errEncode).WithField("type", ev.Type).Error("request archive: dropping an event that cannot be encoded")
		d := DropCount{Events: 1}
		if ev.Body != nil {
			d.Bodies, d.Bytes = 1, ev.Body.Len()
		}
		w.r.ledger.add(DropEncodeError, d)
		ev.ingress.NoteDrop()
		return nil
	}
	var reused *os.File
	if blob != nil {
		var err error
		if reused, err = w.writeBlob(env.Body.SHA256, blob); err != nil {
			return err
		}
	}
	errLine := w.writeLine(line)
	if reused != nil {
		// The shipper deletes a blob once it has archived an earlier segment
		// that references it, so a reused blob can vanish before this event
		// is written. Write it again then: the event's blob is in the spool
		// once its event is.
		errKeep := w.keepReusedBlob(reused, env.Body.SHA256, blob)
		if errLine == nil {
			errLine = errKeep
		}
	}
	if errLine != nil {
		return errLine
	}
	w.seq++
	w.eventsWritten.Add(1)
	return nil
}

// writeLine appends one complete line with a single write.
func (w *writer) writeLine(line []byte) error {
	if w.seg != nil && w.seg.size > 0 && w.seg.size+int64(len(line)) > w.opts.SegmentMaxBytes {
		if err := w.closeSegment(); err != nil {
			return err
		}
	}
	if w.seg == nil {
		if err := w.openSegment(); err != nil {
			return err
		}
	}
	if err := fault("segment.write"); err != nil {
		return err
	}
	n, err := w.seg.f.Write(line)
	if err != nil {
		// Keep the segment ending on a complete event.
		if n > 0 {
			_ = w.seg.f.Truncate(w.seg.size)
		}
		return fmt.Errorf("write segment %s: %w", w.seg.path, err)
	}
	trace("segment.write", w.seg.path)
	w.seg.size += int64(n)
	w.bytesWritten.Add(uint64(n))
	w.dirty = true
	return nil
}

// openSegment creates the next segment. The number advances only when the
// segment exists, so a failed open leaves no gap in the numbering.
func (w *writer) openSegment() error {
	name := fmt.Sprintf("%s-%06d", w.prefix, w.segN+1)
	path := filepath.Join(w.spool, name+".open.jsonl")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	w.segN++
	trace("segment.create", path)
	seg := &segment{f: f, name: name, path: path, opened: time.Now()}
	// The unit's UMask=0077 would leave the file 0600.
	if err = f.Chmod(0o640); err != nil {
		w.discardSegment(seg)
		return err
	}
	trace("segment.chmod", path)
	if err = syncDir(w.spool); err != nil {
		w.discardSegment(seg)
		return err
	}
	w.seg = seg
	return nil
}

// discardSegment removes a segment that holds no event and gives its number
// back, so a failing disk leaves neither empty segments nor gaps.
func (w *writer) discardSegment(seg *segment) {
	_ = seg.f.Close()
	if err := os.Remove(seg.path); err != nil {
		log.WithError(err).Warn("request archive: cannot remove an empty segment")
		return
	}
	trace("segment.discard", seg.path)
	w.segN--
}

// endFailedSegment ends the open segment on its last complete event after a
// failure, or removes it when it holds none.
func (w *writer) endFailedSegment() {
	seg := w.seg
	if seg == nil {
		return
	}
	if seg.size == 0 {
		w.seg = nil
		w.dirty = false
		w.discardSegment(seg)
		return
	}
	_ = seg.f.Truncate(seg.size)
	if err := w.closeSegment(); err != nil {
		log.WithError(err).Error("request archive: cannot close the failed segment; recovery retries it")
	}
}

// closeSegment fsyncs, renames to .closed.jsonl and fsyncs the directory. A
// segment whose close fails is kept in unclosed for recovery to finish.
func (w *writer) closeSegment() error {
	seg := w.seg
	w.seg = nil
	w.dirty = false
	if err := w.finishSegment(seg); err != nil {
		w.unclosed = append(w.unclosed, seg)
		return err
	}
	return nil
}

// finishSegment runs the close steps not yet done for seg.
func (w *writer) finishSegment(seg *segment) error {
	if !seg.fileClosed {
		if !seg.synced {
			if err := fault("segment.close"); err != nil {
				return fmt.Errorf("sync segment %s: %w", seg.path, err)
			}
			if err := seg.f.Sync(); err != nil {
				return fmt.Errorf("sync segment %s: %w", seg.path, err)
			}
			seg.synced = true
			trace("segment.sync", seg.path)
		}
		// The descriptor is released even when Close reports an error.
		errClose := seg.f.Close()
		seg.fileClosed = true
		if errClose != nil {
			return fmt.Errorf("close segment %s: %w", seg.path, errClose)
		}
	}
	closed := filepath.Join(w.spool, seg.name+".closed.jsonl")
	if !seg.renamed {
		if err := fault("segment.rename"); err != nil {
			return fmt.Errorf("close segment %s: %w", seg.path, err)
		}
		if err := os.Rename(seg.path, closed); err != nil {
			return fmt.Errorf("close segment %s: %w", seg.path, err)
		}
		seg.renamed = true
		trace("segment.rename", closed)
	}
	if err := syncDir(w.spool); err != nil {
		return err
	}
	w.segmentsClosed.Add(1)
	return nil
}

// finishUnclosed retries the close of every segment whose close failed.
func (w *writer) finishUnclosed() error {
	for len(w.unclosed) > 0 {
		if err := w.finishSegment(w.unclosed[0]); err != nil {
			return err
		}
		w.unclosed[0] = nil
		w.unclosed = w.unclosed[1:]
	}
	w.unclosed = nil
	return nil
}

func (w *writer) sync() error {
	if w.seg == nil || !w.dirty {
		return nil
	}
	if err := fault("segment.sync"); err != nil {
		return err
	}
	if err := w.seg.f.Sync(); err != nil {
		return fmt.Errorf("sync segment %s: %w", w.seg.path, err)
	}
	trace("segment.sync", w.seg.path)
	w.dirty = false
	return nil
}

// writeBlob persists a blob durably before any event references it. When a
// blob of that name and size is already there it is reused, and returned
// open so keepReusedBlob can check it is still the same file once the event
// is written.
func (w *writer) writeBlob(sum string, data []byte) (*os.File, error) {
	final := filepath.Join(w.blobDir, sum)
	if info, err := os.Lstat(final); err == nil && info.Mode().IsRegular() && info.Size() == int64(len(data)) {
		f, errOpen := os.Open(final)
		if errOpen == nil {
			// An earlier attempt may have renamed the blob into place and
			// then failed; finish its durability before an event references it.
			if err = f.Sync(); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("write blob %s: %w", sum, err)
			}
			trace("blob.reuse", final)
			if err = w.syncBlobDir(); err != nil {
				_ = f.Close()
				return nil, err
			}
			w.blobsReused.Add(1)
			return f, nil
		}
		// Gone since the Lstat: write it again below.
	}
	return nil, w.writeBlobFile(sum, final, data)
}

// keepReusedBlob closes a reused blob and writes it again when the name no
// longer refers to that file (the shipper deleted it meanwhile).
func (w *writer) keepReusedBlob(reused *os.File, sum string, data []byte) error {
	held, errHeld := reused.Stat()
	_ = reused.Close()
	final := filepath.Join(w.blobDir, sum)
	if current, err := os.Lstat(final); err == nil && errHeld == nil && os.SameFile(current, held) {
		return nil
	}
	trace("blob.rewrite", final)
	if err := w.writeBlobFile(sum, final, data); err != nil {
		return err
	}
	w.blobsRewritten.Add(1)
	return nil
}

// writeBlobFile writes data to a temporary name, fsyncs, makes it 0640,
// renames it to final and fsyncs the directory.
func (w *writer) writeBlobFile(sum, final string, data []byte) error {
	tmp, err := os.CreateTemp(w.blobDir, ".tmp-"+sum+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	trace("blob.create", tmpName)
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write blob %s: %w", sum, err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fail(err)
	}
	if err = tmp.Sync(); err != nil {
		return fail(err)
	}
	trace("blob.sync", tmpName)
	if err = tmp.Chmod(0o640); err != nil {
		return fail(err)
	}
	trace("blob.chmod", tmpName)
	if err = tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("write blob %s: %w", sum, err)
	}
	if err = os.Rename(tmpName, final); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("write blob %s: %w", sum, err)
	}
	trace("blob.rename", final)
	if err = w.syncBlobDir(); err != nil {
		return err
	}
	w.blobsWritten.Add(1)
	return nil
}

func (w *writer) syncBlobDir() error {
	if err := fault("blob.dirsync"); err != nil {
		return err
	}
	if err := syncDir(w.blobDir); err != nil {
		return err
	}
	trace("blob.dirsync", w.blobDir)
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	errSync := d.Sync()
	errClose := d.Close()
	if errSync != nil {
		return fmt.Errorf("sync directory %s: %w", dir, errSync)
	}
	return errClose
}

func (w *writer) shutdown() error {
	if err := w.drain(w.r.q.close()); err != nil {
		return err
	}
	if err := w.finishUnclosed(); err != nil {
		log.WithError(err).Error("request archive: a segment could not be closed at shutdown; the shipper recovers it after exit")
	}
	now := time.Now()
	if err := w.flushGap(now); err != nil {
		return err
	}
	if err := w.writeEvent(&Event{Type: TypeShutdown, Time: now, Data: w.stats("clean")}); err != nil {
		return err
	}
	if w.seg != nil {
		if err := w.closeSegment(); err != nil {
			return err
		}
	}
	w.persistLedger()
	return nil
}

// handleFailure turns capture off, drops the batch in progress and ends the
// open segment on its last complete event.
func (w *writer) handleFailure() {
	w.r.writerOK.Store(false)
	w.writerErrors.Add(1)
	failure := w.failure
	if failure == nil {
		failure = errors.New("unknown writer failure")
		w.failure = failure
	}
	log.WithError(failure).Error("request archive: writer failed; capture is off until it recovers")
	for _, item := range w.inflight {
		w.dropQueued(item, DropWriterError)
	}
	w.inflight = nil
	w.endFailedSegment()
	w.persistLedger()
}

// recoverFromFailure retries with backoff until a gap event can be written
// to a new segment, then turns capture back on. It returns false on stop.
func (w *writer) recoverFromFailure(backoff *time.Duration) bool {
	for {
		timer := time.NewTimer(*backoff)
		select {
		case <-w.r.stopCh:
			timer.Stop()
			w.safely("abandon", w.abandon)
			return false
		case <-timer.C:
		}
		*backoff = min(*backoff*2, maxWriterBackoff)
		errReopen := errors.New("writer panic during recovery")
		w.safely("recover", func() { errReopen = w.reopen() })
		if errReopen != nil {
			log.WithError(errReopen).Warn("request archive: writer still failing")
			continue
		}
		*backoff = writerBackoff
		select {
		case w.r.q.notify <- struct{}{}:
		default:
		}
		log.Info("request archive: writer recovered; capture is on")
		return true
	}
}

func (w *writer) reopen() error {
	// The spool may have been unmounted or changed: check it as at start
	// before writing anything, then finish the segments left unclosed.
	st, errCheck := checkSpool(w.opts)
	if errCheck != nil {
		return fmt.Errorf("spool check: %w", errCheck)
	}
	w.free.Store(st.free)
	w.r.spaceMode.Store(spaceModeFor(st.free, w.opts))
	if err := w.finishUnclosed(); err != nil {
		return err
	}
	pending, since, prior, _ := w.r.ledger.pendingSnapshot()
	gap := gapData{Reason: DropWriterError, Drops: pending, PriorBootID: prior}
	if w.failure != nil {
		gap.Error = w.failure.Error()
	}
	if !since.IsZero() {
		gap.Since = FormatTime(since)
	}
	err := w.writeEvent(&Event{Type: TypeGap, Time: time.Now(), Data: gap})
	if err == nil {
		err = w.sync()
	}
	if err != nil {
		w.endFailedSegment()
		return err
	}
	w.r.ledger.settle(pending)
	w.persistLedger()
	w.failure = nil
	w.r.writerOK.Store(true)
	return nil
}

func (w *writer) abandon() {
	for _, item := range w.r.q.close() {
		w.dropQueued(item, DropWriterError)
	}
	w.persistLedger()
}

func (w *writer) dropQueued(item *queued, reason string) {
	if item.flushed != nil {
		close(item.flushed)
		return
	}
	w.r.q.release(item.reserved)
	d := DropCount{Events: 1}
	if item.ev != nil && item.ev.Body != nil {
		d.Bodies, d.Bytes = 1, item.ev.Body.Len()
	}
	w.r.ledger.add(reason, d)
	if item.ev != nil {
		item.ev.ingress.NoteDrop()
	}
}

func (w *writer) persistLedger() {
	if err := w.r.ledger.persist(w.r.bootID); err != nil && time.Since(w.lastPersistWarn) >= time.Minute {
		w.lastPersistWarn = time.Now()
		log.WithError(err).Warn("request archive: cannot persist drop counters")
	}
	trace("ledger.persist", w.opts.StateDir)
}
