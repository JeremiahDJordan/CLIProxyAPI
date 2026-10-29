package archive

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Drop reasons used in gap events, heartbeats and the persisted state.
const (
	DropQueueFull    = "queue_full"
	DropWriterError  = "writer_error"
	DropLowSpaceBody = "low_space_body"
	DropLowSpaceHard = "low_space_hard"
	DropStopped      = "stopped"
	DropEncodeError  = "encode_error"
	DropTapPanic     = "tap_panic"
	// DropNotCaptured marks a body an executor's tap cannot record: an
	// outbound body it cannot record as sent, or a response body it
	// discards without the archive reading it (body_dropped only: it counts
	// against its request, never as a gap).
	DropNotCaptured = "not_captured"
	// Start refusals are counted as gaps of unknown size.
	DropStartRefusedSteering = "start_refused_steering"
	DropStartRefusedSpool    = "start_refused_spool"
	DropStartRefusedConfig   = "start_refused_config"
	// DropStartTimeout counts a start whose disk work did not finish in time.
	DropStartTimeout = "start_timeout"
	// DropSteeringTurns counts WebSocket connections whose turns were not
	// recorded because codex.response-steering was on for them.
	DropSteeringTurns = "steering_turns"
)

const stateFileName = "drops.json"

// DropCount aggregates dropped events, bodies and body bytes for one reason.
type DropCount struct {
	Events int64 `json:"events"`
	Bodies int64 `json:"bodies"`
	Bytes  int64 `json:"bytes"`
}

func (d DropCount) add(o DropCount) DropCount {
	return DropCount{Events: d.Events + o.Events, Bodies: d.Bodies + o.Bodies, Bytes: d.Bytes + o.Bytes}
}

// SuspectRange names events of one boot, written to one segment, whose
// fsync failed: each was written with a single write, but a later fsync
// that succeeds does not prove the failed one's data reached the disk. The
// gap reporting a range is fsynced, so the range is recorded even when the
// segment then closes normally. Assembly treats a request with an event in a
// suspect range as capture-incomplete.
type SuspectRange struct {
	BootID string `json:"boot_id"`
	// Segment is the segment's name without .open.jsonl or .closed.jsonl.
	Segment  string `json:"segment"`
	FirstSeq uint64 `json:"first_seq"`
	LastSeq  uint64 `json:"last_seq"`
}

// stateFile is the persisted form of drops and suspect ranges not yet
// reported as a gap event.
type stateFile struct {
	V       int                  `json:"v"`
	BootID  string               `json:"boot_id,omitempty"`
	Since   string               `json:"since,omitempty"`
	Updated string               `json:"updated"`
	Drops   map[string]DropCount `json:"drops"`
	Suspect []SuspectRange       `json:"suspect,omitempty"`
}

// dropLedger counts drops and suspect ranges. Pending ones become a gap
// event once capture is healthy again; until then they are persisted so
// they survive a restart.
type dropLedger struct {
	mu      sync.Mutex
	dir     string
	pending map[string]DropCount
	suspect []SuspectRange
	since   time.Time
	priorID string
	carried bool
	total   map[string]DropCount
	dirty   bool
	// closed ignores drops counted after the final persist at Stop, which
	// nothing would persist or report.
	closed bool
}

func newDropLedger(dir string) *dropLedger {
	return &dropLedger{dir: dir, pending: map[string]DropCount{}, total: map[string]DropCount{}}
}

func (l *dropLedger) add(reason string, d DropCount) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	if len(l.pending) == 0 {
		l.since = time.Now()
	}
	l.pending[reason] = l.pending[reason].add(d)
	l.total[reason] = l.total[reason].add(d)
	l.dirty = true
}

// addSuspect records a suspect range until a durable gap reports it.
func (l *dropLedger) addSuspect(r SuspectRange) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	if len(l.pending) == 0 && len(l.suspect) == 0 {
		l.since = time.Now()
	}
	l.suspect = append(l.suspect, r)
	l.dirty = true
}

// close makes later adds no-ops; drops counted before it are persisted by
// the persist that follows.
func (l *dropLedger) close() {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
}

// pendingGap is what the next gap event reports.
type pendingGap struct {
	drops   map[string]DropCount
	suspect []SuspectRange
	since   time.Time
	priorID string
	// carried says some were carried over from an earlier boot or a refused start.
	carried bool
}

func (p pendingGap) empty() bool {
	return len(p.drops) == 0 && len(p.suspect) == 0
}

// pendingSnapshot returns the drops and suspect ranges not yet reported.
func (l *dropLedger) pendingSnapshot() pendingGap {
	l.mu.Lock()
	defer l.mu.Unlock()
	return pendingGap{drops: maps.Clone(l.pending), suspect: slices.Clone(l.suspect), since: l.since, priorID: l.priorID, carried: l.carried}
}

// settle removes what a written gap event reported. Suspect ranges are only
// appended, so the reported ones are the oldest.
func (l *dropLedger) settle(reported pendingGap) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.suspect = slices.Delete(l.suspect, 0, min(len(reported.suspect), len(l.suspect)))
	if len(l.suspect) == 0 {
		l.suspect = nil
	}
	for reason, d := range reported.drops {
		left := l.pending[reason]
		left = DropCount{Events: left.Events - d.Events, Bodies: left.Bodies - d.Bodies, Bytes: left.Bytes - d.Bytes}
		if left == (DropCount{}) {
			delete(l.pending, reason)
		} else {
			l.pending[reason] = left
		}
	}
	if len(l.pending) == 0 && len(l.suspect) == 0 {
		l.since = time.Time{}
	}
	l.priorID = ""
	l.carried = false
	l.dirty = true
}

func (l *dropLedger) totals() map[string]DropCount {
	l.mu.Lock()
	defer l.mu.Unlock()
	return maps.Clone(l.total)
}

// load merges drops and suspect ranges persisted by earlier boots or
// refused starts.
func (l *dropLedger) load() error {
	st, err := readState(l.dir)
	if err != nil || (len(st.Drops) == 0 && len(st.Suspect) == 0) {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for reason, d := range st.Drops {
		l.pending[reason] = l.pending[reason].add(d)
	}
	l.suspect = append(l.suspect, st.Suspect...)
	if since, errParse := time.Parse(time.RFC3339Nano, st.Since); errParse == nil {
		l.since = since
	} else if l.since.IsZero() {
		l.since = time.Now()
	}
	l.priorID = st.BootID
	l.carried = true
	return nil
}

// persist writes the pending drops and suspect ranges when they changed
// since the last write.
func (l *dropLedger) persist(bootID string) error {
	l.mu.Lock()
	if !l.dirty {
		l.mu.Unlock()
		return nil
	}
	st := stateFile{V: 1, BootID: bootID, Updated: FormatTime(time.Now()), Drops: maps.Clone(l.pending), Suspect: slices.Clone(l.suspect)}
	if !l.since.IsZero() {
		st.Since = l.since.UTC().Format(time.RFC3339Nano)
	}
	l.dirty = false
	l.mu.Unlock()
	if err := writeState(l.dir, st); err != nil {
		l.mu.Lock()
		l.dirty = true
		l.mu.Unlock()
		return err
	}
	return nil
}

func readState(dir string) (stateFile, error) {
	var st stateFile
	data, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err = json.Unmarshal(data, &st); err != nil {
		return stateFile{}, fmt.Errorf("parse %s: %w", stateFileName, err)
	}
	return st, nil
}

func writeState(dir string, st stateFile) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+stateFileName+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(dir, stateFileName))
}

// recordRefusal counts a refused start as a gap the next running boot reports.
func recordRefusal(dir, reason string) error {
	if dir == "" {
		return nil
	}
	st, err := readState(dir)
	if err != nil {
		return err
	}
	if st.Drops == nil {
		st.Drops = map[string]DropCount{}
	}
	if len(st.Drops) == 0 && len(st.Suspect) == 0 {
		st.Since = time.Now().UTC().Format(time.RFC3339Nano)
	}
	st.V = 1
	st.Updated = FormatTime(time.Now())
	st.Drops[reason] = st.Drops[reason].add(DropCount{Events: 1})
	return writeState(dir, st)
}
