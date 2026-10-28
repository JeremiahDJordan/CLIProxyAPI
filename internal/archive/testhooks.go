package archive

import (
	"context"
	"os"
	"sync/atomic"
	"time"
)

type fsStat struct {
	fsType string
	isZFS  bool
	free   uint64
}

// TestOverrides adjusts recorder start-up so tests can run on any platform.
// Production code never sets it.
type TestOverrides struct {
	// StateDir replaces DefaultStateDir.
	StateDir string
	// SpoolGroup replaces DefaultSpoolGroup.
	SpoolGroup string
	// FreeBytes, when set, replaces statfs: the spool counts as ZFS (unless
	// NotZFS) with this much free space.
	FreeBytes func() uint64
	NotZFS    bool
	// Writer cadence and limits; zero keeps the configured value.
	FsyncInterval      time.Duration
	HeartbeatInterval  time.Duration
	SpaceCheckInterval time.Duration
	SegmentDuration    time.Duration
	SegmentMaxBytes    int64
	QueueBytes         int64
	BlobThresholdBytes int64
}

var (
	overrides atomic.Pointer[TestOverrides]
	traceHook atomic.Pointer[func(op, path string)]
	// faultHook lets package tests fail or panic a writer operation.
	faultHook atomic.Pointer[func(op string) error]
	// writerBackoff is the first retry delay after a writer failure.
	writerBackoff = time.Second
)

// SetTestOverrides installs o and returns a function that stops any running
// recorder, releases its boot lock and clears the overrides so the next test
// can start a fresh recorder.
func SetTestOverrides(o TestOverrides) (restore func()) {
	overrides.Store(&o)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = Stop(ctx)
		lifecycleMu.Lock()
		startAttempted = false
		for _, f := range heldLocks {
			_ = f.Close()
		}
		heldLocks = nil
		lifecycleMu.Unlock()
		overrides.Store(nil)
		traceHook.Store(nil)
		faultHook.Store(nil)
	}
}

// FlushForTest waits until the running recorder has written everything
// queued so far.
func FlushForTest(ctx context.Context) error {
	rec := Current()
	if rec == nil {
		return nil
	}
	return rec.flush(ctx)
}

func applyOverrides(opts Options) Options {
	o := overrides.Load()
	if o == nil {
		return opts
	}
	if o.StateDir != "" {
		opts.StateDir = o.StateDir
	}
	if o.SpoolGroup != "" {
		opts.SpoolGroup = o.SpoolGroup
	}
	if o.FsyncInterval > 0 {
		opts.FsyncInterval = o.FsyncInterval
	}
	if o.HeartbeatInterval > 0 {
		opts.HeartbeatInterval = o.HeartbeatInterval
	}
	if o.SpaceCheckInterval > 0 {
		opts.SpaceCheckInterval = o.SpaceCheckInterval
	}
	if o.SegmentDuration > 0 {
		opts.SegmentDuration = o.SegmentDuration
	}
	if o.SegmentMaxBytes > 0 {
		opts.SegmentMaxBytes = o.SegmentMaxBytes
	}
	if o.QueueBytes > 0 {
		opts.QueueBytes = o.QueueBytes
	}
	if o.BlobThresholdBytes > 0 {
		opts.BlobThresholdBytes = o.BlobThresholdBytes
	}
	return opts
}

func statFS(path string) (fsStat, error) {
	if o := overrides.Load(); o != nil && o.FreeBytes != nil {
		if _, err := os.Stat(path); err != nil {
			return fsStat{}, err
		}
		return fsStat{fsType: "test", isZFS: !o.NotZFS, free: o.FreeBytes()}, nil
	}
	return platformStatFS(path)
}

func trace(op, path string) {
	if h := traceHook.Load(); h != nil {
		(*h)(op, path)
	}
}

func fault(op string) error {
	if h := faultHook.Load(); h != nil {
		return (*h)(op)
	}
	return nil
}
