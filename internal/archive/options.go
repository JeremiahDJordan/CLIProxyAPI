package archive

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

const (
	mib = int64(1) << 20
	gib = int64(1) << 30

	defaultSegmentSeconds  = 300
	defaultSegmentMaxMB    = 128
	defaultQueueMB         = 256
	defaultBlobThresholdMB = 8
	defaultBodyFreeGB      = 20
	defaultHardFreeGB      = 5

	// DefaultStateDir holds drop counters that outlive a boot (design section 6).
	DefaultStateDir = "/var/lib/cliproxyapi/archive-state"
	// DefaultSpoolGroup must own the spool root and blobs/ (design section 7).
	DefaultSpoolGroup = "fleet-archive"
)

// Options is the validated recorder configuration.
type Options struct {
	SpoolDir           string
	SegmentDuration    time.Duration
	SegmentMaxBytes    int64
	QueueBytes         int64
	BlobThresholdBytes int64
	BodyFreeBytes      uint64
	HardFreeBytes      uint64
	StateDir           string
	SpoolGroup         string

	// Writer cadence. Production uses the defaults; tests shorten them.
	FsyncInterval      time.Duration
	HeartbeatInterval  time.Duration
	SpaceCheckInterval time.Duration
}

// optionsFromConfig applies the design defaults to the YAML configuration.
func optionsFromConfig(cfg config.ArchiveConfig) (Options, error) {
	opts := Options{
		SpoolDir:           strings.TrimSpace(cfg.SpoolDir),
		SegmentDuration:    time.Duration(positiveOr(cfg.SegmentSeconds, defaultSegmentSeconds)) * time.Second,
		SegmentMaxBytes:    int64(positiveOr(cfg.SegmentMaxMB, defaultSegmentMaxMB)) * mib,
		QueueBytes:         int64(positiveOr(cfg.QueueMB, defaultQueueMB)) * mib,
		BlobThresholdBytes: int64(positiveOr(cfg.BlobThresholdMB, defaultBlobThresholdMB)) * mib,
		BodyFreeBytes:      uint64(positiveOr(cfg.BodyFreeGB, defaultBodyFreeGB)) * uint64(gib),
		HardFreeBytes:      uint64(positiveOr(cfg.HardFreeGB, defaultHardFreeGB)) * uint64(gib),
		StateDir:           DefaultStateDir,
		SpoolGroup:         DefaultSpoolGroup,
		FsyncInterval:      time.Second,
		HeartbeatInterval:  time.Minute,
		SpaceCheckInterval: 10 * time.Second,
	}
	if opts.SpoolDir == "" {
		return opts, fmt.Errorf("archive.spool_dir is required")
	}
	if !filepath.IsAbs(opts.SpoolDir) {
		return opts, fmt.Errorf("archive.spool_dir must be absolute: %q", opts.SpoolDir)
	}
	opts.SpoolDir = filepath.Clean(opts.SpoolDir)
	return opts, nil
}

func positiveOr(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

// bootConfig is the configuration recorded in the boot event.
type bootConfig struct {
	SpoolDir        string `json:"spool_dir"`
	SegmentSeconds  int64  `json:"segment_seconds"`
	SegmentMaxBytes int64  `json:"segment_max_bytes"`
	QueueBytes      int64  `json:"queue_bytes"`
	BlobThreshold   int64  `json:"blob_threshold_bytes"`
	BodyFreeBytes   uint64 `json:"body_free_bytes"`
	HardFreeBytes   uint64 `json:"hard_free_bytes"`
	StateDir        string `json:"state_dir"`
}

func (o Options) bootConfig() bootConfig {
	return bootConfig{
		SpoolDir:        o.SpoolDir,
		SegmentSeconds:  int64(o.SegmentDuration / time.Second),
		SegmentMaxBytes: o.SegmentMaxBytes,
		QueueBytes:      o.QueueBytes,
		BlobThreshold:   o.BlobThresholdBytes,
		BodyFreeBytes:   o.BodyFreeBytes,
		HardFreeBytes:   o.HardFreeBytes,
		StateDir:        o.StateDir,
	}
}
