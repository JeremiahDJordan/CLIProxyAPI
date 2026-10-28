package config

// ArchiveConfig configures the fleet request archive recorder (fleet fork).
// It is read once at process start; configuration reloads never turn capture
// on or off. The legacy layout spells it `archive:`; the v8 layout keeps it
// under `observability.archive`. Keys follow the archive design document.
type ArchiveConfig struct {
	// Enabled turns the recorder on. When false nothing is installed and no
	// files are opened.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// SpoolDir is the spool dataset root. It must contain the sentinel file
	// .fleet-archive-spool, and it and its blobs/ directory must be mode 2770
	// and owned by group fleet-archive.
	SpoolDir string `yaml:"spool_dir,omitempty" json:"spool_dir,omitempty"`
	// SegmentSeconds rotates a segment after this many seconds (default 300).
	SegmentSeconds int `yaml:"segment_seconds,omitempty" json:"segment_seconds,omitempty"`
	// SegmentMaxMB rotates a segment once it reaches this size (default 128).
	SegmentMaxMB int `yaml:"segment_max_mb,omitempty" json:"segment_max_mb,omitempty"`
	// QueueMB bounds the in-memory queue, blob payloads included (default 256).
	QueueMB int `yaml:"queue_mb,omitempty" json:"queue_mb,omitempty"`
	// BlobThresholdMB stores larger bodies as separate blobs (default 8).
	BlobThresholdMB int `yaml:"blob_threshold_mb,omitempty" json:"blob_threshold_mb,omitempty"`
	// BodyFreeGB drops bodies while the spool has less free space (default 20).
	BodyFreeGB int `yaml:"body_free_gb,omitempty" json:"body_free_gb,omitempty"`
	// HardFreeGB stops capture while the spool has less free space (default 5).
	HardFreeGB int `yaml:"hard_free_gb,omitempty" json:"hard_free_gb,omitempty"`
}
