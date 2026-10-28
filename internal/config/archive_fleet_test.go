package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestArchiveConfigLayouts(t *testing.T) {
	want := ArchiveConfig{Enabled: true, SpoolDir: "/nvmessd/fleet-archive/spool", SegmentSeconds: 120, BodyFreeGB: 30, HardFreeGB: 10}
	legacy := `port: 8317
archive:
  enabled: true
  spool_dir: /nvmessd/fleet-archive/spool
  segment_seconds: 120
  body_free_gb: 30
  hard_free_gb: 10
`
	cfg, err := ParseConfigBytes([]byte(legacy))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Archive != want {
		t.Fatalf("legacy archive = %+v", cfg.Archive)
	}

	v8 := `config-version: 8
server:
  port: 8317
observability:
  archive:
    enabled: true
    spool_dir: /nvmessd/fleet-archive/spool
    segment_seconds: 120
    body_free_gb: 30
    hard_free_gb: 10
`
	if err = ValidateV8Config([]byte(v8)); err != nil {
		t.Fatalf("v8 layout rejected: %v", err)
	}
	cfg, err = ParseConfigBytes([]byte(v8))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Archive != want {
		t.Fatalf("v8 archive = %+v", cfg.Archive)
	}

	// A management save migrates the legacy layout; the archive section moves
	// instead of being commented out as unknown.
	migrated, _, err := NormalizeConfigLayout([]byte(legacy), true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(migrated), "# archive") {
		t.Fatalf("migration commented the archive out:\n%s", migrated)
	}
	if err = ValidateV8Config(migrated); err != nil {
		t.Fatalf("migrated layout rejected: %v\n%s", err, migrated)
	}
	cfg, err = ParseConfigBytes(migrated)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Archive != want {
		t.Fatalf("migrated archive = %+v\n%s", cfg.Archive, migrated)
	}
}

func TestArchiveConfigOmittedByDefault(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte("port: 8317\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Archive.Enabled {
		t.Fatal("archive enabled by default")
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "archive") {
		t.Fatalf("default config writes an archive section:\n%s", out)
	}
}
