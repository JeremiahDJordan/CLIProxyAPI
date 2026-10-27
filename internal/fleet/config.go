// Package fleet implements the fleet gateway policy plugin: per-tool client keys,
// a native-client gate for subscription providers, provider quota tracking and a
// weekly-reset-first scheduler. The cgo shim in plugins/fleet exposes it through the
// standard CLIProxyAPI plugin ABI.
package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	cliproxysession "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/session"
	"gopkg.in/yaml.v3"
)

// PrincipalPrefix namespaces principals issued by this plugin.
const PrincipalPrefix = "fleet:"

// Config is the plugin's YAML configuration under plugins.configs.fleet.
type Config struct {
	Enabled bool `yaml:"enabled"`
	// Keys are per-tool client keys. Only SHA-256 hex digests are configured.
	Keys []KeyConfig `yaml:"keys"`
	// Exclusive makes this plugin the only request authentication provider, which
	// disables access.api-keys. Defaults to true when keys are configured.
	Exclusive *bool           `yaml:"exclusive"`
	Gate      GateConfig      `yaml:"gate"`
	Scheduler SchedulerConfig `yaml:"scheduler"`
}

// KeyConfig is one client key. Providers lists the target provider formats
// ("claude", "codex") the key may reach.
type KeyConfig struct {
	Name      string   `yaml:"name"`
	SHA256    string   `yaml:"sha256"`
	Providers []string `yaml:"providers"`
}

// GateConfig controls the native-client gate applied after credential selection.
type GateConfig struct {
	// Enabled defaults to true.
	Enabled *bool `yaml:"enabled"`
}

// SchedulerConfig controls the weekly-reset-first scheduler.
type SchedulerConfig struct {
	// Enabled defaults to true.
	Enabled *bool `yaml:"enabled"`
	// ClaudeCacheTTL is the affinity idle limit when a Claude session did not
	// request extended caching. Defaults to 5m.
	ClaudeCacheTTL string `yaml:"claude-cache-ttl"`
	// ClaudeExtendedCacheTTL applies when a Claude request used cache_control
	// ttl "1h". Defaults to 1h.
	ClaudeExtendedCacheTTL string `yaml:"claude-extended-cache-ttl"`
	// CodexIdleTTL is the Codex affinity idle limit. Defaults to 1h.
	CodexIdleTTL string `yaml:"codex-idle-ttl"`
}

// Settings is the normalized, validated configuration.
type Settings struct {
	Enabled                bool
	Keys                   []Key
	Exclusive              bool
	GateEnabled            bool
	SchedulerEnabled       bool
	ClaudeCacheTTL         time.Duration
	ClaudeExtendedCacheTTL time.Duration
	CodexIdleTTL           time.Duration
}

// Key is a validated client key.
type Key struct {
	Name      string
	Digest    [32]byte
	Providers map[string]bool
	// CallerScope is the host's caller-scope hash for this key's principal.
	CallerScope string
}

// Principal returns the principal the plugin reports for this key.
func (k Key) Principal() string { return PrincipalPrefix + k.Name }

// subscriptionProviders are the providers the gate protects and the scheduler ranks.
var subscriptionProviders = map[string]bool{"claude": true, "codex": true}

// ParseConfig decodes and normalizes the plugin YAML configuration.
func ParseConfig(raw []byte) (Settings, error) {
	var cfg Config
	if len(raw) > 0 {
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return Settings{}, fmt.Errorf("fleet: config: %w", err)
		}
	}
	s := Settings{
		Enabled:          cfg.Enabled,
		GateEnabled:      boolDefault(cfg.Gate.Enabled, true),
		SchedulerEnabled: boolDefault(cfg.Scheduler.Enabled, true),
	}
	var err error
	if s.ClaudeCacheTTL, err = durationDefault(cfg.Scheduler.ClaudeCacheTTL, 5*time.Minute); err != nil {
		return Settings{}, err
	}
	if s.ClaudeExtendedCacheTTL, err = durationDefault(cfg.Scheduler.ClaudeExtendedCacheTTL, time.Hour); err != nil {
		return Settings{}, err
	}
	if s.CodexIdleTTL, err = durationDefault(cfg.Scheduler.CodexIdleTTL, time.Hour); err != nil {
		return Settings{}, err
	}
	seen := map[string]bool{}
	for _, kc := range cfg.Keys {
		name := strings.TrimSpace(kc.Name)
		if name == "" || seen[name] {
			return Settings{}, fmt.Errorf("fleet: key names must be unique and non-empty")
		}
		seen[name] = true
		digest, errHex := hex.DecodeString(strings.TrimSpace(kc.SHA256))
		if errHex != nil || len(digest) != sha256.Size {
			return Settings{}, fmt.Errorf("fleet: key %q needs a 64-character sha256 hex digest", name)
		}
		if len(kc.Providers) == 0 {
			return Settings{}, fmt.Errorf("fleet: key %q must list allowed providers", name)
		}
		k := Key{Name: name, Digest: [sha256.Size]byte(digest), Providers: lowerSet(kc.Providers)}
		k.CallerScope = cliproxysession.CallerScope(k.Principal())
		s.Keys = append(s.Keys, k)
	}
	s.Exclusive = boolDefault(cfg.Exclusive, len(s.Keys) > 0)
	// Non-plugin credentials (access.api-keys) are authenticated by the host without this
	// plugin, so they could reach routes the gate never inspects. The gate therefore
	// requires fleet keys to be the only authentication.
	if s.GateEnabled && (len(s.Keys) == 0 || !s.Exclusive) {
		return Settings{}, fmt.Errorf("fleet: the client gate requires fleet keys with exclusive authentication")
	}
	return s, nil
}

func boolDefault(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func durationDefault(raw string, def time.Duration) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("fleet: invalid duration %q", raw)
	}
	return d, nil
}

func lowerSet(values []string) map[string]bool {
	out := map[string]bool{}
	for _, v := range values {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			out[v] = true
		}
	}
	return out
}
