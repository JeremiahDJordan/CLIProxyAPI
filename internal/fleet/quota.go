package fleet

import (
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Window kinds tracked per account.
const (
	kindFiveHour = "5h"
	kindWeekly   = "weekly"
)

var (
	fiveHourPeriod = 5 * time.Hour
	weeklyPeriod   = 7 * 24 * time.Hour

	// Anthropic-Ratelimit-Unified-<window>-<field>; window is 5h, 7d or a
	// model-specific 7d_<name> claim (for example 7d_oi). Overage is not a window.
	claudeWindowHeader = regexp.MustCompile(`(?i)^anthropic-ratelimit-unified-([a-z0-9_]+)-(status|reset|utilization)$`)
	// X-Codex-[<limit>-]<primary|secondary>-<field>, as produced by the Codex backend
	// and by upstream helps.ParseCodexQuotaEventHeaders for WebSocket rate-limit events.
	// Limit identifiers use upstream's normalized alphabet (letters, digits, '.', '_', '-'),
	// e.g. X-Codex-Additional-GPT-5.3-Codex-Spark-Secondary-Used-Percent.
	codexWindowHeader = regexp.MustCompile(`(?i)^x-codex-(?:([a-z0-9][a-z0-9._-]*?)-)?(primary|secondary)-(used-percent|window-minutes|reset-after-seconds|reset-at)$`)
)

// Window is the latest observation of one quota window.
type Window struct {
	Name       string        `json:"name"`
	Kind       string        `json:"kind"`
	Used       float64       `json:"used"`
	Rejected   bool          `json:"rejected,omitempty"`
	ResetAt    time.Time     `json:"reset_at"`
	ObservedAt time.Time     `json:"observed_at"`
	Period     time.Duration `json:"-"`
}

// effective projects the window forward: after its reset passes it is a fresh window
// whose next reset is one period later.
func (w Window) effective(now time.Time) Window {
	if w.ResetAt.IsZero() || w.Period <= 0 || now.Before(w.ResetAt) {
		return w
	}
	steps := math.Floor(float64(now.Sub(w.ResetAt))/float64(w.Period)) + 1
	w.ResetAt = w.ResetAt.Add(time.Duration(steps) * w.Period)
	w.Used = 0
	w.Rejected = false
	return w
}

// Exhausted reports whether the window currently blocks use.
func (w Window) Exhausted(now time.Time) bool {
	e := w.effective(now)
	return e.Rejected || e.Used >= 1
}

// Account is the tracked quota state for one credential.
type Account struct {
	AuthID   string `json:"auth_id"`
	Provider string `json:"provider"`
	// Windows keyed by window name ("5h", "7d", "7d_oi", "primary", "spark-secondary"...).
	Windows map[string]Window `json:"windows"`
	// ModelWeekly maps a model to the model-specific weekly window observed for it.
	ModelWeekly map[string]string `json:"model_weekly,omitempty"`
	// ManualResets counts observations where a window reset early (quota restored or
	// reset time moved later before the previous reset was due).
	ManualResets int       `json:"manual_resets,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// QuotaBook stores quota observations for all accounts.
type QuotaBook struct {
	mu       sync.Mutex
	accounts map[string]*Account
	probed   map[string]time.Time // auth ID -> when it was last chosen to learn its quota
}

// NewQuotaBook returns an empty quota book.
func NewQuotaBook() *QuotaBook {
	return &QuotaBook{accounts: map[string]*Account{}, probed: map[string]time.Time{}}
}

// probeRetry is how long an account chosen to learn its quota waits before it is
// tried first again, when its response did not report quota (an error or no headers).
const probeRetry = time.Hour

// NoteProbe records that authID was chosen so its response reveals its quota.
func (b *QuotaBook) NoteProbe(authID string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probed[authID] = now
}

func (b *QuotaBook) probeDue(authID string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	at, ok := b.probed[authID]
	return !ok || now.Sub(at) >= probeRetry
}

// Observe records rate-limit headers returned for authID while serving model; any
// aliases (the requested route model) share the model-specific association. A Codex
// response metered by the shared limit clears earlier associations for those names.
// It reports whether any quota window was recognized.
func (b *QuotaBook) Observe(provider, authID, model string, headers http.Header, now time.Time, aliases ...string) bool {
	authID = strings.TrimSpace(authID)
	if authID == "" || len(headers) == 0 {
		return false
	}
	var windows []Window
	modelSpecific, shared := "", false
	switch strings.ToLower(provider) {
	case "claude":
		windows, modelSpecific = parseClaudeWindows(headers, now)
	case "codex":
		windows, modelSpecific, shared = parseCodexWindows(headers, now)
	}
	if len(windows) == 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	acct := b.accounts[authID]
	if acct == nil {
		acct = &Account{AuthID: authID, Windows: map[string]Window{}, ModelWeekly: map[string]string{}}
		b.accounts[authID] = acct
	}
	acct.Provider = strings.ToLower(provider)
	for _, w := range windows {
		if prev, ok := acct.Windows[w.Name]; ok && earlyReset(prev, w, now) {
			acct.ManualResets++
		}
		acct.Windows[w.Name] = w
	}
	if modelSpecific != "" || shared {
		for _, name := range append([]string{model}, aliases...) {
			if key := modelKey(name); key == "" {
				continue
			} else if modelSpecific != "" {
				acct.ModelWeekly[key] = modelSpecific
			} else {
				delete(acct.ModelWeekly, key)
			}
		}
	}
	acct.UpdatedAt = now
	return true
}

// earlyReset detects a reset before the previously reported reset time: the window
// was consumed and is now restored, or its reset time moved later while still due.
func earlyReset(prev, next Window, now time.Time) bool {
	if prev.ResetAt.IsZero() || !now.Before(prev.ResetAt) {
		return false
	}
	restored := prev.Used-next.Used >= 0.25 || (prev.Rejected && !next.Rejected)
	moved := next.ResetAt.Sub(prev.ResetAt) > 10*time.Minute
	return restored || moved
}

// Snapshot returns a copy of the tracked state for authID.
func (b *QuotaBook) Snapshot(authID string) (Account, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	acct := b.accounts[authID]
	if acct == nil {
		return Account{}, false
	}
	out := *acct
	out.Windows = make(map[string]Window, len(acct.Windows))
	for k, v := range acct.Windows {
		out.Windows[k] = v
	}
	out.ModelWeekly = make(map[string]string, len(acct.ModelWeekly))
	for k, v := range acct.ModelWeekly {
		out.ModelWeekly[k] = v
	}
	return out, true
}

// All returns copies of all tracked accounts sorted by auth ID.
func (b *QuotaBook) All() []Account {
	b.mu.Lock()
	ids := make([]string, 0, len(b.accounts))
	for id := range b.accounts {
		ids = append(ids, id)
	}
	b.mu.Unlock()
	sort.Strings(ids)
	out := make([]Account, 0, len(ids))
	for _, id := range ids {
		if a, ok := b.Snapshot(id); ok {
			out = append(out, a)
		}
	}
	return out
}

// View is the scheduler's interpretation of an account for one model.
type View struct {
	Known           bool      `json:"known"`
	FiveHourBlock   bool      `json:"five_hour_exhausted"`
	WeeklyBlock     bool      `json:"weekly_exhausted"`
	WeeklyWindow    string    `json:"weekly_window,omitempty"`
	WeeklyResetAt   time.Time `json:"weekly_reset_at,omitempty"`
	WeeklyLeft      float64   `json:"weekly_remaining"`
	FiveHourResetAt time.Time `json:"five_hour_reset_at,omitempty"`
}

// Excluded reports whether the scheduler must skip the account.
func (v View) Excluded() bool { return v.FiveHourBlock || v.WeeklyBlock }

// ViewFor evaluates acct for model at now. The ordering window is the model-specific
// weekly window when one was observed for this model, otherwise the general weekly
// window. Any exhausted weekly window excludes the account, since each still blocks.
func ViewFor(acct Account, model string, now time.Time) View {
	v := View{}
	if len(acct.Windows) == 0 {
		return v
	}
	general := ""
	for name, w := range acct.Windows {
		if w.Kind == kindWeekly && isGeneralWeekly(name) {
			general = name
		}
	}
	order := general
	specific := acct.ModelWeekly[modelKey(model)]
	if specific != "" {
		if _, ok := acct.Windows[specific]; ok {
			order = specific
		}
	}
	// Shared 5-hour windows block every model; a named (model-specific) Codex 5-hour
	// limit such as "spark-primary" blocks only models whose weekly limit shares its name.
	specificLimit, _ := limitPrefix(specific)
	for name, w := range acct.Windows {
		if w.Kind != kindFiveHour {
			continue
		}
		if prefix, named := limitPrefix(name); named && prefix != specificLimit {
			continue
		}
		e := w.effective(now)
		if v.FiveHourResetAt.IsZero() || e.ResetAt.Before(v.FiveHourResetAt) {
			v.FiveHourResetAt = e.ResetAt
		}
		if w.Exhausted(now) {
			v.FiveHourBlock = true
		}
	}
	// A model-specific weekly window only blocks the model it was observed for;
	// the general weekly window blocks every model.
	for _, name := range []string{general, order} {
		if w, ok := acct.Windows[name]; ok && w.Exhausted(now) {
			v.WeeklyBlock = true
		}
	}
	if order != "" {
		e := acct.Windows[order].effective(now)
		v.Known = !e.ResetAt.IsZero()
		v.WeeklyWindow = order
		v.WeeklyResetAt = e.ResetAt
		v.WeeklyLeft = math.Max(0, 1-e.Used)
	}
	return v
}

// limitPrefix returns the named-limit prefix of a Codex window ("spark" for
// "spark-secondary"); unnamed windows report false.
func limitPrefix(name string) (string, bool) {
	if i := strings.LastIndexByte(name, '-'); i > 0 {
		return name[:i], true
	}
	return "", false
}

func isGeneralWeekly(name string) bool {
	switch name {
	case "7d", "secondary", "primary":
		return true
	}
	return false
}

func parseClaudeWindows(headers http.Header, now time.Time) ([]Window, string) {
	byName := map[string]*Window{}
	for name, values := range headers {
		m := claudeWindowHeader.FindStringSubmatch(name)
		if m == nil || len(values) == 0 {
			continue
		}
		window := strings.ToLower(m[1])
		var kind string
		var period time.Duration
		switch {
		case window == "5h":
			kind, period = kindFiveHour, fiveHourPeriod
		case window == "7d" || strings.HasPrefix(window, "7d_"):
			kind, period = kindWeekly, weeklyPeriod
		default:
			continue // overage and unrecognized claims are not scheduling windows
		}
		w := byName[window]
		if w == nil {
			w = &Window{Name: window, Kind: kind, Period: period, ObservedAt: now}
			byName[window] = w
		}
		value := strings.TrimSpace(values[0])
		switch strings.ToLower(m[2]) {
		case "status":
			w.Rejected = strings.EqualFold(value, "rejected")
		case "reset":
			if t, ok := parseResetTime(value); ok {
				w.ResetAt = t
			}
		case "utilization":
			if f, err := strconv.ParseFloat(value, 64); err == nil && f >= 0 {
				w.Used = f
			}
		}
	}
	specific := ""
	out := make([]Window, 0, len(byName))
	for name, w := range byName {
		if strings.HasPrefix(name, "7d_") {
			specific = name
		}
		out = append(out, *w)
	}
	return out, specific
}

// codexSharedLimits are X-Codex-Active-Limit names Codex uses for the plan-wide limit
// (the unnamed primary/secondary windows); named limits look like "codex_bengalfox" or
// "GPT-5.3-Codex-Spark".
var codexSharedLimits = map[string]bool{"codex": true, "premium": true}

// parseCodexWindows also reports shared when X-Codex-Active-Limit names the plan-wide
// limit. Other unmatched names (such as a named limit whose weekly window is missing
// from a partial update) are not treated as shared.
func parseCodexWindows(headers http.Header, now time.Time) (out []Window, specific string, shared bool) {
	type raw struct {
		used, minutes, after float64
		at                   time.Time
		hasUsed, hasMinutes  bool
		hasAfter             bool
	}
	byName := map[string]*raw{}
	for name, values := range headers {
		m := codexWindowHeader.FindStringSubmatch(name)
		if m == nil || len(values) == 0 {
			continue
		}
		key := strings.ToLower(m[2])
		if strings.EqualFold(m[1], "code-review") {
			continue // code-review limits do not gate model requests
		}
		if m[1] != "" {
			key = strings.ToLower(m[1]) + "-" + key
		}
		r := byName[key]
		if r == nil {
			r = &raw{}
			byName[key] = r
		}
		value := strings.TrimSpace(values[0])
		f, errF := strconv.ParseFloat(value, 64)
		switch strings.ToLower(m[3]) {
		case "used-percent":
			if errF == nil {
				r.used, r.hasUsed = f/100, true
			}
		case "window-minutes":
			if errF == nil {
				r.minutes, r.hasMinutes = f, true
			}
		case "reset-after-seconds":
			if errF == nil && f >= 0 {
				r.after, r.hasAfter = f, true
			}
		case "reset-at":
			if t, ok := parseResetTime(value); ok {
				r.at = t
			}
		}
	}
	for name, r := range byName {
		if !r.hasUsed || !r.hasMinutes || r.minutes <= 0 {
			continue
		}
		w := Window{Name: name, Used: r.used, ObservedAt: now, Period: time.Duration(r.minutes) * time.Minute}
		switch {
		case r.minutes <= 6*60:
			w.Kind = kindFiveHour
		case r.minutes >= 6*24*60:
			w.Kind = kindWeekly
		default:
			continue
		}
		if !r.at.IsZero() {
			w.ResetAt = r.at
		} else if r.hasAfter {
			w.ResetAt = now.Add(time.Duration(r.after * float64(time.Second)))
		}
		out = append(out, w)
	}
	// Responses carry every limit's windows; only the limit that metered this request
	// (X-Codex-Active-Limit) is model-specific for it. Without a match the model uses
	// the shared weekly window.
	if active := strings.ToLower(strings.TrimSpace(headerGet(headers, "X-Codex-Active-Limit"))); active != "" {
		for _, w := range out {
			if prefix, named := limitPrefix(w.Name); named && w.Kind == kindWeekly && activeLimitMatches(active, prefix) {
				specific = w.Name
				break
			}
		}
		shared = specific == "" && codexSharedLimits[active]
	}
	return out, specific, shared
}

// activeLimitMatches relates X-Codex-Active-Limit ("codex_bengalfox",
// "GPT-5.3-Codex-Spark") to a window's limit prefix ("bengalfox",
// "additional-gpt-5.3-codex-spark").
func activeLimitMatches(active, prefix string) bool {
	return prefix == active || prefix == "additional-"+active || strings.HasSuffix(active, "_"+prefix)
}

// parseResetTime accepts Unix seconds, Unix milliseconds or RFC 3339.
func parseResetTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if f, err := strconv.ParseFloat(raw, 64); err == nil && f > 0 {
		if f > 1e12 {
			return time.UnixMilli(int64(f)).UTC(), true
		}
		sec, frac := math.Modf(f)
		return time.Unix(int64(sec), int64(frac*1e9)).UTC(), true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

// modelKey normalizes a model ID for per-model bookkeeping (drops thinking suffixes).
func modelKey(model string) string {
	model = strings.ToLower(strings.TrimSpace(model))
	if i := strings.IndexByte(model, '('); i > 0 {
		model = model[:i]
	}
	return model
}
