package fleet

import (
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// Binding keeps a session on the account that holds its prompt cache.
type Binding struct {
	AuthID   string        `json:"auth_id"`
	LastUsed time.Time     `json:"last_used"`
	TTL      time.Duration `json:"-"`
}

// Sessions tracks session affinity and per-session cache lifetimes.
type Sessions struct {
	mu       sync.Mutex
	bindings map[string]Binding       // provider|session -> binding
	cacheTTL map[string]time.Duration // session -> requested Claude cache lifetime
	seen     map[string]time.Time     // session -> last cacheTTL update, for pruning
}

// NewSessions returns empty session state.
func NewSessions() *Sessions {
	return &Sessions{bindings: map[string]Binding{}, cacheTTL: map[string]time.Duration{}, seen: map[string]time.Time{}}
}

func bindingKey(provider, session string) string { return strings.ToLower(provider) + "|" + session }

// NoteCacheTTL records the Claude cache lifetime a session requested.
func (s *Sessions) NoteCacheTTL(session string, ttl time.Duration, now time.Time) {
	if session == "" || ttl <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ttl > s.cacheTTL[session] {
		s.cacheTTL[session] = ttl
	}
	s.seen[session] = now
}

// Bind records that session is using authID now.
func (s *Sessions) Bind(provider, session, authID string, ttl time.Duration, now time.Time) {
	if session == "" || authID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindings[bindingKey(provider, session)] = Binding{AuthID: authID, LastUsed: now, TTL: ttl}
	s.pruneLocked(now)
}

// Touch refreshes an existing binding after a completed request on the same account.
func (s *Sessions) Touch(provider, session, authID string, now time.Time) {
	if session == "" || authID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := bindingKey(provider, session)
	if b, ok := s.bindings[key]; ok && b.AuthID == authID {
		b.LastUsed = now
		s.bindings[key] = b
	}
}

// Lookup returns a live binding for the session: one whose idle time has not exceeded
// the cache lifetime that applies to it.
func (s *Sessions) Lookup(provider, session string, ttl time.Duration, now time.Time) (Binding, bool) {
	if session == "" {
		return Binding{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bindings[bindingKey(provider, session)]
	if !ok {
		return Binding{}, false
	}
	if ttl <= 0 {
		ttl = b.TTL
	}
	if now.Sub(b.LastUsed) > ttl {
		return b, false
	}
	return b, true
}

// TTLFor returns the affinity idle limit for a session on provider.
func (s *Sessions) TTLFor(settings Settings, provider, session string) time.Duration {
	if strings.EqualFold(provider, "codex") {
		return settings.CodexIdleTTL
	}
	s.mu.Lock()
	requested := s.cacheTTL[session]
	s.mu.Unlock()
	if requested >= time.Hour {
		return settings.ClaudeExtendedCacheTTL
	}
	return settings.ClaudeCacheTTL
}

// Count returns the number of tracked bindings.
func (s *Sessions) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bindings)
}

func (s *Sessions) pruneLocked(now time.Time) {
	if len(s.bindings) < 4096 && len(s.seen) < 4096 {
		return
	}
	for k, b := range s.bindings {
		if now.Sub(b.LastUsed) > 24*time.Hour {
			delete(s.bindings, k)
		}
	}
	for k, t := range s.seen {
		if now.Sub(t) > 24*time.Hour {
			delete(s.seen, k)
			delete(s.cacheTTL, k)
		}
	}
}

// Ranked is one candidate with its scheduling view.
type Ranked struct {
	AuthID string `json:"auth_id"`
	View   View   `json:"view"`
}

// Rank orders candidates: excluded accounts are dropped; accounts with a known weekly
// reset come first by soonest weekly reset, then by more weekly quota remaining;
// accounts without quota data follow in host priority order, then by ID.
func Rank(book *QuotaBook, candidates []pluginapi.SchedulerAuthCandidate, model string, now time.Time) []Ranked {
	type entry struct {
		Ranked
		priority int
	}
	var known, unknown []entry
	for _, c := range candidates {
		acct, _ := book.Snapshot(c.ID)
		v := ViewFor(acct, model, now)
		if v.Excluded() {
			continue
		}
		e := entry{Ranked: Ranked{AuthID: c.ID, View: v}, priority: c.Priority}
		if v.Known {
			known = append(known, e)
		} else {
			unknown = append(unknown, e)
		}
	}
	sort.SliceStable(known, func(i, j int) bool {
		a, b := known[i].View, known[j].View
		if !a.WeeklyResetAt.Equal(b.WeeklyResetAt) {
			return a.WeeklyResetAt.Before(b.WeeklyResetAt)
		}
		if a.WeeklyLeft != b.WeeklyLeft {
			return a.WeeklyLeft > b.WeeklyLeft
		}
		return known[i].AuthID < known[j].AuthID
	})
	sort.SliceStable(unknown, func(i, j int) bool {
		if unknown[i].priority != unknown[j].priority {
			return unknown[i].priority > unknown[j].priority
		}
		return unknown[i].AuthID < unknown[j].AuthID
	})
	out := make([]Ranked, 0, len(known)+len(unknown))
	for _, e := range known {
		out = append(out, e.Ranked)
	}
	for _, e := range unknown {
		out = append(out, e.Ranked)
	}
	return out
}

func headerGet(headers http.Header, name string) string {
	if v := headers.Get(name); v != "" {
		return v
	}
	for k, values := range headers {
		if strings.EqualFold(k, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}
