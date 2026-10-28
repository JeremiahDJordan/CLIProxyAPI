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
	AuthID   string    `json:"auth_id"`
	LastUsed time.Time `json:"last_used"`
}

// Sessions tracks session affinity and which Claude sessions requested the one-hour cache.
type Sessions struct {
	mu       sync.Mutex
	bindings map[string]Binding   // provider|session -> binding
	extended map[string]time.Time // session -> last request with cache_control ttl "1h"
}

// NewSessions returns empty session state.
func NewSessions() *Sessions {
	return &Sessions{bindings: map[string]Binding{}, extended: map[string]time.Time{}}
}

func bindingKey(provider, session string) string { return strings.ToLower(provider) + "|" + session }

// NoteExtendedCache records that a Claude session requested the one-hour cache.
func (s *Sessions) NoteExtendedCache(session string, now time.Time) {
	if session == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.extended[session] = now
}

// Bind records that session is using authID now.
func (s *Sessions) Bind(provider, session, authID string, now time.Time) {
	if session == "" || authID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindings[bindingKey(provider, session)] = Binding{AuthID: authID, LastUsed: now}
	s.pruneLocked(now)
}

// Lookup returns the session's binding and whether it is live: idle for no longer
// than ttl, the cache lifetime that applies to the session.
func (s *Sessions) Lookup(provider, session string, ttl time.Duration, now time.Time) (Binding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bindings[bindingKey(provider, session)]
	return b, ok && session != "" && now.Sub(b.LastUsed) <= ttl
}

// TTLFor returns the affinity idle limit for a session on provider.
func (s *Sessions) TTLFor(settings Settings, provider, session string) time.Duration {
	if strings.EqualFold(provider, "codex") {
		return settings.CodexIdleTTL
	}
	s.mu.Lock()
	_, extended := s.extended[session]
	s.mu.Unlock()
	if extended {
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
	if len(s.bindings) < 4096 && len(s.extended) < 4096 {
		return
	}
	for k, b := range s.bindings {
		if now.Sub(b.LastUsed) > 24*time.Hour {
			delete(s.bindings, k)
		}
	}
	for k, t := range s.extended {
		if now.Sub(t) > 24*time.Hour {
			delete(s.extended, k)
		}
	}
}

// Ranked is one candidate with its scheduling view.
type Ranked struct {
	AuthID string `json:"auth_id"`
	View   View   `json:"view"`
	// Probe marks an account without quota data that has not been tried within
	// probeRetry; one request through it reveals its windows.
	Probe bool `json:"probe,omitempty"`
}

// Rank orders candidates: excluded accounts are dropped; accounts without quota data
// that are due a probe come first (one request learns their windows), then accounts
// with a known weekly reset by soonest weekly reset and more weekly quota remaining,
// then recently probed accounts that still have no data. Accounts without data are
// ordered by host priority, then by ID.
func Rank(book *QuotaBook, candidates []pluginapi.SchedulerAuthCandidate, model string, now time.Time) []Ranked {
	type entry struct {
		Ranked
		priority int
	}
	var entries []entry
	for _, c := range candidates {
		acct, _ := book.Snapshot(c.ID)
		if v := ViewFor(acct, model, now); !v.Excluded() {
			probe := !v.Known && book.probeDue(c.ID, now)
			entries = append(entries, entry{Ranked: Ranked{AuthID: c.ID, View: v, Probe: probe}, priority: c.Priority})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		switch {
		case a.Probe != b.Probe:
			return a.Probe
		case a.View.Known != b.View.Known:
			return a.View.Known
		case a.View.Known && !a.View.WeeklyResetAt.Equal(b.View.WeeklyResetAt):
			return a.View.WeeklyResetAt.Before(b.View.WeeklyResetAt)
		case a.View.Known && a.View.WeeklyLeft != b.View.WeeklyLeft:
			return a.View.WeeklyLeft > b.View.WeeklyLeft
		case !a.View.Known && a.priority != b.priority:
			return a.priority > b.priority
		}
		return a.AuthID < b.AuthID
	})
	out := make([]Ranked, len(entries))
	for i, e := range entries {
		out[i] = e.Ranked
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
