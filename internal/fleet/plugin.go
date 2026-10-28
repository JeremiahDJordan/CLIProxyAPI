package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// PluginName is the plugin's metadata name; the shared library must be named
// fleet.so so its ID matches plugins.configs.fleet.
const PluginName = "fleet"

// Version is the plugin version reported at registration.
const Version = "1.0.0"

// Plugin holds all runtime state shared across hook calls.
type Plugin struct {
	mu         sync.RWMutex
	settings   Settings
	Book       *QuotaBook
	Sessions   *Sessions
	Classifier *Classifier
	Now        func() time.Time

	// pickMu makes ranking, probe recording and session binding one step, so
	// concurrent picks cannot both probe the same unknown account.
	pickMu sync.Mutex

	decisionsMu sync.Mutex
	decisions   []PickDecision
	gateDenials map[string]int
	denials     []GateDenial

	// Log writes one line to the proxy's log; tests replace it.
	Log func(line string)
}

// GateDenial records why one request was refused, for the log and the
// management view. It holds no keys or request content.
type GateDenial struct {
	At       time.Time `json:"at"`
	Code     string    `json:"code"`
	TraceID  string    `json:"trace_id,omitempty"`
	Key      string    `json:"key,omitempty"`
	Provider string    `json:"provider,omitempty"`
	Model    string    `json:"model,omitempty"`
	Format   string    `json:"format,omitempty"`
	Route    string    `json:"route,omitempty"`
	Failed   []string  `json:"failed,omitempty"`
	// Classified is "before selection" when the gate used the classification
	// made from the client's original request, or "after selection" when it had
	// to classify the request again without the body.
	Classified string        `json:"classified,omitempty"`
	Checks     *ClientChecks `json:"checks,omitempty"`
}

// line renders the denial in the proxy's log format, keyed by the access log's request ID.
func (d GateDenial) line() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] [%s] [warn ] [fleet] gate denied %s", d.At.Format("2006-01-02 15:04:05"), emptyAs(d.TraceID, "--------"), d.Code)
	if len(d.Failed) > 0 {
		fmt.Fprintf(&b, "; failed: %s", strings.Join(d.Failed, ", "))
	}
	field := func(name, value string) {
		if value != "" {
			fmt.Fprintf(&b, " %s=%q", name, value)
		}
	}
	field("key", d.Key)
	field("provider", d.Provider)
	field("model", d.Model)
	field("format", d.Format)
	field("route", d.Route)
	field("classified", d.Classified)
	if c := d.Checks; c != nil {
		field("entrypoint", c.Entrypoint)
		field("user_agent", c.UserAgent)
		field("originator", c.Originator)
		fmt.Fprintf(&b, " body_inspected=%t x_app_cli=%t claude_user_agent=%t claude_code_beta=%t metadata_user_id=%t codex_user_agent=%t official_originator=%t",
			c.BodyInspected, c.XAppCLI, c.ClaudeUserAgent, c.ClaudeCodeBeta, c.MetadataUserID, c.CodexUserAgent, c.OfficialOriginator)
	}
	return b.String()
}

// targetProvider is the selected credential's provider, which the fork host reports
// to after-selection interceptors for each execution. Target formats are not used:
// openai-response (for example responses/compact) can reach either provider.
func targetProvider(metadata map[string]any) string {
	v, _ := metadata["selected_auth_provider"].(string)
	return strings.ToLower(strings.TrimSpace(v))
}

// PickDecision records one scheduler outcome for the management view.
type PickDecision struct {
	At          time.Time `json:"at"`
	Provider    string    `json:"provider"`
	Model       string    `json:"model"`
	SessionHash string    `json:"session_hash,omitempty"`
	AuthID      string    `json:"auth_id,omitempty"`
	Reason      string    `json:"reason"`
	Candidates  int       `json:"candidates"`
}

// New returns a plugin with empty state.
func New() *Plugin {
	return &Plugin{
		Book:        NewQuotaBook(),
		Sessions:    NewSessions(),
		Classifier:  NewClassifier(),
		Now:         time.Now,
		gateDenials: map[string]int{},
		Log:         func(line string) { fmt.Fprintln(os.Stderr, line) },
	}
}

// Settings returns the active settings.
func (p *Plugin) Settings() Settings {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.settings
}

type lifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type capabilities struct {
	FrontendAuthProvider            bool `json:"frontend_auth_provider"`
	FrontendAuthProviderExclusive   bool `json:"frontend_auth_provider_exclusive"`
	Scheduler                       bool `json:"scheduler"`
	SchedulerAcrossPriorities       bool `json:"scheduler_across_priorities,omitempty"`
	RequestInterceptor              bool `json:"request_interceptor"`
	RequestInterceptorOmitBodyAfter bool `json:"request_interceptor_omit_body_after,omitempty"`
	WebSocketResponseObserver       bool `json:"websocket_response_observer"`
	UsagePlugin                     bool `json:"usage_plugin"`
	ManagementAPI                   bool `json:"management_api"`
}

type registration struct {
	SchemaVersion uint32             `json:"schema_version"`
	Metadata      pluginapi.Metadata `json:"metadata"`
	Capabilities  capabilities       `json:"capabilities"`
}

type identifierResponse struct {
	Identifier string `json:"identifier"`
}

type managementRegistration struct {
	Routes []pluginapi.ManagementRoute `json:"routes,omitempty"`
}

// Handle dispatches one ABI call and returns the response envelope.
func (p *Plugin) Handle(method string, request []byte) []byte {
	result, err := p.dispatch(method, request)
	if err != nil {
		return errorEnvelope("plugin_error", err.Error())
	}
	return result
}

func (p *Plugin) dispatch(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return p.configure(request)
	case pluginabi.MethodPluginQuiesce, pluginabi.MethodPluginShutdown:
		return okEnvelope(struct{}{})
	case pluginabi.MethodFrontendAuthIdentifier:
		return okEnvelope(identifierResponse{Identifier: PluginName})
	case pluginabi.MethodFrontendAuthAuthenticate:
		var req pluginapi.FrontendAuthRequest
		if err := json.Unmarshal(request, &req); err != nil {
			return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
		}
		resp, key := authenticate(p.Settings(), req)
		if resp.DenyStatusCode != 0 {
			p.deny(GateDenial{At: p.Now(), Code: "fleet_route_denied", Key: key.Name, Route: req.Method + " " + req.Path})
		}
		return okEnvelope(resp)
	case pluginabi.MethodRequestInterceptBefore:
		return p.interceptBefore(request)
	case pluginabi.MethodRequestInterceptAfter:
		return p.interceptAfter(request)
	case pluginabi.MethodSchedulerPick:
		return p.pick(request)
	case pluginabi.MethodUsageHandle:
		return p.usage(request)
	case pluginabi.MethodWebSocketResponseEvent:
		return p.websocketEvent(request)
	case pluginabi.MethodManagementRegister:
		return okEnvelope(managementRegistration{Routes: []pluginapi.ManagementRoute{{
			Method:      http.MethodGet,
			Path:        "/fleet/status",
			Description: "Per-account quota windows, scheduling order and gate counters (no secrets).",
		}}})
	case pluginabi.MethodManagementHandle:
		return p.management(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func (p *Plugin) configure(raw []byte) ([]byte, error) {
	var req lifecycleRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
	}
	settings, err := ParseConfig(req.ConfigYAML)
	if err != nil {
		return nil, err
	}
	if req.SchemaVersion != 0 && req.SchemaVersion < pluginabi.SchemaVersionWebSocketResponseObserver {
		return nil, fmt.Errorf("fleet: host schema version %d is too old", req.SchemaVersion)
	}
	p.mu.Lock()
	p.settings = settings
	p.mu.Unlock()
	hasKeys := len(settings.Keys) > 0
	return okEnvelope(registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             PluginName,
			Version:          Version,
			Author:           "Jeremiah Jordan",
			GitHubRepository: "https://github.com/JeremiahDJordan/CLIProxyAPI",
			ConfigFields: []pluginapi.ConfigField{
				{Name: "keys", Type: pluginapi.ConfigFieldTypeArray, Description: "Client keys: name, sha256 digest and allowed providers (claude, codex)."},
				{Name: "exclusive", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Make fleet keys the only request authentication (default true when keys exist)."},
				{Name: "gate", Type: pluginapi.ConfigFieldTypeObject, Description: "Native-client gate for subscription providers."},
				{Name: "scheduler", Type: pluginapi.ConfigFieldTypeObject, Description: "Weekly-reset-first scheduler and affinity cache lifetimes."},
			},
		},
		Capabilities: capabilities{
			FrontendAuthProvider:          hasKeys,
			FrontendAuthProviderExclusive: hasKeys && settings.Exclusive,
			Scheduler:                     settings.SchedulerEnabled,
			// The weekly-reset rule ignores credential priority tiers, so rank every eligible account.
			SchedulerAcrossPriorities: settings.SchedulerEnabled,
			RequestInterceptor:        settings.GateEnabled || hasKeys || settings.SchedulerEnabled,
			// The after-selection check needs only headers, formats and caller scope.
			RequestInterceptorOmitBodyAfter: true,
			WebSocketResponseObserver:       true,
			UsagePlugin:                     true,
			ManagementAPI:                   true,
		},
	})
}

func (p *Plugin) interceptBefore(raw []byte) ([]byte, error) {
	var req pluginapi.RequestInterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	now := p.Now()
	cl := Classify(req)
	p.Classifier.Store(req.RequestID, cl, now)
	if cl.ExtendedCache {
		p.Sessions.NoteExtendedCache(cl.Session, now)
	}
	return okEnvelope(pluginapi.RequestInterceptResponse{})
}

func (p *Plugin) interceptAfter(raw []byte) ([]byte, error) {
	var req pluginapi.RequestInterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		// An unreadable request cannot be verified; deny gated traffic by failing closed.
		d := Decision{Code: "fleet_unreadable_request", Reason: "request could not be inspected"}
		p.deny(GateDenial{At: p.Now(), Code: d.Code})
		return okEnvelope(Denial(d))
	}
	cl, ok := p.Classifier.Load(req.RequestID)
	classified := "before selection"
	if !ok {
		cl = Classify(req)
		classified = "after selection"
	}
	settings := p.Settings()
	provider := targetProvider(req.Metadata)
	d := Evaluate(settings, cl, provider, req.CallerScope)
	if d.Allow {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	key, _ := KeyForScope(settings, req.CallerScope)
	checks := cl.Checks
	p.deny(GateDenial{
		At: p.Now(), Code: d.Code, TraceID: req.TraceID, Key: key.Name, Provider: provider,
		Model: req.Model, Format: cl.SourceFormat, Failed: d.Failed, Classified: classified, Checks: &checks,
	})
	if req.TraceID != "" {
		d.Reason += " (request " + req.TraceID + ")"
	}
	return okEnvelope(Denial(d))
}

// deny counts, keeps and logs one denial.
func (p *Plugin) deny(d GateDenial) {
	p.decisionsMu.Lock()
	p.gateDenials[d.Code]++
	p.denials = append(p.denials, d)
	if len(p.denials) > 50 {
		p.denials = p.denials[len(p.denials)-50:]
	}
	p.decisionsMu.Unlock()
	if p.Log != nil {
		p.Log(d.line())
	}
}

func (p *Plugin) pick(raw []byte) ([]byte, error) {
	var req pluginapi.SchedulerPickRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	resp, decision := p.Pick(req)
	p.record(decision)
	return okEnvelope(resp)
}

// Pick applies the weekly-reset-first rule with cache-aware session affinity.
func (p *Plugin) Pick(req pluginapi.SchedulerPickRequest) (pluginapi.SchedulerPickResponse, PickDecision) {
	settings := p.Settings()
	now := p.Now()
	provider := pickProvider(req)
	decision := PickDecision{At: now, Provider: provider, Model: req.Model, Candidates: len(req.Candidates)}
	if !settings.SchedulerEnabled || !subscriptionProviders[provider] {
		decision.Reason = "not-handled"
		return pluginapi.SchedulerPickResponse{Handled: false}, decision
	}
	// Prefer the host's canonical identity (derived from headers and body, as in the
	// before-selection hook); re-deriving from headers alone can be weaker.
	session, _ := req.Options.Metadata["canonical_session_id"].(string)
	if session = strings.TrimSpace(session); session == "" {
		session = cliproxyauth.CanonicalSessionID(req.Options.Headers, nil, req.Options.Metadata)
	}
	if session != "" {
		decision.SessionHash = shortHash(session)
	}
	p.pickMu.Lock()
	defer p.pickMu.Unlock()
	ranked := Rank(p.Book, req.Candidates, req.Model, now)
	if len(ranked) == 0 {
		decision.Reason = "all-excluded-fallback"
		return pluginapi.SchedulerPickResponse{Handled: false}, decision
	}
	ttl := p.Sessions.TTLFor(settings, provider, session)
	chosen, reason := ranked[0].AuthID, "weekly-soonest"
	switch {
	case ranked[0].Probe:
		reason = "probe-unknown"
	case !ranked[0].View.Known:
		reason = "no-quota-data"
	}
	if b, live := p.Sessions.Lookup(provider, session, ttl, now); live {
		for _, r := range ranked {
			if r.AuthID == b.AuthID {
				chosen, reason = b.AuthID, "affinity"
				break
			}
		}
		if reason != "affinity" {
			reason = "affinity-rebind-excluded"
		}
	} else if b.AuthID != "" {
		reason = "affinity-expired:" + reason
	}
	if chosen == ranked[0].AuthID && ranked[0].Probe {
		p.Book.NoteProbe(chosen, now)
	}
	p.Sessions.Bind(provider, session, chosen, now)
	decision.AuthID, decision.Reason = chosen, reason
	return pluginapi.SchedulerPickResponse{AuthID: chosen, Handled: true}, decision
}

// pickProvider resolves the provider for a pick. Mixed routes (a model served by
// several providers) arrive with an empty Provider; the scheduler then handles the
// pick only when every candidate belongs to the same provider.
func pickProvider(req pluginapi.SchedulerPickRequest) string {
	if p := strings.ToLower(strings.TrimSpace(req.Provider)); p != "" {
		return p
	}
	provider := ""
	for _, c := range req.Candidates {
		cp := strings.ToLower(strings.TrimSpace(c.Provider))
		if cp == "" || (provider != "" && cp != provider) {
			return ""
		}
		provider = cp
	}
	return provider
}

func (p *Plugin) usage(raw []byte) ([]byte, error) {
	var rec pluginapi.UsageRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return okEnvelope(struct{}{})
	}
	now := p.Now()
	p.Book.Observe(rec.Provider, rec.AuthID, rec.Model, rec.ResponseHeaders, now, rec.Alias)
	return okEnvelope(struct{}{})
}

func (p *Plugin) websocketEvent(raw []byte) ([]byte, error) {
	var ev pluginapi.WebSocketResponseEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		return okEnvelope(struct{}{})
	}
	if headers := helps.ParseCodexQuotaEventHeaders(ev.Payload); len(headers) > 0 {
		provider := ev.Provider
		if provider == "" {
			provider = "codex"
		}
		p.Book.Observe(provider, ev.AuthID, ev.Model, headers, p.Now(), ev.RequestedModel)
	}
	return okEnvelope(struct{}{})
}

// Status is the management view.
type Status struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Version     string          `json:"version"`
	Settings    StatusSettings  `json:"settings"`
	Accounts    []AccountStatus `json:"accounts"`
	Bindings    int             `json:"session_bindings"`
	GateDenials map[string]int  `json:"gate_denials"`
	// RecentDenials are the last 50 denials with the checks that failed.
	RecentDenials []GateDenial   `json:"recent_denials"`
	Recent        []PickDecision `json:"recent_picks"`
}

// StatusSettings summarizes configuration without key digests.
type StatusSettings struct {
	KeyNames          []string `json:"key_names"`
	Exclusive         bool     `json:"exclusive"`
	Gate              bool     `json:"gate"`
	Scheduler         bool     `json:"scheduler"`
	ClaudeCacheTTL    string   `json:"claude_cache_ttl"`
	ClaudeExtendedTTL string   `json:"claude_extended_cache_ttl"`
	CodexIdleTTL      string   `json:"codex_idle_ttl"`
}

// AccountStatus is one account's windows and per-model views.
type AccountStatus struct {
	Account
	Views map[string]View `json:"views"`
}

// BuildStatus assembles the management view.
func (p *Plugin) BuildStatus() Status {
	settings := p.Settings()
	now := p.Now()
	st := Status{GeneratedAt: now, Version: Version, Bindings: p.Sessions.Count(), GateDenials: map[string]int{}}
	for _, k := range settings.Keys {
		st.Settings.KeyNames = append(st.Settings.KeyNames, k.Name)
	}
	st.Settings.Exclusive, st.Settings.Gate, st.Settings.Scheduler = settings.Exclusive, settings.GateEnabled, settings.SchedulerEnabled
	st.Settings.ClaudeCacheTTL = settings.ClaudeCacheTTL.String()
	st.Settings.ClaudeExtendedTTL = settings.ClaudeExtendedCacheTTL.String()
	st.Settings.CodexIdleTTL = settings.CodexIdleTTL.String()
	for _, acct := range p.Book.All() {
		as := AccountStatus{Account: acct, Views: map[string]View{"*": ViewFor(acct, "", now)}}
		for model := range acct.ModelWeekly {
			as.Views[model] = ViewFor(acct, model, now)
		}
		st.Accounts = append(st.Accounts, as)
	}
	p.decisionsMu.Lock()
	for k, v := range p.gateDenials {
		st.GateDenials[k] = v
	}
	st.RecentDenials = append(st.RecentDenials, p.denials...)
	st.Recent = append(st.Recent, p.decisions...)
	p.decisionsMu.Unlock()
	return st
}

func (p *Plugin) management(raw []byte) ([]byte, error) {
	var req pluginapi.ManagementRequest
	_ = json.Unmarshal(raw, &req)
	if req.Method != "" && req.Method != http.MethodGet {
		return okEnvelope(pluginapi.ManagementResponse{StatusCode: http.StatusMethodNotAllowed})
	}
	body, err := json.MarshalIndent(p.BuildStatus(), "", "  ")
	if err != nil {
		return nil, err
	}
	return okEnvelope(pluginapi.ManagementResponse{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       body,
	})
}

func (p *Plugin) record(d PickDecision) {
	p.decisionsMu.Lock()
	defer p.decisionsMu.Unlock()
	p.decisions = append(p.decisions, d)
	if len(p.decisions) > 50 {
		p.decisions = p.decisions[len(p.decisions)-50:]
	}
}

func shortHash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:6])
}

func okEnvelope(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(pluginabi.Envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := pluginabi.NewErrorEnvelope(code, message)
	return raw
}
