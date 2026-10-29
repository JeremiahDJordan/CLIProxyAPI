package archive

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"sync"
	"time"
)

// Attempt is one provider attempt of a request: a credential and model the
// conductor tries (design section 3). Its outbound requests (the first one
// and executor-local resends) are its sub-attempts. The conductor opens an
// attempt context per execution attempt; the attempt takes its attempt_seq
// when it is first used (a gate decision, an outbound request or a result),
// so contexts that are never used leave no gap in the numbering.
type Attempt struct {
	in *Ingress

	mu       sync.Mutex
	info     AttemptInfo
	seq      uint16
	begun    bool
	ended    bool
	started  time.Time
	subs     uint16 // outbound requests so far
	chunkSeq uint32 // upstream events of the current sub-attempt
	frameSeq uint32 // upstream WebSocket frames of the current sub-attempt
	status   int
	gate     string // gate decision: allow or deny
	gateCode string
	ids      identities
	last     requestCredential // of the latest outbound request
}

// requestCredential names the provider and credential of an outbound request.
type requestCredential struct {
	Provider, AuthID, AuthLabel, AuthType string
}

// AttemptInfo describes an attempt. Empty fields keep earlier values.
type AttemptInfo struct {
	AuthID         string `json:"auth_id,omitempty"`
	Provider       string `json:"provider,omitempty"`
	Model          string `json:"model,omitempty"`
	RequestedModel string `json:"requested_model,omitempty"`
	PickReason     string `json:"pick_reason,omitempty"`
	SessionID      string `json:"session_id,omitempty"`
}

func (i *AttemptInfo) merge(o AttemptInfo) {
	for _, f := range []struct {
		dst *string
		src string
	}{
		{&i.AuthID, o.AuthID}, {&i.Provider, o.Provider}, {&i.Model, o.Model},
		{&i.RequestedModel, o.RequestedModel}, {&i.PickReason, o.PickReason}, {&i.SessionID, o.SessionID},
	} {
		if f.src != "" {
			*f.dst = f.src
		}
	}
}

func (i AttemptInfo) sizeHint() int64 {
	return stringsSize(i.AuthID, i.Provider, i.Model, i.RequestedModel, i.PickReason, i.SessionID)
}

// AttemptEnd is an attempt's outcome. Error text is redacted when recorded.
type AttemptEnd struct {
	AuthID     string
	Provider   string
	Model      string
	Success    bool
	StatusCode int
	Error      string
	// Reason is why the attempt ended: result (the conductor recorded its
	// outcome), request_end or shutdown (closed with its request).
	Reason string
}

// Attempt end reasons.
const (
	AttemptEndedResult     = "result"
	AttemptEndedRequestEnd = "request_end"
	AttemptEndedShutdown   = "shutdown"
)

type attemptContextKey struct{}

// WithAttempt returns ctx carrying a new attempt of the request in ctx. It
// inherits the description of the attempt ctx already carries, so a resend
// after a credential refresh keeps its credential and model. With capture
// off, without an inference request in ctx, or after a recovered tap panic,
// it returns ctx itself, so the caller keeps its cancellation, deadline and
// values.
func WithAttempt(ctx context.Context) (out context.Context) {
	out = ctx
	if !Installed() || ctx == nil {
		return ctx
	}
	// A lost attempt leaves its traffic on the request's implicit attempt.
	var in *Ingress
	defer recoverTap("attempt.open", &in)
	in = IngressFromContext(ctx)
	if in == nil || in.rec == nil || in.class != RouteInference {
		return ctx
	}
	a := &Attempt{in: in}
	if prev := AttemptFromContext(ctx); prev != nil && prev.in == in {
		prev.mu.Lock()
		a.info = prev.info
		prev.mu.Unlock()
	}
	return context.WithValue(ctx, attemptContextKey{}, a)
}

// AttemptFromContext returns the attempt ctx carries, or nil.
func AttemptFromContext(ctx context.Context) *Attempt {
	if ctx == nil {
		return nil
	}
	a, _ := ctx.Value(attemptContextKey{}).(*Attempt)
	return a
}

// DescribeAttempt records what the conductor chose for the attempt in ctx.
func DescribeAttempt(ctx context.Context, info AttemptInfo) {
	if !Installed() {
		return
	}
	var in *Ingress
	defer recoverTap("attempt.describe", &in)
	if a := AttemptFromContext(ctx); a != nil {
		in = a.in
		a.mu.Lock()
		a.info.merge(info)
		a.mu.Unlock()
	}
}

// Gate decisions.
const (
	GateAllow = "allow"
	GateDeny  = "deny"
)

// NoteGate records the fleet gate's decision for the attempt in ctx, and a
// denial's code for its request too.
func NoteGate(ctx context.Context, decision, code string) {
	if !Installed() {
		return
	}
	var in *Ingress
	defer recoverTap("attempt.gate", &in)
	if a := AttemptFromContext(ctx); a != nil {
		in = a.in
		a.mu.Lock()
		a.gate, a.gateCode = decision, code
		if decision == GateDeny {
			// A denied attempt sends nothing; it begins here.
			a.beginLocked(time.Now())
		}
		a.mu.Unlock()
		a.in.NoteGate(code)
		return
	}
	IngressFromContext(ctx).NoteGate(code)
}

// EndAttempt records the outcome of the attempt in ctx. Only the first end
// counts; an attempt never used before begins here.
func EndAttempt(ctx context.Context, end AttemptEnd) {
	if !Installed() {
		return
	}
	var in *Ingress
	defer recoverTap("attempt.end", &in)
	if a := AttemptFromContext(ctx); a != nil {
		in = a.in
		if end.Reason == "" {
			end.Reason = AttemptEndedResult
		}
		a.end(end, time.Now())
	}
}

// CloseAttempts ends the request's attempts still open (their stream was
// abandoned, or the conductor returned without recording a result).
func (in *Ingress) CloseAttempts(reason string) {
	if in == nil {
		return
	}
	in.mu.Lock()
	open := in.open
	in.open = nil
	in.mu.Unlock()
	now := time.Now()
	for _, a := range open {
		a.end(AttemptEnd{Reason: reason}, now)
	}
}

// implicitAttempt is the attempt of taps that run outside any conductor
// attempt (a route that calls a provider directly).
func (in *Ingress) implicitAttempt() *Attempt {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.implicit == nil {
		in.implicit = &Attempt{in: in}
	}
	return in.implicit
}

type attemptStartData struct {
	AttemptInfo
}

type attemptEndData struct {
	AttemptInfo
	Success    bool   `json:"success"`
	Status     int    `json:"status,omitempty"`
	Error      string `json:"error,omitempty"`
	Ended      string `json:"ended"`
	Gate       string `json:"gate,omitempty"`
	GateCode   string `json:"gate_code,omitempty"`
	Requests   uint16 `json:"requests"`
	DurationUS int64  `json:"duration_us"`
	identities
}

// beginLocked assigns the attempt_seq and queues attempt_start, once. The
// caller holds a.mu, so attempt_start precedes the attempt's other events.
func (a *Attempt) beginLocked(now time.Time) {
	if a.begun {
		return
	}
	a.begun = true
	a.started = now
	a.seq = uint16(min(a.in.attempts.Add(1), 1<<16-1))
	a.in.mu.Lock()
	a.in.open = append(a.in.open, a)
	a.in.mu.Unlock()
	data := attemptStartData{AttemptInfo: a.info}
	a.in.Emit(&Event{Type: TypeAttemptStart, Time: now, AttemptSeq: a.seq, Capture: CaptureFull, Data: data, SizeHint: data.sizeHint()})
}

// nextRequest starts a sub-attempt for an outbound request. A resend's
// empty provider and credential fields are filled from the previous request.
func (a *Attempt) nextRequest(now time.Time, req *UpstreamRequest) (uint16, uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if req.Resend != "" {
		req.Provider = cmp.Or(req.Provider, a.last.Provider)
		req.AuthID = cmp.Or(req.AuthID, a.last.AuthID)
		req.AuthLabel = cmp.Or(req.AuthLabel, a.last.AuthLabel)
		req.AuthType = cmp.Or(req.AuthType, a.last.AuthType)
	}
	a.last = requestCredential{Provider: req.Provider, AuthID: req.AuthID, AuthLabel: req.AuthLabel, AuthType: req.AuthType}
	// The request names the credential where the conductor did not.
	chosen := a.info
	a.info.merge(AttemptInfo{AuthID: req.AuthID, Provider: req.Provider})
	a.info.merge(chosen)
	a.beginLocked(now)
	sub := a.subs
	if a.subs < 1<<16-1 {
		a.subs++
	}
	a.chunkSeq, a.frameSeq = 0, 0
	return a.seq, sub
}

// current returns the attempt_seq and the sub_attempt of the latest request.
func (a *Attempt) current(now time.Time) (uint16, uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.beginLocked(now)
	return a.seq, a.currentSubLocked()
}

func (a *Attempt) currentSubLocked() uint16 {
	if a.subs == 0 {
		return 0
	}
	return a.subs - 1
}

// nextChunk numbers an upstream event of the current sub-attempt (from 1).
func (a *Attempt) nextChunk(now time.Time) (uint16, uint16, uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.beginLocked(now)
	a.chunkSeq++
	return a.seq, a.currentSubLocked(), a.chunkSeq
}

// nextFrame numbers an upstream WebSocket frame of the current sub-attempt.
func (a *Attempt) nextFrame(now time.Time) (uint16, uint16, uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.beginLocked(now)
	a.frameSeq++
	return a.seq, a.currentSubLocked(), a.frameSeq
}

func (a *Attempt) setStatus(status int) {
	a.mu.Lock()
	a.status = status
	a.mu.Unlock()
}

// noteIDs records identities found in the attempt's upstream exchange, on
// the attempt and on its request.
func (a *Attempt) noteIDs(found identities) {
	if found.empty() {
		return
	}
	a.mu.Lock()
	a.ids.merge(found)
	a.mu.Unlock()
	a.in.mu.Lock()
	a.in.ids.merge(found)
	a.in.mu.Unlock()
}

func (a *Attempt) end(end AttemptEnd, now time.Time) {
	a.mu.Lock()
	if a.ended {
		a.mu.Unlock()
		return
	}
	a.beginLocked(now)
	a.ended = true
	a.info.merge(AttemptInfo{AuthID: end.AuthID, Provider: end.Provider, Model: end.Model})
	status := end.StatusCode
	if status == 0 {
		status = a.status
	}
	data := attemptEndData{
		AttemptInfo: a.info,
		Success:     end.Success,
		Status:      status,
		Error:       RedactText(end.Error),
		Ended:       end.Reason,
		Gate:        a.gate,
		GateCode:    a.gateCode,
		Requests:    a.subs,
		DurationUS:  now.Sub(a.started).Microseconds(),
		identities:  a.ids.clone(),
	}
	seq := a.seq
	a.mu.Unlock()

	a.in.mu.Lock()
	for i, open := range a.in.open {
		if open == a {
			a.in.open = append(a.in.open[:i], a.in.open[i+1:]...)
			break
		}
	}
	a.in.mu.Unlock()
	size := data.AttemptInfo.sizeHint() + stringsSize(data.Error, data.Ended, data.Gate, data.GateCode) + data.identities.sizeHint()
	a.in.Emit(&Event{Type: TypeAttemptEnd, Time: now, AttemptSeq: seq, Capture: CaptureFull, Data: data, SizeHint: size})
}

// identities are the joins of design section 5 found in upstream traffic.
type identities struct {
	ResponseIDs        []string `json:"upstream_response_ids,omitempty"`
	PreviousResponseID string   `json:"previous_response_id,omitempty"`
	OutputItemIDs      []string `json:"output_item_ids,omitempty"`
}

const (
	maxResponseIDs   = 64
	maxOutputItemIDs = 1024
)

func (ids *identities) empty() bool {
	return len(ids.ResponseIDs) == 0 && ids.PreviousResponseID == "" && len(ids.OutputItemIDs) == 0
}

// addResponse and addItem collect identities found in one upstream event,
// as views of it; merge copies those an attempt or request keeps.
func (ids *identities) addResponse(id string) {
	ids.ResponseIDs = appendUnique(ids.ResponseIDs, id, maxResponseIDs, false)
}

func (ids *identities) addItem(id string) {
	ids.OutputItemIDs = appendUnique(ids.OutputItemIDs, id, maxOutputItemIDs, false)
}

// merge adds o's identities, copying each one it keeps, so a kept identity
// never refers to the event it was read from; one over the limits, or
// already kept, is never copied.
func (ids *identities) merge(o identities) {
	for _, id := range o.ResponseIDs {
		ids.ResponseIDs = appendUnique(ids.ResponseIDs, id, maxResponseIDs, true)
	}
	if ids.PreviousResponseID == "" && len(o.PreviousResponseID) <= maxOwnedLen {
		ids.PreviousResponseID = strings.Clone(o.PreviousResponseID)
	}
	for _, id := range o.OutputItemIDs {
		ids.OutputItemIDs = appendUnique(ids.OutputItemIDs, id, maxOutputItemIDs, true)
	}
}

func (ids identities) clone() identities {
	return identities{
		ResponseIDs:        append([]string(nil), ids.ResponseIDs...),
		PreviousResponseID: ids.PreviousResponseID,
		OutputItemIDs:      append([]string(nil), ids.OutputItemIDs...),
	}
}

func (ids identities) sizeHint() int64 {
	return stringsSize(ids.ResponseIDs...) + stringsSize(ids.PreviousResponseID) + stringsSize(ids.OutputItemIDs...) + 64
}

// appendUnique appends id when it is new and list has room, copying it
// first when keep is set.
func appendUnique(list []string, id string, limit int, keep bool) []string {
	if id == "" || len(id) > maxOwnedLen || len(list) >= limit || slices.Contains(list, id) {
		return list
	}
	if keep {
		id = strings.Clone(id)
	}
	return append(list, id)
}
