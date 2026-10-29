//go:build unix

package archive

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// inspectSetup starts a recorder and an inference request whose attempt
// has sent a request and had it rejected (415).
func inspectSetup(t *testing.T, mutate func(*TestOverrides)) (*testEnv, *Recorder, *Ingress, context.Context) {
	t.Helper()
	env := setup(t, "", mutate)
	rec := mustStart(t, env)
	in := rec.BeginIngress(RouteInference, time.Now())
	ctx := WithAttempt(WithIngress(context.Background(), in))
	TapUpstreamRequest(ctx, UpstreamRequest{URL: "https://api.example/v1/responses", Body: []byte(`{}`)})
	TapUpstreamResponse(ctx, 415, nil)
	return env, rec, in, ctx
}

// Round-5 decision A: a response body the executor discards before its
// resend is recorded without being read, at once, as the next upstream_event
// of the sub-attempt it answered: not_captured, with its reason, counted
// against the request like any not-captured body and never as a gap. The
// resend that follows is the next sub-attempt.
func TestUpstreamBodyNotCapturedIsRecordedWithoutReading(t *testing.T) {
	env, rec, in, ctx := inspectSetup(t, nil)
	TapUpstreamBodyNotCaptured(ctx, NotCapturedRejectedBeforeResend)
	TapUpstreamRequest(ctx, UpstreamRequest{URL: "https://api.example/v1/responses", Body: []byte(`{}`), Resend: ResendCompressionRejected})
	TapUpstreamChunk(ctx, []byte(`data: {}`))
	flush(t)
	events := readEvents(t, env.spool)
	upstream := ofType(events, TypeUpstreamEvent)
	if len(upstream) != 2 {
		t.Fatalf("upstream_event = %v", upstream)
	}
	ev := upstream[0]
	if ev["sub_attempt"] != float64(0) || ev["chunk_seq"] != float64(1) || ev["capture"] != CaptureDroppedBody ||
		ev["body_dropped"] != DropNotCaptured || ev["not_captured_reason"] != NotCapturedRejectedBeforeResend || ev["body"] != nil {
		t.Fatalf("rejected upstream_event = %v", ev)
	}
	requests := ofType(events, TypeUpstreamRequest)
	if len(requests) != 2 || ev["seq"].(float64) > requests[1]["seq"].(float64) ||
		upstream[1]["sub_attempt"] != float64(1) || upstream[1]["chunk_seq"] != float64(1) || upstream[1]["not_captured_reason"] != nil {
		t.Fatalf("the rejected body does not precede the resend: requests %v, events %v", requests, upstream)
	}
	if in.Drops() != 1 || len(rec.ledger.totals()) != 0 {
		t.Fatalf("request drops %d, ledger %v", in.Drops(), rec.ledger.totals())
	}
}

// jsonEscapes is n bytes of JSON escapes of the byte hex (two hex digits),
// six bytes each; it is built from 0x5c, so this source holds no escape.
func jsonEscapes(n int, hex string) string {
	return strings.Repeat(string([]byte{0x5c, 'u', '0', '0', hex[0], hex[1]}), n/6)
}

// largeEscapedID is a response.completed event whose response ID is n
// bytes of escapes.
func largeEscapedID(n int) []byte {
	return []byte(`data: {"type":"response.completed","response":{"id":"` + jsonEscapes(n, "61") +
		`","model":"gpt-x","usage":{"input_tokens":1}}}`)
}

// Round-4 finding 3: inspecting upstream JSON bounds every raw token before
// it is unescaped and checks the identity limits and duplicates before it
// copies. With the queue full, an 8 MiB escaped ID, an 8 MiB escaped member
// name, and a 10 MiB body of 50 000 identical 200-byte item IDs allocate
// nothing of their size, and only one ID is kept.
func TestInspectBoundsEscapedAndDuplicateIdentities(t *testing.T) {
	_, rec, in, ctx := inspectSetup(t, func(o *TestOverrides) { o.QueueBytes = 1 << 20; o.FsyncInterval = time.Hour })
	flush(t)
	if !rec.q.reserve(rec.q.limit) {
		t.Fatal("cannot fill the queue")
	}
	defer rec.q.release(rec.q.limit)
	escapedID := largeEscapedID(8 << 20)
	escapedName := []byte(`data: {"` + jsonEscapes(8<<20, "62") + `":1,"type":"response.completed","response":{"id":"resp_named","usage":{"input_tokens":1}}}`)
	id := strings.Repeat("i", 200)
	var dup bytes.Buffer
	dup.WriteString(`{"object":"response","id":"resp_dup","output":[`)
	for i := range 50000 {
		if i > 0 {
			dup.WriteByte(',')
		}
		dup.WriteString(`{"type":"message","id":"` + id + `"}`)
	}
	dup.WriteString(`],"usage":{"input_tokens":1}}`)
	escapedPrev := []byte(`{"model":"m","previous_response_id":"` + jsonEscapes(8<<20, "63") + `"}`)
	cases := []struct {
		name string
		tap  func()
	}{
		{"escaped id", func() { TapUpstreamChunk(ctx, escapedID) }},
		{"escaped member name", func() { TapUpstreamChunk(ctx, escapedName) }},
		{"duplicate ids", func() { TapUpstreamChunk(ctx, dup.Bytes()) }},
		{"escaped previous_response_id", func() {
			TapUpstreamRequest(ctx, UpstreamRequest{URL: "https://api.example/v1/responses", Body: escapedPrev})
		}},
	}
	for _, c := range cases {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		c.tap()
		runtime.ReadMemStats(&after)
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= 256<<10 {
			t.Errorf("%s: allocated %d bytes", c.name, allocated)
		}
	}
	sum := in.Summary()
	if len(sum.OutputItemIDs) != 1 || sum.OutputItemIDs[0] != id || sum.PreviousResponseID != "" ||
		!slicesEqual(sum.ResponseIDs, []string{"resp_named", "resp_dup"}) {
		t.Fatalf("identities = %+v", sum.identities)
	}
	runtime.KeepAlive(escapedID)
	runtime.KeepAlive(escapedName)
	runtime.KeepAlive(escapedPrev)
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Round-4 finding 3: short escaped strings are still read, unescaped.
func TestInspectStillReadsShortEscapedIdentities(t *testing.T) {
	_, _, in, ctx := inspectSetup(t, nil)
	TapUpstreamChunk(ctx, []byte(`data: {"type":"response.completed","response":{"id":"resp_`+jsonEscapes(6, "31")+`","previous_response_id":"resp_`+jsonEscapes(6, "30")+`"}}`))
	sum := in.Summary()
	if len(sum.ResponseIDs) != 1 || sum.ResponseIDs[0] != "resp_1" || sum.PreviousResponseID != "resp_0" {
		t.Fatalf("identities = %+v", sum.identities)
	}
	if got := JSONText(`{"a":{"b":"x\"y"},"c":[1,{"d":2}],"e":"`+strings.Repeat("z", 300)+`"}`, 256, "a", "b"); got != `x"y` {
		t.Fatalf("JSONText = %q", got)
	}
	if got := JSONText(`{"e":"`+strings.Repeat("z", 300)+`"}`, 256, "e"); got != "" {
		t.Fatalf("JSONText kept a 300-byte value: %q", got)
	}
}
