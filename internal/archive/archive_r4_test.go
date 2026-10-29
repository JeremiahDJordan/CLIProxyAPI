//go:build unix

package archive

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tidwall/gjson"
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

// responseWithItems is a non-streamed Responses body, with response ID
// respID, of n output items whose IDs id(i) returns, as written.
func responseWithItems(respID string, n int, id func(i int) string) []byte {
	var b bytes.Buffer
	b.WriteString(`{"object":"response","id":"` + respID + `","output":[`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"type":"message","id":"` + id(i) + `"}`)
	}
	b.WriteString(`],"usage":{"input_tokens":1}}`)
	return b.Bytes()
}

// Round-4 finding 3 and round-5 finding B: inspecting upstream JSON bounds
// every raw token before it is unescaped, and checks the identity limits
// and duplicates before it copies. With the queue full, an 8 MiB escaped
// ID, an 8 MiB escaped member name, a 10 MiB body of 50 000 identical
// 200-byte item IDs, and the same written with one escape each, allocate
// nothing of their size, and only one ID of each is kept (round 5: each
// escaped ID was unescaped into its own copy before the duplicate check,
// 20 MB for that body). 50 000 distinct escaped IDs allocate only for the
// IDs the limits keep.
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
	dup := responseWithItems("resp_dup", 50000, func(int) string { return id })
	// 194 bytes and one escape: 200 bytes written, 195 read.
	escapedDupID := strings.Repeat("j", 194) + jsonEscapes(6, "6a")
	escapedDup := responseWithItems("resp_escaped_dup", 50000, func(int) string { return escapedDupID })
	distinctID := func(i int) string { return fmt.Sprintf("k%07d", i) + strings.Repeat("k", 186) + jsonEscapes(6, "6b") }
	escapedDistinct := responseWithItems("resp_escaped_distinct", 50000, distinctID)
	escapedPrev := []byte(`{"model":"m","previous_response_id":"` + jsonEscapes(8<<20, "63") + `"}`)
	const small = 256 << 10
	cases := []struct {
		name  string
		limit uint64
		tap   func()
	}{
		{"escaped id", small, func() { TapUpstreamChunk(ctx, escapedID) }},
		{"escaped member name", small, func() { TapUpstreamChunk(ctx, escapedName) }},
		{"duplicate ids", small, func() { TapUpstreamChunk(ctx, dup) }},
		{"escaped previous_response_id", small, func() {
			TapUpstreamRequest(ctx, UpstreamRequest{URL: "https://api.example/v1/responses", Body: escapedPrev})
		}},
		{"escaped duplicate ids", small, func() { TapUpstreamChunk(ctx, escapedDup) }},
		// The event, the attempt and the request each keep a copy of at
		// most maxOutputItemIDs IDs.
		{"escaped distinct ids", 3*maxOutputItemIDs*maxOwnedLen + small, func() { TapUpstreamChunk(ctx, escapedDistinct) }},
	}
	for _, c := range cases {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		c.tap()
		runtime.ReadMemStats(&after)
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= c.limit {
			t.Errorf("%s: allocated %d bytes", c.name, allocated)
		}
	}
	sum := in.Summary()
	items := sum.OutputItemIDs
	if len(items) != maxOutputItemIDs || items[0] != id || items[1] != strings.Repeat("j", 195) ||
		items[2] != fmt.Sprintf("k%07d", 0)+strings.Repeat("k", 187) || items[len(items)-1] != fmt.Sprintf("k%07d", maxOutputItemIDs-3)+strings.Repeat("k", 187) ||
		sum.PreviousResponseID != "" ||
		!slicesEqual(sum.ResponseIDs, []string{"resp_named", "resp_dup", "resp_escaped_dup", "resp_escaped_distinct"}) {
		t.Fatalf("identities: %d items (first %.20q, last %.20q), previous %q, responses %v",
			len(items), items[:min(3, len(items))], items[len(items)-1:], sum.PreviousResponseID, sum.ResponseIDs)
	}
	runtime.KeepAlive(escapedID)
	runtime.KeepAlive(escapedName)
	runtime.KeepAlive(escapedPrev)
	runtime.KeepAlive(dup)
	runtime.KeepAlive(escapedDup)
	runtime.KeepAlive(escapedDistinct)
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
	var scratch JSONScratch
	if got := JSONText(`{"a":{"b":"x\"y"},"c":[1,{"d":2}],"e":"`+strings.Repeat("z", 300)+`"}`, 256, &scratch, "a", "b"); got != `x"y` {
		t.Fatalf("JSONText = %q", got)
	}
	if got := JSONText(`{"e":"`+strings.Repeat("z", 300)+`"}`, 256, &scratch, "e"); got != "" {
		t.Fatalf("JSONText kept a 300-byte value: %q", got)
	}
}

// Round-5 finding B: jsonText unescapes into its scratch exactly as gjson
// unescapes (surrogate pairs, lone surrogates, invalid hex, unknown escapes
// and control bytes included), through one scratch reused across values of
// every length, and refuses a value over its limit.
func TestJSONTextUnescapesAsGjson(t *testing.T) {
	bs := string([]byte{0x5c}) // a backslash, so this source holds no escape
	fragments := []string{
		"a", "Z", "0", " ", "é", "€", "😀", string([]byte{0xff}), string([]byte{0x7f}), string([]byte{0x01}),
		bs + bs, bs + "/", bs + `"`, bs + "b", bs + "f", bs + "n", bs + "r", bs + "t",
		bs + "u0041", bs + "u00e9", bs + "u20AC", bs + "ud83d" + bs + "ude00", bs + "uD83D" + bs + "uDE00",
		bs + "ud83d", bs + "ude00", bs + "ud83d" + bs + "u0041", bs + "uZZZZ", bs + "u12", bs + "u0000", bs + "x",
	}
	rng := rand.New(rand.NewPCG(1, 5))
	var scratch JSONScratch
	for n := range 20000 {
		var b strings.Builder
		for range rng.IntN(1 + n%300) {
			b.WriteString(fragments[rng.IntN(len(fragments))])
		}
		inner := b.String()
		if strings.HasSuffix(inner, bs) && !strings.HasSuffix(inner, bs+bs) || len(inner) > 6*maxOwnedLen {
			continue
		}
		token := `"` + inner + `"`
		want := gjson.Parse(token).String()
		if len(want) > maxOwnedLen {
			want = ""
		}
		got, escaped := jsonText(token, maxOwnedLen, &scratch)
		if got != want || escaped != (want != "" && strings.Contains(inner, bs)) {
			t.Fatalf("%q: jsonText = %q (escaped %v), gjson %q", token, got, escaped, want)
		}
	}
	if cap(scratch.buf) > maxOwnedLen {
		t.Fatalf("scratch grew to %d bytes", cap(scratch.buf))
	}
}
