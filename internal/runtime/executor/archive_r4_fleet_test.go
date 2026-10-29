//go:build unix

package executor

// Fleet fork: round-4 review findings on the archive's capture of Codex's
// rejected zstd responses (helps.ArchiveRejectedResponse).

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/archive"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// executeCodexCompressed runs one compressed Codex request through rt.
func executeCodexCompressed(ctx context.Context, rt http.RoundTripper) error {
	ctx = context.WithValue(ctx, "cliproxy.roundtripper", rt)
	e := NewCodexExecutor(codexCompressionConfig())
	req := cliproxyexecutor.Request{Model: "gpt-5.4", Payload: codexCompressionPayload()}
	_, err := e.Execute(ctx, codexCompressionAuth(), req, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse})
	return err
}

// Round-4 finding 1: recording must not gate the plaintext resend. The
// upstream rejects the zstd request with a 415 whose body sends 15 bytes and
// then stalls; with recording off and on alike the resend goes out at once
// and the request succeeds (before the fix, recording read the body until
// the request's deadline, and the request failed). The stalled body is
// recorded as truncated, on the first sub-attempt, and counted.
func TestArchiveStalledRejectedBodyDoesNotDelayTheResend(t *testing.T) {
	const head = `{"error":"zstd `
	// run returns how long after the rejection the resend reached the
	// upstream; the rejected body stalls until the test ends.
	run := func(t *testing.T, ctx context.Context) time.Duration {
		t.Helper()
		release := make(chan struct{})
		var rejectedAt, resentAt atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			if r.Header.Get("Content-Encoding") == "zstd" {
				w.WriteHeader(http.StatusUnsupportedMediaType)
				_, _ = io.WriteString(w, head)
				w.(http.Flusher).Flush()
				rejectedAt.Store(time.Now().UnixNano())
				select {
				case <-release:
				case <-r.Context().Done():
				}
				return
			}
			resentAt.Store(time.Now().UnixNano())
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: "+codexCompletedEventBody+"\n\n")
		}))
		transport := http.DefaultTransport.(*http.Transport).Clone()
		t.Cleanup(func() {
			close(release)
			transport.CloseIdleConnections()
			server.Close()
		})
		local, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			mapped := req.Clone(req.Context())
			mapped.URL.Scheme, mapped.URL.Host, mapped.Host = local.Scheme, local.Host, local.Host
			return transport.RoundTrip(mapped)
		})
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		t.Cleanup(cancel)
		if err = executeCodexCompressed(ctx, rt); err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if resentAt.Load() == 0 || rejectedAt.Load() == 0 {
			t.Fatal("no resend")
		}
		return time.Duration(resentAt.Load() - rejectedAt.Load())
	}
	var off time.Duration
	t.Run("recording off", func(t *testing.T) {
		if archive.Installed() {
			t.Fatal("a recorder is running")
		}
		off = run(t, context.Background())
	})
	t.Run("recording on", func(t *testing.T) {
		spool, in := startArchiveForExecutorWith(t, func(o *archive.TestOverrides) { o.DiscardedBodyWait = 200 * time.Millisecond })
		on := run(t, archive.WithIngress(context.Background(), in))
		if on > time.Second || on > off+500*time.Millisecond {
			t.Fatalf("resend %v after the rejection with recording on, %v with it off", on, off)
		}
		rejected := waitDiscardedEvent(t, spool)
		if rejected["sub_attempt"] != float64(0) || rejected["capture"] != archive.CaptureDroppedBody ||
			rejected["body_dropped"] != archive.DropTruncated || rejected["stopped"] != "timeout" || rejected["read_bytes"] != float64(len(head)) {
			t.Fatalf("discarded upstream_event = %v", rejected)
		}
		if in.Drops() == 0 {
			t.Fatal("the truncated body was not counted against the request")
		}
	})
}

// panicAfterHead returns head, and panics on the next read: a decoder (or
// any reader under the executor) failing inside a read only the archive
// makes. The executor itself only peeks at the first bytes.
type panicAfterHead struct {
	head []byte
	done bool
}

func (b *panicAfterHead) Read(p []byte) (int, error) {
	if b.done {
		panic("rejected body read failed")
	}
	b.done = true
	return copy(p, b.head), nil
}

func (*panicAfterHead) Close() error { return nil }

// Round-4 finding 1: a panic in the archive-only read of the rejected body
// is contained (before the fix it escaped into the executor): the request
// succeeds as it does with recording off, and the panic counts against it.
func TestArchiveRejectedBodyReadPanicIsContained(t *testing.T) {
	rt := func() http.RoundTripper {
		sent := 0
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			_, _ = io.Copy(io.Discard, req.Body)
			if sent++; sent == 1 {
				return &http.Response{StatusCode: http.StatusUnsupportedMediaType, Header: http.Header{},
					Body: &panicAfterHead{head: []byte(`{"error":"compression rejected"}`)}}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}},
				Body: io.NopCloser(strings.NewReader("data: " + codexCompletedEventBody + "\n\n"))}, nil
		})
	}
	if err := executeCodexCompressed(context.Background(), rt()); err != nil {
		t.Fatalf("recording off: %v", err)
	}
	spool, in := startArchiveForExecutor(t)
	if err := executeCodexCompressed(archive.WithIngress(context.Background(), in), rt()); err != nil {
		t.Fatalf("recording on: %v", err)
	}
	rejected := waitDiscardedEvent(t, spool)
	if rejected["sub_attempt"] != float64(0) || rejected["body_dropped"] != archive.DropTapPanic || rejected["body"] != nil {
		t.Fatalf("discarded upstream_event = %v", rejected)
	}
	if in.Drops() == 0 {
		t.Fatal("the contained panic was not counted against the request")
	}
}

// Round-4 finding 2: the rejected body is read only within reservations.
// With a queue too small for its first bytes, and after Stop, nothing is
// read or allocated for it and the executor keeps (and closes) the body.
func TestArchiveRejectedBodyIsReadOnlyWithinReservations(t *testing.T) {
	check := func(t *testing.T, ctx context.Context) {
		t.Helper()
		body := &countingBody{Reader: bytes.NewReader(bytes.Repeat([]byte("r"), 512<<10))}
		resp := &http.Response{StatusCode: http.StatusUnsupportedMediaType, Header: http.Header{}, Body: body}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		helps.ArchiveRejectedResponse(ctx, resp)
		runtime.ReadMemStats(&after)
		if body.read != 0 || resp.Body != body {
			t.Fatalf("read %d bytes of the rejected body (body handed off: %v)", body.read, resp.Body != body)
		}
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= 64<<10 {
			t.Fatalf("allocated %d bytes for a 512 KiB body it could not record", allocated)
		}
	}
	t.Run("queue too small", func(t *testing.T) {
		_, in := startArchiveForExecutorWith(t, func(o *archive.TestOverrides) { o.QueueBytes = 1024 })
		check(t, archive.WithIngress(context.Background(), in))
		if in.Drops() == 0 {
			t.Fatal("the refused body was not counted")
		}
	})
	t.Run("after stop", func(t *testing.T) {
		_, in := startArchiveForExecutor(t)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := archive.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		check(t, archive.WithIngress(context.Background(), in))
	})
}

// Round-4 finding 2 (Opus): a rejected body over the 1 MiB limit is
// recorded as truncated and counted in the drop ledger too, so a gap shows
// it (before the fix it counted only against its request).
func TestArchiveOversizedRejectedBodyReachesTheDropLedger(t *testing.T) {
	spool, in := startArchiveForExecutor(t)
	ctx := archive.WithIngress(context.Background(), in)
	body := io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), 3<<20)))
	helps.ArchiveRejectedResponse(ctx, &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{}, Body: body})
	rejected := waitDiscardedEvent(t, spool)
	if rejected["body_dropped"] != archive.DropTruncated || rejected["stopped"] != "limit" {
		t.Fatalf("discarded upstream_event = %v", rejected)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, gap := range executorArchiveEvents(t, spool, archive.TypeGap) {
			if drops, ok := gap["drops"].(map[string]any); ok && drops[archive.DropTruncated] != nil {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("no gap reports the truncated body")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
