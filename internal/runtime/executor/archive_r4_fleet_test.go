//go:build unix

package executor

// Fleet fork: review findings on the archive's capture of Codex's rejected
// zstd responses (helps.ArchiveRejectedResponse).

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
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

// Round-4 finding 1 and round-5 decision A: recording must not gate the
// plaintext resend. The upstream rejects the zstd request with a 415 whose
// body sends 15 bytes and then stalls. With recording off and on the resend
// goes out as soon as the executor closes the rejected body, and the
// request succeeds, also through a transport allowing one connection per
// host, where a rejected body still open holds the only connection (round
// 5: the archive's own read of it delayed the resend by its time bound).
// The body is recorded as not captured, on the first sub-attempt, before
// the resend.
func TestArchiveStalledRejectedBodyDoesNotDelayTheResend(t *testing.T) {
	const head = `{"error":"zstd `
	type outcome struct {
		err   error
		sends int64
		delay time.Duration // from the rejection to the resend
	}
	run := func(t *testing.T, ctx context.Context, maxConns int) outcome {
		t.Helper()
		release := make(chan struct{})
		var sends, rejectedAt, resentAt atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			sends.Add(1)
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
		transport.MaxConnsPerHost = maxConns
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
		out := outcome{err: executeCodexCompressed(ctx, rt), sends: sends.Load()}
		if resentAt.Load() != 0 && rejectedAt.Load() != 0 {
			out.delay = time.Duration(resentAt.Load() - rejectedAt.Load())
		}
		return out
	}
	for _, c := range []struct {
		name     string
		maxConns int
	}{{"default transport", 0}, {"one connection per host", 1}} {
		t.Run(c.name, func(t *testing.T) {
			if archive.Installed() {
				t.Fatal("a recorder is running")
			}
			off := run(t, context.Background(), c.maxConns)
			if off.err != nil || off.sends != 2 || off.delay == 0 {
				t.Fatalf("recording off: %+v", off)
			}
			spool, in := startArchiveForExecutor(t)
			on := run(t, archive.WithIngress(context.Background(), in), c.maxConns)
			if on.err != nil || on.sends != off.sends || on.delay == 0 || on.delay > off.delay+250*time.Millisecond {
				t.Fatalf("recording on: %+v; off: %+v", on, off)
			}
			rejected := rejectedBodyEvent(t, spool)
			if rejected["sub_attempt"] != float64(0) || rejected["chunk_seq"] != float64(1) {
				t.Fatalf("rejected upstream_event = %v", rejected)
			}
			requests := executorArchiveEvents(t, spool, archive.TypeUpstreamRequest)
			if len(requests) != 2 || requests[1]["resend"] != archive.ResendCompressionRejected || rejected["seq"].(float64) > requests[1]["seq"].(float64) {
				t.Fatalf("upstream_request = %v", requests)
			}
			if in.Drops() != 1 {
				t.Fatalf("request drops = %d, want the not-captured body", in.Drops())
			}
		})
	}
}

// Round-5 decision A: the archive reads nothing of a rejected body and
// allocates nothing of its size, whether it records the request, its queue
// is too small for the body, or Stop has begun; the body stays the
// executor's, which closes it as without capture.
func TestArchiveRejectedBodyIsNeverRead(t *testing.T) {
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
			t.Fatalf("read %d bytes of the rejected body (body replaced: %v)", body.read, resp.Body != body)
		}
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= 64<<10 {
			t.Fatalf("allocated %d bytes for a 512 KiB rejected body", allocated)
		}
	}
	t.Run("recorded", func(t *testing.T) {
		spool, in := startArchiveForExecutor(t)
		check(t, archive.WithIngress(context.Background(), in))
		if rejected := rejectedBodyEvent(t, spool); rejected["sub_attempt"] != float64(0) {
			t.Fatalf("rejected upstream_event = %v", rejected)
		}
		if in.Drops() != 1 {
			t.Fatalf("request drops = %d", in.Drops())
		}
	})
	t.Run("queue too small", func(t *testing.T) {
		_, in := startArchiveForExecutorWith(t, func(o *archive.TestOverrides) { o.QueueBytes = 1024 })
		check(t, archive.WithIngress(context.Background(), in))
		if in.Drops() == 0 {
			t.Fatal("the body was not counted")
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
