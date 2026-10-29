//go:build unix

package executor

// Fleet fork: request archive taps of executors whose request-log body is
// not the body they send (antigravity_executor_request.go, devin_executor.go).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/archive"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"google.golang.org/protobuf/encoding/protowire"
)

// startArchiveForExecutor starts a recorder on a temporary spool and returns
// the spool and an inference request's context.
func startArchiveForExecutor(t *testing.T) (string, *archive.Ingress) {
	t.Helper()
	group, err := user.LookupGroupId(strconv.Itoa(os.Getegid()))
	if err != nil {
		t.Skipf("cannot name the effective group: %v", err)
	}
	spool := t.TempDir()
	if err = os.WriteFile(filepath.Join(spool, archive.SentinelName), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(spool, archive.BlobDirName), 0o770); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{spool, filepath.Join(spool, archive.BlobDirName)} {
		if err = os.Chmod(dir, os.ModeSetgid|0o770); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(archive.SetTestOverrides(archive.TestOverrides{
		StateDir: filepath.Join(t.TempDir(), "state"), SpoolGroup: group.Name, FreeBytes: func() uint64 { return 1 << 50 },
		FsyncInterval: 20 * time.Millisecond, HeartbeatInterval: time.Hour, SpaceCheckInterval: time.Hour,
	}))
	rec := archive.Start(archive.StartParams{Config: config.ArchiveConfig{Enabled: true, SpoolDir: spool}})
	if rec == nil {
		t.Fatal("recorder did not start")
	}
	return spool, rec.BeginIngress(archive.RouteInference, time.Now())
}

func executorArchiveEvents(t *testing.T, spool, typ string) []map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := archive.FlushForTest(ctx); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(spool, "*.jsonl"))
	sort.Strings(files)
	var out []map[string]any
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 1<<20), 64<<20)
		for scanner.Scan() {
			var ev map[string]any
			if err = json.Unmarshal(scanner.Bytes(), &ev); err != nil {
				t.Fatal(err)
			}
			if ev["type"] == typ {
				out = append(out, ev)
			}
		}
	}
	return out
}

func executorArchiveBody(t *testing.T, ev map[string]any) []byte {
	t.Helper()
	body, ok := ev["body"].(map[string]any)
	if !ok {
		t.Fatalf("no body: %v", ev)
	}
	switch body["form"] {
	case archive.FormText:
		return []byte(body["value"].(string))
	case archive.FormBase64:
		data, err := base64.StdEncoding.DecodeString(body["value"].(string))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	t.Fatalf("form %v", body["form"])
	return nil
}

// Round-2 finding 7: with request logging off, Antigravity keeps no
// request-log body; the archive records the bytes it sends, on both of its
// body paths (schemas sanitized or not).
func TestArchiveAntigravityRecordsTheBodySent(t *testing.T) {
	spool, in := startArchiveForExecutor(t)
	ctx := archive.WithIngress(context.Background(), in)
	executor := &AntigravityExecutor{cfg: &config.Config{}}
	auth := &cliproxyauth.Auth{Metadata: map[string]any{"project_id": "project-1"}}
	payloads := [][]byte{
		[]byte(`{"request":{"contents":[{"role":"user","parts":[{"text":"plain"}]}]}}`),
		[]byte(`{"request":{"contents":[{"role":"user","parts":[{"text":"tools"}]}],"tools":[{"function_declarations":[{"name":"t","parametersJsonSchema":{"type":"object","$comment":"removed"}}]}]}}`),
	}
	var sent [][]byte
	for _, payload := range payloads {
		req, err := executor.buildRequest(ctx, auth, "token", "gemini-2.5-pro", payload, false, "", "https://example.com")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		sent = append(sent, body)
	}
	requests := executorArchiveEvents(t, spool, archive.TypeUpstreamRequest)
	if len(requests) != len(sent) {
		t.Fatalf("%d upstream_request events", len(requests))
	}
	for i, ev := range requests {
		if ev["capture"] != archive.CaptureFull || !bytes.Equal(executorArchiveBody(t, ev), sent[i]) {
			t.Fatalf("request %d: recorded %v, sent %s", i, ev, sent[i])
		}
	}
}

// Round-2 finding 7: Devin's request-log body is a JSON rendering of the
// protobuf it sends, which carries the credential. The archive records the
// outbound body as not captured (counted against the request), never as a
// complete body, and the credential is nowhere in the spool.
func TestArchiveDevinOutboundBodyIsNotCaptured(t *testing.T) {
	spool, in := startArchiveForExecutor(t)
	var usage []byte
	usage = protowire.AppendTag(usage, 2, protowire.VarintType)
	usage = protowire.AppendVarint(usage, 10)
	var frame []byte
	frame = protowire.AppendTag(frame, 7, protowire.BytesType)
	frame = protowire.AppendBytes(frame, usage)
	var response bytes.Buffer
	response.Write(helps.WrapConnectEnvelope(frame))
	response.Write(helps.WrapConnectEnvelopeWithFlag(helps.ConnectFlagEndStream, []byte(`{}`)))
	ctx := context.WithValue(archive.WithIngress(context.Background(), in), "cliproxy.roundtripper", roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/connect+proto"}},
			Body:       io.NopCloser(bytes.NewReader(response.Bytes())),
		}, nil
	}))
	const key = "devin-archive-credential-0001"
	auth := &cliproxyauth.Auth{ID: "devin-archive", Provider: "devin", Attributes: map[string]string{"api_key": key}}
	req := cliproxyexecutor.Request{Model: "devin/swe-2", Payload: []byte(`{"messages":[{"role":"user","content":"hello"}]}`)}
	if _, err := NewDevinExecutor(&config.Config{}).Execute(ctx, auth, req, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI}); err != nil {
		t.Fatal(err)
	}
	requests := executorArchiveEvents(t, spool, archive.TypeUpstreamRequest)
	if len(requests) != 1 || requests[0]["capture"] != archive.CaptureDroppedBody ||
		requests[0]["body_dropped"] != archive.DropNotCaptured || requests[0]["body"] != nil {
		t.Fatalf("upstream_request = %v", requests)
	}
	if in.Drops() == 0 {
		t.Fatal("the uncaptured body was not counted against the request")
	}
	files, _ := filepath.Glob(filepath.Join(spool, "*.jsonl"))
	for _, path := range files {
		if data, _ := os.ReadFile(path); bytes.Contains(data, []byte(key)) {
			t.Fatalf("%s holds the Devin credential", filepath.Base(path))
		}
	}
}

// Round-3 finding 3: with upstream request compression on, the archive
// records each send's own bytes and headers: the zstd body first, then the
// rejected response (status, headers and body, before it is discarded), then
// the uncompressed resend as its own sub-attempt of the same attempt, marked
// resend compression_rejected and carrying the first request's credential.
func TestArchiveCodexCompressionRecordsEachSend(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", stream), func(t *testing.T) {
			spool, in := startArchiveForExecutor(t)
			var wires [][]byte
			var encodings []string
			rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				data, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatal(err)
				}
				wires = append(wires, data)
				encodings = append(encodings, req.Header.Get("Content-Encoding"))
				if len(wires) == 1 {
					return &http.Response{StatusCode: http.StatusUnsupportedMediaType, Header: http.Header{"X-Reject": {"zstd"}},
						Body: io.NopCloser(strings.NewReader(`{"error":"compression rejected"}`))}, nil
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}},
					Body: io.NopCloser(strings.NewReader("data: " + codexCompletedEventBody + "\n\n"))}, nil
			})
			ctx := context.WithValue(archive.WithIngress(context.Background(), in), "cliproxy.roundtripper", rt)
			auth := codexCompressionAuth()
			auth.ID, auth.Label = "codex-archive-auth", "codex-archive-label"
			e := NewCodexExecutor(codexCompressionConfig())
			req := cliproxyexecutor.Request{Model: "gpt-5.4", Payload: codexCompressionPayload()}
			opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
			if stream {
				result, err := e.ExecuteStream(ctx, auth, req, opts)
				if err != nil {
					t.Fatal(err)
				}
				for range result.Chunks {
				}
			} else if _, err := e.Execute(ctx, auth, req, opts); err != nil {
				t.Fatal(err)
			}
			if len(wires) != 2 || encodings[0] != "zstd" || encodings[1] != "" {
				t.Fatalf("sent %d requests with encodings %v", len(wires), encodings)
			}
			requests := executorArchiveEvents(t, spool, archive.TypeUpstreamRequest)
			if len(requests) != 2 {
				t.Fatalf("%d upstream_request events for 2 sends", len(requests))
			}
			for i, ev := range requests {
				if !bytes.Equal(executorArchiveBody(t, ev), wires[i]) || ev["sub_attempt"] != float64(i) || ev["attempt_seq"] != requests[0]["attempt_seq"] {
					t.Fatalf("request %d: recorded %v; sent %d bytes", i, ev, len(wires[i]))
				}
				encoding, _ := ev["headers"].(map[string]any)["Content-Encoding"].([]any)
				bodyEncoding, _ := ev["body"].(map[string]any)["content_encoding"].(string)
				if (i == 0) != (len(encoding) == 1 && encoding[0] == "zstd" && bodyEncoding == "zstd") || (i == 1 && bodyEncoding != "") {
					t.Fatalf("request %d: Content-Encoding %v, body content_encoding %q", i, encoding, bodyEncoding)
				}
				if ev["auth_id"] != auth.ID || ev["auth_label"] != auth.Label || ev["provider"] != "codex" {
					t.Fatalf("request %d: credential %v %v %v", i, ev["auth_id"], ev["auth_label"], ev["provider"])
				}
			}
			if requests[0]["resend"] != nil || requests[1]["resend"] != archive.ResendCompressionRejected {
				t.Fatalf("resend: %v / %v", requests[0]["resend"], requests[1]["resend"])
			}
			meta := executorArchiveEvents(t, spool, archive.TypeUpstreamResponseMeta)
			if len(meta) != 2 || meta[0]["status"] != float64(http.StatusUnsupportedMediaType) || meta[0]["sub_attempt"] != float64(0) ||
				meta[1]["status"] != float64(http.StatusOK) || meta[1]["sub_attempt"] != float64(1) {
				t.Fatalf("upstream_response_meta = %v", meta)
			}
			chunks := executorArchiveEvents(t, spool, archive.TypeUpstreamEvent)
			if len(chunks) == 0 || chunks[0]["sub_attempt"] != float64(0) || string(executorArchiveBody(t, chunks[0])) != `{"error":"compression rejected"}` {
				t.Fatalf("upstream_event = %v", chunks)
			}
		})
	}
}

// Round-3 finding 3: with capture off for the request, the rejected body is
// not read for the archive (the executor closes it unread, as upstream does).
func TestArchiveRejectedResponseReadsNothingWhenNotRecorded(t *testing.T) {
	body := &countingBody{Reader: strings.NewReader("rejected")}
	helps.ArchiveRejectedResponse(context.Background(), &http.Response{StatusCode: http.StatusUnsupportedMediaType, Body: body})
	if body.read != 0 {
		t.Fatalf("read %d bytes of a response no archive records", body.read)
	}
}

type countingBody struct {
	io.Reader
	read int
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}

func (*countingBody) Close() error { return nil }
