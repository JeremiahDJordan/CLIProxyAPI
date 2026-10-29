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
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
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
