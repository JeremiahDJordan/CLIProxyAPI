//go:build unix

package auth

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/archive"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// startArchiveForConductor starts a recorder on a temporary spool.
func startArchiveForConductor(t *testing.T) string {
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
	if archive.Start(archive.StartParams{Config: internalconfig.ArchiveConfig{Enabled: true, SpoolDir: spool}}) == nil {
		t.Fatal("recorder did not start")
	}
	return spool
}

func conductorArchiveEvents(t *testing.T, spool, typ string) []map[string]any {
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
		data, _ := os.ReadFile(path)
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 1<<20), 64<<20)
		for scanner.Scan() {
			var ev map[string]any
			if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
				t.Fatal(err)
			}
			if ev["type"] == typ {
				out = append(out, ev)
			}
		}
	}
	return out
}

// The conductor numbers its attempts: a credential that fails and the one
// that succeeds are attempts 1 and 2, described with their credential and
// model and ended with their result; the executor's outbound request belongs
// to its attempt. This holds for Execute and ExecuteStream alike.
func TestArchiveConductorAttempts(t *testing.T) {
	for _, path := range []string{"execute", "stream"} {
		t.Run(path, func(t *testing.T) {
			spool := startArchiveForConductor(t)
			manager := NewManager(nil, &FillFirstSelector{}, nil)
			manager.SetRetryConfig(3, 30*time.Second, 0)
			failing, healthy := "archive-failing-"+path, "archive-healthy-"+path
			for _, candidate := range []*Auth{
				{ID: failing, Provider: "claude", Status: StatusActive, Attributes: map[string]string{"priority": "9"}},
				{ID: healthy, Provider: "claude", Status: StatusActive, Attributes: map[string]string{"priority": "1"}},
			} {
				registry.GetGlobalRegistry().RegisterClient(candidate.ID, "claude", []*registry.ModelInfo{{ID: "archive-model"}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(candidate.ID) })
				if _, err := manager.Register(context.Background(), candidate); err != nil {
					t.Fatal(err)
				}
			}
			execute := func(ctx context.Context, selected *Auth, req cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
				archive.TapUpstreamRequest(ctx, archive.UpstreamRequest{URL: "https://api.anthropic.example/v1/messages", Body: []byte(selected.ID), AuthID: selected.ID})
				if selected.ID == failing {
					return cliproxyexecutor.Response{}, customStatusError{code: http.StatusServiceUnavailable, msg: "overloaded"}
				}
				return cliproxyexecutor.Response{Payload: []byte("ok")}, nil
			}
			manager.RegisterExecutor(&customStreamMockExecutor{
				identifier: "claude", mockCustomErrorExecutor: mockCustomErrorExecutor{executeFn: execute},
				streamFn: func(ctx context.Context, selected *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
					if _, err := execute(ctx, selected, req, opts); err != nil {
						return nil, err
					}
					chunks := make(chan cliproxyexecutor.StreamChunk, 1)
					chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("ok")}
					close(chunks)
					return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
				},
			})
			in := archive.Current().BeginIngress(archive.RouteInference, time.Now())
			ctx := archive.WithIngress(context.Background(), in)
			req := cliproxyexecutor.Request{Model: "archive-model"}
			if path == "execute" {
				if _, err := manager.Execute(ctx, []string{"claude"}, req, cliproxyexecutor.Options{}); err != nil {
					t.Fatal(err)
				}
			} else {
				result, err := manager.ExecuteStream(ctx, []string{"claude"}, req, cliproxyexecutor.Options{Stream: true})
				if err != nil {
					t.Fatal(err)
				}
				for range result.Chunks {
				}
			}
			in.CloseAttempts(archive.AttemptEndedRequestEnd)
			starts := conductorArchiveEvents(t, spool, archive.TypeAttemptStart)
			ends := conductorArchiveEvents(t, spool, archive.TypeAttemptEnd)
			requests := conductorArchiveEvents(t, spool, archive.TypeUpstreamRequest)
			if len(starts) != 2 || starts[0]["auth_id"] != failing || starts[1]["auth_id"] != healthy ||
				starts[0]["provider"] != "claude" || starts[0]["model"] != "archive-model" {
				t.Fatalf("attempt_start = %v", starts)
			}
			if len(ends) != 2 || ends[0]["success"] != false || ends[0]["status"] != float64(http.StatusServiceUnavailable) ||
				ends[1]["success"] != true || ends[0]["ended"] != archive.AttemptEndedResult || ends[1]["ended"] != archive.AttemptEndedResult {
				t.Fatalf("attempt_end = %v", ends)
			}
			if len(requests) != 2 || requests[0]["attempt_seq"] != float64(1) || requests[1]["attempt_seq"] != float64(2) {
				t.Fatalf("upstream_request = %v", requests)
			}
		})
	}
}

// A gate denial from the after-auth interceptor is recorded on the attempt
// (decision and code) and on the request; an allowed attempt records allow.
func TestArchiveGateDecisionOnTheAttempt(t *testing.T) {
	spool := startArchiveForConductor(t)
	in := archive.Current().BeginIngress(archive.RouteInference, time.Now())
	ctx := archive.WithIngress(context.Background(), in)
	for _, deny := range []bool{false, true} {
		attemptCtx := newUpstreamAttemptContext(ctx)
		opts := cliproxyexecutor.Options{
			Metadata: map[string]any{cliproxyexecutor.SelectedAuthMetadataKey: "auth-gated", schedulerPickReasonMetadataKey: "affinity"},
			RequestAfterAuthInterceptor: func(context.Context, cliproxyexecutor.RequestAfterAuthInterceptRequest) cliproxyexecutor.RequestAfterAuthInterceptResponse {
				if !deny {
					return cliproxyexecutor.RequestAfterAuthInterceptResponse{}
				}
				return cliproxyexecutor.RequestAfterAuthInterceptResponse{Terminate: true, StatusCode: http.StatusForbidden,
					ResponseBody: []byte(`{"error":{"type":"permission_error","code":"fleet_codex_client","message":"no"}}`)}
			},
		}
		_, _, err := applyRequestAfterAuthInterceptor(attemptCtx, nil, "codex", cliproxyexecutor.Request{Model: "gpt-test"}, opts, "gpt-test")
		if (err != nil) != deny {
			t.Fatalf("deny=%v: err %v", deny, err)
		}
		if !deny {
			archiveEndAttempt(attemptCtx, Result{AuthID: "auth-gated", Provider: "codex", Model: "gpt-test", Success: true})
		}
	}
	in.CloseAttempts(archive.AttemptEndedRequestEnd)
	ends := conductorArchiveEvents(t, spool, archive.TypeAttemptEnd)
	if len(ends) != 2 || ends[0]["gate"] != archive.GateAllow || ends[1]["gate"] != archive.GateDeny || ends[1]["gate_code"] != "fleet_codex_client" {
		t.Fatalf("attempt_end = %v", ends)
	}
	if ends[0]["pick_reason"] != "affinity" || ends[1]["auth_id"] != "auth-gated" {
		t.Fatalf("attempt description = %v", ends)
	}
	if in.Summary().GateCode != "fleet_codex_client" {
		t.Fatalf("request gate_code = %q", in.Summary().GateCode)
	}
}

// The plugin scheduler's reason travels back through the metadata, also for
// a pick the plugin did not handle.
func TestRecordSchedulerPickReason(t *testing.T) {
	meta := map[string]any{}
	recordSchedulerPickReason(meta, "not-handled")
	if meta[schedulerPickReasonMetadataKey] != "not-handled" {
		t.Fatalf("metadata = %v", meta)
	}
	recordSchedulerPickReason(meta, "")
	if _, ok := meta[schedulerPickReasonMetadataKey]; ok {
		t.Fatal("an empty reason kept the previous pick's reason")
	}
	recordSchedulerPickReason(nil, "x")
}
