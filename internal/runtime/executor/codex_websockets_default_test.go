package executor

import (
	"context"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestCodexWebsocketsOAuthDefaultAndExplicitOverrides(t *testing.T) {
	for _, tt := range []struct {
		name string
		auth *cliproxyauth.Auth
		want bool
	}{
		{"nil", nil, false},
		{"oauth", &cliproxyauth.Auth{Provider: "codex"}, true},
		{"other provider", &cliproxyauth.Auth{Provider: "claude"}, false},
		{"api key", &cliproxyauth.Auth{Provider: "codex", Attributes: map[string]string{"api_key": "test"}}, false},
		{"metadata api key", &cliproxyauth.Auth{Provider: "codex", Metadata: map[string]any{"api_key": "test"}}, false},
		{"metadata opt out", &cliproxyauth.Auth{Provider: "codex", Metadata: map[string]any{"websockets": false}}, false},
		{"string opt out", &cliproxyauth.Auth{Provider: "codex", Metadata: map[string]any{"websockets": "false"}}, false},
		{"attribute opt out", &cliproxyauth.Auth{Provider: "codex", Attributes: map[string]string{"websockets": "false"}, Metadata: map[string]any{"websockets": true}}, false},
		{"api key opt in", &cliproxyauth.Auth{Provider: "codex", Attributes: map[string]string{"api_key": "test", "websockets": "true"}}, true},
		{"malformed explicit value", &cliproxyauth.Auth{Provider: "codex", Metadata: map[string]any{"websockets": "invalid"}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := codexWebsocketsEnabled(tt.auth); got != tt.want {
				t.Fatalf("enabled = %v, want %v", got, tt.want)
			}
		})
	}
}

// A fresh OAuth login has no websockets flag. Two tool-cycle requests must use
// one persistent upstream socket rather than silently issuing HTTP requests.
func TestCodexAutoExecutorFreshOAuthReusesWebsocketAcrossToolCycle(t *testing.T) {
	var connections, httpRequests, frames atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !websocket.IsWebSocketUpgrade(r) {
			httpRequests.Add(1)
			http.Error(w, "HTTP transport is not expected", http.StatusBadRequest)
			return
		}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		connections.Add(1)
		for {
			_, body, errRead := conn.ReadMessage()
			if errRead != nil {
				return
			}
			index := frames.Add(1)
			if got := gjson.GetBytes(body, "type").String(); got != "response.create" {
				t.Errorf("frame type = %q", got)
			}
			if index == 2 && gjson.GetBytes(body, "previous_response_id").String() != "resp_1" {
				t.Errorf("continuation lost previous_response_id: %s", body)
			}
			event := fmt.Sprintf(`{"type":"response.completed","response":{"id":"resp_%d","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1}}}`, index)
			if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(event)); errWrite != nil {
				return
			}
		}
	}))
	defer server.Close()
	executor := NewCodexAutoExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}})
	executor.wsExec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	defer executor.CloseExecutionSession("fresh-oauth-tool-cycle")
	auth := &cliproxyauth.Auth{ID: "synthetic-oauth", Provider: "codex", Attributes: map[string]string{"base_url": server.URL}, Metadata: map[string]any{"access_token": "synthetic-test-token"}}
	ctx := cliproxyexecutor.WithDownstreamWebsocket(context.Background())
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response"), ResponseFormat: sdktranslator.FromString("openai-response"), Metadata: map[string]any{cliproxyexecutor.ExecutionSessionMetadataKey: "fresh-oauth-tool-cycle"}}
	for index := 0; index < 2; index++ {
		body := `{"model":"gpt-6.1-sol","input":[{"role":"user","content":"hello"}]}`
		if index == 1 {
			body = `{"model":"gpt-6.1-sol","previous_response_id":"resp_1","input":[{"type":"function_call_output","call_id":"call_test","output":"42"}]}`
		}
		result, err := executor.ExecuteStream(ctx, auth, cliproxyexecutor.Request{Model: "gpt-6.1-sol", Payload: []byte(body)}, opts)
		if err != nil {
			t.Fatalf("ExecuteStream: %v", err)
		}
		completed := false
		for chunk := range result.Chunks {
			if chunk.Err != nil {
				t.Fatalf("stream: %v", chunk.Err)
			}
			if gjson.GetBytes(chunk.Payload, "type").String() == "response.completed" {
				completed = true
			}
		}
		if !completed {
			t.Fatal("missing completed event")
		}
	}
	if connections.Load() != 1 || httpRequests.Load() != 0 || frames.Load() != 2 {
		t.Fatalf("connections=%d HTTP=%d frames=%d, want 1/0/2", connections.Load(), httpRequests.Load(), frames.Load())
	}
}
