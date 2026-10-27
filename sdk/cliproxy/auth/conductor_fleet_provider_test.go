package auth

import (
	"context"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Fleet fork: the after-auth interceptor receives the selected credential's provider,
// and the execution metadata itself is not modified.
func TestApplyRequestAfterAuthInterceptorReportsSelectedProvider(t *testing.T) {
	for _, metadata := range []map[string]any{nil, {cliproxyexecutor.RequestPathMetadataKey: "/v1/responses/compact"}} {
		var seen map[string]any
		opts := cliproxyexecutor.Options{
			Metadata: metadata,
			Alt:      "responses/compact",
			RequestAfterAuthInterceptor: func(_ context.Context, req cliproxyexecutor.RequestAfterAuthInterceptRequest) cliproxyexecutor.RequestAfterAuthInterceptResponse {
				seen = req.Metadata
				return cliproxyexecutor.RequestAfterAuthInterceptResponse{}
			},
		}
		_, finalOpts, err := applyRequestAfterAuthInterceptor(context.Background(), nil, "codex", cliproxyexecutor.Request{Model: "gpt-6-1"}, opts, "gpt-6-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := seen[cliproxyexecutor.SelectedAuthProviderMetadataKey]; got != "codex" {
			t.Fatalf("interceptor provider = %v, want codex", got)
		}
		if _, leaked := finalOpts.Metadata[cliproxyexecutor.SelectedAuthProviderMetadataKey]; leaked {
			t.Fatal("selected provider leaked into execution metadata")
		}
	}
}
