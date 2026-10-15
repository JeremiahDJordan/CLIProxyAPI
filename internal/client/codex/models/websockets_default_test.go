package models

import "testing"

func TestCatalogPrefersWebsocketsOnlyForKnownPureCodexRoutes(t *testing.T) {
	for _, providers := range [][]string{{"codex"}, {"claude"}, {"codex", "claude"}, {}} {
		for _, modelID := range []string{"gpt-6.1-sol", "fleet-synthetic-codex-alias"} {
			response := BuildResponse([]map[string]any{{"id": modelID}}, func(string) []string { return providers }, false)
			models := response["models"].([]map[string]any)
			if len(models) != 1 {
				t.Fatalf("catalog length = %d", len(models))
			}
			want := len(providers) == 1 && providers[0] == "codex"
			if got, _ := models[0]["prefer_websockets"].(bool); got != want {
				t.Fatalf("model %s providers %v: prefer_websockets = %v, want %v", modelID, providers, got, want)
			}
		}
	}
}
