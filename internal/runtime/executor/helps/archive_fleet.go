package helps

// Fleet fork: request archive executor taps (internal/archive/upstream.go).
// The logging helpers call them before their request-log checks.

import (
	"context"
	"encoding/json"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/archive"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

// archiveUpstreamRequest converts the request-log record. AuthValue (a
// masked credential) is not recorded.
func archiveUpstreamRequest(info UpstreamRequestLog) archive.UpstreamRequest {
	return archive.UpstreamRequest{
		URL:       info.URL,
		Method:    info.Method,
		Headers:   info.Headers,
		Body:      info.Body,
		Provider:  info.Provider,
		AuthID:    info.AuthID,
		AuthLabel: info.AuthLabel,
		AuthType:  info.AuthType,
	}
}

// archiveReporterUsage records the usage reporter's token breakdown for the
// attempt (design section 3, raw usage: the reporter's TokenBreakdown).
func archiveReporterUsage(ctx context.Context, record usage.Record) {
	if archive.Current() == nil {
		return
	}
	raw, err := json.Marshal(struct {
		InputTokens         int64                `json:"input_tokens"`
		OutputTokens        int64                `json:"output_tokens"`
		ReasoningTokens     int64                `json:"reasoning_tokens"`
		CachedTokens        int64                `json:"cached_tokens"`
		CacheReadTokens     int64                `json:"cache_read_tokens"`
		CacheCreationTokens int64                `json:"cache_creation_tokens"`
		TotalTokens         int64                `json:"total_tokens"`
		TokenBreakdown      usage.TokenBreakdown `json:"token_breakdown"`
		ResponseServiceTier string               `json:"response_service_tier,omitempty"`
		Failed              bool                 `json:"failed,omitempty"`
	}{
		InputTokens:         record.Detail.InputTokens,
		OutputTokens:        record.Detail.OutputTokens,
		ReasoningTokens:     record.Detail.ReasoningTokens,
		CachedTokens:        record.Detail.CachedTokens,
		CacheReadTokens:     record.Detail.CacheReadTokens,
		CacheCreationTokens: record.Detail.CacheCreationTokens,
		TotalTokens:         record.Detail.TotalTokens,
		TokenBreakdown:      record.Detail.TokenBreakdown,
		ResponseServiceTier: record.Detail.ResponseServiceTier,
		Failed:              record.Failed,
	})
	if err != nil {
		return
	}
	archive.TapUsage(ctx, archive.UsageSourceReporter, record.Model, raw)
}
