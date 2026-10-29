package helps

// Fleet fork: request archive executor taps (internal/archive/upstream.go).
// The logging helpers call them before their request-log checks.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/archive"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
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

// RecordAPIRequestSent is RecordAPIRequest for an executor whose request-log
// body (info.Body) is not the bytes it sends, such as one kept only while
// request logging is on: the archive records sent, request logging keeps
// info.Body.
func RecordAPIRequestSent(ctx context.Context, cfg *config.Config, info UpstreamRequestLog, sent []byte) {
	req := archiveUpstreamRequest(info)
	req.Body = sent
	archive.TapUpstreamRequest(ctx, req)
	recordAPIRequest(ctx, cfg, info)
}

// RecordAPIRequestBodyNotCaptured is RecordAPIRequest for an executor whose
// request-log body is only a rendering of what it sends, and whose wire
// bytes must not be kept (Devin's protobuf carries the credential): the
// archive records the body as not captured, request logging keeps info.Body.
func RecordAPIRequestBodyNotCaptured(ctx context.Context, cfg *config.Config, info UpstreamRequestLog) {
	req := archiveUpstreamRequest(info)
	req.Body, req.BodyNotCaptured = nil, true
	archive.TapUpstreamRequest(ctx, req)
	recordAPIRequest(ctx, cfg, info)
}

// RecordAPIRequestOnWire is RecordAPIRequest for an executor whose request
// req may send info.Body encoded (Codex's zstd request compression):
// request logging keeps info.Body, the archive records req's own body, the
// bytes sent, with info's headers (req's, as sent).
func RecordAPIRequestOnWire(ctx context.Context, cfg *config.Config, info UpstreamRequestLog, req *http.Request) {
	archive.TapUpstreamRequest(ctx, archiveWireRequest(archiveUpstreamRequest(info), req))
	recordAPIRequest(ctx, cfg, info)
}

// ArchiveResentRequest records, in the archive only, a request the executor
// sends again itself (req, exactly as sent) as a new sub-attempt of the same
// attempt, with why (archive.ResendCompressionRejected). Request logging
// keeps only the first request, as before.
func ArchiveResentRequest(req *http.Request, reason string) {
	if req == nil || !archive.Recorded(req.Context()) {
		return
	}
	info := archive.UpstreamRequest{Method: req.Method, Headers: req.Header, Resend: reason}
	if req.URL != nil {
		info.URL = req.URL.String()
	}
	archive.TapUpstreamRequest(req.Context(), archiveWireRequest(info, req))
}

// archiveWireRequest makes the archive read req's body as sent. A body req
// cannot replay is recorded as not captured when it is encoded, since info's
// Body is then not what was sent.
func archiveWireRequest(info archive.UpstreamRequest, req *http.Request) archive.UpstreamRequest {
	switch {
	case req == nil:
	case req.GetBody != nil:
		info.GetBody, info.ContentLength = req.GetBody, req.ContentLength
	case req.Header.Get("Content-Encoding") != "":
		info.BodyNotCaptured = true
	}
	return info
}

// archiveRejectedBodyLimit bounds how much of a discarded response's body
// ArchiveRejectedResponse reads.
const archiveRejectedBodyLimit = 1 << 20

// ArchiveRejectedResponse records, in the archive only, a response the
// executor discards before resending (Codex's rejection of a zstd body): its
// status and headers, and its body, which it reads (at most
// archiveRejectedBodyLimit bytes) before the executor closes it. A longer
// body is not recorded and counts as a drop. With capture off, or for a
// request capture does not record, it reads nothing.
func ArchiveRejectedResponse(ctx context.Context, resp *http.Response) {
	if resp == nil || !archive.Recorded(ctx) {
		return
	}
	archive.TapUpstreamResponse(ctx, resp.StatusCode, resp.Header)
	if resp.Body == nil {
		return
	}
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, archiveRejectedBodyLimit+1))
	if len(body) > archiveRejectedBodyLimit {
		archive.IngressFromContext(ctx).NoteDrop()
		return
	}
	archive.TapUpstreamChunk(ctx, body)
	if errRead != nil {
		archive.TapUpstreamError(ctx, errRead)
	}
}

// archiveReporterUsage records the usage reporter's token breakdown for the
// attempt (design section 3, raw usage: the reporter's TokenBreakdown).
func archiveReporterUsage(ctx context.Context, record usage.Record) {
	if !archive.Installed() {
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
