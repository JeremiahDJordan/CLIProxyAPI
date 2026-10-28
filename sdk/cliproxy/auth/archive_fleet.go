package auth

// Fleet fork: request archive attempts (internal/archive/attempt.go). Each
// upstream attempt context carries an archive attempt (newUpstreamAttemptContext);
// it is described where the after-auth interceptor (the fleet gate) runs and
// ended where the conductor records the attempt's result.

import (
	"context"
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/archive"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

// schedulerPickReasonMetadataKey carries the plugin scheduler's reason for a
// pick (including Handled:false), like SelectionIDMetadataKey, because
// pickViaPluginScheduler returns only the auth.
const schedulerPickReasonMetadataKey = "fleet_pick_reason"

func recordSchedulerPickReason(meta map[string]any, reason string) {
	if meta == nil {
		return
	}
	if reason = strings.TrimSpace(reason); reason == "" {
		delete(meta, schedulerPickReasonMetadataKey)
		return
	}
	meta[schedulerPickReasonMetadataKey] = reason
}

// archiveAttemptContext opens the archive attempt of an upstream attempt.
func archiveAttemptContext(ctx context.Context) context.Context {
	return archive.WithAttempt(ctx)
}

func archiveDescribeAttempt(ctx context.Context, provider string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, requestedModel string) {
	if archive.Current() == nil {
		return
	}
	info := archive.AttemptInfo{Provider: provider, Model: req.Model, RequestedModel: requestedModel}
	if meta := opts.Metadata; meta != nil {
		info.AuthID, _ = meta[cliproxyexecutor.SelectedAuthMetadataKey].(string)
		info.PickReason, _ = meta[schedulerPickReasonMetadataKey].(string)
		info.SessionID, _ = meta[cliproxyexecutor.CanonicalSessionIDMetadataKey].(string)
	}
	archive.DescribeAttempt(ctx, info)
}

// archiveNoteGate records the after-auth interceptor's decision. A denial's
// code is the error code of its response body (the fleet gate's
// fleet_* codes), or the status when the body has none.
func archiveNoteGate(ctx context.Context, terminate bool, status int, body []byte) {
	if archive.Current() == nil {
		return
	}
	if !terminate {
		archive.NoteGate(ctx, archive.GateAllow, "")
		return
	}
	code := strings.TrimSpace(gjson.GetBytes(body, "error.code").String())
	if code == "" {
		code = "intercepted_" + strconv.Itoa(status)
	}
	archive.NoteGate(ctx, archive.GateDeny, code)
}

func archiveEndAttempt(ctx context.Context, result Result) {
	if archive.Current() == nil {
		return
	}
	end := archive.AttemptEnd{AuthID: result.AuthID, Provider: result.Provider, Model: result.Model, Success: result.Success}
	if result.Error != nil {
		end.StatusCode = result.Error.HTTPStatus
		end.Error = strings.TrimSpace(strings.TrimPrefix(result.Error.Code+": "+result.Error.Message, ": "))
	}
	archive.EndAttempt(ctx, end)
}
