package pluginapi

import (
	"encoding/json"
	"testing"
)

// Fleet fork: the scheduler's reason, in either spelling, survives the
// plugin boundary (recorded as the request archive's pick_reason).
func TestSchedulerPickResponseReason(t *testing.T) {
	for _, raw := range []string{`{"Handled":true,"AuthID":"a","Reason":"affinity"}`, `{"handled":true,"auth_id":"a","reason":"affinity"}`} {
		var resp SchedulerPickResponse
		if err := json.Unmarshal([]byte(raw), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Reason != "affinity" || resp.AuthID != "a" || !resp.Handled {
			t.Fatalf("%s -> %+v", raw, resp)
		}
	}
}
