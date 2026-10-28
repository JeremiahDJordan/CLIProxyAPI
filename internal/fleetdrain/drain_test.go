package fleetdrain

import (
	"context"
	"testing"
	"time"
)

func TestTrackerCountsAndQuiet(t *testing.T) {
	tr := New()
	endReq := tr.BeginRequest()
	endSock := tr.BeginWebSocket()
	endTurn := tr.BeginTurn()
	got := tr.Snapshot()
	if got.Requests != 1 || got.WebSockets != 1 || got.WebSocketTurns != 1 || got.Quiet || got.Draining {
		t.Fatalf("snapshot = %+v", got)
	}
	endReq()
	endReq() // a second call must not count twice
	endTurn()
	got = tr.Snapshot()
	if got.Requests != 0 || got.WebSocketTurns != 0 || got.WebSockets != 1 || !got.Quiet {
		t.Fatalf("idle socket should be quiet: %+v", got)
	}
	endSock()
	if got = tr.Snapshot(); got.WebSockets != 0 {
		t.Fatalf("snapshot = %+v", got)
	}
}

func TestTrackerWaitFinishesWhenWorkEnds(t *testing.T) {
	tr := New()
	endReq := tr.BeginRequest()
	endSock := tr.BeginWebSocket()
	done := make(chan error, 1)
	go func() { done <- tr.Wait(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("Wait returned early: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	endReq()
	select {
	case err := <-done:
		t.Fatalf("Wait returned with a WebSocket open: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	endSock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after the work ended")
	}
}

func TestTrackerWaitHonoursDeadline(t *testing.T) {
	tr := New()
	defer tr.BeginTurn()()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := tr.Wait(ctx); err == nil {
		t.Fatal("Wait returned nil with a turn in flight")
	}
}

func TestTrackerDrain(t *testing.T) {
	tr := New()
	select {
	case <-tr.Draining():
		t.Fatal("draining before StartDrain")
	default:
	}
	tr.StartDrain()
	tr.StartDrain()
	select {
	case <-tr.Draining():
	default:
		t.Fatal("Draining channel not closed")
	}
	if !tr.IsDraining() || !tr.Snapshot().Draining {
		t.Fatal("tracker should report draining")
	}
}

func TestNilTrackerIsInert(t *testing.T) {
	var tr *Tracker
	tr.BeginRequest()()
	tr.BeginTurn()()
	tr.StartDrain()
	if tr.IsDraining() || tr.Draining() != nil || !tr.Snapshot().Quiet {
		t.Fatal("nil tracker should never drain and always be quiet")
	}
	if err := tr.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if FromContext(context.Background()) != nil || FromContext(WithTracker(context.Background(), nil)) != nil {
		t.Fatal("FromContext should be nil without a tracker")
	}
}
