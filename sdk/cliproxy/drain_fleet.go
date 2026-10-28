package cliproxy

import (
	"context"
	"time"
)

// fleetDrainTimeout bounds how long shutdown waits for work in flight (fleet fork,
// internal/api/drain_fleet.go). With the 30 s shutdown that follows it stays
// within the systemd unit's TimeoutStopSec=120.
const fleetDrainTimeout = 75 * time.Second

// drainFleetServer lets requests and WebSocket turns in flight finish before
// shutdown closes anything; nothing else has stopped yet while it waits.
func (s *Service) drainFleetServer() {
	if s == nil || s.server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), fleetDrainTimeout)
	defer cancel()
	s.server.DrainFleet(ctx)
}
