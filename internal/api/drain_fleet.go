package api

// Fleet fork: restarts without interrupting work. The server counts requests and
// Responses WebSocket turns in flight (GET /v0/management/fleet/activity), so an
// installer can restart in a quiet moment; on shutdown it stops accepting and
// lets that work finish before closing. Under systemd socket activation the
// listening socket outlives the process, so connections arriving meanwhile wait
// in the kernel queue for the next process instead of being refused.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/fleetdrain"
	log "github.com/sirupsen/logrus"
)

const fleetActivityPath = "/v0/management/fleet/activity"

// installDrainTracker counts every request except WebSocket upgrades (the
// Responses WebSocket handler counts its own connections and turns) and the
// activity route, and carries the tracker in the request context.
func (s *Server) installDrainTracker(engine *gin.Engine) {
	if s == nil || engine == nil {
		return
	}
	s.drain = fleetdrain.New()
	tracker := s.drain
	middleware := func(c *gin.Context) {
		c.Request = c.Request.WithContext(fleetdrain.WithTracker(c.Request.Context(), tracker))
		if c.Request.URL.Path == fleetActivityPath ||
			strings.EqualFold(strings.TrimSpace(c.Request.Header.Get("Upgrade")), "websocket") {
			c.Next()
			return
		}
		defer tracker.BeginRequest()()
		c.Next()
	}
	if len(engine.Handlers) == 0 {
		engine.Use(middleware)
		return
	}
	engine.Handlers = append(gin.HandlersChain{middleware}, engine.Handlers...)
}

// getFleetActivity reports the work in flight; management authentication applies.
func (s *Server) getFleetActivity(c *gin.Context) {
	c.JSON(http.StatusOK, s.drain.Snapshot())
}

// DrainFleet stops accepting connections and waits, until ctx ends, for requests
// and WebSocket turns in flight to finish. Idle Responses WebSockets close at once
// with 1012 (service restart) and busy ones after their current turn; clients
// reconnect on their next request. Stop closes whatever remains.
func (s *Server) DrainFleet(ctx context.Context) {
	if s == nil || s.drain == nil {
		return
	}
	s.listenerMu.Lock()
	muxHTTP := s.muxHTTPListener
	muxBase := s.muxBaseListener
	s.muxHTTPListener = nil
	s.muxBaseListener = nil
	s.listenerMu.Unlock()
	if muxHTTP == nil && muxBase == nil {
		return // never started, or already stopped
	}
	if muxHTTP != nil {
		_ = muxHTTP.Close()
	}
	if muxBase != nil {
		_ = muxBase.Close()
	}
	if s.server != nil {
		// Close idle keep-alive connections now and the rest after their response.
		s.server.SetKeepAlivesEnabled(false)
	}
	s.drain.StartDrain()
	before := s.drain.Snapshot()
	started := time.Now()
	if errWait := s.drain.Wait(ctx); errWait != nil {
		left := s.drain.Snapshot()
		log.Warnf("fleet drain: stopped waiting after %s (%v); closing %d requests, %d websocket turns, %d websockets",
			time.Since(started).Round(time.Millisecond), errWait, left.Requests, left.WebSocketTurns, left.WebSockets)
		return
	}
	log.Infof("fleet drain: finished in %s (%d requests, %d websocket turns, %d websockets were open)",
		time.Since(started).Round(time.Millisecond), before.Requests, before.WebSocketTurns, before.WebSockets)
}

// fleetListen returns the listening socket systemd passed (socket activation,
// one TCP socket), or a new listener on addr.
func fleetListen(addr string) (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") == "" {
		return net.Listen("tcp", addr)
	}
	count := os.Getenv("LISTEN_FDS")
	// Child processes must not see a socket meant for this one.
	_ = os.Unsetenv("LISTEN_PID")
	_ = os.Unsetenv("LISTEN_FDS")
	_ = os.Unsetenv("LISTEN_FDNAMES")
	if count != "1" {
		return nil, fmt.Errorf("socket activation passed %s sockets; expected one", count)
	}
	file := os.NewFile(3, "systemd-socket") // SD_LISTEN_FDS_START
	listener, errListen := net.FileListener(file)
	_ = file.Close()
	if errListen != nil {
		return nil, fmt.Errorf("socket activation: %w", errListen)
	}
	if listener.Addr().Network() != "tcp" {
		_ = listener.Close()
		return nil, fmt.Errorf("socket activation passed a %s socket; expected tcp", listener.Addr().Network())
	}
	if listener.Addr().String() != addr {
		log.Warnf("socket activation: listening on %s, not the configured %s", listener.Addr(), addr)
	}
	log.Infof("socket activation: serving on the inherited socket %s", listener.Addr())
	return listener, nil
}
