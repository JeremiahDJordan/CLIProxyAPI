package api

// Fleet fork: restarts without interrupting work. The server counts requests and
// Responses WebSocket turns in flight (GET /v0/management/fleet/activity), so an
// installer can restart in a quiet moment; on shutdown it stops accepting and
// lets that work finish before closing. Under systemd socket activation the
// listening socket outlives the process, so connections arriving meanwhile wait
// in the kernel queue for the next process instead of being refused.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/fleetdrain"
	log "github.com/sirupsen/logrus"
)

const fleetActivityPath = "/v0/management/fleet/activity"

// installDrainTracker counts every request except the activity route and carries
// the tracker in the request context. The Responses WebSocket handler ends the
// request's count once it has upgraded and counts the connection itself.
func (s *Server) installDrainTracker(engine *gin.Engine, cfg *config.Config) {
	if s == nil || engine == nil {
		return
	}
	if cfg != nil && (cfg.Codex.ResponseSteering || cfg.CodexResponseSteering) {
		log.Warn("fleet drain: codex.response-steering is on; steering WebSockets count as busy for their whole life and are closed only when a drain times out")
	}
	s.drain = fleetdrain.New()
	tracker := s.drain
	middleware := func(c *gin.Context) {
		ctx := fleetdrain.WithTracker(c.Request.Context(), tracker)
		if c.Request.URL.Path == fleetActivityPath {
			c.Request = c.Request.WithContext(ctx)
			c.Next()
			return
		}
		end := tracker.BeginRequest()
		defer end()
		c.Request = c.Request.WithContext(fleetdrain.WithRequest(ctx, end))
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

// DrainFleet stops accepting connections and lets the work in flight finish,
// until ctx ends; Stop closes whatever remains. In order:
//   - the base listener closes, so new connections stay in the kernel queue
//     (under socket activation, for the next process);
//   - connections already accepted are still routed and taken by the HTTP server;
//   - with keep-alives off, every HTTP/1 connection finishes its response, including
//     the writes net/http makes after the handler returns, and closes. This does not
//     use http.Server.Shutdown, which drops a request read after it has started;
//   - idle Responses WebSockets close at once with 1012 (service restart) and busy
//     ones after their current turn; clients reconnect on their next request;
//   - Shutdown then sends HTTP/2 connections GOAWAY and waits for their streams.
func (s *Server) DrainFleet(ctx context.Context) {
	if s == nil || s.drain == nil {
		return
	}
	s.listenerMu.Lock()
	muxBase := s.muxBaseListener
	muxHTTP := s.muxHTTPListener
	if muxBase != nil {
		s.fleetDraining.Store(true) // Start must leave the HTTP listener to us
		s.muxBaseListener = nil
	}
	s.listenerMu.Unlock()
	if muxBase == nil {
		return // never started, or already stopped
	}
	started := time.Now()
	before := s.drain.Snapshot()
	s.drain.StartDrain()
	if s.server != nil {
		// Idle keep-alive connections close now and the rest after their response.
		s.server.SetKeepAlivesEnabled(false)
	}
	_ = muxBase.Close()

	step := "routing accepted connections"
	errWait := waitFleetGroup(ctx, &s.fleetAcceptLoops)
	if errWait == nil {
		errWait = waitFleetGroup(ctx, &s.fleetRouting)
	}
	if errWait == nil && muxHTTP != nil {
		step = "handing queued connections to the HTTP server"
		// Routing is over, so the queued total is final. A connection taken off the
		// queue is not tracked yet: wait until net/http has seen every one of them.
		errWait = waitFleetCondition(ctx, func() bool {
			return s.fleetConns.adopted() >= muxHTTP.queued.Load()
		})
	}
	if errWait == nil {
		step = "finishing HTTP responses"
		errWait = waitFleetCondition(ctx, func() bool { return s.fleetConns.busy(time.Now()) == 0 })
	}
	if errWait == nil {
		step = "finishing websocket turns"
		errWait = s.drain.Wait(ctx)
	}
	if errWait == nil && s.server != nil {
		step = "finishing HTTP/2 streams"
		errWait = s.server.Shutdown(ctx)
	}
	if errWait != nil {
		left := s.drain.Snapshot()
		log.Warnf("fleet drain: stopped waiting after %s while %s (%v); closing %d requests, %d websocket turns, %d websockets",
			time.Since(started).Round(time.Millisecond), step, errWait, left.Requests, left.WebSocketTurns, left.WebSockets)
		return
	}
	log.Infof("fleet drain: finished in %s (%d requests, %d websocket turns, %d websockets were open)",
		time.Since(started).Round(time.Millisecond), before.Requests, before.WebSocketTurns, before.WebSockets)
}

// fleetNewConnIdle matches net/http: a new connection that has sent no request
// for this long counts as idle and is closed.
const fleetNewConnIdle = 5 * time.Second

// fleetConnTracker follows HTTP connection states (http.Server.ConnState) so a
// drain can wait for responses to finish.
type fleetConnTracker struct {
	mu    sync.Mutex
	conns map[net.Conn]fleetConnState
	news  int64 // connections net/http has reported as new
}

func (t *fleetConnTracker) adopted() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.news
}

type fleetConnState struct {
	state http.ConnState
	since time.Time
}

func (t *fleetConnTracker) track(conn net.Conn, state http.ConnState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if state == http.StateNew {
		t.news++
	}
	switch state {
	case http.StateHijacked, http.StateClosed:
		delete(t.conns, conn)
	default:
		if t.conns == nil {
			t.conns = make(map[net.Conn]fleetConnState)
		}
		t.conns[conn] = fleetConnState{state: state, since: time.Now()}
	}
}

// busy counts HTTP/1 connections that may still carry a response and closes new
// ones that have stayed silent. HTTP/2 connections are left to Shutdown.
func (t *fleetConnTracker) busy(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	busy := 0
	for conn, st := range t.conns {
		if tlsConn, ok := conn.(*tls.Conn); ok && tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
			continue
		}
		switch st.state {
		case http.StateActive:
			busy++
		case http.StateNew:
			if now.Sub(st.since) >= fleetNewConnIdle {
				_ = conn.Close()
				delete(t.conns, conn)
				continue
			}
			busy++
		}
	}
	return busy
}

func waitFleetGroup(ctx context.Context, group *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		group.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func waitFleetCondition(ctx context.Context, ok func() bool) error {
	for !ok() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	return nil
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

// fleetListenerForTest wraps the server's listener in tests.
var fleetListenerForTest func(net.Listener) net.Listener
