package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	proxyconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/fleetdrain"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"golang.org/x/crypto/bcrypt"
)

func waitForActivity(t *testing.T, tracker *fleetdrain.Tracker, ok func(fleetdrain.Activity) bool) fleetdrain.Activity {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := tracker.Snapshot()
		if ok(got) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("activity never reached the expected state: %+v", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDrainTrackerCountsRequestsButNotUpgradesOrActivity(t *testing.T) {
	s := newTestServer(t)
	release := make(chan struct{})
	entered := make(chan *fleetdrain.Tracker, 3)
	block := func(c *gin.Context) {
		entered <- fleetdrain.FromContext(c.Request.Context())
		<-release
		c.Status(http.StatusNoContent)
	}
	s.engine.GET("/fleet-test/slow", block)
	s.engine.GET("/fleet-test/upgrade", block)

	served := make(chan int, 2)
	serve := func(req *http.Request) {
		recorder := httptest.NewRecorder()
		s.engine.ServeHTTP(recorder, req)
		served <- recorder.Code
	}
	go serve(httptest.NewRequest(http.MethodGet, "/fleet-test/slow", nil))
	upgrade := httptest.NewRequest(http.MethodGet, "/fleet-test/upgrade", nil)
	upgrade.Header.Set("Upgrade", "websocket")
	go serve(upgrade)
	for range 2 {
		if tracker := <-entered; tracker != s.drain {
			t.Fatal("request context does not carry the server's tracker")
		}
	}

	got := s.drain.Snapshot()
	if got.Requests != 1 || got.Quiet {
		t.Fatalf("one plain request should be counted, upgrades not: %+v", got)
	}
	// The activity route is not counted, so a poller never sees itself.
	recorder := httptest.NewRecorder()
	activity := httptest.NewRequest(http.MethodGet, fleetActivityPath, nil)
	s.engine.ServeHTTP(recorder, activity)
	if got := s.drain.Snapshot(); got.Requests != 1 {
		t.Fatalf("activity route changed the count: %+v", got)
	}

	close(release)
	for range 2 {
		<-served
	}
	waitForActivity(t, s.drain, func(a fleetdrain.Activity) bool { return a.Requests == 0 && a.Quiet })
}

func TestFleetActivityRouteRequiresManagementKey(t *testing.T) {
	cfg := &proxyconfig.Config{SDKConfig: sdkconfig.SDKConfig{APIKeys: []string{"test-key"}}}
	hash, err := bcrypt.GenerateFromPassword([]byte("fleet-test-management-key"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RemoteManagement.SecretKey = string(hash)
	s := newTestServerWithConfig(t, cfg)

	request := func(key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, fleetActivityPath, nil)
		req.RemoteAddr = "127.0.0.1:40000"
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		recorder := httptest.NewRecorder()
		s.engine.ServeHTTP(recorder, req)
		return recorder
	}
	if code := request("").Code; code != http.StatusUnauthorized {
		t.Fatalf("without a key: status %d, want 401", code)
	}
	response := request("fleet-test-management-key")
	if response.Code != http.StatusOK {
		t.Fatalf("with the management key: status %d: %s", response.Code, response.Body.String())
	}
	if body := response.Body.String(); body != `{"requests":0,"websockets":0,"websocket_turns":0,"draining":false,"quiet":true}` {
		t.Fatalf("activity body = %s", body)
	}
}

// startTestServer serves s on a loopback port with /fleet-test/slow, which
// answers once release is called.
func startTestServer(t *testing.T) (s *Server, addr string, release func()) {
	t.Helper()
	cfg := &proxyconfig.Config{SDKConfig: sdkconfig.SDKConfig{APIKeys: []string{"test-key"}}}
	cfg.Host = "127.0.0.1"
	s = newTestServerWithConfig(t, cfg)
	released := make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(released) }) }
	t.Cleanup(release)
	s.engine.GET("/fleet-test/slow", func(c *gin.Context) {
		select {
		case <-released:
		case <-c.Request.Context().Done():
		}
		c.String(http.StatusOK, "finished")
	})
	go func() { _ = s.Start() }()
	deadline := time.Now().Add(5 * time.Second)
	for addr == "" {
		s.listenerMu.Lock()
		if s.muxBaseListener != nil {
			addr = s.muxBaseListener.Addr().String()
		}
		s.listenerMu.Unlock()
		if addr == "" && time.Now().After(deadline) {
			t.Fatal("server did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Cleanup(func() { _ = s.Stop(context.Background()) })
	return s, addr, release
}

func TestDrainFleetLetsRequestsFinishAndStopsAccepting(t *testing.T) {
	s, addr, release := startTestServer(t)
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	type result struct {
		code int
		body string
		err  error
	}
	slow := make(chan result, 1)
	go func() {
		resp, err := client.Get("http://" + addr + "/fleet-test/slow")
		if err != nil {
			slow <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		slow <- result{code: resp.StatusCode, body: string(body)}
	}()
	waitForActivity(t, s.drain, func(a fleetdrain.Activity) bool { return a.Requests == 1 })

	drained := make(chan struct{})
	go func() {
		s.DrainFleet(context.Background())
		close(drained)
	}()
	waitForActivity(t, s.drain, func(a fleetdrain.Activity) bool { return a.Draining })
	select {
	case <-drained:
		t.Fatal("drain finished with a request in flight")
	case <-time.After(50 * time.Millisecond):
	}
	if conn, errDial := net.DialTimeout("tcp", addr, time.Second); errDial == nil {
		_ = conn.Close()
		t.Fatal("a draining server still accepts connections")
	}

	// Finish the request in flight; the drain then completes and the response is intact.
	release()
	got := <-slow
	if got.err != nil || got.code != http.StatusOK || got.body != "finished" {
		t.Fatalf("request in flight = %+v, want 200 finished", got)
	}
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not finish after the request ended")
	}
}

func TestDrainFleetStopsWaitingAtDeadline(t *testing.T) {
	s, addr, _ := startTestServer(t)
	go func() {
		resp, err := http.Get("http://" + addr + "/fleet-test/slow")
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	waitForActivity(t, s.drain, func(a fleetdrain.Activity) bool { return a.Requests == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	s.DrainFleet(ctx)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("drain ignored its deadline (%s)", elapsed)
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("Stop after an unfinished drain: %v", err)
	}
	waitForActivity(t, s.drain, func(a fleetdrain.Activity) bool { return a.Requests == 0 })
}

func TestDrainFleetBeforeStartIsNoop(t *testing.T) {
	s := newTestServer(t)
	s.DrainFleet(context.Background())
	if s.drain.IsDraining() {
		t.Fatal("drain of a server that never started should do nothing")
	}
}

// TestFleetListenUsesSystemdSocket runs the helper below in a child process that
// receives a listening socket as fd 3, as systemd socket activation passes it.
func TestFleetListenUsesSystemdSocket(t *testing.T) {
	if os.Getenv("FLEET_LISTEN_HELPER") == "1" {
		fleetListenHelper()
		return
	}
	parent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close() }()
	file, err := parent.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()

	cmd := exec.Command(os.Args[0], "-test.run=^TestFleetListenUsesSystemdSocket$")
	cmd.Env = append(os.Environ(), "FLEET_LISTEN_HELPER=1", "LISTEN_FDS=1", "LISTEN_FDNAMES=cliproxyapi.socket",
		"FLEET_LISTEN_ADDR="+parent.Addr().String())
	cmd.ExtraFiles = []*os.File{file}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
}

func fleetListenHelper() {
	// systemd sets LISTEN_PID to the activated process after fork.
	_ = os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	want := os.Getenv("FLEET_LISTEN_ADDR")
	listener, err := fleetListen("127.0.0.1:1") // a different configured address only warns
	if err != nil {
		panic(err)
	}
	if listener.Addr().String() != want {
		panic("inherited socket " + listener.Addr().String() + ", want " + want)
	}
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		if _, set := os.LookupEnv(name); set {
			panic(name + " still set")
		}
	}
	accepted := make(chan error, 1)
	go func() {
		conn, errAccept := listener.Accept()
		if errAccept == nil {
			_ = conn.Close()
		}
		accepted <- errAccept
	}()
	conn, err := net.DialTimeout("tcp", want, time.Second)
	if err != nil {
		panic(err)
	}
	_ = conn.Close()
	if err := <-accepted; err != nil {
		panic(err)
	}
	_ = listener.Close()
}

func TestFleetListenWithoutActivationListensItself(t *testing.T) {
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()+1)) // meant for another process
	t.Setenv("LISTEN_FDS", "1")
	listener, err := fleetListen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if os.Getenv("LISTEN_FDS") != "1" {
		t.Fatal("another process's activation variables were cleared")
	}
}

func TestFleetListenRejectsSeveralSockets(t *testing.T) {
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "2")
	if _, err := fleetListen("127.0.0.1:0"); err == nil {
		t.Fatal("two activated sockets should be refused")
	}
	if _, set := os.LookupEnv("LISTEN_FDS"); set {
		t.Fatal("activation variables should be cleared")
	}
}

func TestDrainTrackerIsOutermostWithoutArchive(t *testing.T) {
	s := newTestServer(t)
	if name := handlerName(s.engine.Handlers[0]); !strings.Contains(name, "installDrainTracker") {
		t.Fatalf("first middleware is %s", name)
	}
}
