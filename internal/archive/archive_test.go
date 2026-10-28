//go:build unix

package archive

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"golang.org/x/sys/unix"
)

type testEnv struct {
	spool string
	state string
	free  atomic.Uint64
}

// makeSpool provisions a spool like section 7: root and blobs/ 2770, owned
// by the test's spool group (the process's effective group).
func makeSpool(t *testing.T) string {
	t.Helper()
	spool := t.TempDir()
	if err := os.WriteFile(filepath.Join(spool, SentinelName), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	blobs := filepath.Join(spool, BlobDirName)
	if err := os.Mkdir(blobs, 0o770); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{spool, blobs} {
		if err := os.Chown(dir, -1, os.Getegid()); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, os.ModeSetgid|0o770); err != nil {
			t.Fatal(err)
		}
	}
	return spool
}

// testSpoolGroup names the group makeSpool uses.
func testSpoolGroup(t *testing.T) string {
	t.Helper()
	g, err := user.LookupGroupId(strconv.Itoa(os.Getegid()))
	if err != nil {
		t.Skipf("cannot name the effective group: %v", err)
	}
	return g.Name
}

// setup installs overrides for one test. stateDir may be shared between
// setups to test drop counters that outlive a boot.
func setup(t *testing.T, stateDir string, mutate func(*TestOverrides)) *testEnv {
	t.Helper()
	if stateDir == "" {
		stateDir = filepath.Join(t.TempDir(), "archive-state")
	}
	env := &testEnv{spool: makeSpool(t), state: stateDir}
	env.free.Store(1 << 50)
	o := TestOverrides{
		StateDir:           env.state,
		SpoolGroup:         testSpoolGroup(t),
		FreeBytes:          env.free.Load,
		FsyncInterval:      20 * time.Millisecond,
		HeartbeatInterval:  time.Hour,
		SpaceCheckInterval: time.Hour,
	}
	if mutate != nil {
		mutate(&o)
	}
	restore := SetTestOverrides(o)
	t.Cleanup(restore)
	return env
}

func enabledConfig(spool string) config.ArchiveConfig {
	return config.ArchiveConfig{Enabled: true, SpoolDir: spool}
}

func mustStart(t *testing.T, env *testEnv) *Recorder {
	t.Helper()
	rec := Start(StartParams{Config: enabledConfig(env.spool)})
	if rec == nil {
		t.Fatal("Start returned nil")
	}
	return rec
}

func flush(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := FlushForTest(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

func stop(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func segmentFiles(t *testing.T, spool string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(spool, "*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(matches)
	return matches
}

type event map[string]any

// readEvents reads every segment. The writer may rename or remove a segment
// between the listing and the read (closing it, or ending it after a
// failure); the listing is then taken again.
func readEvents(t *testing.T, spool string) []event {
	t.Helper()
	for attempt := 0; ; attempt++ {
		out, vanished := readEventsOnce(t, spool)
		if !vanished {
			return out
		}
		if attempt == 100 {
			t.Fatal("segments kept vanishing while being read")
		}
	}
}

func readEventsOnce(t *testing.T, spool string) (out []event, vanished bool) {
	t.Helper()
	for _, path := range segmentFiles(t, spool) {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil, true
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > 0 && data[len(data)-1] != '\n' {
			t.Fatalf("%s does not end on a complete line", path)
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 1<<20), 64<<20)
		for scanner.Scan() {
			var ev event
			if err = json.Unmarshal(scanner.Bytes(), &ev); err != nil {
				t.Fatalf("%s: bad line %q: %v", path, scanner.Text(), err)
			}
			out = append(out, ev)
		}
		if err = scanner.Err(); err != nil {
			t.Fatal(err)
		}
	}
	return out, false
}

func ofType(events []event, typ string) []event {
	var out []event
	for _, ev := range events {
		if ev["type"] == typ {
			out = append(out, ev)
		}
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func spoolNames(t *testing.T, spool string) []string {
	t.Helper()
	entries, err := os.ReadDir(spool)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func withUmask(t *testing.T, mask int) {
	t.Helper()
	old := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(old) })
}

func TestDisabledStartsNothing(t *testing.T) {
	env := setup(t, "", nil)
	before := spoolNames(t, env.spool)
	if rec := Start(StartParams{Config: config.ArchiveConfig{Enabled: false, SpoolDir: env.spool}}); rec != nil {
		t.Fatal("disabled config started a recorder")
	}
	if Current() != nil {
		t.Fatal("Current() is set while disabled")
	}
	if after := spoolNames(t, env.spool); !slices.Equal(before, after) {
		t.Fatalf("disabled recorder touched the spool: %v -> %v", before, after)
	}
	if _, err := os.Stat(env.state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disabled recorder touched the state directory: %v", err)
	}
	// The first configuration wins: a later enabled Start starts nothing.
	if rec := Start(StartParams{Config: enabledConfig(env.spool)}); rec != nil || Current() != nil {
		t.Fatal("an enabled Start after a disabled one started a recorder")
	}
	if after := spoolNames(t, env.spool); !slices.Equal(before, after) {
		t.Fatalf("a later enabled Start touched the spool: %v -> %v", before, after)
	}
}

// otherGroup returns a group the process belongs to, other than its
// effective group, that has a name.
func otherGroup(t *testing.T) (int, string) {
	t.Helper()
	groups, _ := os.Getgroups()
	for _, gid := range groups {
		if gid == os.Getegid() {
			continue
		}
		if g, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
			return gid, g.Name
		}
	}
	t.Skip("no second named group")
	return 0, ""
}

func TestStartRefusesUnsafeSpool(t *testing.T) {
	groups, _ := os.Getgroups()
	cases := []struct {
		name   string
		mutate func(t *testing.T, env *testEnv) config.ArchiveConfig
		notZFS bool
		group  func(t *testing.T) string
		reason string
	}{
		{name: "spool root without setgid", reason: DropStartRefusedSpool, mutate: func(t *testing.T, env *testEnv) config.ArchiveConfig {
			if err := os.Chmod(env.spool, 0o770); err != nil {
				t.Fatal(err)
			}
			return enabledConfig(env.spool)
		}},
		{name: "spool root world readable", reason: DropStartRefusedSpool, mutate: func(t *testing.T, env *testEnv) config.ArchiveConfig {
			if err := os.Chmod(env.spool, os.ModeSetgid|0o775); err != nil {
				t.Fatal(err)
			}
			return enabledConfig(env.spool)
		}},
		{name: "spool group does not exist", reason: DropStartRefusedSpool,
			group: func(*testing.T) string { return "fleet-archive-test-no-such-group" },
			mutate: func(t *testing.T, env *testEnv) config.ArchiveConfig {
				return enabledConfig(env.spool)
			}},
		{name: "spool owned by another group", reason: DropStartRefusedSpool,
			group: func(t *testing.T) string { _, name := otherGroup(t); return name },
			mutate: func(t *testing.T, env *testEnv) config.ArchiveConfig {
				return enabledConfig(env.spool)
			}},
		{name: "spool root owned by another group", reason: DropStartRefusedSpool, mutate: func(t *testing.T, env *testEnv) config.ArchiveConfig {
			gid, _ := otherGroup(t)
			if err := os.Chown(env.spool, -1, gid); err != nil {
				t.Skipf("chown to group %d: %v", gid, err)
			}
			if err := os.Chmod(env.spool, os.ModeSetgid|0o770); err != nil {
				t.Fatal(err)
			}
			return enabledConfig(env.spool)
		}},
		{name: "missing sentinel", reason: DropStartRefusedSpool, mutate: func(t *testing.T, env *testEnv) config.ArchiveConfig {
			if err := os.Remove(filepath.Join(env.spool, SentinelName)); err != nil {
				t.Fatal(err)
			}
			return enabledConfig(env.spool)
		}},
		{name: "sentinel is a directory", reason: DropStartRefusedSpool, mutate: func(t *testing.T, env *testEnv) config.ArchiveConfig {
			path := filepath.Join(env.spool, SentinelName)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o750); err != nil {
				t.Fatal(err)
			}
			return enabledConfig(env.spool)
		}},
		{name: "blobs missing", reason: DropStartRefusedSpool, mutate: func(t *testing.T, env *testEnv) config.ArchiveConfig {
			if err := os.Remove(filepath.Join(env.spool, BlobDirName)); err != nil {
				t.Fatal(err)
			}
			return enabledConfig(env.spool)
		}},
		{name: "blobs without setgid", reason: DropStartRefusedSpool, mutate: func(t *testing.T, env *testEnv) config.ArchiveConfig {
			if err := os.Chmod(filepath.Join(env.spool, BlobDirName), 0o770); err != nil {
				t.Fatal(err)
			}
			return enabledConfig(env.spool)
		}},
		{name: "blobs world readable", reason: DropStartRefusedSpool, mutate: func(t *testing.T, env *testEnv) config.ArchiveConfig {
			if err := os.Chmod(filepath.Join(env.spool, BlobDirName), os.ModeSetgid|0o775); err != nil {
				t.Fatal(err)
			}
			return enabledConfig(env.spool)
		}},
		{name: "not ZFS", notZFS: true, reason: DropStartRefusedSpool, mutate: func(t *testing.T, env *testEnv) config.ArchiveConfig {
			return enabledConfig(env.spool)
		}},
		{name: "spool missing", reason: DropStartRefusedSpool, mutate: func(t *testing.T, env *testEnv) config.ArchiveConfig {
			return enabledConfig(filepath.Join(env.spool, "unmounted"))
		}},
		{name: "relative spool", reason: DropStartRefusedConfig, mutate: func(t *testing.T, env *testEnv) config.ArchiveConfig {
			return config.ArchiveConfig{Enabled: true, SpoolDir: "spool"}
		}},
	}
	if len(groups) > 1 {
		cases = append(cases, struct {
			name   string
			mutate func(t *testing.T, env *testEnv) config.ArchiveConfig
			notZFS bool
			group  func(t *testing.T) string
			reason string
		}{name: "blobs owned by another group", reason: DropStartRefusedSpool, mutate: func(t *testing.T, env *testEnv) config.ArchiveConfig {
			blobs := filepath.Join(env.spool, BlobDirName)
			info, err := os.Stat(env.spool)
			if err != nil {
				t.Fatal(err)
			}
			spoolGID := int(info.Sys().(*syscall.Stat_t).Gid)
			for _, gid := range groups {
				if gid != spoolGID {
					if err = os.Chown(blobs, -1, gid); err != nil {
						t.Skipf("chown to group %d: %v", gid, err)
					}
					break
				}
			}
			if err = os.Chmod(blobs, os.ModeSetgid|0o770); err != nil {
				t.Fatal(err)
			}
			return enabledConfig(env.spool)
		}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := setup(t, "", func(o *TestOverrides) {
				o.NotZFS = tc.notZFS
				if tc.group != nil {
					o.SpoolGroup = tc.group(t)
				}
			})
			cfg := tc.mutate(t, env)
			before := spoolNames(t, env.spool)
			if rec := Start(StartParams{Config: cfg}); rec != nil {
				t.Fatal("Start accepted an unsafe spool")
			}
			if Current() != nil {
				t.Fatal("Current() set after a refused start")
			}
			if after := spoolNames(t, env.spool); !slices.Equal(before, after) {
				t.Fatalf("refused start wrote to the spool: %v -> %v", before, after)
			}
			st, err := readState(env.state)
			if err != nil {
				t.Fatal(err)
			}
			if st.Drops[tc.reason].Events != 1 {
				t.Fatalf("refusal not counted as a gap: %+v", st.Drops)
			}
		})
	}
}

func TestSteeringGuardRefusesAndCountsGap(t *testing.T) {
	state := filepath.Join(t.TempDir(), "archive-state")
	t.Run("refused", func(t *testing.T) {
		env := setup(t, state, nil)
		if rec := Start(StartParams{Config: enabledConfig(env.spool), ResponseSteering: true}); rec != nil {
			t.Fatal("capture started while codex.response-steering is on")
		}
		if names := spoolNames(t, env.spool); len(names) != 2 {
			t.Fatalf("refused start wrote to the spool: %v", names)
		}
	})
	t.Run("next boot reports the gap", func(t *testing.T) {
		env := setup(t, state, nil)
		mustStart(t, env)
		stop(t)
		gaps := ofType(readEvents(t, env.spool), TypeGap)
		if len(gaps) != 1 {
			t.Fatalf("got %d gap events, want 1", len(gaps))
		}
		drops := gaps[0]["drops"].(map[string]any)
		if got := drops[DropStartRefusedSteering].(map[string]any)["events"]; got != float64(1) {
			t.Fatalf("steering refusal not reported: %v", gaps[0])
		}
		if gaps[0]["reason"] != "carried_over" {
			t.Fatalf("gap reason = %v", gaps[0]["reason"])
		}
		st, err := readState(state)
		if err != nil {
			t.Fatal(err)
		}
		if len(st.Drops) != 0 {
			t.Fatalf("reported drops still pending: %+v", st.Drops)
		}
	})
}

func TestStartReadsConfigOnce(t *testing.T) {
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	other := makeSpool(t)
	if got := Start(StartParams{Config: enabledConfig(other)}); got != rec {
		t.Fatal("a second Start replaced the recorder")
	}
	if got := Start(StartParams{Config: config.ArchiveConfig{}}); got != rec {
		t.Fatal("a disabled Start did not return the running recorder")
	}
	if Current() != rec {
		t.Fatal("a disabled reload turned capture off")
	}
	if names := spoolNames(t, other); len(names) != 2 {
		t.Fatalf("second Start wrote to another spool: %v", names)
	}
}

func TestBootLockOrderAndModes(t *testing.T) {
	withUmask(t, 0o077)
	env := setup(t, "", nil)
	var mu sync.Mutex
	var ops []string
	hook := func(op, path string) {
		mu.Lock()
		ops = append(ops, op+" "+filepath.Base(path))
		mu.Unlock()
	}
	traceHook.Store(&hook)
	rec := mustStart(t, env)
	id := rec.bootID

	mu.Lock()
	got := slices.Clone(ops)
	mu.Unlock()
	want := []string{
		"lock.create " + id + ".lock.tmp",
		"lock.flock " + id + ".lock.tmp",
		"lock.chmod " + id + ".lock.tmp",
		"lock.rename " + id + ".lock",
	}
	if len(got) < len(want)+1 || !slices.Equal(got[:len(want)], want) {
		t.Fatalf("lock steps = %v, want prefix %v", got, want)
	}
	if !strings.HasPrefix(got[len(want)], "segment.create ") {
		t.Fatalf("first step after the lock = %q, want segment.create", got[len(want)])
	}

	lockPath := filepath.Join(env.spool, id+".lock")
	assertMode(t, lockPath, 0o640)
	if _, err := os.Stat(lockPath + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary lock left behind: %v", err)
	}
	assertLocked(t, lockPath)
	for _, path := range segmentFiles(t, env.spool) {
		assertMode(t, path, 0o640)
	}

	stop(t)
	// The lock is never removed and stays held for the life of the process.
	assertLocked(t, lockPath)
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", filepath.Base(path), got, want)
	}
}

func assertLocked(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		t.Fatalf("%s is not locked", filepath.Base(path))
	}
	if !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("flock probe: %v", err)
	}
}

var segmentName = regexp.MustCompile(`^(\d{8}T\d{6}\.\d{6}Z)-([0-9a-f-]{36})-(\d{6})\.(open|closed)\.jsonl$`)

func TestSegmentsRotateBySizeAndClose(t *testing.T) {
	withUmask(t, 0o077)
	env := setup(t, "", func(o *TestOverrides) { o.SegmentMaxBytes = 2048 })
	rec := mustStart(t, env)
	for i := 0; i < 30; i++ {
		rec.Emit(&Event{Type: TypeGap, Data: map[string]any{"reason": "test", "pad": strings.Repeat("x", 200), "i": i}})
	}
	stop(t)

	files := segmentFiles(t, env.spool)
	if len(files) < 3 {
		t.Fatalf("got %d segments, want rotation by size", len(files))
	}
	for i, path := range files {
		m := segmentName.FindStringSubmatch(filepath.Base(path))
		if m == nil {
			t.Fatalf("bad segment name %s", filepath.Base(path))
		}
		if m[2] != rec.bootID || m[3] != fmt.Sprintf("%06d", i+1) || m[4] != "closed" {
			t.Fatalf("segment %d named %s", i, filepath.Base(path))
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > 2048 {
			t.Fatalf("%s is %d bytes, over the limit", filepath.Base(path), info.Size())
		}
		assertMode(t, path, 0o640)
	}
	events := readEvents(t, env.spool)
	for i, ev := range events {
		if ev["seq"] != float64(i+1) {
			t.Fatalf("event %d has seq %v", i, ev["seq"])
		}
		if ev["boot_id"] != rec.bootID || ev["v"] != float64(EnvelopeVersion) {
			t.Fatalf("bad envelope %v", ev)
		}
	}
	if events[0]["type"] != TypeBoot || events[len(events)-1]["type"] != TypeShutdown {
		t.Fatalf("first %v, last %v", events[0]["type"], events[len(events)-1]["type"])
	}
	if events[len(events)-1]["reason"] != "clean" {
		t.Fatalf("shutdown event %v", events[len(events)-1])
	}
}

func TestSegmentsRotateByTime(t *testing.T) {
	env := setup(t, "", func(o *TestOverrides) { o.SegmentDuration = 100 * time.Millisecond })
	rec := mustStart(t, env)
	rec.Emit(&Event{Type: TypeGap, Data: map[string]any{"reason": "test"}})
	waitFor(t, "a time-rotated segment", func() bool {
		for _, path := range segmentFiles(t, env.spool) {
			if strings.HasSuffix(path, ".closed.jsonl") {
				return true
			}
		}
		return false
	})
	if Current() != rec {
		t.Fatal("recorder stopped")
	}
}

func TestEventsAreSyncedWithinTheInterval(t *testing.T) {
	env := setup(t, "", nil)
	var synced atomic.Int64
	var wrote atomic.Int64
	hook := func(op, _ string) {
		switch op {
		case "segment.write":
			wrote.Add(1)
		case "segment.sync":
			if wrote.Load() > 1 {
				synced.Add(1)
			}
		}
	}
	traceHook.Store(&hook)
	rec := mustStart(t, env)
	rec.Emit(&Event{Type: TypeGap, Data: map[string]any{"reason": "test"}})
	waitFor(t, "an fsync after the write", func() bool { return synced.Load() > 0 })
}

func TestBlobPersistedBeforeItsEvent(t *testing.T) {
	withUmask(t, 0o077)
	env := setup(t, "", func(o *TestOverrides) { o.BlobThresholdBytes = 64 })
	var mu sync.Mutex
	var ops []string
	hook := func(op, _ string) {
		if op == "segment.sync" {
			return // fsync ticks interleave freely
		}
		mu.Lock()
		ops = append(ops, op)
		mu.Unlock()
	}
	rec := mustStart(t, env)
	traceHook.Store(&hook)
	payload := bytes.Repeat([]byte("blob body \x00\xff "), 100)
	rec.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: &BodyData{Bytes: payload}})
	flush(t)

	mu.Lock()
	got := slices.Clone(ops)
	ops = nil
	mu.Unlock()
	want := []string{"blob.create", "blob.sync", "blob.chmod", "blob.rename", "blob.dirsync", "segment.write"}
	if !slices.Equal(got, want) {
		t.Fatalf("steps = %v, want %v", got, want)
	}

	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])
	blobPath := filepath.Join(env.spool, BlobDirName, hexSum)
	stored, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, payload) {
		t.Fatal("blob content differs")
	}
	assertMode(t, blobPath, 0o640)
	bodies := ofType(readEvents(t, env.spool), TypeClientBody)
	body := bodies[0]["body"].(map[string]any)
	if body["form"] != FormBlob || body["sha256"] != hexSum || body["bytes"] != float64(len(payload)) {
		t.Fatalf("blob body = %v", body)
	}
	if _, ok := body["value"]; ok {
		t.Fatal("blob body carries its value inline")
	}

	// The same bytes again reuse the stored blob.
	rec.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: &BodyData{Bytes: payload}})
	flush(t)
	mu.Lock()
	again := slices.Clone(ops)
	mu.Unlock()
	if !slices.Equal(again, []string{"blob.reuse", "blob.dirsync", "segment.write"}) {
		t.Fatalf("second identical blob steps = %v", again)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(env.spool, BlobDirName, ".tmp-*")); len(leftovers) != 0 {
		t.Fatalf("temporary blobs left: %v", leftovers)
	}
}

func compress(t *testing.T, encoding string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	switch encoding {
	case "gzip":
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(data)
		_ = zw.Close()
	case "zstd":
		zw, err := zstd.NewWriter(&buf)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = zw.Write(data)
		_ = zw.Close()
	}
	return buf.Bytes()
}

// bodyCases are payloads whose JSON round trips are not byte-exact.
func bodyCases(t *testing.T) map[string]*BodyData {
	jsonish := []byte(`{"a":"line sep para` + " " + `","a":1E5,"path":"\/x","name":"é","html":"<b>&amp;</b>"}`)
	return map[string]*BodyData{
		"u2028 literal":  {Bytes: []byte("before after end")},
		"invalid utf8":   {Bytes: []byte{'{', '"', 0xff, 0xfe, '"', '}', 0xc3}},
		"e acute":        {Bytes: []byte("café café")},
		"duplicate keys": {Bytes: jsonish},
		"gzip":           {Bytes: compress(t, "gzip", jsonish), ContentEncoding: "gzip"},
		"zstd":           {Bytes: compress(t, "zstd", jsonish), ContentEncoding: "zstd"},
		"empty":          {Bytes: []byte{}},
		"nul and crlf":   {Bytes: []byte("a\x00b\r\nc\t")},
	}
}

// DecodeBody returns the exact bytes a spool body carries.
func decodeBody(t *testing.T, spool string, body map[string]any) []byte {
	t.Helper()
	switch body["form"] {
	case FormText:
		return []byte(body["value"].(string))
	case FormBase64:
		data, err := base64.StdEncoding.DecodeString(body["value"].(string))
		if err != nil {
			t.Fatal(err)
		}
		return data
	case FormBlob:
		data, err := os.ReadFile(filepath.Join(spool, BlobDirName, body["sha256"].(string)))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	t.Fatalf("unknown form %v", body["form"])
	return nil
}

func TestBodiesRoundTripByteExact(t *testing.T) {
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	cases := bodyCases(t)
	for name, body := range cases {
		rec.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: body, Data: map[string]any{"case": name}})
	}
	flush(t)
	raw, err := os.ReadFile(segmentFiles(t, env.spool)[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("\\u003c")) || bytes.Contains(raw, []byte("\\u0026")) || !bytes.Contains(raw, []byte("<b>&amp;")) {
		t.Fatal("spool lines are HTML-escaped")
	}
	seen := 0
	for _, ev := range ofType(readEvents(t, env.spool), TypeClientBody) {
		name := ev["case"].(string)
		want := cases[name]
		body := ev["body"].(map[string]any)
		got := decodeBody(t, env.spool, body)
		if !bytes.Equal(got, want.Bytes) {
			t.Fatalf("%s: round trip %q != %q", name, got, want.Bytes)
		}
		sum := sha256.Sum256(want.Bytes)
		if body["sha256"] != hex.EncodeToString(sum[:]) || body["bytes"] != float64(len(want.Bytes)) {
			t.Fatalf("%s: hash or size wrong: %v", name, body)
		}
		if ce, _ := body["content_encoding"].(string); ce != want.ContentEncoding {
			t.Fatalf("%s: content_encoding = %q", name, ce)
		}
		wantForm := FormText
		if name == "invalid utf8" || name == "gzip" || name == "zstd" {
			wantForm = FormBase64
		}
		if body["form"] != wantForm {
			t.Fatalf("%s: form = %v, want %s", name, body["form"], wantForm)
		}
		seen++
	}
	if seen != len(cases) {
		t.Fatalf("saw %d bodies, want %d", seen, len(cases))
	}
}

var tsPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$`)

func TestEnvelopeAndBootEvent(t *testing.T) {
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	id, err := uuid.Parse(rec.bootID)
	if err != nil || id.Version() != 7 {
		t.Fatalf("boot id %q is not a UUIDv7", rec.bootID)
	}
	in := rec.BeginIngress(RouteInference, time.Now())
	if parsed, errParse := uuid.Parse(in.ID()); errParse != nil || parsed.Version() != 7 {
		t.Fatalf("ingress id %q is not a UUIDv7", in.ID())
	}
	in.Emit(&Event{Type: TypeIngressStart, Capture: CaptureFull, Data: map[string]any{"method": "POST"}})
	stop(t)
	events := readEvents(t, env.spool)
	for _, ev := range events {
		if !tsPattern.MatchString(ev["ts"].(string)) {
			t.Fatalf("ts %q is not RFC 3339 UTC with microseconds", ev["ts"])
		}
	}
	boot := events[0]
	if boot["recorder_version"] != RecorderVersion || boot["redaction_version"] != float64(RedactionVersion) ||
		boot["envelope_version"] != float64(EnvelopeVersion) || boot["build_commit"] == nil || boot["config"] == nil {
		t.Fatalf("boot event = %v", boot)
	}
	start := ofType(events, TypeIngressStart)[0]
	if start["ingress_id"] != in.ID() || start["capture"] != CaptureFull || start["method"] != "POST" {
		t.Fatalf("ingress_start = %v", start)
	}
}

func TestQueueReservation(t *testing.T) {
	q := newQueue(100)
	if !q.reserve(60) || q.reserve(41) || !q.reserve(40) {
		t.Fatal("reservations do not respect the byte limit")
	}
	q.release(50)
	if !q.reserve(50) || q.reserve(1) {
		t.Fatal("release did not return bytes")
	}
	if q.reserve(-1) {
		t.Fatal("negative reservation accepted")
	}
	if !q.push(&queued{}) || len(q.close()) != 1 || q.push(&queued{}) {
		t.Fatal("push after close accepted")
	}
}

func TestFullQueueDropsWithoutBlocking(t *testing.T) {
	env := setup(t, "", func(o *TestOverrides) { o.QueueBytes = 64 << 10 })
	rec := mustStart(t, env)
	release := make(chan struct{})
	var blocked atomic.Bool
	hook := func(op string) error {
		if op == "segment.write" && blocked.CompareAndSwap(false, true) {
			<-release
		}
		return nil
	}
	faultHook.Store(&hook)

	// Too large for the queue at all.
	if rec.Emit(&Event{Type: TypeClientBody, Body: &BodyData{Bytes: make([]byte, 128<<10)}}) {
		t.Fatal("an event larger than the queue was accepted")
	}
	rec.Emit(&Event{Type: TypeGap, Data: map[string]any{"reason": "first"}})
	waitFor(t, "the writer to block", blocked.Load)

	started := time.Now()
	accepted, dropped := 0, 0
	for i := 0; i < 200; i++ {
		if rec.Emit(&Event{Type: TypeClientBody, Body: &BodyData{Bytes: make([]byte, 1024)}}) {
			accepted++
		} else {
			dropped++
		}
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("emitting into a full queue took %v", elapsed)
	}
	if dropped == 0 || accepted == 0 {
		t.Fatalf("accepted %d, dropped %d; want both", accepted, dropped)
	}
	if got := rec.ledger.totals()[DropQueueFull]; got.Events != int64(dropped)+1 || got.Bodies != int64(dropped)+1 {
		t.Fatalf("queue_full drops = %+v, want %d", got, dropped+1)
	}
	close(release)
	flush(t)
	waitFor(t, "a gap event for the drops", func() bool {
		for _, gap := range ofType(readEvents(t, env.spool), TypeGap) {
			if drops, ok := gap["drops"].(map[string]any); ok && drops[DropQueueFull] != nil {
				return true
			}
		}
		return false
	})
	if used := rec.q.used.Load(); used != 0 {
		t.Fatalf("queue still holds %d reserved bytes", used)
	}
}

func TestWriterFailureDisablesCaptureAndRecovers(t *testing.T) {
	for _, mode := range []string{"error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			old := writerBackoff
			writerBackoff = 20 * time.Millisecond
			t.Cleanup(func() { writerBackoff = old })
			env := setup(t, "", nil)
			rec := mustStart(t, env)
			var failures atomic.Int32
			hook := func(op string) error {
				if op == "segment.write" && failures.CompareAndSwap(0, 1) {
					if mode == "panic" {
						panic("injected writer panic")
					}
					return errors.New("injected disk error")
				}
				return nil
			}
			faultHook.Store(&hook)
			rec.Emit(&Event{Type: TypeGap, Data: map[string]any{"reason": "lost"}})
			waitFor(t, "a writer_error gap", func() bool {
				for _, gap := range ofType(readEvents(t, env.spool), TypeGap) {
					if gap["reason"] == DropWriterError {
						return true
					}
				}
				return false
			})
			waitFor(t, "capture to resume", rec.CaptureEvents)
			if !rec.Emit(&Event{Type: TypeGap, Data: map[string]any{"reason": "after"}}) {
				t.Fatal("capture did not resume")
			}
			stop(t)
			events := readEvents(t, env.spool)
			var gap event
			for _, ev := range ofType(events, TypeGap) {
				if ev["reason"] == DropWriterError {
					gap = ev
				}
			}
			if errText, _ := gap["error"].(string); !strings.Contains(errText, "injected") {
				t.Fatalf("gap error = %q", gap["error"])
			}
			if drops := gap["drops"].(map[string]any); drops[DropWriterError] == nil {
				t.Fatalf("gap does not count the dropped event: %v", gap)
			}
			if ofType(events, TypeShutdown) == nil {
				t.Fatal("no shutdown event after recovery")
			}
			files := segmentFiles(t, env.spool)
			if len(files) < 2 {
				t.Fatalf("failure did not end the segment: %v", files)
			}
			for _, path := range files {
				if !strings.HasSuffix(path, ".closed.jsonl") {
					t.Fatalf("segment left open: %s", path)
				}
			}
		})
	}
}

func TestFreeSpaceThresholds(t *testing.T) {
	state := filepath.Join(t.TempDir(), "archive-state")
	env := setup(t, state, func(o *TestOverrides) { o.SpaceCheckInterval = 10 * time.Millisecond })
	rec := Start(StartParams{Config: config.ArchiveConfig{Enabled: true, SpoolDir: env.spool, BodyFreeGB: 2, HardFreeGB: 1}})
	if rec == nil {
		t.Fatal("Start returned nil")
	}
	if !rec.CaptureBodies() {
		t.Fatal("bodies off with plenty of space")
	}
	env.free.Store(uint64(gib) + uint64(gib)/2)
	waitFor(t, "bodies to stop", func() bool { return !rec.CaptureBodies() })
	if !rec.CaptureEvents() || rec.BodyDropReason() != DropLowSpaceBody {
		t.Fatalf("events %v, reason %s", rec.CaptureEvents(), rec.BodyDropReason())
	}
	// A body already in progress can reserve no more, nor be queued.
	if rec.ReserveBody(10) {
		t.Fatal("body bytes reserved below body_free_gb")
	}
	if rec.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: &BodyData{Bytes: []byte("late body")}}) {
		t.Fatal("a body event was queued below body_free_gb")
	}
	if got := rec.ledger.totals()[DropLowSpaceBody]; got.Bodies != 1 {
		t.Fatalf("low_space_body drops = %+v", got)
	}
	if used := rec.q.used.Load(); used != 0 {
		t.Fatalf("queue holds %d bytes after refused bodies", used)
	}
	env.free.Store(uint64(gib) / 2)
	waitFor(t, "capture to stop", func() bool { return !rec.CaptureEvents() })
	for i := 0; i < 3; i++ {
		if rec.Emit(&Event{Type: TypeGap, Data: map[string]any{"reason": "x"}}) {
			t.Fatal("event accepted below hard_free_gb")
		}
	}
	waitFor(t, "drops to persist", func() bool {
		st, err := readState(state)
		return err == nil && st.Drops[DropLowSpaceHard].Events == 3
	})
	env.free.Store(uint64(10 * gib))
	waitFor(t, "a gap once space returns", func() bool {
		for _, gap := range ofType(readEvents(t, env.spool), TypeGap) {
			if drops, ok := gap["drops"].(map[string]any); ok && drops[DropLowSpaceHard] != nil {
				return true
			}
		}
		return false
	})
	stop(t)
	st, err := readState(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Drops) != 0 {
		t.Fatalf("reported drops still persisted: %+v", st.Drops)
	}
}

func TestHeartbeatCarriesCounters(t *testing.T) {
	env := setup(t, "", func(o *TestOverrides) { o.HeartbeatInterval = 20 * time.Millisecond })
	mustStart(t, env)
	waitFor(t, "a heartbeat", func() bool { return len(ofType(readEvents(t, env.spool), TypeHeartbeat)) > 0 })
	hb := ofType(readEvents(t, env.spool), TypeHeartbeat)[0]
	for _, key := range []string{"queue_bytes", "queue_limit", "events_written", "segments_closed", "free_bytes", "capture_state"} {
		if _, ok := hb[key]; !ok {
			t.Fatalf("heartbeat lacks %s: %v", key, hb)
		}
	}
}

func TestEmitAfterStopIsSafe(t *testing.T) {
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	in := rec.BeginIngress(RouteInference, time.Now())
	stop(t)
	if in.Emit(&Event{Type: TypeIngressEnd}) {
		t.Fatal("event accepted after stop")
	}
	if in.Drops() != 1 {
		t.Fatalf("drop not counted against the request: %d", in.Drops())
	}
	if Current() != nil {
		t.Fatal("Current() set after Stop")
	}
}

// traceOps records the named trace operations in order.
func traceOps(t *testing.T, names ...string) func() []string {
	t.Helper()
	var mu sync.Mutex
	var ops []string
	hook := func(op, _ string) {
		if slices.Contains(names, op) {
			mu.Lock()
			ops = append(ops, op)
			mu.Unlock()
		}
	}
	traceHook.Store(&hook)
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(ops)
	}
}

func shortBackoff(t *testing.T, d time.Duration) {
	t.Helper()
	old := writerBackoff
	writerBackoff = d
	t.Cleanup(func() { writerBackoff = old })
}

func TestLongBatchStillSyncs(t *testing.T) {
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	release := make(chan struct{})
	var blocked atomic.Bool
	hook := func(op string) error {
		if op == "segment.write" {
			if blocked.CompareAndSwap(false, true) {
				<-release
			}
			time.Sleep(5 * time.Millisecond)
		}
		return nil
	}
	faultHook.Store(&hook)
	ops := traceOps(t, "segment.write", "segment.sync")
	rec.Emit(&Event{Type: TypeGap, Data: map[string]any{"reason": "first"}})
	waitFor(t, "the writer to block", blocked.Load)
	// One batch of 60 slow writes, about 300 ms against a 20 ms interval.
	for i := 0; i < 60; i++ {
		rec.Emit(&Event{Type: TypeGap, Data: map[string]any{"reason": "batch", "i": i}})
	}
	close(release)
	flush(t)
	got := ops()
	var writes []int
	for i, op := range got {
		if op == "segment.write" {
			writes = append(writes, i)
		}
	}
	if len(writes) < 61 {
		t.Fatalf("saw %d writes", len(writes))
	}
	batch := got[writes[len(writes)-60]:writes[len(writes)-1]]
	if syncs := strings.Count(strings.Join(batch, " "), "segment.sync"); syncs < 2 {
		t.Fatalf("%d fsyncs during a 300 ms batch; the batch held off the fsync cadence", syncs)
	}
}

func TestGapCountersClearOnlyOnceDurable(t *testing.T) {
	shortBackoff(t, time.Hour)
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	flush(t)
	var armed atomic.Bool
	hook := func(op string) error {
		if op == "segment.sync" && armed.CompareAndSwap(true, false) {
			return errors.New("injected fsync failure")
		}
		return nil
	}
	faultHook.Store(&hook)
	armed.Store(true)
	rec.ledger.add(DropQueueFull, DropCount{Events: 1})
	waitFor(t, "the writer to fail", func() bool { return !rec.CaptureEvents() })
	stop(t)
	st, err := readState(env.state)
	if err != nil {
		t.Fatal(err)
	}
	if st.Drops[DropQueueFull].Events != 1 {
		t.Fatalf("drops cleared although their gap was never synced: %+v", st.Drops)
	}
}

func TestWriterDropsCountAgainstTheirRequest(t *testing.T) {
	shortBackoff(t, 10*time.Millisecond)
	env := setup(t, "", nil)
	rec := mustStart(t, env)

	in := rec.BeginIngress(RouteInference, time.Now())
	in.Emit(&Event{Type: TypeIngressStart, Data: map[string]any{"unencodable": make(chan int)}})
	in.Emit(&Event{Type: TypeIngressEnd, ReportDrops: true, Data: map[string]any{"status": 200}})
	flush(t)
	if in.Drops() != 1 {
		t.Fatalf("encode error not counted against the request: %d", in.Drops())
	}
	ends := ofType(readEvents(t, env.spool), TypeIngressEnd)
	if len(ends) != 1 || ends[0]["capture_drops"] != float64(1) {
		t.Fatalf("ingress_end = %v, want capture_drops 1", ends)
	}

	var failed atomic.Bool
	hook := func(op string) error {
		if op == "segment.write" && failed.CompareAndSwap(false, true) {
			return errors.New("injected disk error")
		}
		return nil
	}
	faultHook.Store(&hook)
	failing := rec.BeginIngress(RouteInference, time.Now())
	failing.Emit(&Event{Type: TypeIngressStart, Data: map[string]any{"method": "POST"}})
	waitFor(t, "the writer drop to reach the request", func() bool { return failing.Drops() == 1 })
}

func TestFailingDiskLeavesNoEmptySegments(t *testing.T) {
	shortBackoff(t, 5*time.Millisecond)
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	var writes atomic.Int32
	hook := func(op string) error {
		if op == "segment.write" && writes.Add(1) <= 5 {
			return errors.New("injected disk error")
		}
		return nil
	}
	faultHook.Store(&hook)
	rec.Emit(&Event{Type: TypeGap, Data: map[string]any{"reason": "lost"}})
	waitFor(t, "capture to resume", func() bool { return writes.Load() > 5 && rec.CaptureEvents() })
	stop(t)
	files := segmentFiles(t, env.spool)
	if len(files) != 2 {
		t.Fatalf("segments = %v, want the failed one and one after recovery", files)
	}
	for i, path := range files {
		m := segmentName.FindStringSubmatch(filepath.Base(path))
		if m == nil || m[3] != fmt.Sprintf("%06d", i+1) || m[4] != "closed" {
			t.Fatalf("segment %d named %s", i, filepath.Base(path))
		}
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Fatalf("%s is empty (%v)", filepath.Base(path), err)
		}
	}
}

func TestStopPersistsLateDrops(t *testing.T) {
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	var once sync.Once
	hook := func(op, _ string) {
		// A tap finishing during shutdown counts a drop after the writer's
		// last write of the state file.
		if op == "ledger.persist" && rec.stopping.Load() {
			once.Do(func() { rec.CountDrop(DropStopped, DropCount{Events: 1}) })
		}
	}
	traceHook.Store(&hook)
	stop(t)
	st, err := readState(env.state)
	if err != nil {
		t.Fatal(err)
	}
	if st.Drops[DropStopped].Events != 1 {
		t.Fatalf("a drop counted during shutdown was lost: %+v", st.Drops)
	}
}

func TestBlobReuseCompletesDurability(t *testing.T) {
	shortBackoff(t, 10*time.Millisecond)
	env := setup(t, "", func(o *TestOverrides) { o.BlobThresholdBytes = 64 })
	rec := mustStart(t, env)
	var failed atomic.Bool
	hook := func(op string) error {
		if op == "blob.dirsync" && failed.CompareAndSwap(false, true) {
			return errors.New("injected directory fsync failure")
		}
		return nil
	}
	faultHook.Store(&hook)
	payload := bytes.Repeat([]byte("renamed but not synced "), 10)
	rec.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: &BodyData{Bytes: payload}})
	waitFor(t, "the failure and recovery", func() bool { return failed.Load() && rec.CaptureEvents() })
	flush(t)
	ops := traceOps(t, "blob.create", "blob.reuse", "blob.dirsync", "segment.write")
	rec.Emit(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: &BodyData{Bytes: payload}})
	flush(t)
	if got := ops(); !slices.Equal(got, []string{"blob.reuse", "blob.dirsync", "segment.write"}) {
		t.Fatalf("retry steps = %v; the reused blob skipped its directory fsync", got)
	}
	bodies := ofType(readEvents(t, env.spool), TypeClientBody)
	if len(bodies) != 1 || bodies[0]["body"].(map[string]any)["form"] != FormBlob {
		t.Fatalf("client_body events = %v", bodies)
	}
}

// A body buffer is charged by its capacity: slack in the buffer must not pay
// for the event's metadata, which needs its own reservation.
func TestBodyBufferSlackDoesNotFundMetadata(t *testing.T) {
	env := setup(t, "", func(o *TestOverrides) { o.QueueBytes = 4096 })
	rec := mustStart(t, env)
	in := rec.BeginIngress(RouteInference, time.Now())
	if !rec.ReserveBody(4096) {
		t.Fatal("cannot reserve the buffer")
	}
	body := &BodyData{Bytes: make([]byte, 1, 4096)}
	if in.EmitReserved(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: body}, 4096) {
		t.Fatal("a 1-byte body in a 4096-byte buffer filled a 4096-byte queue with no metadata reserved")
	}
	if used := rec.q.used.Load(); used != 0 {
		t.Fatalf("the refused body left %d bytes reserved", used)
	}
	if got := rec.ledger.totals()[DropQueueFull]; got.Bodies != 1 || got.Bytes != 1 {
		t.Fatalf("queue_full drops = %+v", got)
	}
	// With room for the metadata the same body is accepted, and the writer
	// returns the whole reservation.
	if !rec.ReserveBody(2048) {
		t.Fatal("cannot reserve the smaller buffer")
	}
	small := &BodyData{Bytes: make([]byte, 1, 2048)}
	if !in.EmitReserved(&Event{Type: TypeClientBody, Capture: CaptureFull, Body: small}, 2048) {
		t.Fatal("a body with room for its metadata was refused")
	}
	flush(t)
	if used := rec.q.used.Load(); used != 0 {
		t.Fatalf("queue still holds %d bytes", used)
	}
}

// Drops counted after Stop's final persist could never be persisted or
// reported, so they are not counted at all.
func TestDropsAfterStopAreNotCounted(t *testing.T) {
	env := setup(t, "", nil)
	rec := mustStart(t, env)
	in := rec.BeginIngress(RouteInference, time.Now())
	stop(t)
	before := rec.ledger.totals()
	rec.CountDrop(DropStopped, DropCount{Events: 1})
	in.Emit(&Event{Type: TypeClientBody, Body: &BodyData{Bytes: []byte("late")}})
	if rec.ReserveBody(1) {
		t.Fatal("a body reservation succeeded after Stop")
	}
	if after := rec.ledger.totals(); !maps.Equal(before, after) {
		t.Fatalf("drops counted after Stop: %+v -> %+v", before, after)
	}
	st, err := readState(env.state)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Drops) != 0 {
		t.Fatalf("persisted drops = %+v", st.Drops)
	}
}
