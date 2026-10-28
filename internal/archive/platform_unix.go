//go:build unix

package archive

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// lockExclusive takes a non-blocking exclusive flock on f.
func lockExclusive(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

// checkSpoolDirs requires the spool root and blobs/ to be directories with
// mode 2770 owned by the named group (design sections 6 and 7).
func checkSpoolDirs(spool, blobs, group string) error {
	g, err := user.LookupGroup(group)
	if err != nil {
		return fmt.Errorf("spool group: %w", err)
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return fmt.Errorf("spool group %s has gid %q: %w", group, g.Gid, err)
	}
	spoolInfo, err := os.Stat(spool)
	if err != nil {
		return err
	}
	blobInfo, err := os.Lstat(blobs)
	if err != nil {
		return err
	}
	for _, dir := range []struct {
		path string
		info os.FileInfo
	}{{spool, spoolInfo}, {blobs, blobInfo}} {
		if !dir.info.IsDir() {
			return fmt.Errorf("%s is not a directory", dir.path)
		}
		const want = os.ModeDir | os.ModeSetgid | 0o770
		got := dir.info.Mode() & (os.ModeDir | os.ModeType | os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
		if got != want {
			return fmt.Errorf("%s has mode %v, want %v", dir.path, got, want)
		}
		st, ok := dir.info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("archive: cannot read directory ownership")
		}
		if uint64(st.Gid) != gid {
			return fmt.Errorf("%s is owned by group %d, want %s (%d)", dir.path, st.Gid, group, gid)
		}
	}
	return nil
}
