//go:build unix

package archive

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// lockExclusive takes a non-blocking exclusive flock on f.
func lockExclusive(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

// checkBlobDir requires blobs/ to be a directory with mode 2770 whose group
// is the group that owns the spool root (design section 6).
func checkBlobDir(spool, blobs string) error {
	spoolInfo, err := os.Stat(spool)
	if err != nil {
		return err
	}
	blobInfo, err := os.Lstat(blobs)
	if err != nil {
		return err
	}
	if !blobInfo.IsDir() {
		return fmt.Errorf("%s is not a directory", blobs)
	}
	const want = os.ModeDir | os.ModeSetgid | 0o770
	got := blobInfo.Mode() & (os.ModeDir | os.ModeType | os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	if got != want {
		return fmt.Errorf("%s has mode %v, want %v", blobs, got, want)
	}
	spoolStat, okSpool := spoolInfo.Sys().(*syscall.Stat_t)
	blobStat, okBlob := blobInfo.Sys().(*syscall.Stat_t)
	if !okSpool || !okBlob {
		return errors.New("archive: cannot read directory ownership")
	}
	if spoolStat.Gid != blobStat.Gid {
		return fmt.Errorf("%s group %d differs from spool group %d", blobs, blobStat.Gid, spoolStat.Gid)
	}
	return nil
}
