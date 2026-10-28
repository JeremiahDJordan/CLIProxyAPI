//go:build darwin

package archive

import "golang.org/x/sys/unix"

func platformStatFS(path string) (fsStat, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return fsStat{}, err
	}
	fsType := unix.ByteSliceToString(st.Fstypename[:])
	return fsStat{
		fsType: fsType,
		isZFS:  fsType == "zfs",
		free:   st.Bavail * uint64(st.Bsize),
	}, nil
}
