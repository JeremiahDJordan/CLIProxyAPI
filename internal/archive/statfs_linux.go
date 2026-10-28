//go:build linux

package archive

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// zfsSuperMagic is ZFS_SUPER_MAGIC as reported in statfs f_type.
const zfsSuperMagic = 0x2fc12fc1

func platformStatFS(path string) (fsStat, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return fsStat{}, err
	}
	fsType := uint64(st.Type)
	return fsStat{
		fsType: fmt.Sprintf("0x%x", fsType),
		isZFS:  fsType == zfsSuperMagic,
		free:   st.Bavail * uint64(st.Bsize),
	}, nil
}
