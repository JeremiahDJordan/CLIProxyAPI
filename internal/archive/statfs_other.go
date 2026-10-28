//go:build !linux && !darwin

package archive

import "errors"

func platformStatFS(string) (fsStat, error) {
	return fsStat{}, errors.New("archive: statfs is not supported on this platform")
}
