//go:build !unix

package archive

import (
	"errors"
	"os"
)

func lockExclusive(*os.File) error {
	return errors.New("archive: flock is not supported on this platform")
}

func checkBlobDir(string, string) error {
	return errors.New("archive: blob directory checks are not supported on this platform")
}
