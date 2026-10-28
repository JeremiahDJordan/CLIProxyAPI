//go:build !unix

package archive

import (
	"errors"
	"os"
)

func lockExclusive(*os.File) error {
	return errors.New("archive: flock is not supported on this platform")
}

func checkSpoolDirs(string, string, string) error {
	return errors.New("archive: spool directory checks are not supported on this platform")
}
