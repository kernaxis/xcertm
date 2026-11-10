//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package state

import (
	"errors"
	"os"
)

func fileOwner(os.FileInfo) (int, int, error) {
	return 0, 0, errors.New("local deployment recovery requires a Unix filesystem")
}

func tryLock(*os.File) error {
	return errors.New("local deployment locking requires a Unix platform")
}

func directoryIdentity(os.FileInfo) (uint64, uint64, error) {
	return 0, 0, errors.New("local deployment requires Unix directory identities")
}
