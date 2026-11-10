//go:build linux

package state

import (
	"errors"
	"fmt"
	"syscall"
)

// Atomic replacement preserves the metadata explicitly tracked by Snapshot.
// Refuse ACLs/security labels/other xattrs rather than silently dropping them.
func checkExtendedMetadata(path string) error {
	n, err := syscall.Listxattr(path, nil)
	if errors.Is(err, syscall.ENOTSUP) {
		return nil
	}
	if err != nil {
		return err
	}
	if n != 0 {
		return fmt.Errorf("extended metadata is unsupported for deployment: %s", path)
	}
	return nil
}
