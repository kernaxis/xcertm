//go:build !linux

package state

import "errors"

func checkExtendedMetadata(string) error {
	return errors.New("local deployment currently supports Linux filesystems only")
}
