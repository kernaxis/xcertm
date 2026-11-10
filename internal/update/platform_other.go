//go:build !linux

package update

import (
	"fmt"
	"os"
)

func lockBinary(string) (*os.File, error) {
	return nil, fmt.Errorf("updates support Linux and Synology DSM only")
}

func safeFile(os.FileInfo) error                { return fmt.Errorf("unsupported platform") }
func safeDirectory(os.FileInfo) error           { return fmt.Errorf("unsupported platform") }
func preserveOwner(*os.File, os.FileInfo) error { return fmt.Errorf("unsupported platform") }
