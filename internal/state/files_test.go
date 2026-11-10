//go:build linux

package state_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/kernaxis/xcertm/internal/state"
)

func TestPrivateDirPermissions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    os.FileMode
		allowed bool
	}{
		{"private", 0700, true},
		{"world-readable", 0755, false},
		{"group-writable", 0770, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, tc.mode); err != nil {
				t.Fatal(err)
			}
			err := state.PrivateDir(dir)
			if (err == nil) != tc.allowed {
				t.Fatalf("PrivateDir with permissions %04o: %v", tc.mode, err)
			}
			info, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != tc.mode {
				t.Fatal("existing directory permissions were changed")
			}
		})
	}
}

func TestAtomicWriteFailurePreservesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := state.Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	before.UID = -2
	if err := state.AtomicWrite(path, []byte("new"), before); err == nil {
		t.Fatal("invalid publication metadata accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "old" {
		t.Fatal("failed publication changed active file")
	}
}

func TestInspectRejectsExtendedMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	err := syscall.Setxattr(path, "user.xcertm-test", []byte("keep"), 0)
	if errors.Is(err, syscall.ENOTSUP) {
		t.Skip("filesystem has no xattr support")
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Inspect(path); err == nil {
		t.Fatal("extended metadata would be silently dropped")
	}
}
