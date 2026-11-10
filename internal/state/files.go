package state

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Snapshot includes metadata so recovery does not silently undo an operator's changes.
type Snapshot struct {
	Exists bool   `json:"exists"`
	Hash   string `json:"hash"`
	Mode   uint32 `json:"mode"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
}

func CheckParents(path string) error {
	dir := filepath.Dir(path)
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("unsupported directory or symlink: %s", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

func Inspect(path string) (Snapshot, error) {
	if err := CheckParents(path); err != nil {
		return Snapshot{}, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return Snapshot{}, nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	if !info.Mode().IsRegular() {
		return Snapshot{}, fmt.Errorf("unsupported file or symlink: %s", path)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return Snapshot{}, fmt.Errorf("special file permissions are unsupported: %s", path)
	}
	if err := checkExtendedMetadata(path); err != nil {
		return Snapshot{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	uid, gid, err := fileOwner(info)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{true, Digest(data), uint32(info.Mode().Perm()), uid, gid}, nil
}

func Digest(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

func SyncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// AtomicWrite never truncates the active file. Metadata is set before publication.
func AtomicWrite(path string, data []byte, metadata Snapshot) error {
	if metadata.Mode > 0777 || metadata.UID < 0 || metadata.GID < 0 {
		return fmt.Errorf("invalid publication metadata")
	}
	if _, err := Inspect(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".xcertm-write-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chown(metadata.UID, metadata.GID); err != nil {
		return err
	}
	if err = f.Chmod(os.FileMode(metadata.Mode)); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

func WritePrivate(path string, data []byte) error {
	return AtomicWrite(path, data, Snapshot{Mode: 0600, UID: os.Geteuid(), GID: os.Getegid()})
}

func WritePreserving(path string, data []byte) error {
	metadata, err := Inspect(path)
	if err != nil {
		return err
	}
	if !metadata.Exists {
		metadata = Snapshot{Mode: 0600, UID: os.Geteuid(), GID: os.Getegid()}
	}
	return AtomicWrite(path, data, metadata)
}

// Lock files are deliberately retained: unlinking them would allow locks on different inodes.
func Lock(path string) (*os.File, error) {
	if _, err := Inspect(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = tryLock(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("another deployment process holds %s: %w", path, err)
	}
	return f, nil
}

// Directory guards detect a directory replaced at the same pathname.
type Directory struct {
	Path   string `json:"path"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mode   uint32 `json:"mode"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
}

func InspectDirectory(path string) (Directory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Directory{}, fmt.Errorf("directory path must be absolute and clean: %s", path)
	}
	if err := CheckParents(filepath.Join(path, ".probe")); err != nil {
		return Directory{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Directory{}, err
	}
	if err := checkExtendedMetadata(path); err != nil {
		return Directory{}, err
	}
	device, inode, err := directoryIdentity(info)
	if err != nil {
		return Directory{}, err
	}
	uid, gid, err := fileOwner(info)
	return Directory{path, device, inode, uint32(info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)), uid, gid}, err
}

func SyncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	err = f.Sync()
	return errors.Join(err, f.Close())
}

// PrivateDir creates one directory under an existing, checked parent. Existing
// state directories must already have the expected owner and private mode.
func PrivateDir(path string) error {
	if err := CheckParents(path); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	if _, err := InspectDirectory(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	uid, _, err := fileOwner(info)
	if err != nil {
		return err
	}
	if uid != os.Geteuid() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("state directory must be owned by the executing user with mode 0700: %s", path)
	}
	return SyncDir(filepath.Dir(path))
}

func ReadPrivate(path string) ([]byte, error) {
	info, err := Inspect(path)
	if err != nil {
		return nil, err
	}
	if !info.Exists || info.Mode != 0600 || info.UID != os.Geteuid() {
		return nil, fmt.Errorf("private state file missing or has unsafe ownership or permissions: %s", path)
	}
	return os.ReadFile(path)
}
