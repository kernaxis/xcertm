package update

import (
	"fmt"
	"os"
	"syscall"
)

func lockBinary(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open update lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err == nil {
		err = safeFile(info)
	}
	if err == nil {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot acquire update lock (another update may be running): %w", err)
	}
	return f, nil
}

func safeFile(info os.FileInfo) error {
	stat := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("file must be regular, owned by the executing user and not group/world writable")
	}
	return nil
}

func safeDirectory(info os.FileInfo) error {
	stat := info.Sys().(*syscall.Stat_t)
	root, err := os.Stat("/")
	if err != nil {
		return err
	}
	// The filesystem root owner can be remapped in an unprivileged container.
	rootUID := root.Sys().(*syscall.Stat_t).Uid
	if !info.IsDir() || (stat.Uid != rootUID && int(stat.Uid) != os.Geteuid()) || (info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
		return fmt.Errorf("directory has unsafe ownership or permissions")
	}
	return nil
}

func preserveOwner(file *os.File, original os.FileInfo) error {
	stat := original.Sys().(*syscall.Stat_t)
	return file.Chown(int(stat.Uid), int(stat.Gid))
}
