package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var noticeNames = []string{"LICENSE", "THIRD_PARTY_NOTICES.md", "THIRD_PARTY_LICENSES.txt"}

// Executable resolves symlinks so updates replace the running installation.
func Executable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}

// Install preserves the existing binary until a verified replacement is ready.
func (c *Client) Install(ctx context.Context, release Release, executable string) error {
	if !versionPattern.MatchString(release.Version) || strings.Contains(release.Version, "-") {
		return fmt.Errorf("update requires a stable release version")
	}
	path, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := checkParents(parent); err != nil {
		return fmt.Errorf("unsafe installation path: %w", err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := safeFile(before); err != nil {
		return fmt.Errorf("cannot update %s: %w; use the installation owner (sudo for a system installation)", path, err)
	}
	lock, err := lockBinary(filepath.Join(parent, ".xcertm-update.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	stage, err := os.MkdirTemp(parent, ".xcertm-update-")
	if err != nil {
		return fmt.Errorf("cannot write installation directory; use sudo for a system installation: %w", err)
	}
	defer os.RemoveAll(stage)
	checksumBody, err := c.get(ctx, release.checksumURL)
	if err != nil {
		return err
	}
	checksums, err := readLimited(checksumBody, 64<<10)
	checksumBody.Close()
	if err != nil {
		return err
	}
	expected, err := archiveChecksum(checksums, release.ArchiveName)
	if err != nil {
		return err
	}
	body, err := c.get(ctx, release.archiveURL)
	if err != nil {
		return err
	}
	defer body.Close()
	archive, err := os.CreateTemp(stage, "archive-")
	if err != nil {
		return err
	}
	defer archive.Close()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(archive, hash), io.LimitReader(body, (64<<20)+1))
	if err != nil {
		return err
	}
	if n > 64<<20 {
		return fmt.Errorf("release archive exceeds size limit")
	}
	if !bytes.Equal(hash.Sum(nil), expected) {
		return fmt.Errorf("release archive SHA-256 mismatch; installed binary was not changed")
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := extract(archive, stage); err != nil {
		return err
	}
	binary := filepath.Join(stage, "xcertm")
	file, err := os.OpenFile(binary, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	err = preserveOwner(file, before)
	if err == nil {
		err = file.Chmod(before.Mode().Perm())
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := verifyBinary(ctx, binary, release.Version); err != nil {
		return err
	}
	if err := publishNotices(stage, path, release.Version); err != nil {
		return fmt.Errorf("cannot install release notices: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(before, current) || before.Mode() != current.Mode() || before.Size() != current.Size() || !before.ModTime().Equal(current.ModTime()) {
		return fmt.Errorf("installed binary changed during update; retry")
	}
	if err := os.Rename(binary, path); err != nil {
		return fmt.Errorf("cannot replace installed binary: %w", err)
	}
	if err := syncDir(parent); err != nil {
		return fmt.Errorf("binary replaced, but installation directory sync failed: %w; check xcertm --version", err)
	}
	return nil
}

func archiveChecksum(data []byte, name string) ([]byte, error) {
	var checksum []byte
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != name {
			continue
		}
		if checksum != nil {
			return nil, fmt.Errorf("duplicate checksum for %s", name)
		}
		var err error
		checksum, err = hex.DecodeString(fields[0])
		if err != nil || len(checksum) != sha256.Size {
			return nil, fmt.Errorf("invalid SHA-256 checksum for %s", name)
		}
	}
	if checksum == nil {
		return nil, fmt.Errorf("checksum missing for %s", name)
	}
	return checksum, nil
}

func extract(archive io.Reader, stage string) error {
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return fmt.Errorf("invalid release archive: %w", err)
	}
	defer gz.Close()
	// Bound decompression, including archive members that are not installed.
	limited := &io.LimitedReader{R: gz, N: 96 << 20}
	reader := tar.NewReader(limited)
	wanted := map[string]bool{"xcertm": false}
	for _, name := range noticeNames {
		wanted[name] = false
	}
	for {
		header, err := reader.Next()
		if err == io.EOF && limited.N > 0 {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid or oversized release archive: %w", err)
		}
		found, ok := wanted[header.Name]
		if !ok {
			continue
		}
		if found || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > 64<<20 || (header.Name != "xcertm" && header.Size > 8<<20) {
			return fmt.Errorf("invalid release member %q", header.Name)
		}
		wanted[header.Name] = true
		file, err := os.OpenFile(filepath.Join(stage, header.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = io.Copy(file, reader)
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if _, err := io.Copy(io.Discard, limited); err != nil {
		return fmt.Errorf("invalid compressed release archive: %w", err)
	}
	if limited.N == 0 {
		return fmt.Errorf("release archive exceeds decompression limit")
	}
	for name, found := range wanted {
		if !found {
			return fmt.Errorf("release archive is missing %s", name)
		}
	}
	return nil
}

type versionOutput struct{ bytes.Buffer }

func (b *versionOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 512 {
		return 0, fmt.Errorf("unexpected version output")
	}
	return b.Buffer.Write(p)
}

func verifyBinary(ctx context.Context, path, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, "--version")
	var output versionOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return fmt.Errorf("replacement binary cannot run on this system: %w", err)
	}
	if strings.TrimSpace(output.String()) != "xcertm version "+version {
		return fmt.Errorf("replacement binary version does not match release %s", version)
	}
	return nil
}

func checkParents(path string) error {
	for {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if err := safeDirectory(info); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		parent := filepath.Dir(path)
		if path == parent {
			return nil
		}
		path = parent
	}
}

func publishNotices(stage, executable, version string) error {
	root := filepath.Join(filepath.Dir(filepath.Dir(executable)), "share", "doc", "xcertm")
	// Check every existing ancestor before creating anything through it.
	ancestor := root
	var missing []string
	for {
		_, err := os.Lstat(ancestor)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return err
		}
		missing = append(missing, ancestor)
		ancestor = filepath.Dir(ancestor)
	}
	if err := checkParents(ancestor); err != nil {
		return err
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.Mkdir(missing[i], 0755); err != nil {
			return err
		}
		// Keep public notices accessible even with a private process umask.
		if err := os.Chmod(missing[i], 0755); err != nil {
			return err
		}
		if err := syncDir(filepath.Dir(missing[i])); err != nil {
			return err
		}
	}
	if err := checkParents(root); err != nil {
		return err
	}
	target := filepath.Join(root, version)
	if _, err := os.Lstat(target); err == nil {
		// An earlier attempt may have installed notices before binary replacement.
		if err := checkParents(target); err != nil {
			return err
		}
		for _, name := range noticeNames {
			info, err := os.Lstat(filepath.Join(target, name))
			if err != nil {
				return fmt.Errorf("invalid existing release notices")
			}
			if err := safeFile(info); err != nil {
				return fmt.Errorf("unsafe existing release notices: %w", err)
			}
			a, err := os.ReadFile(filepath.Join(target, name))
			if err != nil {
				return err
			}
			b, err := os.ReadFile(filepath.Join(stage, name))
			if err != nil || !bytes.Equal(a, b) {
				return fmt.Errorf("existing release notices differ")
			}
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	temp, err := os.MkdirTemp(root, ".notices-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	for _, name := range noticeNames {
		data, err := os.ReadFile(filepath.Join(stage, name))
		if err != nil {
			return err
		}
		file, err := os.OpenFile(filepath.Join(temp, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		_, err = file.Write(data)
		if err == nil {
			err = file.Chmod(0644)
		}
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if err := os.Chmod(temp, 0755); err != nil {
		return err
	}
	if err := syncDir(temp); err != nil {
		return err
	}
	if err := os.Rename(temp, target); err != nil {
		return err
	}
	return syncDir(root)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
