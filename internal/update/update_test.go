//go:build linux

package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type member struct {
	name string
	data string
	kind byte
}

func releaseMembers() []member {
	return []member{
		{"xcertm", "#!/bin/sh\nprintf 'xcertm version v0.2.0\\n'\n", tar.TypeReg},
		{"LICENSE", "test license\n", tar.TypeReg},
		{"THIRD_PARTY_NOTICES.md", "test notices\n", tar.TypeReg},
		{"THIRD_PARTY_LICENSES.txt", "test inventory\n", tar.TypeReg},
	}
}

func makeArchive(t *testing.T, members []member) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gz)
	for _, m := range members {
		size := int64(len(m.data))
		if m.kind != tar.TypeReg {
			size = 0
		}
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Size: size, Mode: 0755, Typeflag: m.kind, Linkname: "../outside"}); err != nil {
			t.Fatal(err)
		}
		if size != 0 {
			if _, err := tw.Write([]byte(m.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

type fixture struct {
	archive   []byte
	checksums string
	metadata  string
	status    int
	onArchive func()
	client    *Client
	release   Release
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	arch := runtime.GOARCH
	if arch == "arm" {
		arch = "armv7"
	}
	f := &fixture{status: http.StatusOK}
	f.release = Release{Version: "v0.2.0", ArchiveName: "xcertm_0.2.0_linux_" + arch + ".tar.gz"}
	f.setArchive(t, releaseMembers())
	f.metadata = fmt.Sprintf(`{"tag_name":"v0.2.0","assets":[{"name":%q},{"name":"SHA256SUMS"}]}`, f.release.ArchiveName)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			w.WriteHeader(f.status)
			fmt.Fprint(w, f.metadata)
		case "/download/v0.2.0/SHA256SUMS":
			fmt.Fprint(w, f.checksums)
		case "/download/v0.2.0/" + f.release.ArchiveName:
			if f.onArchive != nil {
				f.onArchive()
			}
			w.Write(f.archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	f.client = &Client{http: server.Client(), latestURL: server.URL + "/latest", downloadBase: server.URL + "/download/"}
	f.release.archiveURL = server.URL + "/download/v0.2.0/" + f.release.ArchiveName
	f.release.checksumURL = server.URL + "/download/v0.2.0/SHA256SUMS"
	return f
}

func (f *fixture) setArchive(t *testing.T, members []member) {
	f.archive = makeArchive(t, members)
	f.checksums = fmt.Sprintf("%x  %s\n", sha256.Sum256(f.archive), f.release.ArchiveName)
}

func installedBinary(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "xcertm")
	if err := os.WriteFile(path, []byte("old installed binary\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCompare(t *testing.T) {
	for _, tc := range []struct {
		current, target string
		want            int
		known           bool
	}{
		{"v0.2.0", "v0.2.0", 0, true},
		{"v0.1.0", "v0.2.0", -1, true},
		{"v1.0.0", "v0.2.0", 1, true},
		{"v0.10.0", "v0.9.0", 1, true},
		{"v0.2.0-rc.1", "v0.2.0", -1, true},
		{"v0.2.0", "v0.2.0-rc.1", 1, true},
		{"v0.2.0-rc.10", "v0.2.0-rc.2", 1, true},
		{"dev", "v0.2.0", 0, false},
		{"v00.2.0", "v0.2.0", 0, false},
	} {
		t.Run(tc.current+"/"+tc.target, func(t *testing.T) {
			got, known := Compare(tc.current, tc.target)
			if got != tc.want || known != tc.known {
				t.Fatalf("Compare = (%d, %v), want (%d, %v)", got, known, tc.want, tc.known)
			}
		})
	}
}

func TestLatest(t *testing.T) {
	for _, name := range []string{"stable", "draft", "prerelease", "rc", "invalid-version", "missing-asset", "duplicate-asset", "invalid-json", "not-found", "rate-limit"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			var metadata map[string]any
			if err := json.Unmarshal([]byte(f.metadata), &metadata); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "draft":
				metadata["draft"] = true
			case "prerelease":
				metadata["prerelease"] = true
			case "rc":
				metadata["tag_name"] = "v0.2.0-rc.1"
			case "invalid-version":
				metadata["tag_name"] = "../outside"
			case "missing-asset":
				metadata["assets"] = []any{}
			case "duplicate-asset":
				assets := metadata["assets"].([]any)
				metadata["assets"] = append(assets, assets[0])
			case "not-found":
				f.status = http.StatusNotFound
			case "rate-limit":
				f.status = http.StatusForbidden
			}
			data, err := json.Marshal(metadata)
			if err != nil {
				t.Fatal(err)
			}
			f.metadata = string(data)
			if name == "invalid-json" {
				f.metadata = "not JSON"
			}
			release, err := f.client.Latest(context.Background())
			if name == "stable" {
				if err != nil || release != f.release {
					t.Fatalf("Latest = %+v, %v", release, err)
				}
			} else if err == nil {
				t.Fatal("invalid release accepted")
			}
		})
	}
}

func TestInstallAndRetry(t *testing.T) {
	f := newFixture(t)
	path := installedBinary(t)
	link := filepath.Join(filepath.Dir(path), "alias")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := f.client.Install(context.Background(), f.release, link); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != releaseMembers()[0].data {
		t.Fatalf("replacement missing: %v", err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("executable symlink was replaced")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("executable permissions changed")
	}
	root := filepath.Dir(filepath.Dir(path))
	for _, name := range noticeNames {
		if _, err := os.Stat(filepath.Join(root, "share/doc/xcertm/v0.2.0", name)); err != nil {
			t.Fatal("release notices missing", err)
		}
	}
	stages, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".xcertm-update-*"))
	if err != nil || len(stages) != 0 {
		t.Fatal("temporary update material remains")
	}
}

func TestFailedInstallPreservesBinary(t *testing.T) {
	for _, name := range []string{"checksum-mismatch", "checksum-missing", "checksum-duplicate", "checksum-invalid", "missing-binary", "missing-notice", "duplicate-binary", "symlink-binary", "bad-version", "invalid-archive", "changed-binary", "cancelled", "unsafe-permissions", "unsafe-notices"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			path := installedBinary(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			members := releaseMembers()
			switch name {
			case "checksum-mismatch":
				f.archive = append(f.archive, 'x')
			case "checksum-missing":
				f.checksums = ""
			case "checksum-duplicate":
				f.checksums += f.checksums
			case "checksum-invalid":
				f.checksums = "bad  " + f.release.ArchiveName
			case "missing-binary":
				f.setArchive(t, members[1:])
			case "missing-notice":
				f.setArchive(t, members[:3])
			case "duplicate-binary":
				f.setArchive(t, append(members, members[0]))
			case "symlink-binary":
				members[0].kind = tar.TypeSymlink
				f.setArchive(t, members)
			case "bad-version":
				members[0].data = "#!/bin/sh\necho unexpected\n"
				f.setArchive(t, members)
			case "invalid-archive":
				f.archive = []byte("not an archive")
				f.checksums = fmt.Sprintf("%x  %s\n", sha256.Sum256(f.archive), f.release.ArchiveName)
			case "changed-binary":
				f.onArchive = func() {
					if err := os.Rename(path, path+".old"); err != nil {
						panic(err)
					}
					if err := os.WriteFile(path, []byte("external replacement\n"), 0755); err != nil {
						panic(err)
					}
				}
			case "cancelled":
				cancel()
			case "unsafe-permissions":
				if err := os.Chmod(path, 0777); err != nil {
					t.Fatal(err)
				}
			case "unsafe-notices":
				root := filepath.Dir(filepath.Dir(path))
				if err := os.Symlink(t.TempDir(), filepath.Join(root, "share")); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.client.Install(ctx, f.release, path); err == nil {
				t.Fatal("invalid installation succeeded")
			}
			data, err := os.ReadFile(path)
			want := "old installed binary\n"
			if name == "changed-binary" {
				want = "external replacement\n"
			}
			if err != nil || string(data) != want {
				t.Fatalf("existing binary was altered: %q, %v", data, err)
			}
		})
	}
}

func TestUpdateLockAndArchivePaths(t *testing.T) {
	f := newFixture(t)
	path := installedBinary(t)
	lock, err := lockBinary(filepath.Join(filepath.Dir(path), ".xcertm-update.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.client.Install(context.Background(), f.release, path); err == nil {
		t.Fatal("concurrent update bypassed lock")
	}
	lock.Close()
	f.setArchive(t, append(releaseMembers(), member{"../outside", "must not escape", tar.TypeReg}))
	if err := f.client.Install(context.Background(), f.release, path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "outside")); !os.IsNotExist(err) {
		t.Fatal("archive path escaped staging")
	}
}

func TestRedirectAndReadLimits(t *testing.T) {
	client := NewClient()
	request, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err := client.http.CheckRedirect(request, nil); err == nil {
		t.Fatal("HTTPS downgrade accepted")
	}
	if _, err := readLimited(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("oversized response accepted")
	}
}

func TestUpdateRunningExecutable(t *testing.T) {
	if base := os.Getenv("XCERTM_TEST_SELF_UPDATE"); base != "" {
		client := &Client{http: http.DefaultClient, latestURL: base + "/latest", downloadBase: base + "/download/"}
		release, err := client.Latest(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		path, err := Executable()
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Install(context.Background(), release, path); err != nil {
			t.Fatal(err)
		}
		return
	}
	f := newFixture(t)
	path := installedBinary(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(path, "-test.run=^TestUpdateRunningExecutable$")
	command.Env = append(os.Environ(), "XCERTM_TEST_SELF_UPDATE="+strings.TrimSuffix(f.client.latestURL, "/latest"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("running binary replacement failed: %v\n%s", err, output)
	}
	output, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil || string(output) != "xcertm version v0.2.0\n" {
		t.Fatalf("replacement cannot run: %v, %q", err, output)
	}
}
