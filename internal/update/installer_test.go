//go:build linux

package update

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The curl shim serves GitHub-shaped requests from a local fixture server.
// No installer option or environment variable can override production URLs.
func TestInstallerCurlHelper(t *testing.T) {
	if os.Getenv("XCERTM_TEST_CURL") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	args = args[1:]
	var output, url string
	head := false
	for len(args) > 0 {
		switch args[0] {
		case "--output":
			output, args = args[1], args[2:]
		case "--proto", "--proto-redir", "--connect-timeout", "--max-time", "--max-filesize", "--write-out":
			args = args[2:]
		case "--head":
			head, args = true, args[1:]
		default:
			if strings.HasPrefix(args[0], "https://") {
				url = args[0]
			}
			args = args[1:]
		}
	}
	response, err := http.Get(os.Getenv("XCERTM_TEST_SERVER") + strings.TrimPrefix(url, repository))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		os.Exit(22)
	}
	if head {
		fmt.Print(repository + "/releases/tag/v0.2.0")
		os.Exit(0)
	}
	file, err := os.Create(output)
	if err != nil {
		os.Exit(1)
	}
	_, err = io.Copy(file, response.Body)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestInstaller(t *testing.T) {
	script, err := filepath.Abs("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"latest", "pinned", "user-default", "spaces", "arm64", "armv7", "386", "checksum", "missing-notices", "already-installed", "unsupported-arm", "unpublished", "invalid-version", "unsafe-directory"} {
		t.Run(name, func(t *testing.T) {
			if name == "user-default" && os.Geteuid() == 0 {
				t.Skip("user installation requires a non-root test process")
			}
			arch, suffix := "x86_64", "amd64"
			switch name {
			case "arm64":
				arch, suffix = "aarch64", "arm64"
			case "armv7":
				arch, suffix = "armv7l", "armv7"
			case "386":
				arch, suffix = "i686", "386"
			case "unsupported-arm":
				arch = "armv6l"
			}
			members := releaseMembers()
			if name == "missing-notices" {
				members = members[:3]
			}
			archive := makeArchive(t, members)
			archiveName := "xcertm_0.2.0_linux_" + suffix + ".tar.gz"
			checksum := fmt.Sprintf("%x  %s\n", sha256.Sum256(archive), archiveName)
			if name == "checksum" {
				checksum = strings.Repeat("0", 64) + "  " + archiveName + "\n"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/releases/latest":
					if name == "unpublished" {
						http.NotFound(w, r)
					}
				case "/releases/download/v0.2.0/SHA256SUMS":
					fmt.Fprint(w, checksum)
				case "/releases/download/v0.2.0/" + archiveName:
					w.Write(archive)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			root := t.TempDir()
			bin := filepath.Join(root, "prefix", "bin")
			if name == "user-default" {
				bin = filepath.Join(root, ".local", "bin")
			}
			if name == "spaces" {
				bin = filepath.Join(root, "prefix with spaces", "bin")
			}
			shims := filepath.Join(root, "tools")
			if err := os.Mkdir(shims, 0700); err != nil {
				t.Fatal(err)
			}
			writeExecutable := func(path, text string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(text), 0700); err != nil {
					t.Fatal(err)
				}
			}
			// Executable paths are passed as arguments, not interpolated shell code.
			writeExecutable(filepath.Join(shims, "curl"), "#!/bin/sh\nexec \"$XCERTM_TEST_EXECUTABLE\" -test.run='^TestInstallerCurlHelper$' -- \"$@\"\n")
			writeExecutable(filepath.Join(shims, "uname"), "#!/bin/sh\ncase \"$1\" in -s) echo Linux;; -m) echo \"$XCERTM_TEST_ARCH\";; esac\n")
			if name == "already-installed" || name == "unsafe-directory" {
				if err := os.MkdirAll(bin, 0700); err != nil {
					t.Fatal(err)
				}
				if name == "already-installed" {
					writeExecutable(filepath.Join(bin, "xcertm"), "keep existing binary")
				} else if err := os.Chmod(bin, 0777); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{script, "--bin-dir", bin}
			if name == "user-default" {
				args = []string{script}
			}
			if name == "pinned" {
				args = append(args, "--version", "v0.2.0")
			}
			if name == "invalid-version" {
				args = append(args, "--version", "../unsafe")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			shell := os.Getenv("XCERTM_TEST_SHELL")
			if shell == "" {
				shell = "sh"
			}
			// BusyBox's standalone ash can prefer its uname applet over PATH.
			// A shell function keeps architecture fixtures effective for both shells.
			invocation := append([]string{"-c", `uname() { "$XCERTM_TEST_UNAME" "$@"; }; installer_script=$1; shift; . "$installer_script"`, "installer-test"}, args...)
			command := exec.CommandContext(ctx, shell, invocation...)
			command.Env = append(os.Environ(), "HOME="+root, "PATH="+shims+":"+os.Getenv("PATH"), "XCERTM_TEST_CURL=1", "XCERTM_TEST_SERVER="+server.URL, "XCERTM_TEST_EXECUTABLE="+executable, "XCERTM_TEST_ARCH="+arch, "XCERTM_TEST_UNAME="+filepath.Join(shims, "uname"))
			output, err := command.CombinedOutput()
			success := name == "latest" || name == "pinned" || name == "user-default" || name == "spaces" || name == "arm64" || name == "armv7" || name == "386"
			if (err == nil) != success {
				t.Fatalf("installer error = %v\n%s", err, output)
			}
			binary := filepath.Join(bin, "xcertm")
			if success {
				data, err := os.ReadFile(binary)
				if err != nil || string(data) != releaseMembers()[0].data {
					t.Fatal("installed binary does not match release")
				}
				for _, notice := range noticeNames {
					if _, err := os.Stat(filepath.Join(filepath.Dir(bin), "share/doc/xcertm/v0.2.0", notice)); err != nil {
						t.Fatal("release notice missing", err)
					}
				}
			} else if name == "already-installed" {
				data, _ := os.ReadFile(binary)
				if string(data) != "keep existing binary" {
					t.Fatal("installer overwrote an existing installation")
				}
			} else if _, err := os.Stat(binary); !os.IsNotExist(err) {
				t.Fatal("failed installation published a binary")
			}
			stages, err := filepath.Glob(filepath.Join(bin, ".xcertm-install*"))
			if err != nil || len(stages) != 0 {
				t.Fatal("installer left staging or a lock", stages)
			}
		})
	}
}
