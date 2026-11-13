//go:build linux

package deploy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernaxis/xcertm/internal/deploy/filesystem"
)

func TestFilesystemDeploymentAndRenewedGeneration(t *testing.T) {
	root, dir := privateTempDir(t), t.TempDir()
	write(t, filepath.Join(dir, "unrelated"), []byte("keep"), 0644)
	s, err := filesystem.Open(root, filesystem.Config{DestinationID: "web", Directory: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	g1 := generation(t, "g1", false)
	deployOK(t, s, "op1", g1)
	checkPublished(t, dir, g1, true)
	before, _ := os.Stat(filepath.Join(dir, "privkey.pem"))
	deployOK(t, s, "op1", g1)
	after, _ := os.Stat(filepath.Join(dir, "privkey.pem"))
	if !os.SameFile(before, after) {
		t.Fatal("idempotent retry replaced the key")
	}
	g2 := generation(t, "g2", false)
	deployOK(t, s, "op2", g2)
	checkPublished(t, dir, g2, true)
	if string(read(t, filepath.Join(dir, "unrelated"))) != "keep" {
		t.Fatal("unrelated file changed")
	}
	for _, name := range []string{"privkey.pem", "fullchain.pem"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("unsafe output permissions")
		}
	}
	j := journal(t, root, "web")
	if !j.Completed() || j.GenerationID != "g2" {
		t.Fatal("latest receipt missing")
	}
	if j.GenerationSource != g2.Provenance().Source || j.GenerationReference != g2.Provenance().Reference || !j.ValidatedAt.Equal(g2.ValidatedAt()) {
		t.Fatal("generation provenance was not retained")
	}
	stages, err := filepath.Glob(filepath.Join(journalDir(root, "web"), "operation-*"))
	if err != nil || len(stages) != 2 {
		t.Fatal("previous generation material was discarded")
	}
	for _, stage := range stages {
		info, err := os.Stat(stage)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("unsafe stage directory")
		}
		info, err = os.Stat(filepath.Join(stage, "file-0"))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("unsafe staged key")
		}
	}
}

func TestFilesystemRecoversEveryBoundary(t *testing.T) {
	for _, point := range []string{"prepared", "file-0", "file-1", "group-files"} {
		t.Run(point, func(t *testing.T) {
			root, dir := privateTempDir(t), t.TempDir()
			config := filesystem.Config{DestinationID: "web", Directory: dir}
			s, err := filesystem.Open(root, config)
			if err != nil {
				t.Fatal(err)
			}
			g := generation(t, "g1", false)
			s.After = func(at string) error {
				if at == point {
					return errors.New("interrupted")
				}
				return nil
			}
			if _, err := s.Deploy(context.Background(), "op1", g); err == nil {
				t.Fatal("boundary not reached")
			}
			s.Close()
			// A new coordinator has neither the generation nor in-memory progress.
			restarted, err := filesystem.Open(root, config)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			r, err := restarted.Recover(context.Background())
			if err != nil || !r.Completed || r.OperationID != "op1" {
				t.Fatalf("recovery failed: %v", err)
			}
			checkPublished(t, dir, g, true)
			if _, err := os.Stat(filepath.Join(dir, ".xcertm-pending")); !os.IsNotExist(err) {
				t.Fatal("resource remains claimed")
			}
		})
	}
}

func TestFilesystemConflictPreflight(t *testing.T) {
	for _, kind := range []string{"content", "mode", "stage", "directory", "journal", "metadata"} {
		t.Run(kind, func(t *testing.T) {
			root, dir := privateTempDir(t), t.TempDir()
			config := filesystem.Config{DestinationID: "web", Directory: dir}
			s, err := filesystem.Open(root, config)
			if err != nil {
				t.Fatal(err)
			}
			g := generation(t, "g1", false)
			s.After = func(at string) error {
				if at == "prepared" {
					return errors.New("interrupted")
				}
				return nil
			}
			if _, err := s.Deploy(context.Background(), "op1", g); err == nil {
				t.Fatal("expected interruption")
			}
			s.Close()
			j := journal(t, root, "web")
			switch kind {
			case "content":
				write(t, filepath.Join(dir, "fullchain.pem"), []byte("external"), 0600)
			case "mode":
				m := read(t, filepath.Join(journalDir(root, "web"), j.Stage, "file-1"))
				write(t, filepath.Join(dir, "fullchain.pem"), m, 0644)
			case "stage":
				write(t, filepath.Join(journalDir(root, "web"), j.Stage, "file-1"), []byte("damaged"), 0600)
			case "directory":
				if err := os.Rename(dir, dir+"-old"); err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(dir + "-old")
				mkdir(t, dir)
			case "journal":
				j.Groups[0].Files = []int{100, 1}
				data, _ := json.Marshal(j)
				write(t, filepath.Join(journalDir(root, "web"), "current.json"), data, 0600)
			case "metadata":
				j.Files[0].After.UID++
				data, _ := json.Marshal(j)
				write(t, filepath.Join(journalDir(root, "web"), "current.json"), data, 0600)
			}
			restarted, err := filesystem.Open(root, config)
			if err == nil {
				defer restarted.Close()
				_, err = restarted.Recover(context.Background())
			}
			if err == nil {
				t.Fatal("conflict was ignored")
			}
			if _, err := os.Stat(filepath.Join(dir, "privkey.pem")); !os.IsNotExist(err) {
				t.Fatal("key written before conflict preflight")
			}
		})
	}
}

func TestFilesystemDetectsDriftAndRejectsUntrackedFiles(t *testing.T) {
	root, dir := privateTempDir(t), t.TempDir()
	config := filesystem.Config{DestinationID: "web", Directory: dir}
	write(t, filepath.Join(dir, "fullchain.pem"), []byte("operator file"), 0600)
	s, err := filesystem.Open(root, config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	g := generation(t, "g1", false)
	if _, err := s.Deploy(context.Background(), "op1", g); err == nil || !strings.Contains(err.Error(), "untracked") {
		t.Fatal("untracked file was accepted")
	}
	if err := os.Remove(filepath.Join(dir, "fullchain.pem")); err != nil {
		t.Fatal(err)
	}
	deployOK(t, s, "op1", g)
	write(t, filepath.Join(dir, "fullchain.pem"), []byte("operator change"), 0600)
	if _, err := s.Deploy(context.Background(), "op2", generation(t, "g2", false)); err == nil {
		t.Fatal("new generation overwrote drift")
	}
	if string(read(t, filepath.Join(dir, "fullchain.pem"))) != "operator change" {
		t.Fatal("drift was overwritten")
	}
}

func TestFilesystemLocksPendingOwnershipAndIndependentTargets(t *testing.T) {
	root, a, b := privateTempDir(t), t.TempDir(), t.TempDir()
	config := filesystem.Config{DestinationID: "a", Directory: a}
	first, err := filesystem.Open(root, config)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := filesystem.Open(privateTempDir(t), filesystem.Config{DestinationID: "other", Directory: a}); err == nil {
		other.Close()
		t.Fatal("resource lock bypassed")
	}
	second, err := filesystem.Open(root, filesystem.Config{DestinationID: "b", Directory: b})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	g := generation(t, "g1", false)
	deployOK(t, second, "op-b", g)
	first.After = func(at string) error {
		if at == "file-0" {
			return errors.New("interrupted")
		}
		return nil
	}
	if _, err := first.Deploy(context.Background(), "op-a", g); err == nil {
		t.Fatal("expected interruption")
	}
	first.Close()
	other, err := filesystem.Open(privateTempDir(t), filesystem.Config{DestinationID: "other", Directory: a})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Deploy(context.Background(), "other-op", g); err == nil {
		t.Fatal("pending file ownership bypassed")
	}
	other.Close()
	if !journal(t, root, "b").Completed() || journal(t, root, "a").Completed() {
		t.Fatal("destinations lost independent results")
	}
	restarted, err := filesystem.Open(root, config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if _, err := restarted.Deploy(context.Background(), "different-op", g); err == nil {
		t.Fatal("new operation replaced pending work")
	}
	if _, err := restarted.Deploy(context.Background(), "op-a", generation(t, "g1", false)); err == nil {
		t.Fatal("operation ID accepted different key material")
	}
	if _, err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	checkPublished(t, a, g, true)
	checkPublished(t, b, g, true)
}

func TestFilesystemRejectsRetargetSymlinksAndBadNames(t *testing.T) {
	for _, kind := range []string{"retarget", "symlink", "filename", "same-name"} {
		t.Run(kind, func(t *testing.T) {
			root, dir := privateTempDir(t), t.TempDir()
			config := filesystem.Config{DestinationID: "a", Directory: dir}
			if kind == "filename" {
				config.KeyFile = "../key"
			}
			if kind == "same-name" {
				config.KeyFile = "fullchain.pem"
			}
			if kind == "symlink" {
				if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), filepath.Join(dir, "privkey.pem")); err != nil {
					t.Fatal(err)
				}
			}
			s, err := filesystem.Open(root, config)
			if err == nil {
				if kind == "retarget" {
					s.After = func(at string) error {
						if at == "prepared" {
							return errors.New("interrupted")
						}
						return nil
					}
					_, err = s.Deploy(context.Background(), "op", generation(t, "g1", false))
					s.Close()
					if err == nil {
						t.Fatal("expected interruption before testing destination changes")
					}
					config.Directory = t.TempDir()
					s, err = filesystem.Open(root, config)
				} else {
					_, err = s.Deploy(context.Background(), "op", generation(t, "g1", false))
				}
				if s != nil {
					s.Close()
				}
			}
			if err == nil {
				t.Fatal("unsafe destination accepted")
			}
		})
	}
}

func TestFilesystemMissingJournalAndCancellation(t *testing.T) {
	root, dir := privateTempDir(t), t.TempDir()
	s, err := filesystem.Open(root, filesystem.Config{DestinationID: "a", Directory: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g := generation(t, "g1", false)
	if _, err := s.Deploy(ctx, "op", g); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	s.After = func(at string) error {
		if at == "prepared" {
			return errors.New("interrupted")
		}
		return nil
	}
	if _, err := s.Deploy(context.Background(), "op", g); err == nil {
		t.Fatal("expected interruption")
	}
	if err := os.Remove(filepath.Join(journalDir(root, "a"), "current.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Recover(context.Background()); err == nil || !strings.Contains(err.Error(), "without its journal") {
		t.Fatal("missing journal ignored")
	}
	if _, err := s.Republish(context.Background(), "forced", g); err == nil {
		t.Fatal("force bypassed a marker without its journal")
	}
}

func TestFilesystemForceCanAdoptSafeOutputsButRejectsSymlinksAndUnsafeKeyMode(t *testing.T) {
	for _, kind := range []string{"safe", "symlink", "unsafe-key-mode"} {
		t.Run(kind, func(t *testing.T) {
			root, dir := privateTempDir(t), t.TempDir()
			keyPath := filepath.Join(dir, "privkey.pem")
			if kind == "symlink" {
				if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), keyPath); err != nil {
					t.Fatal(err)
				}
			} else {
				mode := os.FileMode(0600)
				if kind == "unsafe-key-mode" {
					mode = 0644
				}
				write(t, keyPath, []byte("external key"), mode)
			}
			write(t, filepath.Join(dir, "fullchain.pem"), []byte("external certificate"), 0600)
			s, err := filesystem.Open(root, filesystem.Config{DestinationID: "web", Directory: dir})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			g := generation(t, "g1", false)
			r, err := s.Republish(context.Background(), "forced", g)
			if kind == "safe" {
				if err != nil || !r.Completed {
					t.Fatalf("safe adoption failed: %+v, %v", r, err)
				}
				checkPublished(t, dir, g, true)
			} else if err == nil {
				t.Fatal("force bypassed path or key-metadata safety")
			}
		})
	}
}

func TestFilesystemCrashReleasesLocks(t *testing.T) {
	root, dir := privateTempDir(t), t.TempDir()
	config := filesystem.Config{DestinationID: "crash", Directory: dir}
	s, err := filesystem.Open(root, config)
	if err != nil {
		t.Fatal(err)
	}
	g := generation(t, "g1", false)
	s.After = func(at string) error {
		if at == "prepared" {
			return errors.New("interrupted")
		}
		return nil
	}
	if _, err := s.Deploy(context.Background(), "op", g); err == nil {
		t.Fatal("expected interruption")
	}
	s.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFilesystemCrashHelper$")
	cmd.Env = append(os.Environ(), "XCERTM_CRASH_STATE="+root, "XCERTM_CRASH_TARGET="+dir)
	err = cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 77 {
		t.Fatalf("child did not reach crash boundary: %v", err)
	}
	restarted, err := filesystem.Open(root, config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if _, err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	checkPublished(t, dir, g, true)
	if !bytes.Equal(read(t, filepath.Join(dir, "privkey.pem")), read(t, filepath.Join(journalDir(root, "crash"), journal(t, root, "crash").Stage, "file-0"))) {
		t.Fatal("recovered key differs")
	}
}

func TestFilesystemCrashHelper(t *testing.T) {
	root := os.Getenv("XCERTM_CRASH_STATE")
	if root == "" {
		return
	}
	s, err := filesystem.Open(root, filesystem.Config{DestinationID: "crash", Directory: os.Getenv("XCERTM_CRASH_TARGET")})
	if err != nil {
		t.Fatal(err)
	}
	s.After = func(at string) error {
		if at == "file-0" {
			os.Exit(77)
		}
		return nil
	}
	_, err = s.Recover(context.Background())
	t.Fatalf("crash boundary not reached: %v", err)
}
