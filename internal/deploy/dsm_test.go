//go:build linux

package deploy_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernaxis/xcertm/internal/deploy/dsm"
)

type dsmLayout struct {
	root, state, archive, scriptDir string
	config                          dsm.Config
}

func newDSM(t *testing.T) dsmLayout {
	t.Helper()
	root := t.TempDir()
	archive := filepath.Join(root, "usr/syno/etc/certificate/_archive")
	scripts := filepath.Join(root, "usr/libexec/certificate.d")
	for _, dir := range []string{filepath.Join(archive, "ABC123"), filepath.Join(root, "usr/local/etc/certificate/system/svc1"), filepath.Join(root, "usr/syno/etc/certificate/system/svc2"), scripts} {
		mkdir(t, dir)
	}
	write(t, filepath.Join(archive, "INFO"), []byte(`{"ABC123":{"desc":"keep","services":[{"subscriber":"system","service":"svc1"},{"subscriber":"system","service":"svc2"}],"unknown_metadata":{"keep":true}}}`), 0600)
	write(t, filepath.Join(archive, "DEFAULT"), []byte("ABC123\n"), 0600)
	// A real script exercises exec, error propagation, and replay. It records
	// only synthetic service names and never prints or records key material.
	write(t, filepath.Join(scripts, "system"), []byte("#!/bin/sh\nbase=${0%/*}\nprintf '%s\\n' \"$1\" >> \"$base/calls\"\nif [ -f \"$base/fail-$1\" ]; then exit 9; fi\n"), 0700)
	return dsmLayout{root, privateTempDir(t), archive, scripts, dsm.Config{DestinationID: "nas", UseDefault: true, Root: root}}
}

func (l dsmLayout) dirs() []string {
	return []string{filepath.Join(l.archive, "ABC123"), filepath.Join(l.root, "usr/local/etc/certificate/system/svc1"), filepath.Join(l.root, "usr/syno/etc/certificate/system/svc2")}
}

func (l dsmLayout) calls(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(l.scriptDir, "calls")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return strings.Fields(string(read(t, path)))
}

func count(values []string, want string) int {
	n := 0
	for _, v := range values {
		if v == want {
			n++
		}
	}
	return n
}

func TestDSMDeployAndRecoverFailedService(t *testing.T) {
	l := newDSM(t)
	infoBefore := string(read(t, filepath.Join(l.archive, "INFO")))
	for _, dir := range l.dirs() {
		write(t, filepath.Join(dir, "chain.pem"), []byte("obsolete chain"), 0600)
	}
	write(t, filepath.Join(l.dirs()[1], "privkey.pem"), []byte("old synthetic key"), 0640)
	write(t, filepath.Join(l.scriptDir, "fail-svc2"), nil, 0600)
	s, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	g := generation(t, "g1", true)
	r, err := s.Deploy(context.Background(), "op1", g)
	if err == nil || r.Completed {
		t.Fatal("failed service reported success")
	}
	s.Close()
	for _, dir := range l.dirs() {
		checkPublished(t, dir, g, false)
		if _, err := os.Stat(filepath.Join(dir, "chain.pem")); !os.IsNotExist(err) {
			t.Fatal("obsolete chain was not removed")
		}
	}
	if other, err := dsm.Open(privateTempDir(t), l.config); err == nil {
		other.Close()
		t.Fatal("another state root bypassed pending DSM owner")
	}
	if err := os.Remove(filepath.Join(l.scriptDir, "fail-svc2")); err != nil {
		t.Fatal(err)
	}
	restarted, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	r, err = restarted.Recover(context.Background())
	if err != nil || !r.Completed {
		t.Fatalf("recovery failed: %v", err)
	}
	calls := l.calls(t)
	if count(calls, "svc1") != 1 || count(calls, "svc2") != 2 {
		t.Fatalf("unexpected activation history: %v", calls)
	}
	deployOK(t, restarted, "op1", g)
	if len(l.calls(t)) != len(calls) {
		t.Fatal("completed service activations replayed")
	}
	info, err := os.Stat(filepath.Join(l.dirs()[1], "privkey.pem"))
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatal("DSM service key permissions not preserved")
	}
	if string(read(t, filepath.Join(l.archive, "INFO"))) != infoBefore {
		t.Fatal("DSM metadata or unknown fields changed")
	}
}

func TestDSMRecoversEveryBoundary(t *testing.T) {
	points := []string{"prepared", "file-0", "file-1", "file-2", "file-3", "file-4", "file-5", "file-6", "file-7", "file-8", "file-9", "file-10", "file-11", "group-archive", "reload-system/svc1", "group-system/svc1", "reload-system/svc2", "group-system/svc2"}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			l := newDSM(t)
			s, err := dsm.Open(l.state, l.config)
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
			restarted, err := dsm.Open(l.state, l.config)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			r, err := restarted.Recover(context.Background())
			if err != nil || !r.Completed {
				t.Fatalf("recovery failed: %v", err)
			}
			for _, dir := range l.dirs() {
				checkPublished(t, dir, g, true)
			}
			for _, name := range []string{"svc1", "svc2"} {
				want := 1
				if point == "reload-system/"+name {
					want = 2
				}
				if count(l.calls(t), name) != want {
					t.Fatalf("%s activation count differs", name)
				}
			}
		})
	}
}

func TestDSMConfigurationAndContentConflicts(t *testing.T) {
	for _, kind := range []string{"default", "INFO", "service-content", "permissions", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			l := newDSM(t)
			s, err := dsm.Open(l.state, l.config)
			if err != nil {
				t.Fatal(err)
			}
			s.After = func(at string) error {
				if at == "prepared" {
					return errors.New("interrupted")
				}
				return nil
			}
			if _, err := s.Deploy(context.Background(), "op", generation(t, "g1", false)); err == nil {
				t.Fatal("expected interruption")
			}
			s.Close()
			switch kind {
			case "default":
				write(t, filepath.Join(l.archive, "DEFAULT"), []byte("DEF456"), 0600)
			case "INFO":
				write(t, filepath.Join(l.archive, "INFO"), []byte(`{"ABC123":{"desc":"changed","services":[{"subscriber":"system","service":"svc1"},{"subscriber":"system","service":"svc2"}]}}`), 0600)
			case "service-content":
				write(t, filepath.Join(l.dirs()[2], "cert.pem"), []byte("external"), 0600)
			case "permissions":
				write(t, filepath.Join(l.dirs()[2], "privkey.pem"), []byte("external"), 0644)
			case "symlink":
				if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), filepath.Join(l.dirs()[2], "privkey.pem")); err != nil {
					t.Fatal(err)
				}
			}
			restarted, err := dsm.Open(l.state, l.config)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			if _, err := restarted.Recover(context.Background()); err == nil {
				t.Fatal("external change ignored")
			}
			if _, err := os.Stat(filepath.Join(l.archive, "ABC123/privkey.pem")); !os.IsNotExist(err) {
				t.Fatal("archive changed before conflict preflight")
			}
			if len(l.calls(t)) != 0 {
				t.Fatal("service activated despite conflict")
			}
		})
	}
}

func TestDSMCertificateIDAndArchiveLock(t *testing.T) {
	l := newDSM(t)
	config := l.config
	config.UseDefault = false
	config.CertificateID = "ABC123"
	s, err := dsm.Open(l.state, config)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := os.Stat(filepath.Join(l.archive, ".xcertm.lock"))
	if err != nil || !lock.Mode().IsRegular() || lock.Mode().Perm() != 0600 {
		t.Fatalf("missing or unsafe XCertM archive lock: %v", err)
	}
	if second, err := dsm.Open(privateTempDir(t), l.config); err == nil {
		second.Close()
		t.Fatal("shared archive lock bypassed")
	}
	deployOK(t, s, "op", generation(t, "g1", false))
	s.Close()
	reopened, err := dsm.Open(l.state, config)
	if err != nil {
		t.Fatal("archive lock was not released", err)
	}
	defer reopened.Close()
}

func TestDSMDefaultTLSProfileAndMissingReloadScript(t *testing.T) {
	l := newDSM(t)
	mkdir(t, filepath.Join(l.root, "usr/syno/etc/certificate/system/default"))
	write(t, filepath.Join(l.archive, "INFO"), []byte(`{"ABC123":{"services":[{"subscriber":"system","service":"default"}]}}`), 0600)
	if err := os.Remove(filepath.Join(l.scriptDir, "system")); err != nil {
		t.Fatal(err)
	}
	s, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Deploy(context.Background(), "op", generation(t, "g1", false)); err == nil || !strings.Contains(err.Error(), "no DSM reload script") {
		t.Fatal("missing activation script reported success")
	}
	profile := filepath.Join(l.root, "usr/libexec/security-profile/tls-profile")
	mkdir(t, profile)
	write(t, filepath.Join(profile, "dsm.sh"), []byte("#!/bin/sh\nprintf 'default\\n' >> \"${0%/*}/calls\"\n"), 0700)
	if _, err := s.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(read(t, filepath.Join(profile, "calls")))) != "default" {
		t.Fatal("default TLS profile not called")
	}
}

func TestDSMRejectsUnsafePermissionsAndServicePaths(t *testing.T) {
	for _, kind := range []string{"key-permissions", "service-path", "missing-id"} {
		t.Run(kind, func(t *testing.T) {
			l := newDSM(t)
			switch kind {
			case "key-permissions":
				write(t, filepath.Join(l.archive, "ABC123/privkey.pem"), []byte("synthetic old key"), 0644)
			case "service-path":
				write(t, filepath.Join(l.archive, "INFO"), []byte(`{"ABC123":{"services":[{"subscriber":"../escape","service":"svc1"}]}}`), 0600)
			case "missing-id":
				l.config.UseDefault = false
				l.config.CertificateID = "unknown"
			}
			s, err := dsm.Open(l.state, l.config)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err := s.Deploy(context.Background(), "op", generation(t, "g1", false)); err == nil {
				t.Fatal("unsafe DSM target accepted")
			}
			if _, err := os.Stat(filepath.Join(l.archive, "ABC123/cert.pem")); !os.IsNotExist(err) {
				t.Fatal("unsafe preflight modified archive")
			}
		})
	}
}
