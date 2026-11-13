//go:build linux

package deploy_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernaxis/xcertm/internal/deploy/dsm"
)

func packageDSM(t *testing.T, name string, resource string) (dsmLayout, string) {
	t.Helper()
	l := newDSM(t)
	info := map[string]any{"ABC123": map[string]any{"services": []map[string]any{
		{"subscriber": name, "service": "endpoint", "isPkg": true, "owner": "root"},
		{"subscriber": "system", "service": "svc2"},
	}}}
	data, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(l.archive, "INFO"), data, 0600)
	mkdir(t, filepath.Join(l.root, "usr/local/etc/certificate", name, "endpoint"))
	packageDir := filepath.Join(l.root, "var/packages", name)
	mkdir(t, filepath.Join(packageDir, "conf"))
	target := filepath.Join(l.root, "volume1/@appstore", name)
	mkdir(t, filepath.Join(target, "tool"))
	relative, err := filepath.Rel(packageDir, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(relative, filepath.Join(packageDir, "target")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(packageDir, "conf/resource"), []byte(resource), 0644)
	mkdir(t, filepath.Join(l.root, "usr/local/share/certificate.d"))
	write(t, filepath.Join(l.root, "usr/local/share/certificate.d", name), []byte("#!/bin/sh\necho legacy >> \"${0%/*}/calls\"\nexit 1\n"), 0700)
	write(t, filepath.Join(target, "tool/tls-reload"), []byte("#!/bin/sh\n[ \"$#\" -eq 0 ] || exit 8\necho tls >> \"${0%/*}/calls\"\nif [ -f \"${0%/*}/fail\" ]; then echo 'SENSITIVE-SCRIPT-OUTPUT' >&2; exit 7; fi\n"), 0700)
	return l, target
}

const singleTLSResource = `{"certificate-config":{"reloader-relpath":"tool/old-reload","services":[{"service":"endpoint"}]},"tls-profile":{"services":[{"service":"protocol-name","reloader-relpath":"tool/tls-reload"}]},"unrelated-worker":{"keep":true}}`

func TestDSMDeclaredTLSReloaderIsGenericAndReplacesLegacyHook(t *testing.T) {
	for _, name := range []string{"ExamplePackage", "AnotherPackage"} {
		t.Run(name, func(t *testing.T) {
			l, target := packageDSM(t, name, singleTLSResource)
			s, err := dsm.Open(l.state, l.config)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			r, err := s.Deploy(context.Background(), "op", generation(t, "g1", false))
			if err != nil || !r.Completed || len(r.Services) != 2 || r.Services[0].Activation != "callback-succeeded" {
				t.Fatalf("native activation failed: %+v, %v", r, err)
			}
			if string(read(t, filepath.Join(target, "tool/calls"))) != "tls\n" {
				t.Fatal("declared native TLS reloader was not used")
			}
			if _, err := os.Stat(filepath.Join(l.root, "usr/local/share/certificate.d/calls")); !os.IsNotExist(err) {
				t.Fatal("historical package-starting hook was also executed")
			}
		})
	}
}

func TestDSMNativeReloaderFailureIsRetriedWithoutReplayingOthers(t *testing.T) {
	l, target := packageDSM(t, "ExamplePackage", singleTLSResource)
	write(t, filepath.Join(target, "tool/fail"), nil, 0600)
	s, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Deploy(context.Background(), "op", generation(t, "g1", false))
	if err == nil || r.Completed || strings.Contains(err.Error(), "SENSITIVE-SCRIPT-OUTPUT") || r.Services[0].Activation != "callback-failed" || r.Services[1].Activation != "callback-succeeded" {
		t.Fatalf("incorrect partial result: %+v, %v", r, err)
	}
	s.Close()
	if err := os.Remove(filepath.Join(target, "tool/fail")); err != nil {
		t.Fatal(err)
	}
	restarted, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	r, err = restarted.Recover(context.Background())
	if err != nil || !r.Completed || r.GenerationID != "g1" || count(l.calls(t), "svc2") != 1 {
		t.Fatalf("incorrect native recovery: %+v, %v", r, err)
	}
	if string(read(t, filepath.Join(target, "tool/calls"))) != "tls\ntls\n" {
		t.Fatal("failed native callback not retried")
	}
}

func TestDSMDeclaredReloaderRejectsAmbiguityAndUnsafePaths(t *testing.T) {
	for _, name := range []string{"ambiguous", "duplicate", "traversal", "absolute", "symlink-escape", "missing", "unregistered-service", "invalid-json", "writable-resource", "writable-reloader"} {
		t.Run(name, func(t *testing.T) {
			var resource map[string]any
			if err := json.Unmarshal([]byte(singleTLSResource), &resource); err != nil {
				t.Fatal(err)
			}
			profile := map[string]any{"service": "protocol-name", "reloader-relpath": "tool/tls-reload"}
			profiles := []any{profile}
			switch name {
			case "ambiguous":
				profiles = append(profiles, map[string]any{"service": "other", "reloader-relpath": "tool/other"})
			case "duplicate":
				profile["service"] = "endpoint"
				profiles = append(profiles, profile)
			case "traversal":
				profile["reloader-relpath"] = "../outside"
			case "absolute":
				profile["reloader-relpath"] = "/bin/true"
			case "missing":
				profile["reloader-relpath"] = "tool/missing"
			case "unregistered-service":
				resource["certificate-config"] = map[string]any{"services": []any{}}
			}
			resource["tls-profile"] = map[string]any{"services": profiles}
			data, err := json.Marshal(resource)
			if err != nil {
				t.Fatal(err)
			}
			if name == "invalid-json" {
				data = []byte("invalid: SENSITIVE-RESOURCE-CONTENT")
			}
			l, target := packageDSM(t, "ExamplePackage", string(data))
			if name == "writable-resource" {
				if err := os.Chmod(filepath.Join(l.root, "var/packages/ExamplePackage/conf/resource"), 0666); err != nil {
					t.Fatal(err)
				}
			}
			if name == "writable-reloader" {
				if err := os.Chmod(filepath.Join(target, "tool/tls-reload"), 0777); err != nil {
					t.Fatal(err)
				}
			}
			if name == "symlink-escape" {
				if err := os.Remove(filepath.Join(target, "tool/tls-reload")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/bin/true", filepath.Join(target, "tool/tls-reload")); err != nil {
					t.Fatal(err)
				}
			}
			s, err := dsm.Open(l.state, l.config)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			r, err := s.Deploy(context.Background(), "op", generation(t, "g1", false))
			if err == nil || r.Completed || strings.Contains(err.Error(), "SENSITIVE-RESOURCE-CONTENT") || r.Services[0].Activation != "unavailable" || r.Services[1].Activation != "callback-succeeded" {
				t.Fatalf("unsafe/ambiguous reloader not isolated: %+v, %v", r, err)
			}
			if _, err := os.Stat(filepath.Join(target, "tool/calls")); !os.IsNotExist(err) {
				t.Fatal("unsafe or ambiguous native callback executed")
			}
			if _, err := os.Stat(filepath.Join(l.root, "usr/local/share/certificate.d/calls")); !os.IsNotExist(err) {
				t.Fatal("unsafe native metadata fell back to legacy callback")
			}
		})
	}
}

func TestDSMNativeTLSExactMatchAndLegacyFallback(t *testing.T) {
	for _, native := range []bool{true, false} {
		resource := `{"certificate-config":{"services":[{"service":"endpoint"}]}}`
		if native {
			resource = `{"certificate-config":{"services":[{"service":"endpoint"}]},"tls-profile":{"services":[{"service":"unrelated","reloader-relpath":"tool/missing"},{"service":"endpoint","reloader-relpath":"tool/tls-reload"}]}}`
		}
		l, target := packageDSM(t, "ExamplePackage", resource)
		s, err := dsm.Open(l.state, l.config)
		if err != nil {
			t.Fatal(err)
		}
		r, err := s.Deploy(context.Background(), "op", generation(t, "g1", false))
		s.Close()
		if native {
			if err != nil || !r.Completed || string(read(t, filepath.Join(target, "tool/calls"))) != "tls\n" {
				t.Fatalf("exact TLS service match failed: %+v, %v", r, err)
			}
		} else if err == nil || r.Services[0].Activation != "callback-failed" || !strings.Contains(err.Error(), "exit status 1") {
			t.Fatal("legacy callback behavior was silently changed")
		}
	}
}

func TestDSMDeclaredPackageWithoutCallbackCompletesWithoutClaimingActivation(t *testing.T) {
	for _, name := range []string{"PackageWithoutHook", "AnotherPackageWithoutHook"} {
		t.Run(name, func(t *testing.T) {
			l, _ := packageDSM(t, name, `{"certificate-config":{"services":[{"service":"endpoint"}]}}`)
			if err := os.Remove(filepath.Join(l.root, "usr/local/share/certificate.d", name)); err != nil {
				t.Fatal(err)
			}
			var progress strings.Builder
			l.config.Progress = func(message string) { progress.WriteString(message + "\n") }
			s, err := dsm.Open(l.state, l.config)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			r, err := s.Deploy(context.Background(), "op", generation(t, "g1", false))
			if err != nil || !r.Completed || r.Services[0].Activation != "not-available" || !r.Services[0].FilesPublished {
				t.Fatalf("callback absence was not recorded accurately: %+v, %v", r, err)
			}
			if !strings.Contains(progress.String(), "files published without service activation") || count(l.calls(t), "svc2") != 1 {
				t.Fatal("callback absence was hidden or blocked independent activation")
			}
			if r, err := s.Recover(context.Background()); err != nil || r.Services[0].Activation != "not-available" || count(l.calls(t), "svc2") != 1 {
				t.Fatalf("recorded callback absence did not survive recovery: %+v, %v", r, err)
			}
		})
	}
}

func TestDSMCertificateReloaderUsesDeclaredExecutableAndRetainsExitFailure(t *testing.T) {
	l, target := packageDSM(t, "CertificateHookPackage", `{"certificate-config":{"reloader-relpath":"tool/cert-reload","services":[{"service":"endpoint"}]}}`)
	write(t, filepath.Join(target, "tool/cert-reload"), []byte("#!/bin/sh\n[ \"$1\" = endpoint ] || exit 8\necho invoked >> \"${0%/*}/calls\"\nif [ -f \"${0%/*}/fail\" ]; then exit 255; fi\n"), 0700)
	write(t, filepath.Join(target, "tool/fail"), nil, 0600)
	s, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := s.Deploy(context.Background(), "op", generation(t, "g1", false))
	if err == nil || !strings.Contains(err.Error(), "exit status 255") || r.Services[0].Activation != "callback-failed" || r.Services[1].Activation != "callback-succeeded" {
		t.Fatalf("native failure was masked or blocked others: %+v, %v", r, err)
	}
	if _, err := os.Stat(filepath.Join(l.root, "usr/local/share/certificate.d/calls")); !os.IsNotExist(err) {
		t.Fatal("declared certificate callback fell back to historical hook")
	}
	if err := os.Remove(filepath.Join(target, "tool/fail")); err != nil {
		t.Fatal(err)
	}
	if r, err := s.Recover(context.Background()); err != nil || !r.Completed || count(l.calls(t), "svc2") != 1 {
		t.Fatalf("certificate callback recovery failed: %+v, %v", r, err)
	}
}

func TestDSMLegacyPendingOperationCanResumeWithDeclaredTLSReloader(t *testing.T) {
	l, target := packageDSM(t, "ExamplePackage", singleTLSResource)
	s, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	s.After = func(point string) error {
		if point == "group-archive" {
			return errors.New("interrupted before service activation")
		}
		return nil
	}
	if _, err := s.Deploy(context.Background(), "original-op", generation(t, "original-generation", false)); err == nil {
		t.Fatal("interruption not reached")
	}
	s.Close()
	j := journal(t, l.state, "nas")
	stage := j.Stage
	j.Version = 1
	for i := range j.Groups {
		j.Groups[i].Published = false
		j.Groups[i].Activation = ""
	}
	writeLegacyJournal(t, l, j, 1)
	restarted, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	r, err := restarted.Recover(context.Background())
	if err != nil || !r.Completed || r.OperationID != "original-op" || r.GenerationID != "original-generation" {
		t.Fatalf("legacy operation not recovered: %+v, %v", r, err)
	}
	if journal(t, l.state, "nas").Stage != stage {
		t.Fatal("migration replaced retained generation material")
	}
	if string(read(t, filepath.Join(target, "tool/calls"))) != "tls\n" {
		t.Fatal("legacy recovery did not use native reloader")
	}
	if _, err := os.Stat(filepath.Join(l.root, "usr/local/share/certificate.d/calls")); !os.IsNotExist(err) {
		t.Fatal("legacy recovery executed the package-starting hook")
	}
}
