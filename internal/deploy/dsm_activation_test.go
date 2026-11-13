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

func threeDSMServices(t *testing.T) dsmLayout {
	t.Helper()
	l := newDSM(t)
	mkdir(t, filepath.Join(l.root, "usr/local/etc/certificate/system/svc3"))
	write(t, filepath.Join(l.archive, "INFO"), []byte(`{"ABC123":{"services":[{"subscriber":"system","service":"svc1"},{"subscriber":"system","service":"svc2"},{"subscriber":"system","service":"svc3"}]}}`), 0600)
	return l
}

func TestDSMActivationFailuresDoNotBlockOtherServices(t *testing.T) {
	l := threeDSMServices(t)
	for _, name := range []string{"svc1", "svc2"} {
		write(t, filepath.Join(l.scriptDir, "fail-"+name), nil, 0600)
	}
	s, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	g := generation(t, "g1", false)
	r, err := s.Deploy(context.Background(), "op1", g)
	if err == nil || r.Completed || !strings.Contains(err.Error(), "system/svc1") || !strings.Contains(err.Error(), "system/svc2") {
		t.Fatalf("service failures not reported: %+v, %v", r, err)
	}
	s.Close()
	j := journal(t, l.state, "nas")
	if j.Version != 3 || j.Groups[1].Done || j.Groups[2].Done || !j.Groups[3].Done {
		t.Fatal("independent service results not checkpointed")
	}
	if len(r.Services) != 3 || !r.Services[0].FilesPublished || r.Services[0].Activation != "callback-failed" || r.Services[2].Activation != "callback-succeeded" {
		t.Fatal("partial service outcomes not returned", r.Services)
	}
	for _, group := range j.Groups {
		if !group.Published {
			t.Fatal("activation started before all certificate files were published")
		}
	}
	for _, dir := range append(l.dirs(), filepath.Join(l.root, "usr/local/etc/certificate/system/svc3")) {
		checkPublished(t, dir, g, true)
	}
	for _, name := range []string{"svc1", "svc2", "svc3"} {
		if count(l.calls(t), name) != 1 {
			t.Fatal("an independent service was not attempted", l.calls(t))
		}
	}
	for _, name := range []string{"svc1", "svc2"} {
		if err := os.Remove(filepath.Join(l.scriptDir, "fail-"+name)); err != nil {
			t.Fatal(err)
		}
	}
	restarted, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	r, err = restarted.Recover(context.Background())
	if err != nil || !r.Completed || r.GenerationID != "g1" {
		t.Fatalf("failed to resume same generation: %+v, %v", r, err)
	}
	if count(l.calls(t), "svc1") != 2 || count(l.calls(t), "svc2") != 2 || count(l.calls(t), "svc3") != 1 {
		t.Fatal("recovery repeated completed services", l.calls(t))
	}
}

func TestDSMStopsOnIntegrityConflictAndCancellation(t *testing.T) {
	for _, kind := range []string{"callback-changed-file", "published-file-changed", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			l := threeDSMServices(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "callback-changed-file" {
				path := filepath.Join(l.root, "usr/local/etc/certificate/system/svc3/cert.pem")
				// The test fixture path is passed through an environment-free file
				// locator beside the fake script, never supplied as shell code.
				write(t, filepath.Join(l.scriptDir, "target"), []byte(path), 0600)
				write(t, filepath.Join(l.scriptDir, "system"), []byte("#!/bin/sh\necho \"$1\" >> \"${0%/*}/calls\"\nfile=$(cat \"${0%/*}/target\")\nprintf changed > \"$file\"\nexit 1\n"), 0700)
			}
			s, err := dsm.Open(l.state, l.config)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if kind == "cancelled" {
				s.After = func(point string) error {
					if point == "published-system/svc3" {
						cancel()
					}
					return nil
				}
			}
			if kind == "published-file-changed" {
				s.After = func(point string) error {
					if point == "published-system/svc3" {
						path := filepath.Join(l.root, "usr/local/etc/certificate/system/svc3/cert.pem")
						return os.WriteFile(path, []byte("external change"), 0600)
					}
					return nil
				}
			}
			if _, err := s.Deploy(ctx, "op", generation(t, "g1", false)); err == nil {
				t.Fatal("global failure was masked")
			}
			want := 0
			if kind == "callback-changed-file" {
				want = 1
			}
			if len(l.calls(t)) != want {
				t.Fatal("callbacks continued after an integrity failure/cancellation", l.calls(t))
			}
		})
	}
}

func TestDSMLegacyPendingJournalKeepsCompletedServices(t *testing.T) {
	l := threeDSMServices(t)
	s, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	s.After = func(point string) error {
		if point == "group-system/svc1" {
			return errors.New("interrupted")
		}
		return nil
	}
	if _, err := s.Deploy(context.Background(), "op", generation(t, "g1", false)); err == nil {
		t.Fatal("interruption not reached")
	}
	s.Close()
	j := journal(t, l.state, "nas")
	j.Version = 1
	for i := range j.Groups {
		j.Groups[i].Published = false
		j.Groups[i].Activation = ""
	}
	writeLegacyJournal(t, l, j, 1)
	write(t, filepath.Join(l.scriptDir, "fail-svc2"), nil, 0600)
	restarted, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if _, err := restarted.Recover(context.Background()); err == nil {
		t.Fatal("failed legacy activation was masked")
	}
	if count(l.calls(t), "svc1") != 1 || count(l.calls(t), "svc3") != 1 || !journal(t, l.state, "nas").Groups[3].Done {
		t.Fatal("legacy recovery repeated or blocked independent services")
	}
}
