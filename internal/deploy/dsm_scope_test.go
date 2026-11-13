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

func addDSMEntry(t *testing.T, l dsmLayout, id, service string) {
	t.Helper()
	var info map[string]json.RawMessage
	if err := json.Unmarshal(read(t, filepath.Join(l.archive, "INFO")), &info); err != nil {
		t.Fatal(err)
	}
	entry := `{"services":[]}`
	if service != "" {
		entry = `{"services":[{"subscriber":"system","service":"` + service + `"}]}`
		mkdir(t, filepath.Join(l.root, "usr/syno/etc/certificate/system", service))
	}
	info[id] = json.RawMessage(entry)
	data, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(l.archive, "INFO"), data, 0600)
	mkdir(t, filepath.Join(l.archive, id))
}

func TestDSMPendingFilesAllowIndependentEntriesAndRejectOverlap(t *testing.T) {
	l := newDSM(t)
	addDSMEntry(t, l, "DEF456", "svc3")
	g := generation(t, "g1", false)
	for _, name := range []string{"svc1", "svc3"} {
		write(t, filepath.Join(l.scriptDir, "fail-"+name), nil, 0600)
	}
	first, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Deploy(context.Background(), "op1", g); err == nil {
		t.Fatal("expected callback failure")
	}
	first.Close()
	secondConfig := dsm.Config{DestinationID: "other", CertificateID: "DEF456", Root: l.root}
	second, err := dsm.Open(l.state, secondConfig)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := second.Deploy(context.Background(), "op2", g); err == nil || len(r.Services) != 1 || !r.Services[0].FilesPublished {
		t.Fatalf("independent entry did not publish: %+v, %v", r, err)
	}
	second.Close()
	conflict, err := dsm.Open(privateTempDir(t), dsm.Config{DestinationID: "conflict", CertificateID: "ABC123", Root: l.root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conflict.Republish(context.Background(), "conflict", g); err == nil || !strings.Contains(err.Error(), "unfinished work") {
		t.Fatalf("overlapping forced publication was allowed: %v", err)
	}
	conflict.Close()
	if err := os.Remove(filepath.Join(l.scriptDir, "fail-svc1")); err != nil {
		t.Fatal(err)
	}
	first, err = dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := first.Recover(context.Background()); err != nil || !r.Completed {
		t.Fatalf("first recovery failed: %+v, %v", r, err)
	}
	first.Close()
	if _, err := os.Stat(filepath.Join(l.archive, ".xcertm-pending")); err != nil {
		t.Fatal("first completion removed the other destination's claim", err)
	}
	if err := os.Remove(filepath.Join(l.scriptDir, "fail-svc3")); err != nil {
		t.Fatal(err)
	}
	second, err = dsm.Open(l.state, secondConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if r, err := second.Recover(context.Background()); err != nil || !r.Completed || count(l.calls(t), "svc2") != 1 {
		t.Fatalf("independent recovery failed or replayed successes: %+v, %v", r, err)
	}
	if _, err := os.Stat(filepath.Join(l.archive, ".xcertm-pending")); !os.IsNotExist(err) {
		t.Fatal("completed resource remains claimed")
	}
}

func TestDSMLegacyMarkerAndJournalUpgradeBeforeIndependentCreation(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			l := newDSM(t)
			g := generation(t, "g1", false)
			write(t, filepath.Join(l.scriptDir, "fail-svc2"), nil, 0600)
			s, err := dsm.Open(l.state, l.config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Deploy(context.Background(), "old-op", g); err == nil {
				t.Fatal("expected callback failure")
			}
			s.Close()
			j := journal(t, l.state, "nas")
			stage := j.Stage
			if version == 1 {
				for i := range j.Groups {
					j.Groups[i].Published = false
					j.Groups[i].Activation = ""
				}
			}
			writeLegacyJournal(t, l, j, version)
			marker, err := json.Marshal(map[string]string{"store": journalDir(l.state, "nas"), "operation_id": "old-op"})
			if err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(l.archive, ".xcertm-pending"), marker, 0600)
			infoBefore := string(read(t, filepath.Join(l.archive, "INFO")))
			blocked, err := dsm.Open(l.state, dsm.Config{DestinationID: "blocked-new-entry", Root: l.root})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := blocked.Deploy(context.Background(), "blocked", g); err == nil || !strings.Contains(err.Error(), "whole-file configuration guard") {
				t.Fatal("registration invalidated a legacy INFO guard", err)
			}
			blocked.Close()
			if string(read(t, filepath.Join(l.archive, "INFO"))) != infoBefore {
				t.Fatal("legacy guard changed before migration")
			}
			s, err = dsm.Open(l.state, l.config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Recover(context.Background()); err == nil {
				t.Fatal("real callback failure was masked")
			}
			s.Close()
			j = journal(t, l.state, "nas")
			if j.Version != 3 || j.Stage != stage || j.Guards[0].JSONKey != "ABC123" {
				t.Fatal("legacy recovery did not preserve and scope its journal")
			}
			other, err := dsm.Open(l.state, dsm.Config{DestinationID: "new-entry", Root: l.root})
			if err != nil {
				t.Fatal(err)
			}
			deployOK(t, other, "new-op", generation(t, "g2", false))
			other.Close()
			if err := os.Remove(filepath.Join(l.scriptDir, "fail-svc2")); err != nil {
				t.Fatal(err)
			}
			s, err = dsm.Open(l.state, l.config)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if r, err := s.Recover(context.Background()); err != nil || !r.Completed || count(l.calls(t), "svc1") != 1 {
				t.Fatalf("unrelated INFO registration blocked recovery: %+v, %v", r, err)
			}
		})
	}
}

func TestDSMForceRepublishesAndReactivatesWithoutChangingGeneration(t *testing.T) {
	l := newDSM(t)
	s, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	g := generation(t, "g1", false)
	deployOK(t, s, "op1", g)
	before, _ := os.Stat(filepath.Join(l.archive, "ABC123/privkey.pem"))
	if r, err := s.Deploy(context.Background(), "op1", g); err != nil || !r.Unchanged || len(l.calls(t)) != 2 {
		t.Fatalf("ordinary retry reactivated services: %+v, %v", r, err)
	}
	write(t, filepath.Join(l.archive, "ABC123/cert.pem"), []byte("external drift"), 0600)
	if _, err := s.Deploy(context.Background(), "op1", g); err == nil {
		t.Fatal("ordinary retry ignored external drift")
	}
	if r, err := s.Republish(context.Background(), "forced-op", g); err != nil || !r.Completed || r.Unchanged || r.GenerationID != g.ID() {
		t.Fatalf("forced republication failed: %+v, %v", r, err)
	}
	after, _ := os.Stat(filepath.Join(l.archive, "ABC123/privkey.pem"))
	if os.SameFile(before, after) || count(l.calls(t), "svc1") != 2 || count(l.calls(t), "svc2") != 2 {
		t.Fatal("force did not rewrite files and reactivate services")
	}
	checkPublished(t, filepath.Join(l.archive, "ABC123"), g, true)
	if r, err := s.Deploy(context.Background(), "forced-op", g); err != nil || !r.Unchanged || len(l.calls(t)) != 4 {
		t.Fatalf("ordinary retry after force was not idempotent: %+v, %v", r, err)
	}
}

func TestDSMForceCannotDiscardPendingOperation(t *testing.T) {
	l := newDSM(t)
	write(t, filepath.Join(l.scriptDir, "fail-svc1"), nil, 0600)
	s, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	g := generation(t, "g1", false)
	if _, err := s.Deploy(context.Background(), "pending", g); err == nil {
		t.Fatal("expected activation failure")
	}
	stage := journal(t, l.state, "nas").Stage
	if _, err := s.Republish(context.Background(), "forced-new-operation", g); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatal("force discarded pending operation", err)
	}
	if j := journal(t, l.state, "nas"); j.OperationID != "pending" || j.Stage != stage || count(l.calls(t), "svc2") != 1 {
		t.Fatal("force altered pending recovery material")
	}
}

func TestDSMForceReconcilesCompletedJournalBeforeReplacingItsClaim(t *testing.T) {
	l := newDSM(t)
	s, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.After = func(point string) error {
		if point == "group-system/svc2" {
			return errors.New("interrupted before marker release")
		}
		return nil
	}
	g := generation(t, "g1", false)
	if _, err := s.Deploy(context.Background(), "old", g); err == nil {
		t.Fatal("expected interruption")
	}
	if !journal(t, l.state, "nas").Completed() {
		t.Fatal("last callback was not checkpointed")
	}
	s.After = nil
	if r, err := s.Republish(context.Background(), "forced", g); err != nil || !r.Completed || count(l.calls(t), "svc1") != 2 || count(l.calls(t), "svc2") != 2 {
		t.Fatalf("completed legacy claim blocked a fresh forced publication: %+v, %v", r, err)
	}
}
