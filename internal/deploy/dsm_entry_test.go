//go:build linux

package deploy_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/kernaxis/xcertm/internal/deploy/dsm"
	"github.com/kernaxis/xcertm/internal/domain"
)

func automaticDSM(t *testing.T) dsmLayout {
	t.Helper()
	l := newDSM(t)
	l.config.UseDefault = false
	return l
}
func entryMapping(l dsmLayout) string {
	return filepath.Join(journalDir(l.state, l.config.DestinationID), "dsm-entry.json")
}
func recordedEntryID(t *testing.T, l dsmLayout) string {
	t.Helper()
	var entry struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(read(t, entryMapping(l)), &entry); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9]{6}$`).MatchString(entry.ID) {
		t.Fatal("DSM ID does not follow mktemp's six-character format")
	}
	return entry.ID
}
func dsmInfo(t *testing.T, l dsmLayout) map[string]any {
	t.Helper()
	var info map[string]any
	if err := json.Unmarshal(read(t, filepath.Join(l.archive, "INFO")), &info); err != nil {
		t.Fatal(err)
	}
	return info
}

func TestDSMAutomaticEntryIsDedicatedAndReused(t *testing.T) {
	l := automaticDSM(t)
	before := dsmInfo(t, l)
	defaults := string(read(t, filepath.Join(l.archive, "DEFAULT")))
	write(t, filepath.Join(l.archive, "INFO"), read(t, filepath.Join(l.archive, "INFO")), 0644)
	var messages strings.Builder
	l.config.Progress = func(message string) { messages.WriteString(message + "\n") }
	s, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	g1 := generation(t, "g1", false)
	deployOK(t, s, "op1", g1)
	s.Close()
	id := recordedEntryID(t, l)
	after := dsmInfo(t, l)
	if len(after) != len(before)+1 || !reflect.DeepEqual(before["ABC123"], after["ABC123"]) {
		t.Fatal("unrelated DSM metadata was modified")
	}
	entry := after[id].(map[string]any)
	if entry["user_deletable"] != true || len(entry["services"].([]any)) != 0 || !strings.Contains(entry["desc"].(string), "certificate-1") {
		t.Fatal("new DSM entry has unexpected metadata or assignments")
	}
	if string(read(t, filepath.Join(l.archive, "DEFAULT"))) != defaults {
		t.Fatal("automatic registration changed the default")
	}
	if info, err := os.Stat(filepath.Join(l.archive, "INFO")); err != nil || info.Mode().Perm() != 0644 {
		t.Fatal("INFO permissions were changed")
	}
	if !strings.Contains(messages.String(), id) {
		t.Fatal("generated DSM entry ID was not reported")
	}
	if len(l.calls(t)) != 0 {
		t.Fatal("an unassigned entry reloaded an existing service")
	}
	checkPublished(t, filepath.Join(l.archive, id), g1, true)
	// Intentional UI assignments between deployments are picked up by the next
	// generation while keeping the entry ID and unrelated metadata unchanged.
	entry["services"] = []any{map[string]any{"subscriber": "system", "service": "svc1", "unknown_service_field": "keep"}}
	data, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(l.archive, "INFO"), data, 0644)
	s, err = dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	g2 := generation(t, "g2", false)
	deployOK(t, s, "op2", g2)
	if recordedEntryID(t, l) != id || len(dsmInfo(t, l)) != 2 {
		t.Fatal("renewal allocated another DSM entry")
	}
	checkPublished(t, filepath.Join(l.archive, id), g2, true)
	checkPublished(t, l.dirs()[1], g2, true)
	if count(l.calls(t), "svc1") != 1 || count(l.calls(t), "svc2") != 0 {
		t.Fatal("assigned services were not handled independently")
	}
}

func TestDSMAutomaticEntryRecoversEveryCreationBoundary(t *testing.T) {
	for _, point := range []string{"dsm-create-claimed", "dsm-directory-reserved", "dsm-entry-prepared", "dsm-info-published", "dsm-entry-registered", "dsm-entry-ready", "prepared", "file-0", "file-3", "group-archive"} {
		t.Run(point, func(t *testing.T) {
			l := automaticDSM(t)
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
				t.Fatal("creation boundary was not reached")
			}
			s.Close()
			id := ""
			if _, err := os.Stat(entryMapping(l)); err == nil {
				id = recordedEntryID(t, l)
			}
			if _, err := os.Stat(filepath.Join(l.archive, ".xcertm-dsm-create")); err == nil {
				foreign := l.config
				foreign.DestinationID = "other"
				if other, err := dsm.Open(privateTempDir(t), foreign); err == nil {
					other.Close()
					t.Fatal("another store bypassed pending creation")
				}
				foreign = l.config
				foreign.UseDefault = true
				if other, err := dsm.Open(l.state, foreign); err == nil {
					other.Close()
					t.Fatal("switching selector bypassed pending creation")
				}
			}
			s, err = dsm.Open(l.state, l.config)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			deployOK(t, s, "op1", g)
			actual := recordedEntryID(t, l)
			if id != "" && id != actual {
				t.Fatal("recovery changed the recorded DSM ID")
			}
			if len(dsmInfo(t, l)) != 2 {
				t.Fatal("recovery registered duplicate entries")
			}
			checkPublished(t, filepath.Join(l.archive, actual), g, true)
			if _, err := os.Stat(filepath.Join(l.archive, ".xcertm-dsm-create")); !os.IsNotExist(err) {
				t.Fatal("creation marker was not released")
			}
		})
	}
}

func TestDSMAutomaticEntryStopsOnMetadataOrDirectoryConflicts(t *testing.T) {
	for _, kind := range []string{"INFO-content", "INFO-mode", "directory", "state-corruption", "untracked-files"} {
		t.Run(kind, func(t *testing.T) {
			l := automaticDSM(t)
			s, err := dsm.Open(l.state, l.config)
			if err != nil {
				t.Fatal(err)
			}
			g := generation(t, "g1", false)
			stop := "dsm-entry-prepared"
			if kind == "untracked-files" {
				stop = "dsm-entry-ready"
			}
			s.After = func(at string) error {
				if at == stop {
					return errors.New("interrupt")
				}
				return nil
			}
			if _, err := s.Deploy(context.Background(), "op1", g); err == nil {
				t.Fatal("expected interruption")
			}
			s.Close()
			id := recordedEntryID(t, l)
			path := filepath.Join(l.archive, "INFO")
			switch kind {
			case "INFO-content":
				info := dsmInfo(t, l)
				info["ABC123"].(map[string]any)["external"] = "keep"
				data, _ := json.Marshal(info)
				write(t, path, data, 0600)
			case "INFO-mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "directory":
				dir := filepath.Join(l.archive, id)
				if err := os.Rename(dir, dir+"-moved"); err != nil {
					t.Fatal(err)
				}
				mkdir(t, dir)
			case "state-corruption":
				write(t, entryMapping(l), []byte("corrupted"), 0600)
			case "untracked-files":
				write(t, filepath.Join(l.archive, id, "privkey.pem"), []byte("external material"), 0600)
			}
			before := string(read(t, path))
			s, err = dsm.Open(l.state, l.config)
			if err == nil {
				_, err = s.Deploy(context.Background(), "op1", g)
				s.Close()
			}
			if err == nil {
				t.Fatal("creation conflict was overwritten")
			}
			if string(read(t, path)) != before {
				t.Fatal("conflicting INFO contents were modified")
			}
		})
	}
}

func TestDSMAutomaticEntryDeletionDoesNotAllocateReplacement(t *testing.T) {
	l := automaticDSM(t)
	s, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	deployOK(t, s, "op1", generation(t, "g1", false))
	s.Close()
	id := recordedEntryID(t, l)
	info := dsmInfo(t, l)
	delete(info, id)
	data, _ := json.Marshal(info)
	write(t, filepath.Join(l.archive, "INFO"), data, 0600)
	s, err = dsm.Open(l.state, l.config)
	if err == nil {
		defer s.Close()
		if _, err = s.Deploy(context.Background(), "op2", generation(t, "g2", false)); err == nil {
			t.Fatal("missing automatic entry was silently replaced")
		}
	}
	if recordedEntryID(t, l) != id || len(dsmInfo(t, l)) != 1 {
		t.Fatal("entry mapping changed after deletion")
	}
}

func TestDSMAutomaticEntryMissingMappingDoesNotCreateAnother(t *testing.T) {
	l := automaticDSM(t)
	s, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	deployOK(t, s, "op1", generation(t, "g1", false))
	s.Close()
	before := string(read(t, filepath.Join(l.archive, "INFO")))
	if err := os.Remove(entryMapping(l)); err != nil {
		t.Fatal(err)
	}
	if other, err := dsm.Open(l.state, l.config); err == nil {
		other.Close()
		t.Fatal("missing mapping was ignored")
	}
	if string(read(t, filepath.Join(l.archive, "INFO"))) != before {
		t.Fatal("missing mapping created or changed entries")
	}
}

func TestDSMAutomaticEntryPinsGenerationBeforeFileJournal(t *testing.T) {
	for _, point := range []string{"dsm-create-claimed", "dsm-entry-prepared", "dsm-entry-ready"} {
		t.Run(point, func(t *testing.T) {
			l := automaticDSM(t)
			s, err := dsm.Open(l.state, l.config)
			if err != nil {
				t.Fatal(err)
			}
			g := generation(t, "g1", false)
			s.After = func(at string) error {
				if at == point {
					return errors.New("interrupt")
				}
				return nil
			}
			if _, err := s.Deploy(context.Background(), "op1", g); err == nil {
				t.Fatal("expected interruption")
			}
			s.Close()
			s, err = dsm.Open(l.state, l.config)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err := s.Deploy(context.Background(), "op2", g); err == nil {
				t.Fatal("creation accepted a different operation")
			}
			if _, err := s.Deploy(context.Background(), "op1", generation(t, "g1", false)); err == nil {
				t.Fatal("creation accepted different material under the same generation ID")
			}
			deployOK(t, s, "op1", g)
			if len(dsmInfo(t, l)) != 2 {
				t.Fatal("rejected inputs created extra entries")
			}
		})
	}
}

func TestDSMAutomaticEntryCrashHelper(t *testing.T) {
	root := os.Getenv("XCERTM_DSM_CREATE_ROOT")
	if root == "" {
		return
	}
	var input domain.GenerationInput
	if err := json.Unmarshal(read(t, os.Getenv("XCERTM_DSM_CREATE_GENERATION")), &input); err != nil {
		t.Fatal(err)
	}
	g, err := domain.NewGeneration(input)
	if err != nil {
		t.Fatal(err)
	}
	s, err := dsm.Open(os.Getenv("XCERTM_DSM_CREATE_STATE"), dsm.Config{DestinationID: "nas", Root: root})
	if err != nil {
		t.Fatal(err)
	}
	s.After = func(point string) error {
		if point == "dsm-info-published" {
			os.Exit(77)
		}
		return nil
	}
	_, err = s.Deploy(context.Background(), "op1", g)
	t.Fatalf("crash boundary not reached: %v", err)
}

func TestDSMAutomaticEntrySurvivesProcessLoss(t *testing.T) {
	l := automaticDSM(t)
	g := generation(t, "g1", false)
	// Generated keys remain in a private temporary file so both processes retry
	// the exact same generation, without fixtures or key data in test output.
	input := domain.GenerationInput{ID: g.ID(), CertificateID: g.CertificateID(), Provenance: g.Provenance(), ValidatedAt: g.ValidatedAt(), CertificateDER: g.CertificateDER(), ChainDER: g.ChainDER(), PrivateKeyPKCS8: g.PrivateKeyPKCS8()}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "generation.json")
	write(t, path, data, 0600)
	cmd := exec.Command(os.Args[0], "-test.run=^TestDSMAutomaticEntryCrashHelper$")
	cmd.Env = append(os.Environ(), "XCERTM_DSM_CREATE_ROOT="+l.root, "XCERTM_DSM_CREATE_STATE="+l.state, "XCERTM_DSM_CREATE_GENERATION="+path)
	err = cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 77 {
		t.Fatalf("child did not crash at registration boundary: %v", err)
	}
	id := recordedEntryID(t, l)
	if len(dsmInfo(t, l)) != 2 {
		t.Fatal("child did not register entry")
	}
	s, err := dsm.Open(l.state, l.config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	deployOK(t, s, "op1", g)
	if recordedEntryID(t, l) != id || len(dsmInfo(t, l)) != 2 {
		t.Fatal("process-loss recovery created another entry")
	}
	checkPublished(t, filepath.Join(l.archive, id), g, true)
}
