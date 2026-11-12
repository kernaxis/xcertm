package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type File struct {
	Path   string   `json:"path"`
	Before Snapshot `json:"before"`
	After  Snapshot `json:"after"`
}
type Guard struct {
	Path   string   `json:"path"`
	Before Snapshot `json:"before"`
}
type Group struct {
	Name       string `json:"name"`
	Files      []int  `json:"files"`
	Reload     string `json:"reload,omitempty"`
	Published  bool   `json:"published,omitempty"`
	Activation string `json:"activation,omitempty"`
	Done       bool   `json:"done"`
}

// ActivationError identifies a service-local failure. Integrity, configuration
// conflicts and cancellation must remain ordinary errors and stop replay.
type ActivationError struct {
	Err       error
	Attempted bool
}

func (e *ActivationError) Error() string { return e.Err.Error() }
func (e *ActivationError) Unwrap() error { return e.Err }

// Journal is private operational state, not a user configuration format.
// A completed journal remains the receipt for the latest observed deployment.
type Journal struct {
	Version             int         `json:"version"`
	Stage               string      `json:"stage"`
	OperationID         string      `json:"operation_id"`
	DestinationID       string      `json:"destination_id"`
	CertificateID       string      `json:"certificate_id"`
	GenerationID        string      `json:"generation_id"`
	GenerationSource    string      `json:"generation_source"`
	GenerationReference string      `json:"generation_reference"`
	ValidatedAt         time.Time   `json:"validated_at"`
	Fingerprint         string      `json:"fingerprint"`
	Kind                string      `json:"kind"`
	Resource            string      `json:"resource"`
	Configuration       string      `json:"configuration"`
	Target              string      `json:"target"`
	Files               []File      `json:"files"`
	Groups              []Group     `json:"groups"`
	Guards              []Guard     `json:"guards"`
	Directories         []Directory `json:"directories"`
}

type Content struct {
	Path   string
	Data   []byte
	Remove bool
}
type Batch struct {
	Name   string
	Files  []Content
	Reload string
}

type Store struct {
	Dir      string
	Validate func(*Journal) error
	Reload   func(string) error
	// After injects interruptions at durable boundaries; production leaves it nil.
	After func(string) error
}

const maxJournalSize = 8 << 20

func (j *Journal) Completed() bool {
	if len(j.Groups) == 0 {
		return false
	}
	for _, group := range j.Groups {
		if !group.Done {
			return false
		}
	}
	return true
}

func Decode(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing state data")
	}
	return nil
}

func (s *Store) Load() (*Journal, error) {
	path := filepath.Join(s.Dir, "current.json")
	info, err := Inspect(path)
	if err != nil || !info.Exists {
		return nil, err
	}
	if info.Mode != 0600 || info.UID != os.Geteuid() {
		return nil, errors.New("unsafe journal permissions or ownership")
	}
	data, err := ReadPrivate(path)
	if err != nil {
		return nil, err
	}
	if len(data) > maxJournalSize {
		return nil, errors.New("journal exceeds size limit")
	}
	var journal Journal
	if err := Decode(data, &journal); err != nil {
		return nil, fmt.Errorf("invalid deployment journal: %w", err)
	}
	if err := structure(&journal); err != nil {
		return nil, err
	}
	return &journal, nil
}

func structure(j *Journal) error {
	if (j.Version != 1 && j.Version != 2) || !strings.HasPrefix(j.Stage, "operation-") || filepath.Base(j.Stage) != j.Stage || strings.ContainsAny(j.Stage, "\\\x00") {
		return errors.New("unsupported deployment journal")
	}
	for _, value := range []string{j.OperationID, j.DestinationID, j.CertificateID, j.GenerationID, j.GenerationSource, j.GenerationReference, j.Fingerprint, j.Kind, j.Resource, j.Configuration, j.Target} {
		if strings.TrimSpace(value) == "" {
			return errors.New("incomplete deployment identity")
		}
	}
	if j.ValidatedAt.IsZero() {
		return errors.New("generation validation instant is missing")
	}
	if len(j.Files) == 0 || len(j.Groups) == 0 || len(j.Directories) == 0 {
		return errors.New("empty deployment journal")
	}
	paths := map[string]bool{}
	for _, f := range j.Files {
		if !filepath.IsAbs(f.Path) || filepath.Clean(f.Path) != f.Path || paths[f.Path] {
			return errors.New("invalid deployment file path")
		}
		paths[f.Path] = true
		for _, snapshot := range []Snapshot{f.Before, f.After} {
			if snapshot.Mode > 0777 || snapshot.UID < 0 || snapshot.GID < 0 || (snapshot.Exists && len(snapshot.Hash) != 64) {
				return errors.New("invalid deployment metadata")
			}
			if !snapshot.Exists && snapshot != (Snapshot{}) {
				return errors.New("invalid absent file metadata")
			}
		}
		if f.After.Exists {
			if f.Before.Exists {
				if f.After.Mode != f.Before.Mode || f.After.UID != f.Before.UID || f.After.GID != f.Before.GID {
					return errors.New("deployment must preserve existing file ownership and permissions")
				}
			} else if f.After.Mode != 0600 || f.After.UID != os.Geteuid() || f.After.GID != os.Getegid() {
				return errors.New("new deployment files must use private executing-user metadata")
			}
		}
	}
	seen := map[int]bool{}
	pending := false
	for _, group := range j.Groups {
		if len(group.Files) == 0 || group.Name == "" {
			return errors.New("empty deployment group")
		}
		if j.Version == 1 && group.Published || j.Version == 2 && group.Done && !group.Published {
			return errors.New("invalid deployment publication progress")
		}
		if j.Version == 1 && group.Activation != "" || group.Reload == "" && group.Activation != "" {
			return errors.New("unexpected activation result")
		}
		if j.Version == 2 && group.Reload != "" {
			switch group.Activation {
			case "pending":
				if group.Done {
					return errors.New("pending activation marked completed")
				}
			case "callback-succeeded":
				if !group.Done {
					return errors.New("activation result lacks completion checkpoint")
				}
			case "callback-failed", "unavailable":
				if group.Done || !group.Published {
					return errors.New("invalid failed activation result")
				}
			default:
				return errors.New("invalid activation result")
			}
		}
		if !group.Done {
			pending = true
		} else if pending && j.Version == 1 {
			return errors.New("invalid deployment progress")
		}
		for _, index := range group.Files {
			if index < 0 || index >= len(j.Files) || seen[index] {
				return errors.New("invalid deployment file index")
			}
			seen[index] = true
		}
	}
	if len(seen) != len(j.Files) {
		return errors.New("incomplete deployment file groups")
	}
	dirs := map[string]bool{}
	for _, dir := range j.Directories {
		if !filepath.IsAbs(dir.Path) || filepath.Clean(dir.Path) != dir.Path || dirs[dir.Path] {
			return errors.New("invalid deployment directory guard")
		}
		dirs[dir.Path] = true
	}
	for _, f := range j.Files {
		if !dirs[filepath.Dir(f.Path)] {
			return errors.New("unguarded deployment directory")
		}
	}
	if !dirs[j.Resource] {
		return errors.New("unguarded deployment resource")
	}
	for _, guard := range j.Guards {
		if !filepath.IsAbs(guard.Path) || filepath.Clean(guard.Path) != guard.Path || !guard.Before.Exists {
			return errors.New("invalid deployment configuration guard")
		}
	}
	return nil
}

func (s *Store) checkpoint(j *Journal) error {
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if len(data) > maxJournalSize {
		return errors.New("journal exceeds size limit")
	}
	return WritePrivate(filepath.Join(s.Dir, "current.json"), data)
}

// Prepare durably stages all content before publishing a journal. Old completed
// stages are deliberately retained; no automatic generation or key pruning.
func (s *Store) Prepare(j Journal, batches []Batch, guards []string, allowExisting bool) error {
	previous, err := s.Load()
	if err != nil {
		return err
	}
	if previous != nil && !previous.Completed() {
		return errors.New("a deployment is already pending")
	}
	stage, err := os.MkdirTemp(s.Dir, "operation-")
	if err != nil {
		return err
	}
	j.Version, j.Stage = 2, filepath.Base(stage)
	dirs := map[string]bool{}
	addDir := func(path string) error {
		if dirs[path] {
			return nil
		}
		dir, err := InspectDirectory(path)
		if err != nil {
			return err
		}
		dirs[path] = true
		j.Directories = append(j.Directories, dir)
		return nil
	}
	if err := addDir(j.Resource); err != nil {
		return err
	}
	for _, batch := range batches {
		group := Group{Name: batch.Name, Reload: batch.Reload}
		if group.Reload != "" {
			group.Activation = "pending"
		}
		for _, content := range batch.Files {
			if err := addDir(filepath.Dir(content.Path)); err != nil {
				return err
			}
			before, err := Inspect(content.Path)
			if err != nil {
				return err
			}
			if previous == nil && before.Exists && !allowExisting {
				return fmt.Errorf("untracked existing deployment file: %s", content.Path)
			}
			after := before
			if !before.Exists {
				after = Snapshot{Mode: 0600, UID: os.Geteuid(), GID: os.Getegid()}
			}
			if content.Remove {
				after = Snapshot{}
			} else {
				after.Exists, after.Hash = true, Digest(content.Data)
			}
			index := len(j.Files)
			if !content.Remove {
				if err := WritePrivate(filepath.Join(stage, fmt.Sprintf("file-%d", index)), content.Data); err != nil {
					return err
				}
			}
			j.Files = append(j.Files, File{content.Path, before, after})
			group.Files = append(group.Files, index)
		}
		j.Groups = append(j.Groups, group)
	}
	for _, path := range guards {
		before, err := Inspect(path)
		if err != nil {
			return err
		}
		j.Guards = append(j.Guards, Guard{path, before})
	}
	if err := structure(&j); err != nil {
		return err
	}
	if err := s.Validate(&j); err != nil {
		return err
	}
	if err := SyncDir(stage); err != nil {
		return err
	}
	if err := SyncDir(s.Dir); err != nil {
		return err
	}
	return s.checkpoint(&j)
}

func (s *Store) Boundary(name string) error {
	if s.After != nil {
		return s.After(name)
	}
	return nil
}

func checkDirectories(j *Journal) error {
	for _, before := range j.Directories {
		now, err := InspectDirectory(before.Path)
		if err != nil {
			return err
		}
		if now != before {
			return fmt.Errorf("deployment directory replaced: %s", before.Path)
		}
	}
	return nil
}

func checkGuards(j *Journal) error {
	for _, guard := range j.Guards {
		now, err := Inspect(guard.Path)
		if err != nil {
			return err
		}
		if now != guard.Before {
			return fmt.Errorf("external change to deployment configuration: %s", guard.Path)
		}
	}
	return nil
}

func checkPublishedFiles(j *Journal) error {
	for _, group := range j.Groups {
		if !group.Published && !group.Done {
			continue
		}
		for _, index := range group.Files {
			file := j.Files[index]
			now, err := Inspect(file.Path)
			if err != nil {
				return err
			}
			if now != file.After {
				return fmt.Errorf("published deployment file changed: %s", file.Path)
			}
		}
	}
	return nil
}

func (s *Store) syncJournal() error {
	if err := SyncFile(filepath.Join(s.Dir, "current.json")); err != nil {
		return err
	}
	return SyncDir(s.Dir)
}

// CheckCompleted confirms the latest recorded contents without reactivating
// services. Configuration guards apply during a pending operation, not forever.
func (s *Store) CheckCompleted(j *Journal) error {
	if err := structure(j); err != nil {
		return err
	}
	if !j.Completed() {
		return errors.New("deployment is incomplete")
	}
	if err := checkDirectories(j); err != nil {
		return err
	}
	for _, file := range j.Files {
		now, err := Inspect(file.Path)
		if err != nil {
			return err
		}
		if now != file.After {
			return fmt.Errorf("completed deployment file changed: %s", file.Path)
		}
		if file.After.Exists {
			if err := SyncFile(file.Path); err != nil {
				return err
			}
		}
		if err := SyncDir(filepath.Dir(file.Path)); err != nil {
			return err
		}
	}
	return s.syncJournal()
}

// Replay accepts only the recorded old or new state. Completed groups must
// remain new. Activations without a durable checkpoint may be repeated.
func (s *Store) Replay() error {
	j, err := s.Load()
	if err != nil || j == nil {
		return err
	}
	if j.Completed() {
		return s.CheckCompleted(j)
	}
	// A previous checkpoint rename may have succeeded before its directory
	// synchronization failed. Make the observed journal durable before replay.
	if err := s.syncJournal(); err != nil {
		return err
	}
	if err := s.Validate(j); err != nil {
		return err
	}
	if err := PrivateDir(filepath.Join(s.Dir, j.Stage)); err != nil {
		return err
	}
	if err := checkDirectories(j); err != nil {
		return err
	}
	if err := checkGuards(j); err != nil {
		return err
	}
	completed := map[int]bool{}
	for _, group := range j.Groups {
		if group.Done || group.Published {
			for _, i := range group.Files {
				completed[i] = true
			}
		}
	}
	// Check every destination and every staged blob before the first write.
	for i, file := range j.Files {
		now, err := Inspect(file.Path)
		if err != nil {
			return err
		}
		if now != file.Before && now != file.After {
			return fmt.Errorf("external change to deployment file: %s", file.Path)
		}
		if completed[i] && now != file.After {
			return fmt.Errorf("completed deployment file changed: %s", file.Path)
		}
		if file.After.Exists {
			blob, err := ReadPrivate(filepath.Join(s.Dir, j.Stage, fmt.Sprintf("file-%d", i)))
			if err != nil {
				return err
			}
			if Digest(blob) != file.After.Hash {
				return fmt.Errorf("damaged staged file %d", i)
			}
		}
	}
	if j.Version == 1 {
		// Upgrade sequential journals before checkpointing independent results.
		// Preserve completed groups without inferring success for pending ones.
		j.Version = 2
		for i := range j.Groups {
			j.Groups[i].Published = j.Groups[i].Done
			if j.Groups[i].Reload != "" {
				j.Groups[i].Activation = "pending"
				if j.Groups[i].Done {
					j.Groups[i].Activation = "callback-succeeded"
				}
			}
		}
		if err := s.checkpoint(j); err != nil {
			return err
		}
	}
	// Publish every group before invoking any service hook. An activation
	// failure must not prevent independent services from receiving their files.
	for groupIndex := range j.Groups {
		group := &j.Groups[groupIndex]
		if group.Done || group.Published {
			continue
		}
		if err := checkDirectories(j); err != nil {
			return err
		}
		if err := checkGuards(j); err != nil {
			return err
		}
		for _, i := range group.Files {
			if err := checkDirectories(j); err != nil {
				return err
			}
			if err := checkGuards(j); err != nil {
				return err
			}
			file := j.Files[i]
			now, err := Inspect(file.Path)
			if err != nil {
				return err
			}
			if now != file.Before && now != file.After {
				return fmt.Errorf("deployment conflict: %s", file.Path)
			}
			if now != file.After {
				if file.After.Exists {
					blob, err := ReadPrivate(filepath.Join(s.Dir, j.Stage, fmt.Sprintf("file-%d", i)))
					if err != nil {
						return err
					}
					if Digest(blob) != file.After.Hash {
						return fmt.Errorf("damaged staged file %d", i)
					}
					if err := AtomicWrite(file.Path, blob, file.After); err != nil {
						return err
					}
				} else if now.Exists {
					if err := os.Remove(file.Path); err != nil {
						return err
					}
				}
			}
			if file.After.Exists {
				if err := SyncFile(file.Path); err != nil {
					return err
				}
			}
			if err := SyncDir(filepath.Dir(file.Path)); err != nil {
				return err
			}
			if err := s.Boundary(fmt.Sprintf("file-%d", i)); err != nil {
				return err
			}
		}
		group.Published = true
		if err := s.checkpoint(j); err != nil {
			return err
		}
		if err := s.Boundary("published-" + group.Name); err != nil {
			return err
		}
	}
	var activationErrors error
	for groupIndex := range j.Groups {
		group := &j.Groups[groupIndex]
		if group.Done {
			continue
		}
		if group.Reload != "" {
			if err := checkDirectories(j); err != nil {
				return err
			}
			if err := checkGuards(j); err != nil {
				return err
			}
			if err := checkPublishedFiles(j); err != nil {
				return err
			}
			if s.Reload == nil {
				return errors.New("deployment activation unavailable")
			}
			if err := s.Reload(group.Reload); err != nil {
				var local *ActivationError
				if !errors.As(err, &local) {
					return errors.Join(activationErrors, fmt.Errorf("activate %s: %w", group.Reload, err))
				}
				activationErrors = errors.Join(activationErrors, fmt.Errorf("activate %s: %w", group.Reload, err))
				group.Activation = "callback-failed"
				if !local.Attempted {
					group.Activation = "unavailable"
				}
				if err := s.checkpoint(j); err != nil {
					return errors.Join(activationErrors, err)
				}
				continue
			}
			if err := s.Boundary("reload-" + group.Reload); err != nil {
				return err
			}
			group.Activation = "callback-succeeded"
		}
		group.Done = true
		if err := s.checkpoint(j); err != nil {
			return err
		}
		if err := s.Boundary("group-" + group.Name); err != nil {
			return err
		}
	}
	if activationErrors != nil {
		return errors.Join(activationErrors, checkDirectories(j), checkGuards(j), checkPublishedFiles(j))
	}
	// Final observation is required before declaring success.
	return s.CheckCompleted(j)
}
