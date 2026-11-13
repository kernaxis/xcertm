package deploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/kernaxis/xcertm/internal/state"
)

type owner struct {
	Store       string   `json:"store"`
	OperationID string   `json:"operation_id"`
	Paths       []string `json:"paths,omitempty"`
}

// All changes to this registry are serialized by the existing resource lock.
// Claims survive process loss, but reserve only the files actually published.
type resourceOwners struct {
	Version int     `json:"version"`
	Owners  []owner `json:"owners"`
}

func (s *Session) ownerPath() string { return filepath.Join(s.binding.Resource, ".xcertm-pending") }

func journalPaths(j *state.Journal) []string {
	paths := make([]string, 0, len(j.Files))
	for _, file := range j.Files {
		paths = append(paths, file.Path)
	}
	slices.Sort(paths)
	return paths
}

func samePaths(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func (o resourceOwners) forStore(dir string) *owner {
	for i := range o.Owners {
		if o.Owners[i].Store == dir {
			return &o.Owners[i]
		}
	}
	return nil
}

func (o resourceOwners) check(dir, operationID string, paths []string) error {
	for _, record := range o.Owners {
		if record.Store == dir {
			if record.OperationID != operationID || !samePaths(record.Paths, paths) {
				return errors.New("resource marker and journal disagree; manual recovery required")
			}
			continue
		}
		for _, path := range paths {
			if slices.Contains(record.Paths, path) {
				return fmt.Errorf("deployment file %s has unfinished work owned by %s", path, record.Store)
			}
		}
	}
	return nil
}

func (s *Session) readOwners() (resourceOwners, error) {
	registry := resourceOwners{Version: 1}
	snapshot, err := state.Inspect(s.ownerPath())
	if err != nil || !snapshot.Exists {
		return registry, err
	}
	data, err := state.ReadPrivate(s.ownerPath())
	if err != nil {
		return registry, err
	}
	var header struct{ Version int }
	if err := json.Unmarshal(data, &header); err != nil {
		return registry, errors.New("invalid resource owner marker")
	}
	if header.Version == 0 {
		// A legacy exclusive marker can be scoped only from its intact journal.
		var legacy struct {
			Store       string `json:"store"`
			OperationID string `json:"operation_id"`
		}
		if err := state.Decode(data, &legacy); err != nil || !filepath.IsAbs(legacy.Store) || filepath.Clean(legacy.Store) != legacy.Store || strings.TrimSpace(legacy.OperationID) == "" {
			return registry, errors.New("invalid legacy resource owner marker")
		}
		j, err := (&state.Store{Dir: legacy.Store}).Load()
		if err != nil {
			return registry, err
		}
		if j == nil {
			return registry, errors.New("resource marker exists without its journal; manual recovery required")
		}
		if j.OperationID != legacy.OperationID || j.Resource != s.binding.Resource || j.Kind != s.binding.Kind || filepath.Base(legacy.Store) != state.Digest([]byte(j.DestinationID)) || filepath.Base(filepath.Dir(legacy.Store)) != "deployments" {
			return registry, errors.New("legacy resource marker and journal disagree; manual recovery required")
		}
		registry.Owners = []owner{{legacy.Store, legacy.OperationID, journalPaths(j)}}
	} else if err := state.Decode(data, &registry); err != nil || registry.Version != 1 || len(registry.Owners) == 0 {
		return registry, errors.New("invalid resource ownership registry")
	}
	seen := map[string]bool{}
	for _, record := range registry.Owners {
		if !filepath.IsAbs(record.Store) || filepath.Clean(record.Store) != record.Store || seen[record.Store] || strings.TrimSpace(record.OperationID) == "" || len(record.Paths) == 0 {
			return registry, errors.New("invalid resource owner identity")
		}
		seen[record.Store] = true
		paths := map[string]bool{}
		for _, path := range record.Paths {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path || paths[path] {
				return registry, errors.New("invalid resource owner file scope")
			}
			paths[path] = true
		}
		if err := registry.check(record.Store, record.OperationID, record.Paths); err != nil {
			return registry, err
		}
	}
	return registry, nil
}

func (s *Session) writeOwners(registry resourceOwners) error {
	if len(registry.Owners) == 0 {
		if err := os.Remove(s.ownerPath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return state.SyncDir(s.binding.Resource)
	}
	data, err := json.Marshal(registry)
	if err != nil {
		return err
	}
	return state.WritePrivate(s.ownerPath(), data)
}

func (s *Session) claim(operationID string, paths []string) error {
	registry, err := s.readOwners()
	if err != nil {
		return err
	}
	if err := registry.check(s.store.Dir, operationID, paths); err != nil {
		return err
	}
	if registry.forStore(s.store.Dir) == nil {
		registry.Owners = append(registry.Owners, owner{s.store.Dir, operationID, slices.Clone(paths)})
	}
	return s.writeOwners(registry)
}

// New entry registration must not invalidate a legacy whole-INFO guard before
// its owner has had the opportunity to validate and upgrade that journal.
func (s *Session) checkInitialization(registry resourceOwners, writes []string) error {
	if len(writes) == 0 {
		return nil
	}
	for _, record := range registry.Owners {
		if record.Store == s.store.Dir {
			continue
		}
		j, err := (&state.Store{Dir: record.Store}).Load()
		if err != nil {
			return err
		}
		for _, path := range writes {
			if slices.Contains(record.Paths, path) {
				return fmt.Errorf("initialization file has unfinished work owned by %s", record.Store)
			}
			if j == nil {
				continue
			}
			for _, guard := range j.Guards {
				if guard.Path == path && guard.JSONKey == "" {
					return fmt.Errorf("resume deployment owned by %s before changing its whole-file configuration guard", record.Store)
				}
			}
		}
	}
	return nil
}

func (s *Session) release(operationID string) error {
	registry, err := s.readOwners()
	if err != nil {
		return err
	}
	for i, record := range registry.Owners {
		if record.Store != s.store.Dir {
			continue
		}
		if record.OperationID != operationID {
			return errors.New("resource owner changed during deployment")
		}
		registry.Owners = slices.Delete(registry.Owners, i, i+1)
		break
	}
	return s.writeOwners(registry)
}
