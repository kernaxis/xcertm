package dsm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kernaxis/xcertm/internal/deploy"
	"github.com/kernaxis/xcertm/internal/domain"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/kernaxis/xcertm/internal/state"
)

type creationOwner struct {
	Version       int    `json:"version"`
	Store         string `json:"store"`
	DestinationID string `json:"destination_id"`
	CertificateID string `json:"certificate_id"`
	OperationID   string `json:"operation_id"`
	GenerationID  string `json:"generation_id"`
	Fingerprint   string `json:"fingerprint"`
}

// Entry registration precedes certificate publication. The durable mapping and
// before/after INFO images reconcile a lost write response without allocating a
// second visible entry or overwriting an unrelated edit.
type managedEntry struct {
	Version       int             `json:"version"`
	ID            string          `json:"id"`
	DestinationID string          `json:"destination_id"`
	CertificateID string          `json:"certificate_id"`
	OperationID   string          `json:"operation_id"`
	GenerationID  string          `json:"generation_id"`
	Fingerprint   string          `json:"fingerprint"`
	Archive       state.Directory `json:"archive"`
	Directory     state.Directory `json:"directory"`
	InfoBefore    state.Snapshot  `json:"info_before"`
	Before        []byte          `json:"before"`
	After         []byte          `json:"after"`
	Registered    bool            `json:"registered"`
}

func (t *target) automatic() bool      { return !t.config.UseDefault && t.config.CertificateID == "" }
func (t *target) entryPath() string    { return filepath.Join(t.stateDir, "dsm-entry.json") }
func (t *target) creationPath() string { return filepath.Join(t.archive, ".xcertm-dsm-create") }
func (t *target) report(format string, args ...any) {
	if t.config.Progress != nil {
		t.config.Progress(fmt.Sprintf(format, args...))
	}
}

func (t *target) creation() (*creationOwner, error) {
	snapshot, err := state.Inspect(t.creationPath())
	if err != nil || !snapshot.Exists {
		return nil, err
	}
	data, err := state.ReadPrivate(t.creationPath())
	if err != nil {
		return nil, err
	}
	var owner creationOwner
	if err := state.Decode(data, &owner); err != nil {
		return nil, errors.New("invalid DSM entry creation marker")
	}
	if owner.Version != 1 || owner.Store == "" || owner.DestinationID == "" || owner.CertificateID == "" || owner.OperationID == "" || owner.GenerationID == "" || len(owner.Fingerprint) != 64 {
		return nil, errors.New("incomplete DSM entry creation marker")
	}
	return &owner, nil
}

func (t *target) checkCreationOwner() error {
	owner, err := t.creation()
	if err != nil || owner == nil {
		return err
	}
	if !t.automatic() || owner.Store != t.stateDir || owner.DestinationID != t.config.DestinationID {
		return errors.New("DSM entry creation is pending; resume its original destination and store")
	}
	return nil
}

func (t *target) claimCreation(owner creationOwner) error {
	if err := t.checkCreationOwner(); err != nil {
		return err
	}
	existing, err := t.creation()
	if err != nil {
		return err
	}
	if existing != nil && *existing != owner {
		return errors.New("DSM entry creation belongs to another operation or generation")
	}
	data, err := json.Marshal(owner)
	if err != nil {
		return err
	}
	return state.WritePrivate(t.creationPath(), data)
}

func (t *target) releaseCreation(certificateID string) error {
	if err := t.checkCreationOwner(); err != nil {
		return err
	}
	owner, err := t.creation()
	if err != nil {
		return err
	}
	if owner != nil {
		if owner.CertificateID != certificateID {
			return errors.New("DSM entry creation belongs to another managed certificate")
		}
		if err := os.Remove(t.creationPath()); err != nil {
			return err
		}
	}
	return state.SyncDir(t.archive)
}

func registeredInfo(before []byte, id, certificateID, destinationID string) ([]byte, error) {
	var info map[string]json.RawMessage
	if err := json.Unmarshal(before, &info); err != nil || info == nil {
		return nil, errors.New("invalid DSM INFO object")
	}
	if _, exists := info[id]; exists {
		return nil, errors.New("automatically allocated DSM ID already exists in INFO")
	}
	entry, err := json.Marshal(struct {
		Description   string    `json:"desc"`
		Services      []service `json:"services"`
		UserDeletable bool      `json:"user_deletable"`
	}{"XCertM: " + certificateID + " (" + destinationID + ")", []service{}, true})
	if err != nil {
		return nil, err
	}
	info[id] = entry
	return json.MarshalIndent(info, "", "\t")
}

func validGeneratedID(id string) bool {
	if len(id) != 6 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func (t *target) readEntry(certificateID string) (*managedEntry, error) {
	if _, err := os.Lstat(t.entryPath()); err != nil {
		return nil, err
	}
	data, err := state.ReadPrivate(t.entryPath())
	if err != nil {
		return nil, err
	}
	if len(data) > 32<<20 {
		return nil, errors.New("DSM entry state exceeds size limit")
	}
	var entry managedEntry
	if err := state.Decode(data, &entry); err != nil {
		return nil, errors.New("invalid automatic DSM entry state")
	}
	if entry.Version != 1 || !validGeneratedID(entry.ID) || entry.DestinationID != t.config.DestinationID || entry.CertificateID == "" || certificateID != "" && entry.CertificateID != certificateID || entry.OperationID == "" || entry.GenerationID == "" || len(entry.Fingerprint) != 64 || entry.Archive.Path != t.archive || entry.Directory.Path != filepath.Join(t.archive, entry.ID) || !entry.InfoBefore.Exists || state.Digest(entry.Before) != entry.InfoBefore.Hash {
		return nil, errors.New("automatic DSM entry identity or recorded metadata differs")
	}
	expected, err := registeredInfo(entry.Before, entry.ID, entry.CertificateID, entry.DestinationID)
	if err != nil || !bytes.Equal(expected, entry.After) {
		return nil, errors.New("invalid DSM entry registration contents")
	}
	return &entry, nil
}

// Validate the retained mapping even on receipt-only replays, which intentionally
// skip configuration guards in the generic file coordinator.
func (t *target) checkAutomaticEntry() error {
	journal, err := (&state.Store{Dir: t.stateDir}).Load()
	if err != nil {
		return err
	}
	entry, err := t.readEntry("")
	if os.IsNotExist(err) {
		if journal != nil {
			return errors.New("automatic DSM entry mapping is missing for a recorded deployment")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if journal != nil && (entry.ID != journal.Target || entry.CertificateID != journal.CertificateID || !entry.Registered) {
		return errors.New("automatic DSM mapping differs from its deployment journal")
	}
	if entry.Registered {
		if err := t.checkRegisteredEntry(entry); err != nil {
			return err
		}
		t.report("Using automatically managed DSM entry %q", entry.ID)
	}
	return nil
}

func (t *target) checkRegisteredEntry(entry *managedEntry) error {
	if err := t.checkEntryDirectories(entry); err != nil {
		return err
	}
	info, err := t.readInfo()
	if err != nil {
		return err
	}
	if _, exists := info[entry.ID]; !exists {
		return errors.New("managed DSM entry was removed from INFO; refusing to allocate another ID")
	}
	return nil
}

func (t *target) saveEntry(entry *managedEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if len(data) > 32<<20 {
		return errors.New("DSM entry state exceeds size limit")
	}
	return state.WritePrivate(t.entryPath(), data)
}

func (t *target) checkEntryDirectories(entry *managedEntry) error {
	for _, before := range []state.Directory{entry.Archive, entry.Directory} {
		now, err := state.InspectDirectory(before.Path)
		if err != nil {
			return err
		}
		if now != before {
			return errors.New("DSM entry or archive directory was replaced or changed")
		}
	}
	return nil
}

func (t *target) selectedID(certificateID string) (string, error) {
	if t.config.UseDefault {
		return t.defaultID()
	}
	if !t.automatic() {
		return t.config.CertificateID, nil
	}
	entry, err := t.readEntry(certificateID)
	if err != nil {
		return "", err
	}
	if !entry.Registered {
		return "", errors.New("DSM entry registration is incomplete; retry deployment")
	}
	if err := t.checkEntryDirectories(entry); err != nil {
		return "", err
	}
	return entry.ID, nil
}

// reserveDirectory follows mktemp -d _archive/XXXXXX: six alphanumeric
// characters and an exclusive mkdir. Go's MkdirTemp has a different suffix
// format; using the filesystem primitive avoids an external command dependency.
func (t *target) reserveDirectory(info map[string]json.RawMessage) (state.Directory, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for attempt := 0; attempt < 128; attempt++ {
		id := make([]byte, 6)
		for i := range id {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				return state.Directory{}, err
			}
			id[i] = alphabet[n.Int64()]
		}
		if _, exists := info[string(id)]; exists {
			continue
		}
		path := filepath.Join(t.archive, string(id))
		if err := os.Mkdir(path, 0700); os.IsExist(err) {
			continue
		} else if err != nil {
			return state.Directory{}, err
		}
		if err := state.SyncDir(t.archive); err != nil {
			return state.Directory{}, err
		}
		directory, err := state.InspectDirectory(path)
		if err != nil {
			return state.Directory{}, err
		}
		if directory.Mode != 0700 || directory.UID != os.Geteuid() {
			return state.Directory{}, errors.New("reserved DSM directory must be private and owned by the executing user")
		}
		return directory, nil
	}
	return state.Directory{}, errors.New("unable to reserve a unique six-character DSM entry ID")
}

func (t *target) Initialize(ctx context.Context, operationID string, generation domain.Generation, boundary func(string) error) error {
	if !t.automatic() {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	certificateID := generation.CertificateID()
	material, err := deploy.Render(generation)
	if err != nil {
		return err
	}
	identity, err := json.Marshal(struct {
		Material    string
		Provenance  domain.Provenance
		ValidatedAt time.Time
	}{material.Fingerprint, generation.Provenance(), generation.ValidatedAt()})
	if err != nil {
		return err
	}
	fingerprint := state.Digest(identity)
	owner := creationOwner{1, t.stateDir, t.config.DestinationID, certificateID, operationID, generation.ID(), fingerprint}
	journal, err := state.Inspect(filepath.Join(t.stateDir, "current.json"))
	if err != nil {
		return err
	}
	entry, err := t.readEntry(certificateID)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if entry != nil && !journal.Exists && (entry.OperationID != operationID || entry.GenerationID != generation.ID() || entry.Fingerprint != fingerprint) {
		return errors.New("DSM entry initialization must resume its original operation and generation")
	}
	if err == nil && entry.Registered {
		if err := state.SyncFile(t.entryPath()); err != nil {
			return err
		}
		if err := state.SyncDir(t.stateDir); err != nil {
			return err
		}
		if err := t.checkRegisteredEntry(entry); err != nil {
			return err
		}
		if err := t.releaseCreation(certificateID); err != nil {
			return err
		}
		return nil
	}
	if entry == nil {
		if journal.Exists {
			return errors.New("automatic DSM entry mapping is missing for a recorded deployment")
		}
	}
	if err := t.claimCreation(owner); err != nil {
		return err
	}
	if err := boundary("dsm-create-claimed"); err != nil {
		return err
	}
	if entry == nil {
		t.report("Creating a dedicated DSM certificate entry")
		archive, err := state.InspectDirectory(t.archive)
		if err != nil {
			return err
		}
		path := filepath.Join(t.archive, "INFO")
		before, err := state.Inspect(path)
		if err != nil {
			return err
		}
		if !before.Exists {
			return errors.New("DSM INFO is missing")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(data) > 8<<20 || state.Digest(data) != before.Hash {
			return errors.New("DSM INFO changed while preparing entry creation or exceeds size limit")
		}
		var info map[string]json.RawMessage
		if err := json.Unmarshal(data, &info); err != nil || info == nil {
			return errors.New("invalid DSM INFO object")
		}
		directory, err := t.reserveDirectory(info)
		if err != nil {
			return err
		}
		if err := boundary("dsm-directory-reserved"); err != nil {
			return err
		}
		id := filepath.Base(directory.Path)
		after, err := registeredInfo(data, id, certificateID, t.config.DestinationID)
		if err != nil {
			return err
		}
		entry = &managedEntry{Version: 1, ID: id, DestinationID: t.config.DestinationID, CertificateID: certificateID, OperationID: operationID, GenerationID: generation.ID(), Fingerprint: fingerprint, Archive: archive, Directory: directory, InfoBefore: before, Before: data, After: after}
		if err := t.saveEntry(entry); err != nil {
			return err
		}
		if err := boundary("dsm-entry-prepared"); err != nil {
			return err
		}
	}
	// Complete a prior checkpoint whose rename may have preceded a failed
	// directory sync before allowing any modification of DSM's INFO.
	if err := state.SyncFile(t.entryPath()); err != nil {
		return err
	}
	if err := state.SyncDir(t.stateDir); err != nil {
		return err
	}
	if err := t.checkEntryDirectories(entry); err != nil {
		return err
	}
	if err := t.checkCreationOwner(); err != nil {
		return err
	}
	path := filepath.Join(t.archive, "INFO")
	current, err := state.Inspect(path)
	if err != nil {
		return err
	}
	after := entry.InfoBefore
	after.Hash = state.Digest(entry.After)
	switch current {
	case entry.InfoBefore:
		if err := state.AtomicWrite(path, entry.After, after); err != nil {
			return err
		}
	case after:
	default:
		return errors.New("DSM INFO changed during automatic entry creation; restore the recorded state before retrying")
	}
	if err := state.SyncFile(path); err != nil {
		return err
	}
	if err := state.SyncDir(t.archive); err != nil {
		return err
	}
	if err := boundary("dsm-info-published"); err != nil {
		return err
	}
	entry.Registered = true
	if err := t.saveEntry(entry); err != nil {
		return err
	}
	if err := boundary("dsm-entry-registered"); err != nil {
		return err
	}
	if err := t.releaseCreation(certificateID); err != nil {
		return err
	}
	if err := boundary("dsm-entry-ready"); err != nil {
		return err
	}
	t.report("Created dedicated DSM entry %q; default and service assignments are unchanged", entry.ID)
	return nil
}
