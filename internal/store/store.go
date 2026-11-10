// Package store persists accounts, obtained generations, and lifecycle records.
// It is independent of configuration-file loading and performs no network I/O.
package store

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kernaxis/xcertm/internal/config"
	"github.com/kernaxis/xcertm/internal/dns"
	"github.com/kernaxis/xcertm/internal/domain"
	"github.com/kernaxis/xcertm/internal/state"
)

type Store struct {
	Root string
	lock *os.File
}

func Open(root string, write bool) (*Store, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	s := &Store{Root: abs}
	if !write {
		if _, err := os.Lstat(abs); os.IsNotExist(err) {
			return s, nil
		} else if err != nil {
			return nil, err
		}
		directory, err := state.InspectDirectory(abs)
		if err != nil {
			return nil, err
		}
		if directory.Mode != 0700 || directory.UID != os.Geteuid() {
			return nil, errors.New("store directory must be owned by the executing user with mode 0700")
		}
		return s, nil
	}
	if err := state.PrivateDir(abs); err != nil {
		return nil, err
	}
	lock, err := state.Lock(filepath.Join(abs, ".lifecycle.lock"))
	if err != nil {
		return nil, err
	}
	s.lock = lock
	for _, name := range []string{"accounts", "certificates", "deployment-requests"} {
		if err := state.PrivateDir(filepath.Join(abs, name)); err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) Close() error {
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}
func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func (s *Store) CertDir(id string) string {
	return filepath.Join(s.Root, "certificates", state.Digest([]byte(id)))
}
func (s *Store) EnsureCertificate(id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("certificate ID is required")
	}
	if err := state.PrivateDir(s.CertDir(id)); err != nil {
		return err
	}
	return state.PrivateDir(filepath.Join(s.CertDir(id), "generations"))
}

func readJSON(path string, out any) error {
	if _, err := os.Lstat(path); err != nil {
		return err
	}
	data, err := state.ReadPrivate(path)
	if err != nil {
		return err
	}
	if len(data) > 8<<20 {
		return errors.New("state document is too large")
	}
	if err := state.Decode(data, out); err != nil {
		return fmt.Errorf("invalid persistent state: %w", err)
	}
	return nil
}
func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > 8<<20 {
		return errors.New("state document is too large")
	}
	return state.WritePrivate(path, data)
}

type Account struct {
	Version      int    `json:"version"`
	DirectoryURL string `json:"directory_url"`
	Email        string `json:"email"`
	KID          string `json:"kid"`
	KeyPKCS8     []byte `json:"key_pkcs8"`
}

func (s *Store) accountDir(directory, email string) string {
	return filepath.Join(s.Root, "accounts", state.Digest([]byte(directory+"\x00"+email)))
}
func (s *Store) Account(directory, email string) (Account, error) {
	var a Account
	err := readJSON(filepath.Join(s.accountDir(directory, email), "account.json"), &a)
	if err != nil {
		return a, err
	}
	if a.Version != 1 || a.DirectoryURL != directory || a.Email != email || len(a.KeyPKCS8) == 0 {
		return a, errors.New("invalid ACME account state")
	}
	return a, nil
}
func (s *Store) SaveAccount(a Account) error {
	a.Version = 1
	dir := s.accountDir(a.DirectoryURL, a.Email)
	if err := state.PrivateDir(dir); err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, "account.json"), a)
}

type Pending struct {
	Version        int               `json:"version"`
	ID             string            `json:"id"`
	GenerationID   string            `json:"generation_id"`
	Request        config.Request    `json:"request"`
	DirectoryURL   string            `json:"directory_url"`
	KeyPKCS8       []byte            `json:"key_pkcs8"`
	CSR            []byte            `json:"csr"`
	OrderURL       string            `json:"order_url"`
	OrderAttempted bool              `json:"order_attempted"`
	Publications   []dns.Publication `json:"publications"`
	RetryAt        time.Time         `json:"retry_at"`
}

func (s *Store) Pending(id string) (*Pending, error) {
	var p Pending
	err := readJSON(filepath.Join(s.CertDir(id), "pending.json"), &p)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if p.Version != 1 || p.Request.ID != id || p.ID == "" || !validGenerationID(p.GenerationID) || p.DirectoryURL == "" || len(p.KeyPKCS8) == 0 || len(p.CSR) == 0 {
		return nil, errors.New("invalid pending issuance")
	}
	key, err := x509.ParsePKCS8PrivateKey(p.KeyPKCS8)
	if err != nil {
		return nil, errors.New("invalid pending certificate key")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("pending certificate key cannot sign")
	}
	csr, err := x509.ParseCertificateRequest(p.CSR)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("invalid pending certificate request")
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, csr.RawSubjectPublicKeyInfo) {
		return nil, errors.New("pending certificate request and key differ")
	}
	names, err := domain.NormalizeDNSNames(csr.DNSNames)
	if err != nil {
		return nil, errors.New("invalid pending DNS identifiers")
	}
	wanted, err := domain.NormalizeDNSNames(p.Request.Certificate.Domains)
	if err != nil || !slices.Equal(names, wanted) {
		return nil, errors.New("pending certificate request and desired DNS identifiers differ")
	}
	return &p, nil
}
func (s *Store) SavePending(p *Pending) error {
	p.Version = 1
	return writeJSON(filepath.Join(s.CertDir(p.Request.ID), "pending.json"), p)
}
func (s *Store) FinishPending(id string) error {
	path := filepath.Join(s.CertDir(id), "pending.json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return state.SyncDir(s.CertDir(id))
}
func (s *Store) ArchivePending(p *Pending) error {
	if !validGenerationID(p.ID) {
		return errors.New("invalid issuance operation ID")
	}
	if err := writeJSON(filepath.Join(s.CertDir(p.Request.ID), "failed-"+p.ID+".json"), p); err != nil {
		return err
	}
	return s.FinishPending(p.Request.ID)
}

type GenerationRecord struct {
	Version      int                    `json:"version"`
	DirectoryURL string                 `json:"directory_url"`
	Request      config.Request         `json:"request"`
	Input        domain.GenerationInput `json:"generation"`
}
type manifest struct {
	Version     int      `json:"version"`
	ID          string   `json:"id"`
	Generations []string `json:"generations"`
}

func validGenerationID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func (s *Store) Generation(id, generationID string) (domain.Generation, GenerationRecord, error) {
	var record GenerationRecord
	if !validGenerationID(generationID) {
		return domain.Generation{}, record, errors.New("invalid generation ID")
	}
	err := readJSON(filepath.Join(s.CertDir(id), "generations", generationID+".json"), &record)
	if err != nil {
		return domain.Generation{}, record, err
	}
	if record.Version != 1 || record.Input.ID != generationID || record.Input.CertificateID != id || record.Request.ID != id || record.DirectoryURL == "" {
		return domain.Generation{}, record, errors.New("invalid stored generation identity")
	}
	g, err := domain.NewGeneration(record.Input)
	if err == nil {
		err = g.ValidateDNSNames(record.Request.Certificate.Domains)
	}
	return g, record, err
}

func (s *Store) manifest(id string) (manifest, error) {
	var m manifest
	err := readJSON(filepath.Join(s.CertDir(id), "certificate.json"), &m)
	if err != nil {
		return m, err
	}
	if m.Version != 1 || m.ID != id {
		return m, errors.New("invalid stored certificate manifest")
	}
	seen := map[string]bool{}
	for _, gid := range m.Generations {
		if !validGenerationID(gid) || seen[gid] {
			return m, errors.New("invalid generation references")
		}
		seen[gid] = true
	}
	return m, nil
}

func (s *Store) SaveGeneration(g domain.Generation, request config.Request, directory string) error {
	if g.CertificateID() != request.ID || directory == "" {
		return errors.New("generation identity differs from request")
	}
	if err := g.ValidateDNSNames(request.Certificate.Domains); err != nil {
		return err
	}
	if err := s.EnsureCertificate(request.ID); err != nil {
		return err
	}
	record := GenerationRecord{Version: 1, DirectoryURL: directory, Request: request, Input: domain.GenerationInput{ID: g.ID(), CertificateID: g.CertificateID(), Provenance: g.Provenance(), CertificateDER: g.CertificateDER(), ChainDER: g.ChainDER(), PrivateKeyPKCS8: g.PrivateKeyPKCS8(), ValidatedAt: g.ValidatedAt()}}
	path := filepath.Join(s.CertDir(request.ID), "generations", g.ID()+".json")
	if !validGenerationID(g.ID()) {
		return errors.New("invalid generation ID")
	}
	if _, err := os.Lstat(path); err == nil {
		existing, saved, err := s.Generation(request.ID, g.ID())
		if err != nil {
			return err
		}
		if saved.DirectoryURL != directory || saved.Request.ACME != request.ACME || !slices.EqualFunc(existing.ChainDER(), g.ChainDER(), bytes.Equal) || state.Digest(existing.CertificateDER()) != state.Digest(g.CertificateDER()) || state.Digest(existing.PrivateKeyPKCS8()) != state.Digest(g.PrivateKeyPKCS8()) || existing.Provenance() != g.Provenance() || !existing.ValidatedAt().Equal(g.ValidatedAt()) {
			return errors.New("immutable generation already exists with different material")
		}
	} else if !os.IsNotExist(err) {
		return err
	} else if err := writeJSON(path, record); err != nil {
		return err
	}
	if err := state.SyncFile(path); err != nil {
		return err
	}
	if err := state.SyncDir(filepath.Dir(path)); err != nil {
		return err
	}
	m, err := s.manifest(request.ID)
	if os.IsNotExist(err) {
		m = manifest{Version: 1, ID: request.ID}
	} else if err != nil {
		return err
	}
	if !slices.Contains(m.Generations, g.ID()) {
		m.Generations = append(m.Generations, g.ID())
	}
	return writeJSON(filepath.Join(s.CertDir(request.ID), "certificate.json"), m)
}

func (s *Store) Generations(id string) ([]GenerationRecord, error) {
	m, err := s.manifest(id)
	if err != nil {
		return nil, err
	}
	var records []GenerationRecord
	for _, gid := range m.Generations {
		_, r, err := s.Generation(id, gid)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, nil
}
func (s *Store) Latest(id, environment string) (domain.Generation, GenerationRecord, error) {
	records, err := s.Generations(id)
	if err != nil {
		return domain.Generation{}, GenerationRecord{}, err
	}
	for i := len(records) - 1; i >= 0; i-- {
		r := records[i]
		if environment == "" || r.Request.ACME.Environment == environment {
			return s.Generation(id, r.Input.ID)
		}
	}
	return domain.Generation{}, GenerationRecord{}, os.ErrNotExist
}

func (s *Store) IDs() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.Root, "certificates"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if !e.IsDir() {
			return nil, errors.New("unexpected certificate store entry")
		}
		var m manifest
		err := readJSON(filepath.Join(s.Root, "certificates", e.Name(), "certificate.json"), &m)
		if os.IsNotExist(err) {
			// Pending-only directories are inspected separately; no obtained
			// certificate exists yet, so they do not appear in list.
			var pending Pending
			if err := readJSON(filepath.Join(s.Root, "certificates", e.Name(), "pending.json"), &pending); os.IsNotExist(err) {
				// Preparation or archival can leave a directory with no obtained
				// generation. It is not a certificate listed to the user.
				generations, err := os.ReadDir(filepath.Join(s.Root, "certificates", e.Name(), "generations"))
				if err != nil && !os.IsNotExist(err) {
					return nil, err
				}
				if len(generations) > 0 {
					return nil, errors.New("stored generations have neither a certificate manifest nor pending issuance")
				}
				continue
			} else if err != nil {
				return nil, err
			}
			if pending.Request.ID == "" || state.Digest([]byte(pending.Request.ID)) != e.Name() {
				return nil, errors.New("invalid pending certificate directory")
			}
			if _, err := s.Pending(pending.Request.ID); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		if m.ID == "" || state.Digest([]byte(m.ID)) != e.Name() {
			return nil, errors.New("invalid certificate store directory")
		}
		if _, err := s.Generations(m.ID); err != nil {
			return nil, err
		}
		ids = append(ids, m.ID)
	}
	slices.Sort(ids)
	return ids, nil
}

func (s *Store) WorkIDs() ([]string, error) {
	ids, err := s.IDs()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(s.Root, "certificates"))
	if os.IsNotExist(err) {
		return ids, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		var p Pending
		err := readJSON(filepath.Join(s.Root, "certificates", e.Name(), "pending.json"), &p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if p.Request.ID == "" || state.Digest([]byte(p.Request.ID)) != e.Name() {
			return nil, errors.New("invalid pending issuance identity")
		}
		if _, err := s.Pending(p.Request.ID); err != nil {
			return nil, err
		}
		if !slices.Contains(ids, p.Request.ID) {
			ids = append(ids, p.Request.ID)
		}
	}
	slices.Sort(ids)
	return ids, nil
}

type Deployment struct {
	Version       int                `json:"version"`
	ID            string             `json:"id"`
	CertificateID string             `json:"certificate_id"`
	GenerationID  string             `json:"generation_id"`
	Environment   string             `json:"environment"`
	OperationID   string             `json:"operation_id"`
	Destination   config.Destination `json:"destination"`
	Completed     bool               `json:"completed"`
}

func (s *Store) SaveDeployment(d Deployment) error {
	d.Version = 1
	return writeJSON(filepath.Join(s.Root, "deployment-requests", state.Digest([]byte(d.ID))+".json"), d)
}
func (s *Store) Deployments(id string) ([]Deployment, error) {
	entries, err := os.ReadDir(filepath.Join(s.Root, "deployment-requests"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var found []Deployment
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, errors.New("unexpected deployment store directory")
		}
		var d Deployment
		if err := readJSON(filepath.Join(s.Root, "deployment-requests", entry.Name()), &d); err != nil {
			return nil, err
		}
		if d.Version != 1 || d.ID == "" || d.CertificateID == "" || !validGenerationID(d.GenerationID) || entry.Name() != state.Digest([]byte(d.ID))+".json" {
			return nil, errors.New("invalid deployment request")
		}
		if d.OperationID == "" || d.Environment != "production" && d.Environment != "staging" {
			return nil, errors.New("invalid deployment operation identity")
		}
		if err := d.Destination.Validate(); err != nil {
			return nil, errors.New("invalid stored destination parameters")
		}
		if id == "" || d.CertificateID == id {
			found = append(found, d)
		}
	}
	slices.SortFunc(found, func(a, b Deployment) int { return strings.Compare(a.ID, b.ID) })
	return found, nil
}
