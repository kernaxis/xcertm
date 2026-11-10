package app

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/kernaxis/xcertm/internal/domain"
	"github.com/kernaxis/xcertm/internal/store"
)

// CertificateInfo deliberately contains no private keys, credentials, or full
// persisted request. It is the only shape serialized by list/show.
type CertificateInfo struct {
	ID                 string            `json:"id"`
	GenerationID       string            `json:"generation_id"`
	Environment        string            `json:"environment"`
	Domains            []string          `json:"domains"`
	NotBefore          time.Time         `json:"not_before"`
	NotAfter           time.Time         `json:"not_after"`
	ValidatedAt        time.Time         `json:"validated_at"`
	Issuer             string            `json:"issuer"`
	PublicKeyAlgorithm string            `json:"public_key_algorithm"`
	Fingerprint        string            `json:"sha256"`
	Provenance         domain.Provenance `json:"provenance"`
	Deployments        []DeploymentInfo  `json:"deployments,omitempty"`
	IssuancePending    bool              `json:"issuance_pending"`
}
type DeploymentInfo struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	GenerationID string `json:"generation_id"`
	Completed    bool   `json:"completed"`
}

func (a *Service) Show(id, environment string) ([]CertificateInfo, error) {
	s, err := store.Open(a.Root, false)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	records, err := s.Generations(id)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("certificate %q is not in the store", id)
	}
	if err != nil {
		return nil, err
	}
	deployments, err := s.Deployments(id)
	if err != nil {
		return nil, err
	}
	pending, err := s.Pending(id)
	if err != nil {
		return nil, err
	}
	var infos []CertificateInfo
	for _, r := range records {
		if environment != "" && r.Request.ACME.Environment != environment {
			continue
		}
		leaf, err := x509.ParseCertificate(r.Input.CertificateDER)
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256(leaf.Raw)
		info := CertificateInfo{ID: id, GenerationID: r.Input.ID, Environment: r.Request.ACME.Environment, Domains: leaf.DNSNames, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, ValidatedAt: r.Input.ValidatedAt, Issuer: leaf.Issuer.String(), PublicKeyAlgorithm: leaf.PublicKeyAlgorithm.String(), Fingerprint: hex.EncodeToString(hash[:]), Provenance: r.Input.Provenance, IssuancePending: pending != nil && pending.Request.ACME.Environment == r.Request.ACME.Environment}
		for _, d := range deployments {
			if d.Environment == info.Environment {
				info.Deployments = append(info.Deployments, DeploymentInfo{d.ID, d.Destination.Type, d.GenerationID, d.Completed})
			}
		}
		infos = append(infos, info)
	}
	if len(infos) == 0 {
		return nil, fmt.Errorf("certificate %q has no stored generation in the selected environment", id)
	}
	return infos, nil
}

func (a *Service) List(environment string) ([]CertificateInfo, error) {
	ids, err := a.IDs()
	if err != nil {
		return nil, err
	}
	rows := []CertificateInfo{}
	for _, id := range ids {
		infos, err := a.Show(id, "")
		if err != nil {
			return nil, err
		}
		latest := map[string]CertificateInfo{}
		order := []string{}
		for _, info := range infos {
			if _, ok := latest[info.Environment]; !ok {
				order = append(order, info.Environment)
			}
			latest[info.Environment] = info
		}
		for _, env := range order {
			if environment == "" || env == environment {
				rows = append(rows, latest[env])
			}
		}
	}
	return rows, nil
}
