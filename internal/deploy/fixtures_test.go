//go:build linux

package deploy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kernaxis/xcertm/internal/deploy"
	"github.com/kernaxis/xcertm/internal/domain"
	"github.com/kernaxis/xcertm/internal/state"
)

func generation(t *testing.T, id string, noChain bool) domain.Generation {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"example.com", "*.example.com"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{caDER}
	if noChain {
		chain = nil
	}
	g, err := domain.NewGeneration(domain.GenerationInput{ID: id, CertificateID: "certificate-1", Provenance: domain.Provenance{Source: "test", Reference: "issuance-" + id}, CertificateDER: der, ChainDER: chain, PrivateKeyPKCS8: private, ValidatedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func journalDir(root, id string) string {
	return filepath.Join(root, "deployments", state.Digest([]byte(id)))
}

func journal(t *testing.T, root, id string) *state.Journal {
	t.Helper()
	s := state.Store{Dir: journalDir(root, id)}
	j, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if j == nil {
		t.Fatal("expected durable journal")
	}
	return j
}

func checkPublished(t *testing.T, dir string, g domain.Generation, fullchain bool) {
	t.Helper()
	name := "cert.pem"
	if fullchain {
		name = "fullchain.pem"
	}
	pair, err := tls.X509KeyPair(read(t, filepath.Join(dir, name)), read(t, filepath.Join(dir, "privkey.pem")))
	if err != nil {
		t.Fatal("published certificate and key do not match")
	}
	if state.Digest(pair.Certificate[0]) != state.Digest(g.CertificateDER()) {
		t.Fatal("published generation differs")
	}
}

func deployOK(t *testing.T, s *deploy.Session, op string, g domain.Generation) deploy.Result {
	t.Helper()
	r, err := s.Deploy(context.Background(), op, g)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Completed || r.GenerationID != g.ID() || r.OperationID != op {
		t.Fatal("incorrect deployment result")
	}
	return r
}
