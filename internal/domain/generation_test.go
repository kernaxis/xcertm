package domain_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/kernaxis/xcertm/internal/domain"
)

type certificateFixture struct {
	at                          time.Time
	root, issuer, leaf          *x509.Certificate
	rootKey, issuerKey, leafKey *ecdsa.PrivateKey
	certificateDER              []byte
	chainDER                    [][]byte
	keyDER                      []byte
}

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func issueCertificate(t *testing.T, template, parent *x509.Certificate, publicKey crypto.PublicKey, signingKey crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func privateKeyDER(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func newCertificateFixture(t *testing.T) certificateFixture {
	t.Helper()
	f := certificateFixture{
		at:        time.Date(2026, time.November, 10, 12, 0, 0, 0, time.UTC),
		rootKey:   newECDSAKey(t),
		issuerKey: newECDSAKey(t),
		leafKey:   newECDSAKey(t),
	}
	root := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test root"},
		NotBefore:             f.at.Add(-48 * time.Hour),
		NotAfter:              f.at.Add(48 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            1,
	}
	f.root = issueCertificate(t, root, root, f.rootKey.Public(), f.rootKey)
	issuer := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test issuer"},
		NotBefore:             f.at.Add(-24 * time.Hour),
		NotAfter:              f.at.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	f.issuer = issueCertificate(t, issuer, f.root, f.issuerKey.Public(), f.rootKey)
	leaf := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		DNSNames:              []string{"example.com", "*.example.com"},
		NotBefore:             f.at.Add(-time.Hour),
		NotAfter:              f.at.Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	f.leaf = issueCertificate(t, leaf, f.issuer, f.leafKey.Public(), f.issuerKey)
	f.certificateDER = f.leaf.Raw
	f.chainDER = [][]byte{f.issuer.Raw, f.root.Raw}
	f.keyDER = privateKeyDER(t, f.leafKey)
	return f
}

func TestValidateGeneration(t *testing.T) {
	tests := []struct {
		name   string
		change func(*testing.T, *certificateFixture)
		want   string
	}{
		{name: "valid mixed standard and wildcard SANs"},
		{
			name: "root omitted",
			change: func(t *testing.T, f *certificateFixture) {
				f.chainDER = f.chainDER[:1]
			},
		},
		{
			name: "no issuer supplied",
			change: func(t *testing.T, f *certificateFixture) {
				f.chainDER = nil
			},
		},
		{
			name: "not-before boundary",
			change: func(t *testing.T, f *certificateFixture) {
				f.at = f.leaf.NotBefore
			},
		},
		{
			name: "not-after boundary",
			change: func(t *testing.T, f *certificateFixture) {
				f.at = f.leaf.NotAfter
			},
		},
		{
			name: "missing leaf",
			change: func(t *testing.T, f *certificateFixture) {
				f.certificateDER = nil
			},
			want: "parse leaf certificate",
		},
		{
			name: "malformed leaf",
			change: func(t *testing.T, f *certificateFixture) {
				f.certificateDER = []byte("invalid certificate")
			},
			want: "parse leaf certificate",
		},
		{
			name: "missing key",
			change: func(t *testing.T, f *certificateFixture) {
				f.keyDER = nil
			},
			want: "parse private key",
		},
		{
			name: "malformed key",
			change: func(t *testing.T, f *certificateFixture) {
				f.keyDER = []byte("invalid key")
			},
			want: "parse private key",
		},
		{
			name: "different private key",
			change: func(t *testing.T, f *certificateFixture) {
				f.keyDER = privateKeyDER(t, newECDSAKey(t))
			},
			want: "does not match private key",
		},
		{
			name: "non-signing private key",
			change: func(t *testing.T, f *certificateFixture) {
				xkey, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				f.keyDER = privateKeyDER(t, xkey)
			},
			want: "does not support signing",
		},
		{
			name: "CA as leaf",
			change: func(t *testing.T, f *certificateFixture) {
				f.certificateDER = f.root.Raw
				f.keyDER = privateKeyDER(t, f.rootKey)
			},
			want: "must not be a CA",
		},
		{
			name: "malformed chain certificate",
			change: func(t *testing.T, f *certificateFixture) {
				f.chainDER[0] = []byte("invalid issuer")
			},
			want: "parse chain certificate 0",
		},
		{
			name: "wrong chain order",
			change: func(t *testing.T, f *certificateFixture) {
				f.chainDER[0], f.chainDER[1] = f.chainDER[1], f.chainDER[0]
			},
			want: "issuer name mismatch",
		},
		{
			name: "duplicate root",
			change: func(t *testing.T, f *certificateFixture) {
				f.chainDER = append(f.chainDER, f.root.Raw)
			},
			want: "duplicate certificate",
		},
		{
			name: "leaf repeated in chain",
			change: func(t *testing.T, f *certificateFixture) {
				f.chainDER = [][]byte{f.leaf.Raw}
			},
			want: "duplicate certificate",
		},
		{
			name: "wrong issuer key with same subject",
			change: func(t *testing.T, f *certificateFixture) {
				other := issueCertificate(t, f.issuer, f.root, newECDSAKey(t).Public(), f.rootKey)
				f.chainDER[0] = other.Raw
			},
			want: "invalid issuer or signature",
		},
		{
			name: "wrong issuer subject with same key",
			change: func(t *testing.T, f *certificateFixture) {
				template := *f.issuer
				template.Subject = pkix.Name{CommonName: "Different issuer"}
				// Parsed raw subjects take precedence during certificate creation.
				template.RawSubject = nil
				other := issueCertificate(t, &template, f.root, f.issuerKey.Public(), f.rootKey)
				f.chainDER[0] = other.Raw
			},
			want: "issuer name mismatch",
		},
		{
			name: "issuer is not a CA",
			change: func(t *testing.T, f *certificateFixture) {
				template := *f.issuer
				template.IsCA = false
				template.MaxPathLenZero = false
				other := issueCertificate(t, &template, f.root, f.issuerKey.Public(), f.rootKey)
				f.chainDER[0] = other.Raw
			},
			want: "invalid issuer or signature",
		},
		{
			name: "issuer lacks certificate signing usage",
			change: func(t *testing.T, f *certificateFixture) {
				template := *f.issuer
				template.KeyUsage = x509.KeyUsageDigitalSignature
				other := issueCertificate(t, &template, f.root, f.issuerKey.Public(), f.rootKey)
				f.chainDER[0] = other.Raw
			},
			want: "invalid issuer or signature",
		},
		{
			name: "corrupted leaf signature",
			change: func(t *testing.T, f *certificateFixture) {
				f.certificateDER = bytes.Clone(f.certificateDER)
				clear(f.certificateDER[len(f.certificateDER)-len(f.leaf.Signature):])
			},
			want: "invalid issuer or signature",
		},
		{
			name: "missing validation time",
			change: func(t *testing.T, f *certificateFixture) {
				f.at = time.Time{}
			},
			want: "validation time is required",
		},
		{
			name: "not yet valid leaf",
			change: func(t *testing.T, f *certificateFixture) {
				f.at = f.leaf.NotBefore.Add(-time.Second)
			},
			want: "certificate 0 is not valid",
		},
		{
			name: "expired leaf",
			change: func(t *testing.T, f *certificateFixture) {
				f.at = f.leaf.NotAfter.Add(time.Second)
			},
			want: "certificate 0 is not valid",
		},
		{
			name: "expired issuer",
			change: func(t *testing.T, f *certificateFixture) {
				template := *f.issuer
				template.NotAfter = f.at.Add(-time.Second)
				other := issueCertificate(t, &template, f.root, f.issuerKey.Public(), f.rootKey)
				f.chainDER[0] = other.Raw
			},
			want: "certificate 1 is not valid",
		},
		{
			name: "invalid validity interval",
			change: func(t *testing.T, f *certificateFixture) {
				template := *f.leaf
				template.NotAfter = template.NotBefore
				other := issueCertificate(t, &template, f.issuer, f.leafKey.Public(), f.issuerKey)
				f.certificateDER = other.Raw
			},
			want: "invalid validity interval",
		},
		{
			name: "unknown critical extension",
			change: func(t *testing.T, f *certificateFixture) {
				template := *f.leaf
				template.ExtraExtensions = []pkix.Extension{{
					Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5},
					Critical: true,
					Value:    []byte{5, 0},
				}}
				other := issueCertificate(t, &template, f.issuer, f.leafKey.Public(), f.issuerKey)
				f.certificateDER = other.Raw
			},
			want: "unhandled critical extension",
		},
		{
			name: "path length constraint",
			change: func(t *testing.T, f *certificateFixture) {
				template := *f.root
				template.MaxPathLen = 0
				template.MaxPathLenZero = true
				other := issueCertificate(t, &template, &template, f.rootKey.Public(), f.rootKey)
				f.chainDER[1] = other.Raw
			},
			want: "too many intermediates",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newCertificateFixture(t)
			if tt.change != nil {
				tt.change(t, &f)
			}
			err := domain.ValidateGeneration(f.certificateDER, f.chainDER, f.keyDER, f.at)
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateGenerationKeyAlgorithms(t *testing.T) {
	tests := []struct {
		name string
		key  func(*testing.T) crypto.Signer
	}{
		{name: "ECDSA", key: func(t *testing.T) crypto.Signer { return newECDSAKey(t) }},
		{name: "RSA", key: func(t *testing.T) crypto.Signer {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
		{name: "Ed25519", key: func(t *testing.T) crypto.Signer {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newCertificateFixture(t)
			key := tt.key(t)
			leaf := issueCertificate(t, f.leaf, f.issuer, key.Public(), f.issuerKey)
			if err := domain.ValidateGeneration(leaf.Raw, [][]byte{f.issuer.Raw, f.root.Raw}, privateKeyDER(t, key), f.at); err != nil {
				t.Fatal(err)
			}
		})
	}
}
