// Package domain defines platform-independent certificate lifecycle invariants.
package domain

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// Provenance identifies how and where a generation originated. Source and
// Reference are opaque, non-blank strings; neither requires an ACME account.
type Provenance struct {
	Source    string
	Reference string
}

// GenerationInput supplies the identity, provenance, and material to validate.
// IDs are opaque, non-blank strings supplied by the caller. ValidatedAt is the
// explicit instant at which the material must be valid, not an issuance date.
type GenerationInput struct {
	ID              string
	CertificateID   string
	Provenance      Provenance
	CertificateDER  []byte
	ChainDER        [][]byte
	PrivateKeyPKCS8 []byte
	ValidatedAt     time.Time
}

// Generation is an immutable snapshot of validated certificate material and its
// identity and provenance. Construct it with NewGeneration; the zero value is
// uninitialized. Values may be copied safely. Validity was checked at
// ValidatedAt, which does not establish validity at a later time or public trust.
type Generation struct {
	id              string
	certificateID   string
	provenance      Provenance
	certificateDER  []byte
	chainDER        [][]byte
	privateKeyPKCS8 []byte
	validatedAt     time.Time
}

// NewGeneration validates a private copy of the input material and retains no
// caller-owned buffers. Identifiers are not generated or registered here;
// uniqueness and the existence of the managed certificate are caller concerns.
func NewGeneration(input GenerationInput) (Generation, error) {
	if strings.TrimSpace(input.ID) == "" {
		return Generation{}, fmt.Errorf("generation ID is required")
	}
	if strings.TrimSpace(input.CertificateID) == "" {
		return Generation{}, fmt.Errorf("managed certificate ID is required")
	}
	if strings.TrimSpace(input.Provenance.Source) == "" {
		return Generation{}, fmt.Errorf("provenance source is required")
	}
	if strings.TrimSpace(input.Provenance.Reference) == "" {
		return Generation{}, fmt.Errorf("provenance reference is required")
	}

	generation := Generation{
		id:              input.ID,
		certificateID:   input.CertificateID,
		provenance:      input.Provenance,
		certificateDER:  bytes.Clone(input.CertificateDER),
		chainDER:        cloneChain(input.ChainDER),
		privateKeyPKCS8: bytes.Clone(input.PrivateKeyPKCS8),
		validatedAt:     input.ValidatedAt.UTC(),
	}
	if err := ValidateGeneration(generation.certificateDER, generation.chainDER, generation.privateKeyPKCS8, generation.validatedAt); err != nil {
		return Generation{}, err
	}
	return generation, nil
}

// ID returns the generation's stable identity.
func (g Generation) ID() string { return g.id }

// CertificateID returns the identity of the managed certificate.
func (g Generation) CertificateID() string { return g.certificateID }

// Provenance returns the origin metadata by value.
func (g Generation) Provenance() Provenance { return g.provenance }

// ValidatedAt returns the validation instant in UTC.
func (g Generation) ValidatedAt() time.Time { return g.validatedAt }

// CertificateDER returns an independent copy of the DER leaf certificate.
func (g Generation) CertificateDER() []byte { return bytes.Clone(g.certificateDER) }

// ChainDER returns independent copies of the ordered DER issuer certificates.
func (g Generation) ChainDER() [][]byte { return cloneChain(g.chainDER) }

// PrivateKeyPKCS8 returns an independent copy of the unencrypted PKCS#8 DER key.
func (g Generation) PrivateKeyPKCS8() []byte { return bytes.Clone(g.privateKeyPKCS8) }

func cloneChain(chain [][]byte) [][]byte {
	if chain == nil {
		return nil
	}
	cloned := make([][]byte, len(chain))
	for i, der := range chain {
		cloned[i] = bytes.Clone(der)
	}
	return cloned
}

// ValidateGeneration checks certificate/key correspondence, validity at the
// supplied time, and consistency of the supplied issuer chain. Certificates
// are DER-encoded; the private key is unencrypted PKCS#8 DER. chainDER excludes
// the leaf and runs from its immediate issuer toward the root, which is optional.
// An empty chain is allowed, but provides no issuer-signature verification.
//
// This checks material coherence, not public trust: the last supplied
// certificate is used only as a local verification anchor. System roots, DNS
// ownership, expected names, TLS usage policy, and revocation are not checked.
// No inputs are retained or modified, and no validated generation is stored.
func ValidateGeneration(certificateDER []byte, chainDER [][]byte, privateKeyPKCS8 []byte, at time.Time) error {
	if at.IsZero() {
		return fmt.Errorf("validation time is required")
	}

	leaf, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return fmt.Errorf("parse leaf certificate: %w", err)
	}
	if leaf.IsCA {
		return fmt.Errorf("leaf certificate must not be a CA")
	}

	key, err := x509.ParsePKCS8PrivateKey(privateKeyPKCS8)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key does not support signing")
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("encode private key's public key: %w", err)
	}
	certificatePublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("encode certificate public key: %w", err)
	}
	if !bytes.Equal(keyPublic, certificatePublic) {
		return fmt.Errorf("certificate does not match private key")
	}

	certificates := []*x509.Certificate{leaf}
	seen := map[string]bool{string(leaf.Raw): true}
	for i, der := range chainDER {
		issuer, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parse chain certificate %d: %w", i, err)
		}
		if seen[string(issuer.Raw)] {
			return fmt.Errorf("duplicate certificate at chain position %d", i)
		}
		seen[string(issuer.Raw)] = true
		child := certificates[len(certificates)-1]
		if !bytes.Equal(child.RawIssuer, issuer.RawSubject) {
			return fmt.Errorf("issuer name mismatch at chain position %d", i)
		}
		if err := child.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("invalid issuer or signature at chain position %d: %w", i, err)
		}
		certificates = append(certificates, issuer)
	}

	for i, cert := range certificates {
		if !cert.NotBefore.Before(cert.NotAfter) {
			return fmt.Errorf("certificate %d has an invalid validity interval", i)
		}
		if at.Before(cert.NotBefore) || at.After(cert.NotAfter) {
			return fmt.Errorf("certificate %d is not valid at the supplied time", i)
		}
	}

	// Explicit pools avoid host trust and enforce X.509 constraints without
	// treating coherence with an arbitrary supplied issuer as public trust.
	roots := x509.NewCertPool()
	roots.AddCert(certificates[len(certificates)-1])
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certificates)-1; i++ {
		intermediates.AddCert(certificates[i])
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("verify supplied certificate chain: %w", err)
	}
	return nil
}
