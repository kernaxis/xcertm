package domain_test

import (
	"bytes"
	"crypto/x509/pkix"
	"slices"
	"strings"
	"testing"

	"github.com/kernaxis/xcertm/internal/domain"
)

func generationForNames(t *testing.T, names []string, commonName string) domain.Generation {
	t.Helper()
	f := newCertificateFixture(t)
	template := *f.leaf
	template.DNSNames = names
	template.Subject = pkix.Name{CommonName: commonName}
	template.RawSubject = nil
	leaf := issueCertificate(t, &template, f.issuer, f.leafKey.Public(), f.issuerKey)
	generation, err := domain.NewGeneration(domain.GenerationInput{
		ID:              "generation-1",
		CertificateID:   "certificate-1",
		Provenance:      domain.Provenance{Source: "test-ca", Reference: "issuance-1"},
		CertificateDER:  leaf.Raw,
		ChainDER:        f.chainDER,
		PrivateKeyPKCS8: f.keyDER,
		ValidatedAt:     f.at,
	})
	if err != nil {
		t.Fatal(err)
	}
	return generation
}

func TestGenerationValidateDNSNames(t *testing.T) {
	longest := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	tests := []struct {
		name       string
		actual     []string
		expected   []string
		commonName string
		want       string
	}{
		{name: "standard", actual: []string{"example.com"}, expected: []string{"example.com"}},
		{name: "wildcard", actual: []string{"*.example.com"}, expected: []string{"*.example.com"}},
		{name: "mixed SANs in different order", actual: []string{"example.com", "*.example.com", "www.other.example"}, expected: []string{"www.other.example", "*.example.com", "example.com"}},
		{name: "case and root dot in request", actual: []string{"example.com", "*.example.com"}, expected: []string{"EXAMPLE.COM.", "*.EXAMPLE.COM."}},
		{name: "case and root dot in certificate", actual: []string{"EXAMPLE.COM.", "*.EXAMPLE.COM."}, expected: []string{"example.com", "*.example.com"}},
		{name: "request duplicates", actual: []string{"example.com"}, expected: []string{"example.com", "EXAMPLE.COM.", "example.com"}},
		{name: "certificate duplicates", actual: []string{"example.com", "EXAMPLE.COM.", "example.com"}, expected: []string{"example.com"}},
		{name: "ASCII A-label", actual: []string{"xn--bcher-kva.example"}, expected: []string{"XN--BCHER-KVA.EXAMPLE."}},
		{name: "single label", actual: []string{"intranet"}, expected: []string{"INTRANET"}},
		{name: "maximum length and root dot", actual: []string{longest}, expected: []string{longest + "."}},
		{name: "CN is not part of DNS SAN set", actual: []string{"example.com"}, expected: []string{"example.com"}, commonName: "other.example"},
		{name: "missing requested name", actual: []string{"example.com"}, expected: []string{"example.com", "www.example.com"}, want: `missing=["www.example.com"]; unexpected=[]`},
		{name: "additional name", actual: []string{"example.com", "other.example"}, expected: []string{"example.com"}, want: `missing=[]; unexpected=["other.example"]`},
		{name: "both missing and unexpected sorted", actual: []string{"z.example", "a.example"}, expected: []string{"y.example", "b.example"}, want: `missing=["b.example" "y.example"]; unexpected=["a.example" "z.example"]`},
		{name: "wildcard does not replace apex", actual: []string{"*.example.com"}, expected: []string{"example.com"}, want: `missing=["example.com"]; unexpected=["*.example.com"]`},
		{name: "wildcard does not replace requested hostname", actual: []string{"*.example.com"}, expected: []string{"www.example.com"}, want: `missing=["www.example.com"]; unexpected=["*.example.com"]`},
		{name: "hostname does not replace requested wildcard", actual: []string{"www.example.com"}, expected: []string{"*.example.com"}, want: `missing=["*.example.com"]; unexpected=["www.example.com"]`},
		{name: "apex missing from mixed request", actual: []string{"*.example.com"}, expected: []string{"example.com", "*.example.com"}, want: `missing=["example.com"]; unexpected=[]`},
		{name: "no requested names", actual: []string{"example.com"}, want: "at least one requested DNS name is required"},
		{name: "no DNS SANs", expected: []string{"example.com"}, want: "certificate has no DNS SANs"},
		{name: "no Common Name fallback", expected: []string{"example.com"}, commonName: "example.com", want: "certificate has no DNS SANs"},
		{name: "empty requested name", actual: []string{"example.com"}, expected: []string{""}, want: "requested DNS names: invalid DNS name"},
		{name: "empty certificate name", actual: []string{""}, expected: []string{"example.com"}, want: "certificate DNS SANs: invalid DNS name"},
		{name: "invalid certificate hostname", actual: []string{"bad_name.example"}, expected: []string{"example.com"}, want: "certificate DNS SANs: invalid DNS name"},
		{name: "invalid certificate wildcard", actual: []string{"www.*.example.com"}, expected: []string{"example.com"}, want: "certificate DNS SANs: invalid DNS name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			generation := generationForNames(t, tt.actual, tt.commonName)
			err := generation.ValidateDNSNames(tt.expected)
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

func TestGenerationRejectsInvalidRequestedDNSNames(t *testing.T) {
	generation := generationForNames(t, []string{"example.com"}, "")
	names := []string{
		".", "example..com", ".example.com", "example.com..",
		" example.com", "example.com ", "example.com\n", "ex ample.com",
		"-example.com", "example-.com", "bad_name.example", "https://example.com", "example.com:443",
		"*", "*.", "*example.com", "foo*.example.com", "www.*.example.com", "*.*.example.com",
		"bücher.example", "K.example", "127.0.0.1", "2001:db8::1", "*.127.0.0.1",
		strings.Repeat("a", 64) + ".example",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62),
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := generation.ValidateDNSNames([]string{name}); err == nil || !strings.Contains(err.Error(), "requested DNS names: invalid DNS name") {
				t.Fatalf("error = %v, want invalid requested DNS name", err)
			}
		})
	}
}

func TestGenerationValidateDNSNamesDoesNotModifyInputs(t *testing.T) {
	generation := generationForNames(t, []string{"EXAMPLE.COM.", "*.EXAMPLE.COM."}, "")
	before := generation.CertificateDER()
	expected := []string{"*.example.com", "Example.Com.", "example.com"}
	beforeExpected := slices.Clone(expected)
	if err := generation.ValidateDNSNames(expected); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(expected, beforeExpected) {
		t.Error("requested names were modified")
	}
	if !bytes.Equal(generation.CertificateDER(), before) {
		t.Error("generation certificate was modified")
	}
}

func TestUninitializedGenerationValidateDNSNames(t *testing.T) {
	var generation domain.Generation
	if err := generation.ValidateDNSNames([]string{"example.com"}); err == nil || !strings.Contains(err.Error(), "generation is uninitialized") {
		t.Fatalf("error = %v, want uninitialized generation", err)
	}
}
