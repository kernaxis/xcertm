package domain_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/kernaxis/xcertm/internal/domain"
)

func newGenerationInput(t *testing.T) domain.GenerationInput {
	t.Helper()
	f := newCertificateFixture(t)
	return domain.GenerationInput{
		ID:              "generation-1",
		CertificateID:   "certificate-1",
		Provenance:      domain.Provenance{Source: "acme", Reference: "https://ca.example.test/order/123"},
		CertificateDER:  f.certificateDER,
		ChainDER:        f.chainDER,
		PrivateKeyPKCS8: f.keyDER,
		ValidatedAt:     f.at,
	}
}

func checkGeneration(t *testing.T, generation domain.Generation, want domain.GenerationInput) {
	t.Helper()
	if generation.ID() != want.ID || generation.CertificateID() != want.CertificateID {
		t.Error("generation or managed certificate identity changed")
	}
	if generation.Provenance() != want.Provenance {
		t.Error("generation provenance changed")
	}
	if !generation.ValidatedAt().Equal(want.ValidatedAt) || generation.ValidatedAt().Location() != time.UTC {
		t.Error("validation time does not match the supplied instant in UTC")
	}
	if !bytes.Equal(generation.CertificateDER(), want.CertificateDER) {
		t.Error("certificate material changed")
	}
	if !bytes.Equal(generation.PrivateKeyPKCS8(), want.PrivateKeyPKCS8) {
		t.Error("private key material changed")
	}
	chain := generation.ChainDER()
	if len(chain) != len(want.ChainDER) {
		t.Fatalf("chain length = %d, want %d", len(chain), len(want.ChainDER))
	}
	for i, der := range chain {
		if !bytes.Equal(der, want.ChainDER[i]) {
			t.Errorf("chain certificate %d changed", i)
		}
	}
}

func TestNewGeneration(t *testing.T) {
	tests := []struct {
		name   string
		change func(*testing.T, *domain.GenerationInput)
		want   string
	}{
		{name: "valid ACME provenance"},
		{
			name: "no issuer supplied",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.ChainDER = nil
			},
		},
		{
			name: "non-ACME provenance",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.Provenance = domain.Provenance{Source: "internal-ca", Reference: "issuance-456"}
			},
		},
		{
			name: "explicit validation time in another timezone",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.ValidatedAt = input.ValidatedAt.In(time.FixedZone("test", 2*60*60))
			},
		},
		{
			name: "missing generation ID",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.ID = ""
			},
			want: "generation ID is required",
		},
		{
			name: "blank generation ID",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.ID = " \t\n"
			},
			want: "generation ID is required",
		},
		{
			name: "missing managed certificate ID",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.CertificateID = ""
			},
			want: "managed certificate ID is required",
		},
		{
			name: "blank managed certificate ID",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.CertificateID = " \t"
			},
			want: "managed certificate ID is required",
		},
		{
			name: "missing provenance",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.Provenance = domain.Provenance{}
			},
			want: "provenance source is required",
		},
		{
			name: "blank provenance source",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.Provenance.Source = " \t"
			},
			want: "provenance source is required",
		},
		{
			name: "missing provenance reference",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.Provenance.Reference = ""
			},
			want: "provenance reference is required",
		},
		{
			name: "blank provenance reference",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.Provenance.Reference = " \n"
			},
			want: "provenance reference is required",
		},
		{
			name: "invalid material",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.CertificateDER = nil
			},
			want: "parse leaf certificate",
		},
		{
			name: "mismatched key",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.PrivateKeyPKCS8 = privateKeyDER(t, newECDSAKey(t))
			},
			want: "does not match private key",
		},
		{
			name: "incorrect chain",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.ChainDER[0], input.ChainDER[1] = input.ChainDER[1], input.ChainDER[0]
			},
			want: "issuer name mismatch",
		},
		{
			name: "missing validation time",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.ValidatedAt = time.Time{}
			},
			want: "validation time is required",
		},
		{
			name: "expired material",
			change: func(t *testing.T, input *domain.GenerationInput) {
				input.ValidatedAt = input.ValidatedAt.Add(2 * time.Hour)
			},
			want: "certificate 0 is not valid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input := newGenerationInput(t)
			if tt.change != nil {
				tt.change(t, &input)
			}
			generation, err := domain.NewGeneration(input)
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				checkGeneration(t, generation, input)
			} else {
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("error = %v, want %q", err, tt.want)
				}
				if generation.ID() != "" || len(generation.PrivateKeyPKCS8()) != 0 {
					t.Error("failed construction returned an initialized generation")
				}
			}
		})
	}
}

func TestGenerationCopiesInput(t *testing.T) {
	input := newGenerationInput(t)
	want := input
	want.CertificateDER = bytes.Clone(input.CertificateDER)
	want.PrivateKeyPKCS8 = bytes.Clone(input.PrivateKeyPKCS8)
	want.ChainDER = make([][]byte, len(input.ChainDER))
	for i, der := range input.ChainDER {
		want.ChainDER[i] = bytes.Clone(der)
	}
	generation, err := domain.NewGeneration(input)
	if err != nil {
		t.Fatal(err)
	}

	input.ID = "changed"
	input.CertificateID = "changed"
	input.Provenance.Source = "changed"
	input.Provenance.Reference = "changed"
	input.ValidatedAt = time.Time{}
	clear(input.CertificateDER)
	clear(input.PrivateKeyPKCS8)
	clear(input.ChainDER[0])
	input.ChainDER[1] = nil
	checkGeneration(t, generation, want)
}

func TestGenerationAccessorsReturnCopies(t *testing.T) {
	input := newGenerationInput(t)
	generation, err := domain.NewGeneration(input)
	if err != nil {
		t.Fatal(err)
	}

	clear(generation.CertificateDER())
	clear(generation.PrivateKeyPKCS8())
	chain := generation.ChainDER()
	clear(chain[0])
	chain[1] = nil
	provenance := generation.Provenance()
	provenance.Source = "changed"
	provenance.Reference = "changed"
	checkGeneration(t, generation, input)
}
