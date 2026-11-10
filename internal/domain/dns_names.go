package domain

import (
	"crypto/x509"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// ValidateDNSNames checks that the generation's DNS SANs equal the requested
// set after normalization. ASCII case and one trailing root dot are ignored;
// duplicates are consolidated. Wildcards are literal identifiers, not patterns
// for hostname coverage. Names must use ASCII hostname labels, with an optional
// whole leftmost wildcard label. Unicode names require an ASCII A-label form.
//
// This does not consult DNS, use Common Name as a fallback, check other SAN
// types, or revalidate certificate lifetime or trust. It changes no inputs.
func (g Generation) ValidateDNSNames(expected []string) error {
	if g.id == "" {
		return fmt.Errorf("generation is uninitialized")
	}
	if len(expected) == 0 {
		return fmt.Errorf("at least one requested DNS name is required")
	}
	wanted, err := NormalizeDNSNames(expected)
	if err != nil {
		return fmt.Errorf("requested DNS names: %w", err)
	}
	leaf, err := x509.ParseCertificate(g.certificateDER)
	if err != nil {
		return fmt.Errorf("parse leaf certificate: %w", err)
	}
	if len(leaf.DNSNames) == 0 {
		return fmt.Errorf("certificate has no DNS SANs")
	}
	actual, err := NormalizeDNSNames(leaf.DNSNames)
	if err != nil {
		return fmt.Errorf("certificate DNS SANs: %w", err)
	}
	var missing, unexpected []string
	for _, name := range wanted {
		if _, found := slices.BinarySearch(actual, name); !found {
			missing = append(missing, name)
		}
	}
	for _, name := range actual {
		if _, found := slices.BinarySearch(wanted, name); !found {
			unexpected = append(unexpected, name)
		}
	}
	if len(missing) != 0 || len(unexpected) != 0 {
		return fmt.Errorf("DNS SANs do not match requested names: missing=%q; unexpected=%q", missing, unexpected)
	}
	return nil
}

// NormalizeDNSNames validates ASCII DNS identifiers and returns a sorted,
// deduplicated copy. An empty input is rejected for managed certificates.
func NormalizeDNSNames(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("at least one DNS name is required")
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		canonical, err := normalizeDNSName(name)
		if err != nil {
			return nil, err
		}
		seen[canonical] = true
	}
	canonical := make([]string, 0, len(seen))
	for name := range seen {
		canonical = append(canonical, name)
	}
	slices.Sort(canonical)
	return canonical, nil
}

func normalizeDNSName(name string) (string, error) {
	canonical := strings.TrimSuffix(name, ".")
	if len(canonical) == 0 || len(canonical) > 253 {
		return "", fmt.Errorf("invalid DNS name %q: length must be 1 to 253 bytes excluding the root dot", name)
	}
	base := strings.TrimPrefix(canonical, "*.")
	if _, err := netip.ParseAddr(base); err == nil {
		return "", fmt.Errorf("invalid DNS name %q: IP addresses are not DNS identifiers", name)
	}
	for _, label := range strings.Split(base, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("invalid DNS name %q: labels must be 1 to 63 bytes", name)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS name %q: labels must not start or end with a hyphen", name)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return "", fmt.Errorf("invalid DNS name %q: use ASCII letters, digits, hyphens, and an optional leftmost '*.'", name)
		}
	}
	return strings.ToLower(canonical), nil
}
