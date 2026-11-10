// Package config loads typed YAML and validates explicit lifecycle inputs.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kernaxis/xcertm/internal/domain"
	"go.yaml.in/yaml/v3"
)

type ACME struct {
	Environment string `yaml:"environment" json:"environment"`
	Email       string `yaml:"email" json:"email"`
	AcceptTOS   bool   `yaml:"accept_tos" json:"accept_tos"`
}

type Provider struct {
	Type     string `yaml:"type" json:"type"`
	Zone     string `yaml:"zone" json:"zone,omitempty"`
	Endpoint string `yaml:"endpoint" json:"endpoint,omitempty"`
	// Inline secrets are input-only: request snapshots must never retain them.
	APIToken              *string `yaml:"api_token" json:"-"`
	APITokenEnv           string  `yaml:"api_token_env" json:"api_token_env,omitempty"`
	APITokenFile          string  `yaml:"api_token_file" json:"api_token_file,omitempty"`
	ApplicationKeyEnv     string  `yaml:"application_key_env" json:"application_key_env,omitempty"`
	ApplicationKeyFile    string  `yaml:"application_key_file" json:"application_key_file,omitempty"`
	ApplicationSecretEnv  string  `yaml:"application_secret_env" json:"application_secret_env,omitempty"`
	ApplicationSecretFile string  `yaml:"application_secret_file" json:"application_secret_file,omitempty"`
	ConsumerKeyEnv        string  `yaml:"consumer_key_env" json:"consumer_key_env,omitempty"`
	ConsumerKeyFile       string  `yaml:"consumer_key_file" json:"consumer_key_file,omitempty"`
}

type Destination struct {
	Type            string `yaml:"type" json:"type"`
	Directory       string `yaml:"directory" json:"directory,omitempty"`
	KeyFile         string `yaml:"key_file" json:"key_file,omitempty"`
	CertificateFile string `yaml:"certificate_file" json:"certificate_file,omitempty"`
	CertificateID   string `yaml:"certificate_id" json:"certificate_id,omitempty"`
	Default         bool   `yaml:"default" json:"default,omitempty"`
}

type Certificate struct {
	Domains      []string `yaml:"domains" json:"domains"`
	DNSProvider  string   `yaml:"dns_provider" json:"dns_provider"`
	Destinations []string `yaml:"destinations" json:"destinations,omitempty"`
	RenewBefore  string   `yaml:"renew_before" json:"renew_before,omitempty"`
}

type Config struct {
	Version      int                    `yaml:"version"`
	StateDir     string                 `yaml:"state_dir"`
	ACME         ACME                   `yaml:"acme"`
	DNSProviders map[string]Provider    `yaml:"dns_providers"`
	Destinations map[string]Destination `yaml:"destinations"`
	Certificates map[string]Certificate `yaml:"certificates"`
	Resolvers    []string               `yaml:"resolvers"`
}

// Request holds effective issuance inputs. JSON snapshots omit inline secrets
// and retain provenance/recovery inputs, not a CLI-managed resource registry.
type Request struct {
	ID           string                 `json:"id"`
	ACME         ACME                   `json:"acme"`
	Certificate  Certificate            `json:"certificate"`
	Provider     Provider               `json:"provider"`
	Destinations map[string]Destination `json:"destinations,omitempty"`
}

func Load(path string) (Config, error) {
	c := Config{Version: 1}
	if path == "" {
		return c, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return c, err
	}
	if len(data) > 1<<20 {
		return c, errors.New("configuration exceeds 1 MiB")
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("invalid YAML configuration: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return c, errors.New("configuration must contain one YAML document")
	}
	if c.Version != 1 {
		return c, errors.New("unsupported configuration version")
	}
	for _, provider := range c.DNSProviders {
		if provider.APIToken != nil {
			info, err := f.Stat()
			if err != nil {
				return c, err
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0400 && info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
				return c, errors.New("configuration containing an inline API token must have mode 0400 or 0600")
			}
			break
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return c, err
	}
	base := filepath.Dir(abs)
	resolve := func(value string) string {
		if value != "" && !filepath.IsAbs(value) {
			return filepath.Join(base, value)
		}
		return value
	}
	c.StateDir = resolve(c.StateDir)
	for id, p := range c.DNSProviders {
		p.APITokenFile = resolve(p.APITokenFile)
		p.ApplicationKeyFile = resolve(p.ApplicationKeyFile)
		p.ApplicationSecretFile = resolve(p.ApplicationSecretFile)
		p.ConsumerKeyFile = resolve(p.ConsumerKeyFile)
		c.DNSProviders[id] = p
	}
	for id, d := range c.Destinations {
		d.Directory = resolve(d.Directory)
		c.Destinations[id] = d
	}
	return c, nil
}

// DefaultStateDir detects the executing host, never the selected destination.
// hostRoot is / in the application; tests can supply an isolated host layout.
func DefaultStateDir(hostRoot string) string {
	version, err1 := os.Stat(filepath.Join(hostRoot, "etc.defaults/VERSION"))
	info, err2 := os.Stat(filepath.Join(hostRoot, "etc/synoinfo.conf"))
	if err1 == nil && err2 == nil && version.Mode().IsRegular() && info.Mode().IsRegular() {
		return "/usr/local/share/xcertm"
	}
	return "/var/lib/xcertm"
}

func (r *Request) Validate(issuance bool) error {
	if strings.TrimSpace(r.ID) == "" {
		return errors.New("certificate ID is required")
	}
	if r.ACME.Environment == "" {
		r.ACME.Environment = "production"
	}
	if r.ACME.Environment != "production" && r.ACME.Environment != "staging" {
		return errors.New("ACME environment must be production or staging")
	}
	if issuance {
		address, err := mail.ParseAddress(r.ACME.Email)
		if err != nil || address.Address != r.ACME.Email || strings.ContainsAny(r.ACME.Email, "\r\n ") {
			return errors.New("a valid ACME contact email is required")
		}
		names, err := domain.NormalizeDNSNames(r.Certificate.Domains)
		if err != nil {
			return err
		}
		r.Certificate.Domains = names
		if r.Provider.Type != "cloudflare" && r.Provider.Type != "ovh" {
			return errors.New("DNS provider must be cloudflare or ovh")
		}
		if err := r.Provider.Validate(); err != nil {
			return err
		}
		if r.Provider.Type == "ovh" && r.Provider.Endpoint == "" {
			r.Provider.Endpoint = "ovh-eu"
		}
		if r.Provider.Zone != "" {
			zone, err := domain.NormalizeDNSNames([]string{r.Provider.Zone})
			if err != nil || strings.HasPrefix(zone[0], "*.") {
				return errors.New("DNS zone must be a standard DNS name")
			}
			r.Provider.Zone = zone[0]
		}
		for _, path := range []*string{&r.Provider.APITokenFile, &r.Provider.ApplicationKeyFile, &r.Provider.ApplicationSecretFile, &r.Provider.ConsumerKeyFile} {
			if *path != "" {
				absolute, err := filepath.Abs(*path)
				if err != nil {
					return err
				}
				*path = absolute
			}
		}
	}
	seen := map[string]bool{}
	for _, id := range r.Certificate.Destinations {
		if strings.TrimSpace(id) == "" || seen[id] {
			return errors.New("destination IDs must be non-blank and distinct")
		}
		seen[id] = true
		d, ok := r.Destinations[id]
		if !ok {
			return fmt.Errorf("unknown destination %q", id)
		}
		if err := d.Validate(); err != nil {
			return fmt.Errorf("destination %q: %w", id, err)
		}
	}
	if r.Certificate.RenewBefore != "" {
		if _, err := Duration(r.Certificate.RenewBefore); err != nil {
			return err
		}
	}
	return nil
}

func (d Destination) Validate() error {
	switch d.Type {
	case "filesystem":
		if d.Directory == "" {
			return errors.New("filesystem directory is required")
		}
	case "dsm":
		if d.Default && d.CertificateID != "" {
			return errors.New("DSM certificate_id and default are mutually exclusive")
		}
	default:
		return errors.New("destination type must be filesystem or dsm")
	}
	return nil
}

func (p Provider) Validate() error {
	if p.APIToken != nil {
		if p.APITokenEnv != "" || p.APITokenFile != "" {
			return errors.New("choose api_token, api_token_env, or api_token_file exclusively")
		}
		if _, err := validateSecret(*p.APIToken); err != nil {
			return err
		}
	}
	if p.Type == "ovh" && p.Endpoint != "" && p.Endpoint != "ovh-eu" && p.Endpoint != "ovh-ca" && p.Endpoint != "ovh-us" {
		return errors.New("unsupported OVH endpoint")
	}
	for _, pair := range [][2]string{{p.APITokenEnv, p.APITokenFile}, {p.ApplicationKeyEnv, p.ApplicationKeyFile}, {p.ApplicationSecretEnv, p.ApplicationSecretFile}, {p.ConsumerKeyEnv, p.ConsumerKeyFile}} {
		if pair[0] != "" && pair[1] != "" {
			return errors.New("choose an environment variable or a file per credential")
		}
	}
	return nil
}

func (p Provider) CloudflareToken() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	if p.APIToken != nil {
		return validateSecret(*p.APIToken)
	}
	return Secret(p.APITokenEnv, p.APITokenFile, "CLOUDFLARE_API_TOKEN")
}

func Secret(env, file, defaultEnv string) (string, error) {
	if env != "" && file != "" {
		return "", errors.New("ambiguous credential source")
	}
	var value string
	if file != "" {
		info, err := os.Lstat(file)
		if err != nil {
			return "", errors.New("cannot inspect credential file")
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0400 && info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return "", errors.New("credential file must be regular and private (0400 or 0600)")
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return "", errors.New("cannot read credential file")
		}
		value = string(data)
	} else {
		if env == "" {
			env = defaultEnv
		}
		value = os.Getenv(env)
	}
	return validateSecret(value)
}

func validateSecret(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("required DNS credential is missing")
	}
	if strings.ContainsAny(value, "\r\n") {
		return "", errors.New("DNS credential contains an invalid newline")
	}
	return value, nil
}

func Duration(value string) (time.Duration, error) {
	if strings.HasSuffix(value, "d") {
		value = strings.TrimSuffix(value, "d") + "h"
		d, err := time.ParseDuration(value)
		if err != nil || d <= 0 || d > time.Duration(1<<63-1)/24 {
			return 0, errors.New("invalid positive duration")
		}
		return d * 24, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, errors.New("invalid positive duration")
	}
	return d, nil
}

func Resolver(addresses []string) (*net.Resolver, error) {
	addresses = append([]string(nil), addresses...)
	if len(addresses) == 0 {
		return &net.Resolver{PreferGo: true}, nil
	}
	for i, address := range addresses {
		if net.ParseIP(address) != nil {
			addresses[i] = net.JoinHostPort(address, "53")
			continue
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil || net.ParseIP(host) == nil {
			return nil, errors.New("DNS resolver must be an IP address with optional port")
		}
	}
	return newResolver(append([]string(nil), addresses...)), nil
}
