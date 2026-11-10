package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/kernaxis/xcertm/internal/app"
	"github.com/kernaxis/xcertm/internal/config"
	urfave "github.com/urfave/cli/v3"
)

func TestYAMLFlagsPrecedenceAndListReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xcertm.yaml")
	data := `version: 1
state_dir: state
acme:
  environment: production
  email: yaml@example.com
dns_providers:
  provider:
    type: cloudflare
    zone: example.com
    api_token_env: NONEXISTENT_NOT_NEEDED_FOR_PARSING
destinations:
  local:
    type: filesystem
    directory: tls
  nas:
    type: dsm
    default: true
certificates:
  web:
    domains: [example.com, "*.example.com"]
    dns_provider: provider
    destinations: [local, nas]
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	override := filepath.Join(dir, "override")
	flags := append(selectionFlags(), destinationFlags()...)
	flags = append(flags, issuanceFlags()...)
	command := &urfave.Command{Name: "xcertm", Flags: rootFlags(), Writer: io.Discard, ErrWriter: io.Discard, Commands: []*urfave.Command{{Name: "issue", Flags: flags, Action: func(_ context.Context, c *urfave.Command) error {
		cfg, root, environment, err := load(c)
		if err != nil {
			return err
		}
		if root != override || environment != "staging" {
			t.Fatalf("global precedence failed: %s %s", root, environment)
		}
		jobs, err := requests(c, cfg, app.New(root, app.Options{}), environment, true)
		if err != nil {
			return err
		}
		if len(jobs) != 1 {
			t.Fatalf("expected one request: %d", len(jobs))
		}
		r := jobs[0]
		if r.ACME.Email != "flag@example.com" || !slices.Equal(r.Certificate.Domains, []string{"only.example.com"}) || !slices.Equal(r.Certificate.Destinations, []string{"local"}) {
			t.Fatalf("list replacement or scalar override failed: %+v", r.Certificate)
		}
		if r.Provider.Type != "cloudflare" || r.Provider.APITokenEnv != "NONEXISTENT_NOT_NEEDED_FOR_PARSING" || r.Destinations["local"].Directory != filepath.Join(dir, "tls") {
			t.Fatal("YAML references/relative paths lost")
		}
		if len(cfg.Certificates["web"].Domains) != 2 || len(cfg.Certificates["web"].Destinations) != 2 {
			t.Fatal("flag processing mutated YAML")
		}
		return nil
	}}}}
	if err := command.Run(context.Background(), []string{"xcertm", "issue", "--config", path, "--state-dir", override, "--staging", "--certificate", "web", "--email", "flag@example.com", "--domain", "only.example.com", "--destination", "local"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(override); !os.IsNotExist(err) {
		t.Fatal("parsing created store")
	}
}

func TestExampleYAMLMatchesTheReader(t *testing.T) {
	cfg, err := config.Load("../../examples/xcertm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for id, cert := range cfg.Certificates {
		r := config.Request{ID: id, ACME: cfg.ACME, Certificate: cert, Provider: cfg.DNSProviders[cert.DNSProvider], Destinations: cfg.Destinations}
		if err := r.Validate(true); err != nil {
			t.Fatalf("example profile %s: %v", id, err)
		}
	}
}

func TestCloudflareCredentialFlagsOverrideInlineYAML(t *testing.T) {
	for _, source := range []string{"env", "file"} {
		t.Run(source, func(t *testing.T) {
			literal := "synthetic-inline-value"
			cfg := config.Config{ACME: config.ACME{Email: "admin@example.com"}, DNSProviders: map[string]config.Provider{"cf": {Type: "cloudflare", APIToken: &literal}}, Certificates: map[string]config.Certificate{"web": {DNSProvider: "cf", Domains: []string{"example.com"}}}}
			flags := append(selectionFlags(), issuanceFlags()...)
			cmd := &urfave.Command{Name: "xcertm", Flags: flags, Writer: io.Discard, ErrWriter: io.Discard, Action: func(_ context.Context, c *urfave.Command) error {
				jobs, err := requests(c, cfg, app.New(filepath.Join(t.TempDir(), "state"), app.Options{}), "staging", true)
				if err != nil {
					return err
				}
				p := jobs[0].Provider
				if p.APIToken != nil {
					t.Fatal("inline token survived explicit credential override")
				}
				if source == "env" && p.APITokenEnv != "OVERRIDE" || source == "file" && filepath.Base(p.APITokenFile) != "OVERRIDE" {
					t.Fatal("credential flag was not retained")
				}
				if cfg.DNSProviders["cf"].APIToken == nil {
					t.Fatal("credential override mutated YAML inputs")
				}
				return nil
			}}
			if err := cmd.Run(context.Background(), []string{"xcertm", "--certificate", "web", "--cloudflare-token-" + source, "OVERRIDE"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
