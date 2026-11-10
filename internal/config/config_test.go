package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestInlineCloudflareTokenIsInputOnlyAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xcertm.yaml")
	data := []byte("version: 1\ndns_providers:\n  cf:\n    type: cloudflare\n    api_token: synthetic-inline-value\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLOUDFLARE_API_TOKEN", "unused-default")
	provider := cfg.DNSProviders["cf"]
	value, err := provider.CloudflareToken()
	if err != nil || value != "synthetic-inline-value" {
		t.Fatal("inline token was not resolved")
	}
	encoded, err := json.Marshal(Request{Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), value) || strings.Contains(string(encoded), `"api_token":`) {
		t.Fatal("inline secret entered the persistent request representation")
	}
	for _, mode := range []os.FileMode{0644, 0660, 0700} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || strings.Contains(err.Error(), value) {
			t.Fatal("unsafe YAML permissions accepted or secret leaked")
		}
	}
}

func TestInlineCloudflareCredentialValidation(t *testing.T) {
	for _, value := range []string{"", "  ", "synthetic\nembedded"} {
		p := Provider{Type: "cloudflare", APIToken: &value}
		if _, err := p.CloudflareToken(); err == nil || strings.Contains(err.Error(), "synthetic") {
			t.Fatal("invalid inline credential accepted or exposed")
		}
	}
	value := "synthetic-inline-value"
	for _, p := range []Provider{{Type: "cloudflare", APIToken: &value, APITokenEnv: "TOKEN"}, {Type: "cloudflare", APIToken: &value, APITokenFile: "token"}} {
		if err := p.Validate(); err == nil {
			t.Fatal("ambiguous inline credential accepted")
		}
	}
}

func TestStrictYAMLAndRelativePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xcertm.yaml")
	valid := `version: 1
state_dir: state
acme:
  email: admin@example.com
  environment: staging
dns_providers:
  cf:
    type: cloudflare
    api_token_file: token
destinations:
  local:
    type: filesystem
    directory: tls
certificates:
  web:
    domains: [example.com, "*.example.com"]
    dns_provider: cf
    destinations: [local]
`
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.StateDir != filepath.Join(dir, "state") || c.DNSProviders["cf"].APITokenFile != filepath.Join(dir, "token") || c.Destinations["local"].Directory != filepath.Join(dir, "tls") {
		t.Fatal("relative paths not based on YAML location")
	}
	for name, text := range map[string]string{"unknown": "version: 1\nunknown: true", "duplicate": "version: 1\nversion: 1", "document": "version: 1\n---\nversion: 1", "version": "version: 2", "oversize": valid + strings.Repeat("#", 1<<20)} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("invalid YAML accepted")
			}
		})
	}
}

func TestHostDefaultsAndSecretReferences(t *testing.T) {
	root := t.TempDir()
	if DefaultStateDir(root) != "/var/lib/xcertm" {
		t.Fatal("wrong Linux default")
	}
	for _, name := range []string{"etc.defaults/VERSION", "etc/synoinfo.conf"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if DefaultStateDir(root) != "/usr/local/share/xcertm" {
		t.Fatal("wrong DSM default")
	}
	t.Setenv("XCERTM_TEST_TOKEN", "synthetic-token")
	if token, err := Secret("XCERTM_TEST_TOKEN", "", ""); err != nil || token != "synthetic-token" {
		t.Fatal("env reference failed")
	}
	path := filepath.Join(root, "token")
	if err := os.WriteFile(path, []byte("synthetic-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if token, err := Secret("", path, ""); err != nil || token != "synthetic-token" {
		t.Fatal("private file reference failed")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Secret("", path, ""); err == nil {
		t.Fatal("public secret accepted")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Secret("", link, ""); err == nil {
		t.Fatal("symlink secret accepted")
	}
}

func TestValidationAndDuration(t *testing.T) {
	r := Request{ID: "web", ACME: ACME{Email: "admin@example.com"}, Provider: Provider{Type: "ovh"}, Certificate: Certificate{Domains: []string{"EXAMPLE.COM.", "*.example.com", "example.com"}}}
	if err := r.Validate(true); err != nil {
		t.Fatal(err)
	}
	if r.Provider.Endpoint != "ovh-eu" || r.ACME.Environment != "production" || !reflect.DeepEqual(r.Certificate.Domains, []string{"*.example.com", "example.com"}) {
		t.Fatalf("incorrect normalization: %+v", r)
	}
	if d, err := Duration("20d"); err != nil || d != 480*time.Hour {
		t.Fatal("day duration failed")
	}
	for _, bad := range []string{"0d", "-1d", "forever", "999999999999d"} {
		if _, err := Duration(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	addresses := []string{"127.0.0.1"}
	if _, err := Resolver(addresses); err != nil {
		t.Fatal(err)
	}
	if addresses[0] != "127.0.0.1" {
		t.Fatal("resolver mutated caller config")
	}
}
