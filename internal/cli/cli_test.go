package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernaxis/xcertm/internal/cli"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantOutput string
		wantError  string
	}{
		{name: "help", args: []string{"--help"}, wantOutput: "USAGE:"},
		{name: "no arguments", wantOutput: "USAGE:"},
		{name: "version flag", args: []string{"--version"}, wantOutput: "xcertm version v0.1.0-test\n"},
		{name: "version command", args: []string{"version"}, wantOutput: "xcertm version v0.1.0-test\n"},
		{name: "unknown command", args: []string{"unknown"}, wantCode: 1, wantError: `unknown command "unknown"`},
		{name: "unknown flag", args: []string{"--unknown"}, wantCode: 1, wantError: "flag provided but not defined"},
		{name: "unexpected version argument", args: []string{"version", "extra"}, wantCode: 1, wantError: "version does not accept arguments"},
		{name: "unknown help topic", args: []string{"help", "unknown"}, wantCode: 1, wantError: "No help topic"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			args := append([]string{"xcertm"}, tt.args...)
			code := cli.Run(context.Background(), args, "v0.1.0-test", &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d; stderr: %s", code, tt.wantCode, &stderr)
			}
			if tt.wantError != "" {
				if !strings.Contains(stderr.String(), tt.wantError) {
					t.Errorf("stderr = %q, want %q", stderr.String(), tt.wantError)
				}
				if stdout.Len() != 0 {
					t.Errorf("unexpected stdout: %q", stdout.String())
				}
				if strings.Count(stderr.String(), "\n") != 1 {
					t.Errorf("expected one diagnostic, got %q", stderr.String())
				}
				return
			}
			if stderr.Len() != 0 {
				t.Errorf("unexpected stderr: %q", stderr.String())
			}
			if strings.Contains(tt.wantOutput, "USAGE:") {
				for _, fragment := range []string{"xcertm", "USAGE:", "version", "--help", "--version"} {
					if !strings.Contains(stdout.String(), fragment) {
						t.Errorf("help missing %q: %s", fragment, &stdout)
					}
				}
			} else if stdout.String() != tt.wantOutput {
				t.Errorf("stdout = %q, want %q", stdout.String(), tt.wantOutput)
			}
		})
	}
}

func TestLifecycleHelpAndReadOnlyInspection(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent-store")
	for _, command := range []string{"issue", "renew", "deploy", "list", "show"} {
		var out, errout bytes.Buffer
		if code := cli.Run(context.Background(), []string{"xcertm", command, "--help"}, "test", &out, &errout); code != 0 {
			t.Fatalf("%s help: %s", command, &errout)
		}
		if !strings.Contains(out.String(), command) {
			t.Fatal("missing command help")
		}
	}
	for _, args := range [][]string{{"list", "--state-dir", root, "--json"}, {"--state-dir", root, "list", "--json"}} {
		var out, errout bytes.Buffer
		if code := cli.Run(context.Background(), append([]string{"xcertm"}, args...), "test", &out, &errout); code != 0 || out.String() != "[]\n" {
			t.Fatalf("empty list: code %d, output %q, error %s", code, &out, &errout)
		}
	}
	var out, errout bytes.Buffer
	if code := cli.Run(context.Background(), []string{"xcertm", "show", "unknown", "--state-dir", root}, "test", &out, &errout); code != 1 || !strings.Contains(errout.String(), "not in the store") {
		t.Fatalf("unknown stored ID: code %d, %s", code, &errout)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("inspection created store")
	}
}

func TestInvalidLifecycleInputsDoNotCreateStore(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	for _, args := range [][]string{
		{"issue"},
		{"issue", "--certificate", "web", "--all"},
		{"issue", "--certificate", "web", "--email", "admin@example.com", "--domain", "example.com", "--dns", "cloudflare", "--propagation-timeout", "0s"},
		{"issue", "--certificate", "web", "--email", "admin@example.com", "--domain", "example.com", "--dns", "cloudflare", "--cloudflare-token-env", "TOKEN", "--cloudflare-token-file", "token"},
		{"renew", "--certificate", "web", "--environment", "invalid"},
		{"deploy", "--certificate", "web", "--destination", "nas", "--type", "invalid"},
	} {
		var out, errout bytes.Buffer
		full := append([]string{"xcertm", "--state-dir", root}, args...)
		if code := cli.Run(context.Background(), full, "test", &out, &errout); code != 1 || errout.Len() == 0 {
			t.Fatalf("accepted bad inputs: %v", args)
		}
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("invalid inputs created store")
	}
}
