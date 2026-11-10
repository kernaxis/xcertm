package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestConfirmUpdate(t *testing.T) {
	for _, answer := range []string{"y\n", "YES\n", "n\n", "\n", "", "anything\n"} {
		t.Run(strings.TrimSpace(answer), func(t *testing.T) {
			var output bytes.Buffer
			confirmed, err := confirmUpdate(strings.NewReader(answer), &output)
			if err != nil {
				t.Fatal(err)
			}
			want := answer == "y\n" || answer == "YES\n"
			if confirmed != want || output.String() != "Continue? [y/N] " {
				t.Fatalf("confirmation = %v, output = %q", confirmed, &output)
			}
		})
	}
}

func TestUpdateHelpAndInvalidArguments(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"unexpected"}, {"--check", "--yes"}} {
		var output, errors bytes.Buffer
		code := Run(context.Background(), append([]string{"xcertm", "update"}, args...), "v0.1.0", &output, &errors)
		if args[0] == "--help" {
			if code != 0 || !strings.Contains(output.String(), "--check") || !strings.Contains(output.String(), "--yes") {
				t.Fatalf("update help: %s %s", &output, &errors)
			}
		} else if code != 1 || errors.Len() == 0 {
			t.Fatal("invalid arguments did not fail before network access")
		}
	}
}

func TestReportUpdate(t *testing.T) {
	for _, tc := range []struct {
		version string
		check   bool
		proceed bool
		message string
	}{
		{"v0.2.0", false, false, "You are up to date (v0.2.0)."},
		{"v0.3.0", false, false, "no downgrade performed"},
		{"v0.1.0", true, false, "Latest stable release: v0.2.0 (installed: v0.1.0)."},
		{"v0.1.0", false, true, ""},
		{"dev", false, true, "development or unrecognized build"},
	} {
		t.Run(tc.version+tc.message, func(t *testing.T) {
			var output bytes.Buffer
			proceed, err := reportUpdate(&output, tc.version, "v0.2.0", tc.check)
			if err != nil || proceed != tc.proceed || !strings.Contains(output.String(), tc.message) {
				t.Fatalf("proceed = %v, error = %v, output = %q", proceed, err, &output)
			}
		})
	}
}
