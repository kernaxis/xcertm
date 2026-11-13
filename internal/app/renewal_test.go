package app_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernaxis/xcertm/internal/app"
	"github.com/kernaxis/xcertm/internal/cli"
	"github.com/kernaxis/xcertm/internal/config"
	"github.com/kernaxis/xcertm/internal/store"
)

func TestRenewNotDueSkipsPublishedDestinationsAndDeploysNewOnesOffline(t *testing.T) {
	credentials(t)
	l := newLaboratory(t)
	root := filepath.Join(t.TempDir(), "state")
	dir := t.TempDir()
	r := request("cloudflare", dir)
	first, err := app.New(root, l.options()).Issue(context.Background(), r, app.RunOptions{Deploy: true})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	l.now = l.now.Add(20 * 24 * time.Hour)
	var progress strings.Builder
	options := l.options()
	options.HTTPClient = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		t.Error("renewal not due accessed ACME or DNS")
		return nil, errors.New("offline")
	})}
	options.Progress = func(message string) { progress.WriteString(message + "\n") }
	a := app.New(root, options)
	out, err := a.Issue(context.Background(), r, app.RunOptions{Renew: true, Deploy: true})
	if err != nil || out.State != "not-due" || out.GenerationID != first.GenerationID || !out.Deployments[0].Unchanged {
		t.Fatalf("not-due deployment was not skipped: %+v, %v", out, err)
	}
	after, _ := os.Stat(filepath.Join(dir, "privkey.pem"))
	if !os.SameFile(before, after) || !strings.Contains(progress.String(), "70d 0h (renewal threshold: 30d 0h 20m); renewal skipped") || !strings.Contains(progress.String(), "already up to date; deployment skipped") {
		t.Fatalf("skip rewrote material or lacked decision logs: %s", &progress)
	}
	r.Certificate.Destinations = append(r.Certificate.Destinations, "new-destination")
	r.Destinations["new-destination"] = config.Destination{Type: "filesystem", Directory: t.TempDir()}
	out, err = a.Issue(context.Background(), r, app.RunOptions{Renew: true, Deploy: true})
	if err != nil || len(out.Deployments) != 2 || !out.Deployments[0].Unchanged || out.Deployments[1].Unchanged || !out.Deployments[1].Completed || l.finalizations != 1 {
		t.Fatalf("new destination required issuance or refreshed an existing destination: %+v, %v", out, err)
	}
}

func TestRenewThresholdBoundaryCustomWindowAndForceLogs(t *testing.T) {
	for _, test := range []struct {
		name, window string
		offset       time.Duration
		force, due   bool
	}{
		{name: "before-default-boundary", offset: -time.Second},
		{name: "at-default-boundary", due: true},
		{name: "custom-window-not-due", window: "20d", offset: -time.Second},
		{name: "custom-window-due", window: "20d", due: true},
		{name: "forced", offset: -24 * time.Hour, force: true, due: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			credentials(t)
			l := newLaboratory(t)
			root := filepath.Join(t.TempDir(), "state")
			r := request("cloudflare", t.TempDir())
			r.Certificate.RenewBefore = test.window
			if _, err := app.New(root, l.options()).Issue(context.Background(), r, app.RunOptions{}); err != nil {
				t.Fatal(err)
			}
			s, err := store.Open(root, false)
			if err != nil {
				t.Fatal(err)
			}
			g, _, err := s.Latest(r.ID, "staging")
			s.Close()
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(g.CertificateDER())
			if err != nil {
				t.Fatal(err)
			}
			window := leaf.NotAfter.Sub(leaf.NotBefore) / 3
			if test.window != "" {
				window = 20 * 24 * time.Hour
			}
			l.now = leaf.NotAfter.Add(-window).Add(test.offset)
			var progress strings.Builder
			options := l.options()
			options.Progress = func(message string) { progress.WriteString(message + "\n") }
			out, err := app.New(root, options).Issue(context.Background(), r, app.RunOptions{Renew: true, Force: test.force})
			if err != nil {
				t.Fatal(err)
			}
			if test.due {
				if out.State != "renewed" || l.finalizations != 2 || !strings.Contains(progress.String(), "renewal required") {
					t.Fatal("renewal deadline was missed", out, &progress)
				}
			} else if out.State != "not-due" || l.finalizations != 1 || !strings.Contains(progress.String(), "renewal skipped") {
				t.Fatal("certificate renewed prematurely", out, &progress)
			}
			if test.force && !strings.Contains(progress.String(), "forced by --force") {
				t.Fatal("missing force reason")
			}
			if test.window != "" && !strings.Contains(progress.String(), "renewal threshold: 20d 0h") {
				t.Fatal("custom window was not logged")
			}
		})
	}
}

func TestDeployForceCLIRepairsDriftAndSubsequentRenewSkips(t *testing.T) {
	credentials(t)
	l := newLaboratory(t)
	root, dir := filepath.Join(t.TempDir(), "state"), t.TempDir()
	r := request("cloudflare", dir)
	first, err := app.New(root, l.options()).Issue(context.Background(), r, app.RunOptions{Deploy: true})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "fullchain.pem")
	if err := os.WriteFile(path, []byte("external drift"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"xcertm", "deploy", "--state-dir", root, "--staging", "--certificate", "web", "--json"}
	var out, stderr strings.Builder
	if code := cli.Run(context.Background(), args, "test", &out, &stderr); code == 0 {
		t.Fatal("ordinary deploy overwrote drift")
	}
	out.Reset()
	stderr.Reset()
	if code := cli.Run(context.Background(), append(args, "--force"), "test", &out, &stderr); code != 0 {
		t.Fatalf("forced CLI deployment failed: %s", &stderr)
	}
	var outcomes []app.Outcome
	if err := json.Unmarshal([]byte(out.String()), &outcomes); err != nil {
		t.Fatal(err)
	}
	if outcomes[0].GenerationID != first.GenerationID || outcomes[0].Deployments[0].Unchanged || !outcomes[0].Deployments[0].Completed || !strings.Contains(stderr.String(), "Forcing republication") {
		t.Fatal("force did not republish the stored generation", outcomes, &stderr)
	}
	if l.finalizations != 1 {
		t.Fatal("deploy --force issued another certificate")
	}
	before, _ := os.Stat(path)
	afterForce, err := app.New(root, l.options()).Issue(context.Background(), r, app.RunOptions{Renew: true, Deploy: true})
	if err != nil || !afterForce.Deployments[0].Unchanged || afterForce.State != "not-due" {
		t.Fatalf("ordinary renew redeployed after force: %+v, %v", afterForce, err)
	}
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) {
		t.Fatal("ordinary renewal rewrote forced deployment")
	}
}

func TestForcedDeployCanAdoptOutputsAfterFirstPreparationFailed(t *testing.T) {
	credentials(t)
	l := newLaboratory(t)
	root, dir := filepath.Join(t.TempDir(), "state"), t.TempDir()
	r := request("cloudflare", dir)
	options := l.options()
	first, err := app.New(root, options).Issue(context.Background(), r, app.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "fullchain.pem")
	if err := os.WriteFile(path, []byte("untracked output"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.New(root, options).Deploy(context.Background(), r); err == nil {
		t.Fatal("ordinary deployment adopted existing outputs")
	}
	s, err := store.Open(root, false)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := s.Deployments(r.ID)
	s.Close()
	if err != nil || len(pending) != 1 || pending[0].Completed {
		t.Fatal("failed preparation lost its recorded request", err)
	}
	options.ForceDeploy = true
	out, err := app.New(root, options).Deploy(context.Background(), r)
	if err != nil || len(out.Deployments) != 1 || !out.Deployments[0].Completed || out.Deployments[0].OperationID != pending[0].OperationID || out.GenerationID != first.GenerationID || l.finalizations != 1 {
		t.Fatalf("force could not adopt outputs using the original operation: %+v, %v", out, err)
	}
}

func TestRenewEvaluatesDeadlineAfterRecoveringDeployment(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(map[bool]string{false: "due", true: "forced"}[force], func(t *testing.T) {
			credentials(t)
			l := newLaboratory(t)
			root := filepath.Join(t.TempDir(), "state")
			r := request("cloudflare", t.TempDir())
			options := l.options()
			options.After = func(point string) error {
				if point == "deploy-prepared" {
					return errors.New("interrupted publication")
				}
				return nil
			}
			first, err := app.New(root, options).Issue(context.Background(), r, app.RunOptions{Deploy: true})
			if err == nil {
				t.Fatal("expected interrupted deployment")
			}
			if !force {
				l.now = l.now.Add(70 * 24 * time.Hour)
			}
			var progress strings.Builder
			options = l.options()
			options.Progress = func(message string) { progress.WriteString(message + "\n") }
			out, err := app.New(root, options).Issue(context.Background(), r, app.RunOptions{Renew: true, Deploy: true, Force: force})
			if err != nil || out.State != "renewed" || out.GenerationID == first.GenerationID || l.finalizations != 2 || len(out.Deployments) != 1 || !out.Deployments[0].Completed || out.Deployments[0].GenerationID != out.GenerationID {
				t.Fatalf("recovery masked the renewal decision: %+v, %v", out, err)
			}
			if !strings.Contains(progress.String(), "renewal required") {
				t.Fatal("missing decision after recovery")
			}
		})
	}
}

func TestFailedRecoveryDoesNotIssueAndStillDeploysIndependentDestination(t *testing.T) {
	credentials(t)
	l := newLaboratory(t)
	root := filepath.Join(t.TempDir(), "state")
	r := request("cloudflare", t.TempDir())
	options := l.options()
	options.After = func(point string) error {
		if point == "deploy-prepared" {
			return errors.New("interrupted")
		}
		return nil
	}
	first, err := app.New(root, options).Issue(context.Background(), r, app.RunOptions{Deploy: true})
	if err == nil {
		t.Fatal("expected interrupted deployment")
	}
	r.Certificate.Destinations = append(r.Certificate.Destinations, "independent")
	r.Destinations["independent"] = config.Destination{Type: "filesystem", Directory: t.TempDir()}
	interrupted := false
	options = l.options()
	options.After = func(point string) error {
		if point == "deploy-file-0" && !interrupted {
			interrupted = true
			return errors.New("recovery interrupted")
		}
		return nil
	}
	out, err := app.New(root, options).Issue(context.Background(), r, app.RunOptions{Renew: true, Deploy: true, Force: true})
	if err == nil || l.finalizations != 1 || out.GenerationID != first.GenerationID || len(out.Deployments) != 2 || out.Deployments[0].Completed || !out.Deployments[1].Completed {
		t.Fatalf("failed recovery issued again or blocked an independent destination: %+v, %v", out, err)
	}
}
