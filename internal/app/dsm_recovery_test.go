//go:build linux

package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/kernaxis/xcertm/internal/app"
	"github.com/kernaxis/xcertm/internal/config"
	"github.com/kernaxis/xcertm/internal/deploy"
	"github.com/kernaxis/xcertm/internal/state"
	"github.com/kernaxis/xcertm/internal/store"
)

func TestForcedDeployPreservesAutomaticDSMInitializationWithoutReceipt(t *testing.T) {
	for _, point := range []string{"deploy-dsm-create-claimed", "deploy-dsm-entry-prepared", "deploy-dsm-info-published", "deploy-dsm-entry-registered"} {
		for _, changeBinding := range []bool{false, true} {
			name := point
			if changeBinding {
				name += "/changed-binding"
			}
			t.Run(name, func(t *testing.T) {
				credentials(t)
				lab := newLaboratory(t)
				root, nas := filepath.Join(t.TempDir(), "state"), t.TempDir()
				archive := filepath.Join(nas, "usr/syno/etc/certificate/_archive")
				if err := os.MkdirAll(filepath.Join(archive, "ABC123"), 0700); err != nil {
					t.Fatal(err)
				}
				for path, value := range map[string]string{filepath.Join(archive, "INFO"): `{"ABC123":{"services":[]}}`, filepath.Join(archive, "DEFAULT"): "ABC123\n"} {
					if err := os.WriteFile(path, []byte(value), 0600); err != nil {
						t.Fatal(err)
					}
				}
				r := request("cloudflare", t.TempDir())
				r.Certificate.Destinations = []string{"nas-main"}
				original := config.Destination{Type: "dsm"}
				r.Destinations["nas-main"] = original
				options := lab.options()
				options.DSMRoot = nas
				first, err := app.New(root, options).Issue(context.Background(), r, app.RunOptions{})
				if err != nil {
					t.Fatal(err)
				}
				interrupted := errors.New("interrupted deployment")
				options.After = func(at string) error {
					if at == point {
						return interrupted
					}
					return nil
				}
				if _, err := app.New(root, options).Deploy(context.Background(), r); !errors.Is(err, interrupted) {
					t.Fatalf("registration boundary was not reached: %v", err)
				}
				recorded := func() store.Deployment {
					t.Helper()
					s, err := store.Open(root, false)
					if err != nil {
						t.Fatal(err)
					}
					defer s.Close()
					found, err := s.Deployments(r.ID)
					if err != nil || len(found) != 1 {
						t.Fatalf("missing recorded deployment: %v", err)
					}
					return found[0]
				}
				before := recorded()
				if receipt, err := deploy.Inspect(root, "nas-main"); err != nil || receipt.OperationID != "" {
					t.Fatalf("expected initialization state without a deployment receipt: %+v, %v", receipt, err)
				}
				redirect := t.TempDir()
				if changeBinding {
					r.Destinations["nas-main"] = config.Destination{Type: "filesystem", Directory: redirect}
				}
				options.ForceDeploy = true
				options.After = func(at string) error {
					if at == "deploy-prepared" {
						return interrupted
					}
					return nil
				}
				_, forceErr := app.New(root, options).Deploy(context.Background(), r)
				if after := recorded(); !reflect.DeepEqual(after, before) {
					t.Fatalf("forced retry replaced the pending operation or binding: before=%+v, after=%+v; error: %v", before, after, forceErr)
				}
				if !errors.Is(forceErr, interrupted) {
					t.Fatalf("forced retry did not resume registration through journal preparation: %v", forceErr)
				}
				options.ForceDeploy, options.After = false, nil
				recovered, err := app.New(root, options).Deploy(context.Background(), r)
				if err != nil || len(recovered.Deployments) != 1 || !recovered.Deployments[0].Completed || recovered.Deployments[0].OperationID != before.OperationID || recovered.Deployments[0].GenerationID != first.GenerationID {
					t.Fatalf("ordinary retry could not recover the original operation: %+v, %v", recovered, err)
				}
				if _, err := os.Stat(filepath.Join(redirect, "fullchain.pem")); !os.IsNotExist(err) {
					t.Fatal("pending DSM work was redirected to the new configuration")
				}
				entryData, err := os.ReadFile(filepath.Join(deploy.StateDirectory(root, "nas-main"), "dsm-entry.json"))
				if err != nil {
					t.Fatal(err)
				}
				var entry struct{ ID string }
				if err := json.Unmarshal(entryData, &entry); err != nil {
					t.Fatal(err)
				}
				keyPath := filepath.Join(archive, entry.ID, "privkey.pem")
				keyBefore, err := os.Stat(keyPath)
				if err != nil {
					t.Fatal(err)
				}
				r.Destinations["nas-main"] = original
				options.ForceDeploy = true
				forced, err := app.New(root, options).Deploy(context.Background(), r)
				if err != nil || forced.Deployments[0].OperationID == before.OperationID || forced.Deployments[0].GenerationID != first.GenerationID || !forced.Deployments[0].Completed {
					t.Fatalf("completed recovery prevented an explicit republication: %+v, %v", forced, err)
				}
				keyAfter, err := os.Stat(keyPath)
				if err != nil || os.SameFile(keyBefore, keyAfter) || lab.finalizations != 1 {
					t.Fatal("force did not republish the stored generation or issued a new certificate", err)
				}
				infoData, err := os.ReadFile(filepath.Join(archive, "INFO"))
				if err != nil {
					t.Fatal(err)
				}
				var info map[string]json.RawMessage
				if err := json.Unmarshal(infoData, &info); err != nil || len(info) != 2 || info[entry.ID] == nil {
					t.Fatal("recovery allocated a duplicate DSM entry", err)
				}
				if receipt := recorded(); !receipt.Completed || receipt.GenerationID != first.GenerationID {
					t.Fatal("final deployment request lost its completed generation")
				}
				if marker, err := state.Inspect(filepath.Join(archive, ".xcertm-dsm-create")); err != nil || marker.Exists {
					t.Fatal("completed recovery retained its initialization marker", err)
				}
			})
		}
	}
}
