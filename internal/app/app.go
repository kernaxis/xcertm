// Package app orchestrates issuance, renewal, and independent deployments.
package app

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	issuer "github.com/kernaxis/xcertm/internal/acme"
	"github.com/kernaxis/xcertm/internal/config"
	"github.com/kernaxis/xcertm/internal/deploy"
	"github.com/kernaxis/xcertm/internal/deploy/dsm"
	"github.com/kernaxis/xcertm/internal/deploy/filesystem"
	"github.com/kernaxis/xcertm/internal/dns"
	"github.com/kernaxis/xcertm/internal/dns/cloudflare"
	"github.com/kernaxis/xcertm/internal/dns/ovh"
	"github.com/kernaxis/xcertm/internal/domain"
	"github.com/kernaxis/xcertm/internal/store"
)

type Options struct {
	HTTPClient         *http.Client
	Resolver           dns.Resolver
	DirectoryURL       func(string) string
	Now                func() time.Time
	PollInterval       time.Duration
	PropagationTimeout time.Duration
	Progress           func(string)
	After              func(string) error
	DSMRoot            string
}
type Service struct {
	Root    string
	options Options
}

func New(root string, options Options) *Service {
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	if options.DirectoryURL == nil {
		options.DirectoryURL = issuer.Directory
	}
	if options.Resolver == nil {
		options.Resolver, _ = config.Resolver(nil)
	}
	if options.HTTPClient == nil {
		options.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	client := *options.HTTPClient
	// Authentication headers and signed requests must not be forwarded to
	// another origin by an API redirect. Stable provider endpoints need none.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	options.HTTPClient = &client
	return &Service{root, options}
}

type RunOptions struct{ Renew, Deploy, Force bool }
type Outcome struct {
	CertificateID string          `json:"certificate_id"`
	Environment   string          `json:"environment"`
	GenerationID  string          `json:"generation_id"`
	State         string          `json:"state"`
	Deployments   []deploy.Result `json:"deployments,omitempty"`
}

// configuredProvider resolves secrets only when DNS work is actually needed.
type configuredProvider struct {
	config config.Provider
	client *http.Client
}

func (p configuredProvider) provider() (dns.Provider, error) {
	c := p.config
	switch c.Type {
	case "cloudflare":
		token, err := c.CloudflareToken()
		if err != nil {
			return nil, err
		}
		return cloudflare.New(token, c.Zone, p.client), nil
	case "ovh":
		ak, err := config.Secret(c.ApplicationKeyEnv, c.ApplicationKeyFile, "OVH_APPLICATION_KEY")
		if err != nil {
			return nil, err
		}
		as, err := config.Secret(c.ApplicationSecretEnv, c.ApplicationSecretFile, "OVH_APPLICATION_SECRET")
		if err != nil {
			return nil, err
		}
		ck, err := config.Secret(c.ConsumerKeyEnv, c.ConsumerKeyFile, "OVH_CONSUMER_KEY")
		if err != nil {
			return nil, err
		}
		return ovh.New(c.Endpoint, ak, as, ck, c.Zone, p.client)
	}
	return nil, errors.New("unsupported DNS provider")
}
func (p configuredProvider) Find(ctx context.Context, name, value string) ([]dns.Record, error) {
	provider, err := p.provider()
	if err != nil {
		return nil, err
	}
	return provider.Find(ctx, name, value)
}
func (p configuredProvider) Create(ctx context.Context, name, value string) (dns.Record, error) {
	provider, err := p.provider()
	if err != nil {
		return dns.Record{}, err
	}
	return provider.Create(ctx, name, value)
}
func (p configuredProvider) Delete(ctx context.Context, r dns.Record) error {
	provider, err := p.provider()
	if err != nil {
		return err
	}
	return provider.Delete(ctx, r)
}
func (p configuredProvider) Refresh(ctx context.Context, zone string) error {
	provider, err := p.provider()
	if err != nil {
		return err
	}
	if refresh, ok := provider.(interface {
		Refresh(context.Context, string) error
	}); ok {
		return refresh.Refresh(ctx, zone)
	}
	return nil
}

func (a *Service) Issue(ctx context.Context, r config.Request, options RunOptions) (Outcome, error) {
	out := Outcome{CertificateID: r.ID, Environment: r.ACME.Environment}
	if err := r.Validate(true); err != nil {
		return out, err
	}
	out.Environment = r.ACME.Environment
	if options.Deploy && len(r.Certificate.Destinations) == 0 {
		return out, errors.New("--deploy requires at least one destination")
	}
	s, err := store.Open(a.Root, true)
	if err != nil {
		return out, err
	}
	defer s.Close()
	requests, err := s.Deployments(r.ID)
	if err != nil {
		return out, err
	}
	recovered := false
	for _, d := range requests {
		if d.Completed || d.Environment != r.ACME.Environment {
			continue
		}
		if !options.Deploy || !slices.Contains(r.Certificate.Destinations, d.ID) {
			return out, fmt.Errorf("destination %q has unfinished work; resume it with deploy before another issuance", d.ID)
		}
		result, err := a.publish(ctx, s, d)
		out.Deployments = append(out.Deployments, result)
		if err != nil {
			return out, err
		}
		recovered = true
		out.GenerationID = d.GenerationID
	}
	if recovered {
		out.State = "recovered"
		return out, nil
	}
	pending, err := s.Pending(r.ID)
	if err != nil {
		return out, err
	}
	g, _, loadErr := s.Latest(r.ID, r.ACME.Environment)
	need := options.Force || os.IsNotExist(loadErr)
	if loadErr != nil && !os.IsNotExist(loadErr) {
		return out, loadErr
	}
	if loadErr == nil {
		leaf, err := x509.ParseCertificate(g.CertificateDER())
		if err != nil {
			return out, err
		}
		if err := g.ValidateDNSNames(r.Certificate.Domains); err != nil {
			need = true
		}
		if a.options.Now().Before(leaf.NotBefore) || !a.options.Now().Before(leaf.NotAfter) {
			need = true
		}
		if options.Renew {
			window := leaf.NotAfter.Sub(leaf.NotBefore) / 3
			if r.Certificate.RenewBefore != "" {
				window, err = config.Duration(r.Certificate.RenewBefore)
				if err != nil {
					return out, err
				}
				if window >= leaf.NotAfter.Sub(leaf.NotBefore) {
					return out, errors.New("renew_before must be smaller than certificate lifetime")
				}
			}
			if !a.options.Now().Before(leaf.NotAfter.Add(-window)) {
				need = true
			}
		}
	}
	out.State = "reused"
	if options.Renew {
		out.State = "not-due"
	}
	if need || pending != nil {
		i := issuer.Issuer{HTTPClient: a.options.HTTPClient, DirectoryURL: a.options.DirectoryURL, Now: a.options.Now, After: a.options.After, Progress: a.options.Progress}
		solver := dns.Solver{Provider: configuredProvider{r.Provider, a.options.HTTPClient}, Resolver: a.options.Resolver, PollInterval: a.options.PollInterval, PropagationTimeout: a.options.PropagationTimeout, Progress: a.options.Progress}
		g, err = i.Obtain(ctx, s, r, solver)
		if err != nil {
			return out, err
		}
		out.State = "issued"
		if options.Renew {
			out.State = "renewed"
		}
	}
	out.GenerationID = g.ID()
	if a.options.Progress != nil {
		a.options.Progress(fmt.Sprintf("Using stored generation %q", g.ID()))
	}
	if options.Deploy {
		if len(r.Certificate.Destinations) == 0 {
			return out, errors.New("no deployment destination selected; certificate is stored")
		}
		results, err := a.deploySelected(ctx, s, r, g)
		out.Deployments = append(out.Deployments, results...)
		return out, err
	}
	return out, nil
}

func (a *Service) Deploy(ctx context.Context, r config.Request) (Outcome, error) {
	out := Outcome{CertificateID: r.ID, Environment: r.ACME.Environment, State: "deployed"}
	if err := r.Validate(false); err != nil {
		return out, err
	}
	out.Environment = r.ACME.Environment
	s, err := store.Open(a.Root, true)
	if err != nil {
		return out, err
	}
	defer s.Close()
	g, _, err := s.Latest(r.ID, r.ACME.Environment)
	if err != nil {
		return out, fmt.Errorf("stored certificate unavailable: %w", err)
	}
	if len(r.Certificate.Domains) > 0 {
		if err := g.ValidateDNSNames(r.Certificate.Domains); err != nil {
			return out, err
		}
	}
	if len(r.Certificate.Destinations) == 0 {
		return out, errors.New("no deployment destination selected")
	}
	out.GenerationID = g.ID()
	out.Deployments, err = a.deploySelected(ctx, s, r, g)
	return out, err
}

func (a *Service) deploySelected(ctx context.Context, s *store.Store, r config.Request, g domain.Generation) ([]deploy.Result, error) {
	previous, err := s.Deployments("")
	if err != nil {
		return nil, err
	}
	byID := map[string]store.Deployment{}
	for _, d := range previous {
		byID[d.ID] = d
	}
	var results []deploy.Result
	var combined error
	for _, id := range r.Certificate.Destinations {
		d := store.Deployment{ID: id, CertificateID: r.ID, GenerationID: g.ID(), Environment: r.ACME.Environment, OperationID: g.ID() + ":" + id, Destination: r.Destinations[id]}
		if old, ok := byID[id]; ok {
			if old.CertificateID != r.ID {
				combined = errors.Join(combined, fmt.Errorf("destination %q belongs to another certificate", id))
				continue
			}
			if !old.Completed {
				if old.Environment != r.ACME.Environment {
					combined = errors.Join(combined, fmt.Errorf("destination %q has unfinished work in another ACME environment", id))
					continue
				}
				d = old
			}
		}
		if d.Destination.Type == "filesystem" {
			d.Destination.Directory, err = filepath.Abs(d.Destination.Directory)
			if err != nil {
				combined = errors.Join(combined, err)
				continue
			}
		}
		result, err := a.publish(ctx, s, d)
		results = append(results, result)
		if err != nil {
			combined = errors.Join(combined, fmt.Errorf("destination %q: %w", id, err))
		}
	}
	return results, combined
}

func (a *Service) publish(ctx context.Context, s *store.Store, d store.Deployment) (deploy.Result, error) {
	if a.options.Progress != nil {
		a.options.Progress(fmt.Sprintf("Deploying generation %q to destination %q", d.GenerationID, d.ID))
	}
	expected := deploy.Result{OperationID: d.OperationID, DestinationID: d.ID, CertificateID: d.CertificateID, GenerationID: d.GenerationID}
	g, _, err := s.Generation(d.CertificateID, d.GenerationID)
	if err != nil {
		return expected, err
	}
	var session *deploy.Session
	switch d.Destination.Type {
	case "filesystem":
		session, err = filesystem.Open(a.Root, filesystem.Config{DestinationID: d.ID, Directory: d.Destination.Directory, KeyFile: d.Destination.KeyFile, CertificateFile: d.Destination.CertificateFile})
	case "dsm":
		session, err = dsm.Open(a.Root, dsm.Config{DestinationID: d.ID, CertificateID: d.Destination.CertificateID, UseDefault: d.Destination.Default, Root: a.options.DSMRoot, Progress: a.options.Progress})
	default:
		return expected, errors.New("unsupported recorded destination")
	}
	if err != nil {
		return expected, err
	}
	defer session.Close()
	if err := s.SaveDeployment(d); err != nil {
		return expected, err
	}
	if a.options.After != nil {
		session.After = func(point string) error { return a.options.After("deploy-" + point) }
	}
	result, err := session.Deploy(ctx, d.OperationID, g)
	if result.DestinationID == "" {
		result = expected
	}
	if err != nil {
		return result, err
	}
	d.Completed = true
	if err := s.SaveDeployment(d); err != nil {
		return result, err
	}
	if a.options.Progress != nil {
		a.options.Progress(fmt.Sprintf("Deployment to %q completed", d.ID))
	}
	return result, nil
}

func (a *Service) LastRequest(id, environment string) (config.Request, error) {
	s, err := store.Open(a.Root, false)
	if err != nil {
		return config.Request{}, err
	}
	defer s.Close()
	p, err := s.Pending(id)
	if err != nil {
		return config.Request{}, err
	}
	if p != nil && p.Request.ACME.Environment == environment {
		return p.Request, nil
	}
	_, r, err := s.Latest(id, environment)
	return r.Request, err
}

func (a *Service) IDs() ([]string, error) {
	s, err := store.Open(a.Root, false)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.IDs()
}
func (a *Service) WorkIDs() ([]string, error) {
	s, err := store.Open(a.Root, false)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.WorkIDs()
}
