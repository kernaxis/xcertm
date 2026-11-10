// Package acme adapts x/crypto/acme and coordinates recoverable ACME orders.
package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kernaxis/xcertm/internal/config"
	"github.com/kernaxis/xcertm/internal/dns"
	"github.com/kernaxis/xcertm/internal/domain"
	"github.com/kernaxis/xcertm/internal/state"
	"github.com/kernaxis/xcertm/internal/store"
	xacme "golang.org/x/crypto/acme"
)

func Directory(environment string) string {
	if environment == "staging" {
		return "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	return "https://acme-v02.api.letsencrypt.org/directory"
}

type Issuer struct {
	HTTPClient   *http.Client
	DirectoryURL func(string) string
	Now          func() time.Time
	// After injects interruption after durable lifecycle boundaries.
	After    func(string) error
	Progress func(string)
}

func (i Issuer) report(format string, args ...any) {
	if i.Progress != nil {
		i.Progress(fmt.Sprintf(format, args...))
	}
}

func newKey() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKCS8PrivateKey(key)
}
func signer(der []byte) (crypto.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("invalid persisted signing key")
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("persisted key cannot sign")
	}
	return s, nil
}
func (i Issuer) point(name string) error {
	if i.After != nil {
		return i.After(name)
	}
	return nil
}

func (i Issuer) client(ctx context.Context, s *store.Store, r config.Request, directory string) (*xacme.Client, error) {
	a, err := s.Account(directory, r.ACME.Email)
	if os.IsNotExist(err) {
		key, err := newKey()
		if err != nil {
			return nil, err
		}
		a = store.Account{DirectoryURL: directory, Email: r.ACME.Email, KeyPKCS8: key}
		if err := s.SaveAccount(a); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	key, err := signer(a.KeyPKCS8)
	if err != nil {
		return nil, err
	}
	c := &xacme.Client{Key: key, DirectoryURL: directory, HTTPClient: i.HTTPClient, KID: xacme.KeyID(a.KID), UserAgent: "xcertm"}
	c.RetryBackoff = func(n int, _ *http.Request, response *http.Response) time.Duration {
		if n > 2 || response.StatusCode == http.StatusTooManyRequests {
			return -1
		}
		return time.Duration(n) * time.Second
	}
	if a.KID == "" {
		account, err := c.GetReg(ctx, "")
		if errors.Is(err, xacme.ErrNoAccount) {
			if !r.ACME.AcceptTOS {
				return nil, errors.New("new ACME account requires --accept-tos or acme.accept_tos")
			}
			account, err = c.Register(ctx, &xacme.Account{Contact: []string{"mailto:" + r.ACME.Email}}, func(string) bool { return r.ACME.AcceptTOS })
		}
		if err != nil {
			return nil, err
		}
		if account.URI == "" {
			return nil, errors.New("ACME account response lacks its identity")
		}
		a.KID = account.URI
		if err := s.SaveAccount(a); err != nil {
			return nil, err
		}
		c.KID = xacme.KeyID(a.KID)
	}
	return c, nil
}

func binding(r config.Request) string {
	data, _ := json.Marshal(struct {
		Email, Environment string
		Domains            []string
		Provider           config.Provider
	}{r.ACME.Email, r.ACME.Environment, r.Certificate.Domains, r.Provider})
	return state.Digest(data)
}

func (i Issuer) Obtain(ctx context.Context, s *store.Store, r config.Request, solver dns.Solver) (g domain.Generation, err error) {
	if err = r.Validate(true); err != nil {
		return g, err
	}
	directory := i.DirectoryURL(r.ACME.Environment)
	p, err := s.Pending(r.ID)
	if err != nil {
		return g, err
	}
	if p != nil && (p.DirectoryURL != directory || binding(p.Request) != binding(r)) {
		return g, errors.New("pending issuance uses different account, names, environment, or DNS parameters; resume its original inputs")
	}
	if p != nil {
		i.report("Resuming issuance operation %q", p.ID)
	}
	if p == nil {
		if err := s.EnsureCertificate(r.ID); err != nil {
			return g, err
		}
		id, err := store.NewID()
		if err != nil {
			return g, err
		}
		gid, err := store.NewID()
		if err != nil {
			return g, err
		}
		key, err := newKey()
		if err != nil {
			return g, err
		}
		signingKey, err := signer(key)
		if err != nil {
			return g, err
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: r.Certificate.Domains}, signingKey)
		if err != nil {
			return g, err
		}
		p = &store.Pending{ID: id, GenerationID: gid, Request: r, DirectoryURL: directory, KeyPKCS8: key, CSR: csr}
		if err := s.SavePending(p); err != nil {
			return g, err
		}
		i.report("Prepared issuance operation %q", p.ID)
		if err := i.point("issuance-prepared"); err != nil {
			return g, err
		}
	}
	defer func() {
		if err != nil {
			delay, limited := xacme.RateLimit(err)
			var dnsLimit *dns.RateLimitError
			if errors.As(err, &dnsLimit) {
				delay, limited = dnsLimit.Delay, true
			}
			if limited {
				if delay <= 0 {
					delay = time.Minute
				}
				p.RetryAt = i.Now().Add(delay)
				err = errors.Join(err, s.SavePending(p))
			}
		}
	}()
	if p.RetryAt.After(i.Now()) {
		return g, fmt.Errorf("issuance retry deferred until %s", p.RetryAt.UTC().Format(time.RFC3339))
	}
	save := func() error { return s.SavePending(p) }
	finish := func(g domain.Generation) (domain.Generation, error) {
		if err := s.SaveGeneration(g, p.Request, directory); err != nil {
			return domain.Generation{}, err
		}
		i.report("Certificate generation %q is stored; cleaning up DNS-01", g.ID())
		if err := i.point("generation-stored"); err != nil {
			return domain.Generation{}, err
		}
		var cleanupErr error
		for index := range p.Publications {
			cleanupErr = errors.Join(cleanupErr, solver.Cleanup(ctx, &p.Publications[index], save))
		}
		if cleanupErr != nil {
			return domain.Generation{}, cleanupErr
		}
		if err := s.FinishPending(r.ID); err != nil {
			return domain.Generation{}, err
		}
		return g, nil
	}
	// A certificate saved before cleanup failure is reused without contacting
	// ACME again or rotating its already issued key.
	if existing, _, loadErr := s.Generation(r.ID, p.GenerationID); loadErr == nil {
		if !bytes.Equal(existing.PrivateKeyPKCS8(), p.KeyPKCS8) || existing.Provenance() != (domain.Provenance{Source: "acme", Reference: p.OrderURL}) {
			return g, errors.New("stored generation does not match pending issuance")
		}
		return finish(existing)
	} else if !os.IsNotExist(loadErr) {
		return g, loadErr
	}
	i.report("Loading or registering ACME account (%s)", r.ACME.Environment)
	c, err := i.client(ctx, s, p.Request, directory)
	if err != nil {
		return g, err
	}
	if p.OrderURL == "" {
		i.report("Creating ACME order")
		p.OrderAttempted = true
		if err := save(); err != nil {
			return g, err
		}
		order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(p.Request.Certificate.Domains...))
		if err != nil {
			return g, err
		}
		if order.URI == "" {
			return g, errors.New("ACME order response lacks a URL")
		}
		p.OrderURL = order.URI
		if err := save(); err != nil {
			return g, err
		}
		i.report("ACME order is recorded")
		if err := i.point("order-stored"); err != nil {
			return g, err
		}
	}
	order, err := c.GetOrder(ctx, p.OrderURL)
	if err != nil {
		return g, err
	}
	if order.Status == xacme.StatusInvalid {
		return g, i.terminal(ctx, s, p, solver, errors.New("ACME order is invalid"))
	}
	if order.Status == xacme.StatusPending {
		for _, authorizationURL := range order.AuthzURLs {
			auth, err := c.GetAuthorization(ctx, authorizationURL)
			if err != nil {
				return g, err
			}
			if auth.Status == xacme.StatusValid {
				continue
			}
			if auth.Status != xacme.StatusPending {
				return g, i.terminal(ctx, s, p, solver, errors.New("ACME authorization is no longer usable"))
			}
			if auth.Identifier.Type != "dns" {
				return g, errors.New("only DNS identifiers are supported")
			}
			var challenge *xacme.Challenge
			for _, candidate := range auth.Challenges {
				if candidate.Type == "dns-01" {
					challenge = candidate
					break
				}
			}
			if challenge == nil {
				return g, errors.New("ACME authorization offers no DNS-01 challenge")
			}
			value, err := c.DNS01ChallengeRecord(challenge.Token)
			if err != nil {
				return g, err
			}
			index := -1
			for n, pub := range p.Publications {
				if pub.Authorization == authorizationURL {
					index = n
					break
				}
			}
			if index < 0 {
				name := "_acme-challenge." + strings.TrimPrefix(auth.Identifier.Value, "*.")
				p.Publications = append(p.Publications, dns.Publication{Authorization: authorizationURL, Challenge: challenge.URI, Name: dns.CanonicalName(name), Value: value})
				index = len(p.Publications) - 1
				if err := save(); err != nil {
					return g, err
				}
			} else if p.Publications[index].Value != value || p.Publications[index].Challenge != challenge.URI {
				return g, errors.New("ACME challenge changed during recovery")
			}
			if err := solver.Present(ctx, &p.Publications[index], save); err != nil {
				return g, err
			}
			if err := i.point("dns-presented"); err != nil {
				return g, err
			}
		}
		if err := solver.Wait(ctx, p.Publications); err != nil {
			return g, err
		}
		// All TXT values are present before any authorization is accepted,
		// including apex/wildcard proofs sharing one owner name.
		for _, pub := range p.Publications {
			auth, err := c.GetAuthorization(ctx, pub.Authorization)
			if err != nil {
				return g, err
			}
			if auth.Status == xacme.StatusValid {
				continue
			}
			i.report("Requesting ACME DNS-01 validation for %q", pub.Name)
			if _, err := c.Accept(ctx, &xacme.Challenge{URI: pub.Challenge}); err != nil {
				return g, err
			}
			if _, err := c.WaitAuthorization(ctx, pub.Authorization); err != nil {
				var terminal *xacme.AuthorizationError
				if errors.As(err, &terminal) {
					return g, i.terminal(ctx, s, p, solver, err)
				}
				return g, err
			}
		}
		order, err = c.WaitOrder(ctx, p.OrderURL)
		if err != nil {
			var terminal *xacme.OrderError
			if errors.As(err, &terminal) {
				return g, i.terminal(ctx, s, p, solver, err)
			}
			return g, err
		}
	}
	if order.Status == xacme.StatusProcessing {
		i.report("Waiting for ACME certificate issuance")
		order, err = c.WaitOrder(ctx, p.OrderURL)
		if err != nil {
			var terminal *xacme.OrderError
			if errors.As(err, &terminal) {
				return g, i.terminal(ctx, s, p, solver, err)
			}
			return g, err
		}
	}
	var der [][]byte
	if order.Status == xacme.StatusValid {
		i.report("Downloading issued certificate")
		der, err = c.FetchCert(ctx, order.CertURL, true)
	} else if order.Status == xacme.StatusReady {
		i.report("Finalizing ACME order and retrieving certificate")
		der, _, err = c.CreateCertFromOrder(ctx, order, p.CSR, true)
	} else {
		return g, errors.New("unexpected ACME order state")
	}
	if err != nil {
		return g, err
	}
	if len(der) == 0 {
		return g, errors.New("ACME returned no certificate")
	}
	g, err = domain.NewGeneration(domain.GenerationInput{ID: p.GenerationID, CertificateID: r.ID, Provenance: domain.Provenance{Source: "acme", Reference: p.OrderURL}, CertificateDER: der[0], ChainDER: der[1:], PrivateKeyPKCS8: p.KeyPKCS8, ValidatedAt: i.Now()})
	if err != nil {
		return g, err
	}
	if err := g.ValidateDNSNames(p.Request.Certificate.Domains); err != nil {
		return domain.Generation{}, err
	}
	return finish(g)
}

func (i Issuer) terminal(ctx context.Context, s *store.Store, p *store.Pending, solver dns.Solver, cause error) error {
	var cleanup error
	save := func() error { return s.SavePending(p) }
	for n := range p.Publications {
		cleanup = errors.Join(cleanup, solver.Cleanup(ctx, &p.Publications[n], save))
	}
	if cleanup != nil {
		return errors.Join(cause, cleanup)
	}
	return errors.Join(cause, s.ArchivePending(p))
}
