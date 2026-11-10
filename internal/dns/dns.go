// Package dns coordinates recoverable DNS-01 publications, independently of ACME.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

type Record struct {
	ID    string `json:"id"`
	Zone  string `json:"zone"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Provider interface {
	Find(context.Context, string, string) ([]Record, error)
	Create(context.Context, string, string) (Record, error)
	Delete(context.Context, Record) error
}

type Resolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

// Publication records an intent before mutation. Preexisting matching records
// are reused but never removed. Cleanup is restricted to an identified record.
type Publication struct {
	Authorization string  `json:"authorization"`
	Challenge     string  `json:"challenge"`
	Name          string  `json:"name"`
	Value         string  `json:"value"`
	Intent        bool    `json:"intent"`
	Owned         bool    `json:"owned"`
	Cleaned       bool    `json:"cleaned"`
	Record        *Record `json:"record,omitempty"`
}

type Solver struct {
	Provider           Provider
	Resolver           Resolver
	PollInterval       time.Duration
	PropagationTimeout time.Duration
	Progress           func(string)
}

func (s Solver) report(format string, args ...any) {
	if s.Progress != nil {
		s.Progress(fmt.Sprintf(format, args...))
	}
}

func CanonicalName(value string) string { return strings.ToLower(strings.TrimSuffix(value, ".")) }

func (s Solver) Present(ctx context.Context, p *Publication, save func() error) error {
	if p.Cleaned {
		return errors.New("publication was already cleaned")
	}
	refresh := func() error {
		if provider, ok := s.Provider.(interface {
			Refresh(context.Context, string) error
		}); ok {
			return provider.Refresh(ctx, p.Record.Zone)
		}
		return nil
	}
	if p.Record != nil {
		if err := refresh(); err != nil {
			return err
		}
		s.report("Reusing recorded TXT publication for %q", p.Name)
		return nil
	}
	matches, err := s.Provider.Find(ctx, p.Name, p.Value)
	if err != nil {
		return err
	}
	if len(matches) > 1 {
		return errors.New("ambiguous matching TXT records; manual reconciliation required")
	}
	if len(matches) == 1 {
		p.Record = &matches[0]
		// A unique expected value appearing after our durable create intent is
		// reconciled as its outcome. No exactly-once claim across API calls.
		p.Owned = p.Intent
		if p.Record.ID == "" {
			return errors.New("DNS provider returned an empty record identity")
		}
		if err := save(); err != nil {
			return err
		}
		if err := refresh(); err != nil {
			return err
		}
		s.report("Reconciled existing TXT publication for %q (owned=%t)", p.Name, p.Owned)
		return nil
	}
	p.Intent = true
	if err := save(); err != nil {
		return err
	}
	s.report("Publishing DNS-01 TXT for %q", p.Name)
	record, err := s.Provider.Create(ctx, p.Name, p.Value)
	if err != nil {
		return err
	}
	if record.ID == "" || CanonicalName(record.Name) != CanonicalName(p.Name) || record.Value != p.Value {
		return errors.New("DNS provider returned inconsistent publication")
	}
	p.Record = &record
	p.Owned = true
	if err := save(); err != nil {
		return err
	}
	if err := refresh(); err != nil {
		return err
	}
	s.report("DNS provider accepted TXT publication for %q", p.Name)
	return nil
}

func lookupFailure(err error) string {
	var lookup *net.DNSError
	if errors.As(err, &lookup) {
		reason := "DNS lookup failed"
		switch {
		case lookup.IsTimeout:
			reason = "DNS lookup timed out"
		case lookup.IsNotFound:
			reason = "DNS name or TXT record not found"
		case lookup.IsTemporary:
			reason = "temporary DNS server failure"
		}
		if lookup.Server != "" {
			reason += fmt.Sprintf(" (resolver %q)", lookup.Server)
		}
		return reason
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "DNS lookup timed out"
	}
	if errors.Is(err, context.Canceled) {
		return "DNS lookup canceled"
	}
	return "DNS lookup failed"
}

func (s Solver) Wait(ctx context.Context, publications []Publication) error {
	timeout := s.PropagationTimeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	interval := s.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Group proofs by owner so apex/wildcard values are checked in the same
	// answer. Diagnostics report counts, never challenge values or credentials.
	names := []string{}
	proofs := map[string][]string{}
	for _, p := range publications {
		if p.Cleaned {
			continue
		}
		if _, ok := proofs[p.Name]; !ok {
			names = append(names, p.Name)
		}
		proofs[p.Name] = append(proofs[p.Name], p.Value)
	}
	if len(names) == 0 {
		return ctx.Err()
	}
	s.report("Checking DNS TXT propagation (deadline %s)", timeout)
	started := time.Now()
	lastDetail := "no DNS lookup completed"
	var lastReport time.Time
	failure := func() error { return fmt.Errorf("DNS propagation not confirmed: %s: %w", lastDetail, ctx.Err()) }
	for {
		if ctx.Err() != nil {
			return failure()
		}
		missing := []string{}
		for _, name := range names {
			values, err := s.Resolver.LookupTXT(ctx, name)
			if ctx.Err() != nil {
				if lastDetail == "no DNS lookup completed" {
					lastDetail = fmt.Sprintf("%q: %s", name, lookupFailure(err))
				}
				return failure()
			}
			if err != nil {
				missing = append(missing, fmt.Sprintf("%q: %s", name, lookupFailure(err)))
				continue
			}
			absent := 0
			for _, proof := range proofs[name] {
				if !slices.Contains(values, proof) {
					absent++
				}
			}
			if absent > 0 {
				missing = append(missing, fmt.Sprintf("%q: %d expected TXT value(s) missing, %d TXT value(s) returned", name, absent, len(values)))
			}
		}
		if len(missing) == 0 {
			s.report("DNS propagation confirmed for %d challenge name(s)", len(names))
			return nil
		}
		detail := strings.Join(missing, "; ")
		if detail != lastDetail || lastReport.IsZero() || time.Since(lastReport) >= 15*time.Second {
			s.report("Waiting for DNS propagation (%s elapsed): %s", time.Since(started).Truncate(time.Second), detail)
			lastReport = time.Now()
		}
		lastDetail = detail
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return failure()
		case <-timer.C:
		}
	}
}

func (s Solver) Cleanup(ctx context.Context, p *Publication, save func() error) error {
	if p.Cleaned {
		return nil
	}
	if p.Record == nil && p.Intent {
		matches, err := s.Provider.Find(ctx, p.Name, p.Value)
		if err != nil {
			return err
		}
		if len(matches) > 1 {
			return errors.New("ambiguous TXT cleanup; manual reconciliation required")
		}
		if len(matches) == 1 {
			p.Record = &matches[0]
			p.Owned = true
			if err := save(); err != nil {
				return err
			}
		}
	}
	if p.Owned && p.Record != nil {
		s.report("Removing owned DNS-01 TXT for %q", p.Name)
		if err := s.Provider.Delete(ctx, *p.Record); err != nil {
			return err
		}
	}
	p.Cleaned = true
	if err := save(); err != nil {
		return err
	}
	s.report("DNS-01 cleanup complete for %q", p.Name)
	return nil
}
