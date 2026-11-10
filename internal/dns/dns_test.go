package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type memoryProvider struct {
	records []Record
	lost    bool
	creates int
}

type resolverFunc func(context.Context, string) ([]string, error)

func (f resolverFunc) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return f(ctx, name)
}

func TestPropagationDiagnosticReportsNameAndResolverWithoutValues(t *testing.T) {
	for _, kind := range []string{"negative-answer", "missing-value", "resolver-error", "lookup-timeout"} {
		t.Run(kind, func(t *testing.T) {
			name := "_acme-challenge.test.example.com"
			var log strings.Builder
			resolver := resolverFunc(func(ctx context.Context, query string) ([]string, error) {
				if query != name {
					t.Fatalf("unexpected query name %q", query)
				}
				switch kind {
				case "negative-answer":
					return nil, &net.DNSError{Err: "no such host", IsNotFound: true, Name: query, Server: "10.92.1.1:53"}
				case "missing-value":
					return []string{"synthetic-unrelated-TXT"}, nil
				case "lookup-timeout":
					<-ctx.Done()
					return nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true, Name: query, Server: "10.92.1.1:53"}
				default:
					return nil, errors.New("synthetic-private-error-body")
				}
			})
			s := Solver{Resolver: resolver, PollInterval: time.Millisecond, PropagationTimeout: 10 * time.Millisecond, Progress: func(message string) { log.WriteString(message + "\n") }}
			err := s.Wait(context.Background(), []Publication{{Name: name, Value: "synthetic-expected-proof"}})
			if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), name) {
				t.Fatalf("missing propagation diagnostic: %v", err)
			}
			if kind == "negative-answer" || kind == "lookup-timeout" {
				if !strings.Contains(err.Error(), "10.92.1.1:53") {
					t.Fatal("resolver identity missing from DNS failure")
				}
			}
			if kind == "missing-value" && !strings.Contains(err.Error(), "1 expected TXT value(s) missing, 1 TXT value(s) returned") {
				t.Fatal("missing TXT counts")
			}
			for _, private := range []string{"synthetic-expected-proof", "synthetic-unrelated-TXT", "synthetic-private-error-body"} {
				if strings.Contains(log.String()+err.Error(), private) {
					t.Fatal("DNS diagnostic exposed a value or arbitrary error body")
				}
			}
		})
	}
}

func TestPropagationChecksApexAndWildcardProofsInOneAnswer(t *testing.T) {
	queries := 0
	s := Solver{Resolver: resolverFunc(func(context.Context, string) ([]string, error) {
		queries++
		return []string{"proof-one", "proof-two"}, nil
	})}
	if err := s.Wait(context.Background(), []Publication{{Name: "_acme-challenge.example.com", Value: "proof-one"}, {Name: "_acme-challenge.example.com", Value: "proof-two"}}); err != nil {
		t.Fatal(err)
	}
	if queries != 1 {
		t.Fatal("apex/wildcard proofs sharing an owner were not checked together")
	}
}

func (p *memoryProvider) Find(_ context.Context, name, value string) ([]Record, error) {
	var found []Record
	for _, r := range p.records {
		if r.Name == name && r.Value == value {
			found = append(found, r)
		}
	}
	return found, nil
}
func (p *memoryProvider) Create(_ context.Context, name, value string) (Record, error) {
	p.creates++
	r := Record{ID: fmt.Sprint(p.creates), Zone: "example.com", Name: name, Value: value}
	p.records = append(p.records, r)
	if p.lost {
		p.lost = false
		return Record{}, errors.New("lost response")
	}
	return r, nil
}
func (p *memoryProvider) Delete(_ context.Context, r Record) error {
	for i, existing := range p.records {
		if existing.ID == r.ID {
			if existing != r {
				return errors.New("record changed")
			}
			p.records = append(p.records[:i], p.records[i+1:]...)
			return nil
		}
	}
	return nil
}
func (p *memoryProvider) LookupTXT(_ context.Context, name string) ([]string, error) {
	var values []string
	for _, r := range p.records {
		if r.Name == name {
			values = append(values, r.Value)
		}
	}
	return values, nil
}

func TestTargetedPublicationAndLostCreate(t *testing.T) {
	ctx := context.Background()
	p := &memoryProvider{records: []Record{{ID: "foreign", Zone: "example.com", Name: "_acme-challenge.example.com", Value: "existing"}}, lost: true}
	s := Solver{Provider: p, Resolver: p}
	save := func() error { return nil }
	reused := Publication{Name: "_acme-challenge.example.com", Value: "existing"}
	if err := s.Present(ctx, &reused, save); err != nil {
		t.Fatal(err)
	}
	if reused.Owned {
		t.Fatal("claimed preexisting proof")
	}
	new := Publication{Name: reused.Name, Value: "new-proof"}
	if err := s.Present(ctx, &new, save); err == nil || !new.Intent {
		t.Fatal("expected lost create with recorded intent")
	}
	if err := s.Present(ctx, &new, save); err != nil {
		t.Fatal(err)
	}
	if p.creates != 1 {
		t.Fatal("duplicate DNS record")
	}
	if err := s.Wait(ctx, []Publication{reused, new}); err != nil {
		t.Fatal(err)
	}
	if err := s.Cleanup(ctx, &reused, save); err != nil {
		t.Fatal(err)
	}
	if err := s.Cleanup(ctx, &new, save); err != nil {
		t.Fatal(err)
	}
	if len(p.records) != 1 || p.records[0].ID != "foreign" {
		t.Fatal("removed an unrelated record")
	}
}
func TestAmbiguousRecoveryAndPropagationTimeout(t *testing.T) {
	p := &memoryProvider{records: []Record{{ID: "1", Name: "proof", Value: "value"}, {ID: "2", Name: "proof", Value: "value"}}}
	s := Solver{Provider: p, Resolver: p, PollInterval: time.Millisecond, PropagationTimeout: 5 * time.Millisecond}
	pub := Publication{Name: "proof", Value: "value", Intent: true}
	if err := s.Present(context.Background(), &pub, func() error { return nil }); err == nil {
		t.Fatal("ambiguous ownership accepted")
	}
	if err := s.Cleanup(context.Background(), &pub, func() error { return nil }); err == nil {
		t.Fatal("ambiguous cleanup accepted")
	}
	if len(p.records) != 2 {
		t.Fatal("conflicting proofs deleted")
	}
	if err := s.Wait(context.Background(), []Publication{{Name: "missing", Value: "proof"}}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected bounded propagation: %v", err)
	}
}
func TestHTTPRedactionAndRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(429)
		_, _ = w.Write([]byte("credential-must-not-be-logged"))
	}))
	defer server.Close()
	_, err := HTTPJSON(context.Background(), server.Client(), "GET", server.URL, nil, nil, nil)
	var limited *RateLimitError
	if !errors.As(err, &limited) || limited.Delay != 2*time.Minute {
		t.Fatalf("missing retry-after: %v", err)
	}
}
