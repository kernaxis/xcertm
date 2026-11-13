package app_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kernaxis/xcertm/internal/app"
	"github.com/kernaxis/xcertm/internal/cli"
	"github.com/kernaxis/xcertm/internal/config"
	"github.com/kernaxis/xcertm/internal/dns"
	"github.com/kernaxis/xcertm/internal/dns/cloudflare"
	"github.com/kernaxis/xcertm/internal/dns/ovh"
	"github.com/kernaxis/xcertm/internal/domain"
	"github.com/kernaxis/xcertm/internal/store"
	xacme "golang.org/x/crypto/acme"
)

// The fixture speaks ACME HTTP/JWS to the real x/crypto client and both DNS
// provider protocols. Its transport refuses every unrecognized origin.
type laboratory struct {
	mu                                      sync.Mutex
	t                                       *testing.T
	server                                  *httptest.Server
	client                                  *http.Client
	now                                     time.Time
	ca                                      *x509.Certificate
	key                                     *ecdsa.PrivateKey
	account                                 *ecdsa.PublicKey
	orders                                  []*testOrder
	records                                 map[string]testRecord
	nextRecord                              int
	registrations, finalizations, refreshes int
	loseCreate, failCleanup, loseFinalize   bool
	limitCreate                             bool
}

func TestInlineTokenIssuanceAndCleanupRecoveryNeverPersistSecret(t *testing.T) {
	l := newLaboratory(t)
	root := filepath.Join(t.TempDir(), "state")
	r := request("cloudflare", t.TempDir())
	token := "fixture-token"
	r.Provider.APIToken = &token
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	l.failCleanup = true
	var progress strings.Builder
	options := l.options()
	options.Progress = func(message string) { progress.WriteString(message + "\n") }
	a := app.New(root, options)
	if _, err := a.Issue(context.Background(), r, app.RunOptions{}); err == nil {
		t.Fatal("expected DNS cleanup failure")
	}
	checkStore := func() {
		t.Helper()
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if bytes.Contains(data, []byte(token)) {
				t.Fatal("inline token was persisted in lifecycle state")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	checkStore()
	l.failCleanup = false
	a = app.New(root, options)
	if _, err := a.Issue(context.Background(), r, app.RunOptions{Deploy: true}); err != nil {
		t.Fatal(err)
	}
	if l.finalizations != 1 {
		t.Fatal("cleanup recovery reissued a certificate")
	}
	assertClean(t, l)
	checkStore()
	infos, err := a.Show("web", "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(infos)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(token)) {
		t.Fatal("public inspection exposed inline token")
	}
	if strings.Contains(progress.String(), token) || strings.Contains(progress.String(), "PRIVATE KEY") {
		t.Fatal("progress exposed secret material")
	}
	for _, phase := range []string{"Publishing DNS-01 TXT", "DNS provider accepted TXT", "DNS propagation confirmed", "Finalizing ACME order", "is stored; cleaning up", "Resuming issuance operation", "Deployment to"} {
		if !strings.Contains(progress.String(), phase) {
			t.Fatalf("missing progress phase %q", phase)
		}
	}
	var out, stderr strings.Builder
	if code := cli.Run(context.Background(), []string{"xcertm", "deploy", "--state-dir", root, "--staging", "--certificate", "web", "--json"}, "test", &out, &stderr); code != 0 {
		t.Fatalf("CLI deployment: %s", stderr.String())
	}
	if !json.Valid([]byte(out.String())) {
		t.Fatal("progress contaminated JSON stdout")
	}
	if !strings.Contains(stderr.String(), "[web]") || !strings.Contains(stderr.String(), "already up to date; deployment skipped") {
		t.Fatal("lifecycle progress is missing from stderr")
	}
}

type testRecord struct{ ID, Name, Value string }
type testOrder struct {
	Names       []string
	Valid       []bool
	Certificate []byte
}
type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newLaboratory(t *testing.T) *laboratory {
	t.Helper()
	l := &laboratory{t: t, now: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC), records: map[string]testRecord{"foreign": {ID: "foreign", Name: "_acme-challenge.example.com", Value: "unrelated-value"}}}
	var err error
	l.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Local test CA"}, NotBefore: l.now.Add(-time.Hour), NotAfter: l.now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &l.key.PublicKey, l.key)
	if err != nil {
		t.Fatal(err)
	}
	l.ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	l.server = httptest.NewServer(http.HandlerFunc(l.serve))
	t.Cleanup(l.server.Close)
	base, _ := url.Parse(l.server.URL)
	l.client = &http.Client{Timeout: 3 * time.Second, Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		copy := r.Clone(r.Context())
		u := *r.URL
		copy.URL = &u
		switch r.URL.Host {
		case "api.cloudflare.com", "eu.api.ovh.com":
			copy.URL.Scheme = base.Scheme
			copy.URL.Host = base.Host
		case base.Host:
		default:
			return nil, errors.New("test refuses non-local request")
		}
		return http.DefaultTransport.RoundTrip(copy)
	})}
	return l
}
func (l *laboratory) options() app.Options {
	return app.Options{HTTPClient: l.client, Resolver: l, Now: func() time.Time { return l.now }, DirectoryURL: func(string) string { return l.server.URL + "/directory" }, PollInterval: time.Millisecond, PropagationTimeout: 100 * time.Millisecond}
}
func (l *laboratory) LookupTXT(_ context.Context, name string) ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var values []string
	for _, r := range l.records {
		if r.Name == strings.TrimSuffix(name, ".") {
			values = append(values, r.Value)
		}
	}
	return values, nil
}
func (l *laboratory) serve(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", strconv.Itoa(time.Now().Nanosecond()))
	if strings.HasPrefix(r.URL.Path, "/client/v4/") {
		l.cloudflare(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/1.0/") {
		l.ovh(w, r)
		return
	}
	l.acme(w, r)
}
func writeJSON(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }
func (l *laboratory) problem(w http.ResponseWriter, status int, kind string) {
	w.WriteHeader(status)
	writeJSON(w, map[string]any{"type": "urn:ietf:params:acme:error:" + kind, "detail": "local fixture error"})
}
func (l *laboratory) payload(r *http.Request) []byte {
	var j struct{ Protected, Payload, Signature string }
	if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
		l.t.Error(err)
		return nil
	}
	protected, err := base64.RawURLEncoding.DecodeString(j.Protected)
	if err != nil {
		l.t.Error(err)
		return nil
	}
	var h struct {
		URL, Kid string
		JWK      struct{ Kty, Crv, X, Y string }
	}
	if err = json.Unmarshal(protected, &h); err != nil {
		l.t.Error(err)
		return nil
	}
	if h.URL != l.server.URL+r.URL.RequestURI() {
		l.t.Errorf("JWS URL mismatch: %s", h.URL)
	}
	key := l.account
	if h.JWK.Kty != "" {
		x, err := base64.RawURLEncoding.DecodeString(h.JWK.X)
		if err != nil {
			l.t.Error("invalid JWK x coordinate")
			return nil
		}
		y, err := base64.RawURLEncoding.DecodeString(h.JWK.Y)
		if err != nil || h.JWK.Crv != "P-256" || len(x) != 32 || len(y) != 32 {
			l.t.Error("invalid P-256 JWK")
			return nil
		}
		point := append([]byte{4}, x...)
		point = append(point, y...)
		key, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			l.t.Error("invalid JWK public key")
			return nil
		}
		l.account = key
	}
	if key == nil {
		l.t.Error("missing JWS key")
		return nil
	}
	sig, _ := base64.RawURLEncoding.DecodeString(j.Signature)
	hash := sha256.Sum256([]byte(j.Protected + "." + j.Payload))
	if len(sig) != 64 || !ecdsa.Verify(key, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		l.t.Error("invalid ACME JWS signature")
	}
	data, err := base64.RawURLEncoding.DecodeString(j.Payload)
	if err != nil {
		l.t.Error(err)
	}
	return data
}
func (l *laboratory) order(w http.ResponseWriter, index int) {
	o := l.orders[index]
	status := "pending"
	if !slices.Contains(o.Valid, false) {
		status = "ready"
	}
	if o.Certificate != nil {
		status = "valid"
	}
	root := fmt.Sprintf("%s/order/%d", l.server.URL, index)
	auth := []string{}
	ids := []map[string]string{}
	for i, n := range o.Names {
		auth = append(auth, fmt.Sprintf("%s/auth/%d/%d", l.server.URL, index, i))
		ids = append(ids, map[string]string{"type": "dns", "value": n})
	}
	w.Header().Set("Location", root)
	writeJSON(w, map[string]any{"status": status, "identifiers": ids, "authorizations": auth, "finalize": root + "/finalize", "certificate": root + "/cert"})
}
func (l *laboratory) acme(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/directory" {
		writeJSON(w, map[string]any{"newNonce": l.server.URL + "/nonce", "newAccount": l.server.URL + "/account", "newOrder": l.server.URL + "/new-order", "meta": map[string]string{"termsOfService": l.server.URL + "/tos"}})
		return
	}
	if r.URL.Path == "/nonce" {
		w.WriteHeader(200)
		return
	}
	data := l.payload(r)
	switch r.URL.Path {
	case "/account":
		var body struct{ OnlyReturnExisting bool }
		_ = json.Unmarshal(data, &body)
		if l.registrations == 0 && body.OnlyReturnExisting {
			l.problem(w, 400, "accountDoesNotExist")
			return
		}
		if l.registrations == 0 {
			l.registrations++
		}
		w.Header().Set("Location", l.server.URL+"/account/1")
		w.WriteHeader(201)
		writeJSON(w, map[string]any{"status": "valid", "orders": l.server.URL + "/orders"})
		return
	case "/new-order":
		var body struct{ Identifiers []struct{ Value string } }
		_ = json.Unmarshal(data, &body)
		o := &testOrder{}
		for _, id := range body.Identifiers {
			o.Names = append(o.Names, id.Value)
			o.Valid = append(o.Valid, false)
		}
		l.orders = append(l.orders, o)
		w.Header().Set("Location", fmt.Sprintf("%s/order/%d", l.server.URL, len(l.orders)-1))
		w.WriteHeader(201)
		l.order(w, len(l.orders)-1)
		return
	}
	var index, auth int
	if strings.HasPrefix(r.URL.Path, "/auth/") || strings.HasPrefix(r.URL.Path, "/challenge/") {
		prefix := "/auth/"
		if strings.HasPrefix(r.URL.Path, "/challenge/") {
			prefix = "/challenge/"
		}
		if _, err := fmt.Sscanf(strings.TrimPrefix(r.URL.Path, prefix), "%d/%d", &index, &auth); err != nil {
			l.t.Error(err)
			w.WriteHeader(400)
			return
		}
		o := l.orders[index]
		token := fmt.Sprintf("token-%d-%d", index, auth)
		if prefix == "/challenge/" {
			thumb, _ := xacme.JWKThumbprint(l.account)
			// Apex and wildcard must coexist before *either* is accepted.
			for n, name := range o.Names {
				proof := sha256.Sum256([]byte(fmt.Sprintf("token-%d-%d", index, n) + "." + thumb))
				wanted := base64.RawURLEncoding.EncodeToString(proof[:])
				present := false
				for _, record := range l.records {
					if record.Name == "_acme-challenge."+strings.TrimPrefix(name, "*.") && record.Value == wanted {
						present = true
					}
				}
				if !present {
					l.t.Error("challenge accepted before all TXT values are published")
				}
			}
			o.Valid[auth] = true
			writeJSON(w, map[string]string{"type": "dns-01", "status": "valid", "url": l.server.URL + r.URL.Path, "token": token})
			return
		}
		status := "pending"
		if o.Valid[auth] {
			status = "valid"
		}
		writeJSON(w, map[string]any{"status": status, "identifier": map[string]string{"type": "dns", "value": strings.TrimPrefix(o.Names[auth], "*.")}, "wildcard": strings.HasPrefix(o.Names[auth], "*."), "challenges": []map[string]string{{"type": "dns-01", "url": fmt.Sprintf("%s/challenge/%d/%d", l.server.URL, index, auth), "token": token, "status": status}}})
		return
	}
	if _, err := fmt.Sscanf(r.URL.Path, "/order/%d", &index); err != nil || index >= len(l.orders) {
		l.t.Errorf("unexpected ACME request %s", r.URL.Path)
		w.WriteHeader(404)
		return
	}
	o := l.orders[index]
	if strings.HasSuffix(r.URL.Path, "/finalize") {
		var body struct{ CSR string }
		_ = json.Unmarshal(data, &body)
		der, _ := base64.RawURLEncoding.DecodeString(body.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			l.t.Error(err)
			w.WriteHeader(400)
			return
		}
		if err := csr.CheckSignature(); err != nil {
			l.t.Error(err)
		}
		if !slices.Equal(csr.DNSNames, o.Names) {
			l.t.Error("CSR and order SANs differ")
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(int64(index + 2)), Subject: pkix.Name{CommonName: o.Names[0]}, DNSNames: csr.DNSNames, NotBefore: l.now.Add(-time.Hour), NotAfter: l.now.Add(90 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err = x509.CreateCertificate(rand.Reader, cert, l.ca, csr.PublicKey, l.key)
		if err != nil {
			l.t.Error(err)
		}
		o.Certificate = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: l.ca.Raw})...)
		l.finalizations++
		if l.loseFinalize {
			l.loseFinalize = false
			l.problem(w, 400, "serverInternal")
			return
		}
	}
	if strings.HasSuffix(r.URL.Path, "/cert") {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(o.Certificate)
		return
	}
	l.order(w, index)
}
func (l *laboratory) cloudflare(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer fixture-token" {
		l.t.Error("wrong Cloudflare authentication")
	}
	wrap := func(v any) {
		writeJSON(w, map[string]any{"success": true, "result": v, "result_info": map[string]int{"total_pages": 1}})
	}
	if r.URL.Path == "/client/v4/zones" {
		wrap([]map[string]string{{"id": "zone1", "name": "example.com"}})
		return
	}
	toJSON := func(record testRecord) map[string]string {
		return map[string]string{"id": record.ID, "name": record.Name, "content": record.Value, "type": "TXT"}
	}
	path := "/client/v4/zones/zone1/dns_records"
	id := strings.TrimPrefix(r.URL.Path, path+"/")
	if r.URL.Path == path {
		if r.Method == "GET" {
			records := []map[string]string{}
			for _, record := range l.records {
				if record.Name == r.URL.Query().Get("name") {
					records = append(records, toJSON(record))
				}
			}
			wrap(records)
			return
		}
		var body struct{ Name, Content string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if l.limitCreate {
			l.limitCreate = false
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(429)
			return
		}
		l.nextRecord++
		record := testRecord{strconv.Itoa(l.nextRecord), body.Name, body.Content}
		l.records[record.ID] = record
		if l.loseCreate {
			l.loseCreate = false
			w.WriteHeader(400)
			writeJSON(w, map[string]string{"error": "fixture-token must never escape"})
			return
		}
		wrap(toJSON(record))
		return
	}
	record, ok := l.records[id]
	if !ok {
		w.WriteHeader(404)
		return
	}
	if r.Method == "DELETE" {
		if l.failCleanup {
			w.WriteHeader(403)
			return
		}
		delete(l.records, id)
	}
	wrap(toJSON(record))
}
func (l *laboratory) ovh(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/1.0/auth/time" {
		writeJSON(w, 1800000000)
		return
	}
	body, _ := io.ReadAll(r.Body)
	stamp := r.Header.Get("X-Ovh-Timestamp")
	signature := fmt.Sprintf("$1$%x", sha1.Sum([]byte("fixture-secret+fixture-consumer+"+r.Method+"+https://eu.api.ovh.com"+r.URL.RequestURI()+"+"+string(body)+"+"+stamp)))
	if r.Header.Get("X-Ovh-Application") != "fixture-key" || r.Header.Get("X-Ovh-Consumer") != "fixture-consumer" || r.Header.Get("X-Ovh-Signature") != signature {
		l.t.Error("invalid OVH request signature")
	}
	if r.URL.Path == "/1.0/domain/zone" {
		writeJSON(w, []string{"example.com"})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/refresh") {
		l.refreshes++
		writeJSON(w, nil)
		return
	}
	path := "/1.0/domain/zone/example.com/record"
	encode := func(record testRecord) map[string]any {
		id, _ := strconv.Atoi(record.ID)
		return map[string]any{"id": id, "fieldType": "TXT", "subDomain": strings.TrimSuffix(record.Name, ".example.com"), "target": strconv.Quote(record.Value)}
	}
	if r.URL.Path == path {
		if r.Method == "GET" {
			ids := []int{}
			for _, record := range l.records {
				if record.ID != "foreign" && record.Name == r.URL.Query().Get("subDomain")+".example.com" {
					id, _ := strconv.Atoi(record.ID)
					ids = append(ids, id)
				}
			}
			writeJSON(w, ids)
			return
		}
		var b struct{ SubDomain, Target string }
		_ = json.Unmarshal(body, &b)
		value, _ := strconv.Unquote(b.Target)
		l.nextRecord++
		record := testRecord{strconv.Itoa(l.nextRecord), b.SubDomain + ".example.com", value}
		l.records[record.ID] = record
		if l.loseCreate {
			l.loseCreate = false
			w.WriteHeader(400)
			return
		}
		writeJSON(w, encode(record))
		return
	}
	id := strings.TrimPrefix(r.URL.Path, path+"/")
	record, ok := l.records[id]
	if !ok {
		w.WriteHeader(404)
		return
	}
	if r.Method == "DELETE" {
		if l.failCleanup {
			w.WriteHeader(403)
			return
		}
		delete(l.records, id)
	}
	writeJSON(w, encode(record))
}
func request(provider, dir string) config.Request {
	return config.Request{ID: "web", ACME: config.ACME{Environment: "staging", Email: "admin@example.com", AcceptTOS: true}, Provider: config.Provider{Type: provider, Zone: "example.com"}, Certificate: config.Certificate{Domains: []string{"example.com", "*.example.com"}, Destinations: []string{"web-local"}}, Destinations: map[string]config.Destination{"web-local": {Type: "filesystem", Directory: dir}}}
}
func credentials(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "fixture-token")
	t.Setenv("OVH_APPLICATION_KEY", "fixture-key")
	t.Setenv("OVH_APPLICATION_SECRET", "fixture-secret")
	t.Setenv("OVH_CONSUMER_KEY", "fixture-consumer")
}
func assertClean(t *testing.T, l *laboratory) {
	t.Helper()
	if len(l.records) != 1 || l.records["foreign"].Value != "unrelated-value" {
		t.Fatalf("targeted cleanup failed: %d records remain", len(l.records))
	}
}

func TestIssueRenewDeployAndInspection(t *testing.T) {
	for _, provider := range []string{"cloudflare", "ovh"} {
		t.Run(provider, func(t *testing.T) {
			credentials(t)
			l := newLaboratory(t)
			root := filepath.Join(t.TempDir(), "state")
			r := request(provider, t.TempDir())
			a := app.New(root, l.options())
			ctx := context.Background()
			first, err := a.Issue(ctx, r, app.RunOptions{Deploy: true})
			if err != nil {
				t.Fatal(err)
			}
			if first.State != "issued" || len(first.Deployments) != 1 || !first.Deployments[0].Completed {
				t.Fatalf("unexpected outcome: %+v", first)
			}
			assertClean(t, l)
			s, err := store.Open(root, false)
			if err != nil {
				t.Fatal(err)
			}
			g, _, err := s.Latest("web", "staging")
			s.Close()
			if err != nil {
				t.Fatal(err)
			}
			firstKey := g.PrivateKeyPKCS8()
			second, err := a.Issue(ctx, r, app.RunOptions{Renew: true, Deploy: true})
			if err != nil {
				t.Fatal(err)
			}
			if second.State != "not-due" || second.GenerationID != first.GenerationID || l.finalizations != 1 {
				t.Fatal("renewed before due")
			}
			l.now = l.now.Add(70 * 24 * time.Hour)
			third, err := a.Issue(ctx, r, app.RunOptions{Renew: true, Deploy: true})
			if err != nil {
				t.Fatal(err)
			}
			if third.State != "renewed" || third.GenerationID == first.GenerationID || l.finalizations != 2 || l.registrations != 1 {
				t.Fatalf("bad renewal: %+v", third)
			}
			assertClean(t, l)
			s, err = store.Open(root, false)
			if err != nil {
				t.Fatal(err)
			}
			g, _, err = s.Latest("web", "staging")
			s.Close()
			if err != nil {
				t.Fatal(err)
			}
			if slices.Equal(g.PrivateKeyPKCS8(), firstKey) {
				t.Fatal("private key was not rotated")
			}
			if provider == "ovh" && l.refreshes < 8 {
				t.Fatal("OVH publication/deletion was not refreshed")
			}
			// Inspection and deployment do not resolve DNS credentials or access ACME.
			t.Setenv("CLOUDFLARE_API_TOKEN", "")
			t.Setenv("OVH_APPLICATION_KEY", "")
			a = app.New(root, app.Options{HTTPClient: &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
				t.Error("unexpected network access")
				return nil, errors.New("offline")
			})}})
			if _, err = a.Deploy(ctx, r); err != nil {
				t.Fatal(err)
			}
			var commandOut, commandErr strings.Builder
			if code := cli.Run(ctx, []string{"xcertm", "deploy", "--state-dir", root, "--staging", "--certificate", "web", "--destination", "web-local"}, "test", &commandOut, &commandErr); code != 0 {
				t.Fatalf("flags-only deployment: %s", commandErr.String())
			}
			for _, args := range [][]string{{"list", "--json"}, {"show", "web", "--json"}} {
				var out, stderr strings.Builder
				args = append([]string{"xcertm", "--state-dir", root}, args...)
				if code := cli.Run(ctx, args, "test", &out, &stderr); code != 0 {
					t.Fatalf("inspection exit %d: %s", code, stderr.String())
				}
				if strings.Contains(out.String(), "private_key") || strings.Contains(out.String(), "fixture-") || strings.Contains(out.String(), "api_token") {
					t.Fatal("inspection exposed secret material")
				}
				if !strings.Contains(out.String(), third.GenerationID) {
					t.Fatal("latest generation missing")
				}
			}
			if rows, err := a.List("production"); err != nil || len(rows) != 0 {
				t.Fatal("staging leaked into production listing")
			}
		})
	}
}

func TestIssuanceRecoversWithoutDuplicateCertificate(t *testing.T) {
	for _, point := range []string{"issuance-prepared", "order-stored", "dns-presented", "generation-stored", "lost-create", "lost-finalize", "cleanup-failure", "deploy-file"} {
		t.Run(point, func(t *testing.T) {
			credentials(t)
			l := newLaboratory(t)
			root := filepath.Join(t.TempDir(), "state")
			r := request("cloudflare", t.TempDir())
			options := l.options()
			interrupted := false
			options.After = func(at string) error {
				match := at == point || point == "deploy-file" && strings.HasPrefix(at, "deploy-")
				if match && !interrupted {
					interrupted = true
					return errors.New("simulated interruption")
				}
				return nil
			}
			l.loseCreate = point == "lost-create"
			l.loseFinalize = point == "lost-finalize"
			l.failCleanup = point == "cleanup-failure"
			a := app.New(root, options)
			_, err := a.Issue(context.Background(), r, app.RunOptions{Deploy: true})
			if err == nil {
				t.Fatal("expected interrupted operation")
			}
			if point == "cleanup-failure" {
				s, e := store.Open(root, false)
				if e != nil {
					t.Fatal(e)
				}
				_, _, e = s.Latest("web", "staging")
				s.Close()
				if e != nil {
					t.Fatal("issued certificate was not preserved")
				}
			}
			l.failCleanup = false
			a = app.New(root, l.options())
			result, err := a.Issue(context.Background(), r, app.RunOptions{Deploy: true})
			if err != nil {
				t.Fatal(err)
			}
			if result.GenerationID == "" || len(result.Deployments) != 1 || !result.Deployments[0].Completed {
				t.Fatalf("incomplete recovery: %+v", result)
			}
			if l.finalizations != 1 || len(l.orders) != 1 {
				t.Fatalf("recovery duplicated issuance: orders=%d finalizations=%d", len(l.orders), l.finalizations)
			}
			assertClean(t, l)
		})
	}
}

func TestIndependentDestinationsAndDeploymentRetry(t *testing.T) {
	credentials(t)
	l := newLaboratory(t)
	root := filepath.Join(t.TempDir(), "state")
	r := request("cloudflare", t.TempDir())
	r.Certificate.Destinations = append(r.Certificate.Destinations, "blocked")
	blocked := t.TempDir()
	if err := os.WriteFile(filepath.Join(blocked, "fullchain.pem"), []byte("external file"), 0600); err != nil {
		t.Fatal(err)
	}
	r.Destinations["blocked"] = config.Destination{Type: "filesystem", Directory: blocked}
	a := app.New(root, l.options())
	result, err := a.Issue(context.Background(), r, app.RunOptions{Deploy: true})
	if err == nil {
		t.Fatal("expected deployment conflict")
	}
	if len(result.Deployments) != 2 || !result.Deployments[0].Completed || result.Deployments[1].Completed {
		t.Fatalf("destinations not independent: %+v", result)
	}
	if err := os.Remove(filepath.Join(blocked, "fullchain.pem")); err != nil {
		t.Fatal(err)
	}
	result, err = a.Deploy(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if l.finalizations != 1 || !result.Deployments[1].Completed {
		t.Fatal("deployment retry reissued certificate")
	}
}

func TestIssueToDSMAndFilesystemWithFailedReloadRecovery(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local DSM deployment requires Linux")
	}
	credentials(t)
	l := newLaboratory(t)
	nas := t.TempDir()
	root := filepath.Join(t.TempDir(), "state")
	archive := filepath.Join(nas, "usr/syno/etc/certificate/_archive")
	service := filepath.Join(nas, "usr/syno/etc/certificate/system/default")
	scripts := filepath.Join(nas, "usr/libexec/certificate.d")
	for _, dir := range []string{filepath.Join(archive, "ABC123"), service, scripts} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for path, data := range map[string]string{filepath.Join(archive, "INFO"): `{"ABC123":{"desc":"fixture","services":[{"subscriber":"system","service":"default"}]}}`, filepath.Join(archive, "DEFAULT"): "ABC123\n"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fail := filepath.Join(scripts, "fail")
	if err := os.WriteFile(fail, nil, 0600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nbase=${0%/*}\nif [ -f \"$base/fail\" ]; then exit 9; fi\n"
	if err := os.WriteFile(filepath.Join(scripts, "system"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	r := request("ovh", t.TempDir())
	r.Certificate.Destinations = append(r.Certificate.Destinations, "nas-main")
	r.Destinations["nas-main"] = config.Destination{Type: "dsm", Default: true}
	options := l.options()
	options.DSMRoot = nas
	a := app.New(root, options)
	out, err := a.Issue(context.Background(), r, app.RunOptions{Deploy: true})
	if err == nil {
		t.Fatal("failed DSM reload reported success")
	}
	if len(out.Deployments) != 2 || !out.Deployments[0].Completed || out.Deployments[1].Completed {
		t.Fatalf("invalid independent results: %+v", out)
	}
	if len(out.Deployments[1].Services) != 1 || !out.Deployments[1].Services[0].FilesPublished || out.Deployments[1].Services[0].Activation != "callback-failed" {
		t.Fatal("partial DSM service outcome missing", out.Deployments[1])
	}
	for _, args := range [][]string{{"list"}, {"show", "web"}, {"show", "web", "--json"}} {
		var stdout, stderr strings.Builder
		argv := append([]string{"xcertm", "--state-dir", root, "--staging"}, args...)
		if code := cli.Run(context.Background(), argv, "test", &stdout, &stderr); code != 0 {
			t.Fatalf("partial deployment cannot be inspected: %s", &stderr)
		}
		if args[0] == "list" {
			if !strings.Contains(stdout.String(), "nas-main:partial@") {
				t.Fatal("partial deployment not distinguished from untouched pending work", &stdout)
			}
		} else if !strings.Contains(stdout.String(), "callback-failed") {
			t.Fatal("service callback outcome missing from show", &stdout)
		}
	}
	if err := os.Remove(fail); err != nil {
		t.Fatal(err)
	}
	// Current configuration cannot redirect work already recorded for the NAS.
	r.Destinations["nas-main"] = config.Destination{Type: "dsm", CertificateID: "OTHER"}
	a = app.New(root, options)
	out, err = a.Issue(context.Background(), r, app.RunOptions{Deploy: true})
	if err != nil {
		t.Fatal(err)
	}
	if out.State != "recovered" || l.finalizations != 1 {
		t.Fatal("recovery caused another issuance")
	}
	if len(out.Deployments) != 2 || len(out.Deployments[0].Services) != 1 || out.Deployments[0].Services[0].Activation != "callback-succeeded" || !out.Deployments[1].Unchanged {
		t.Fatal("recovered callback outcome not reported", out.Deployments)
	}
	for _, dir := range []string{filepath.Join(archive, "ABC123"), service} {
		data, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
		if err != nil || !strings.Contains(string(data), "BEGIN CERTIFICATE") {
			t.Fatalf("missing DSM material: %v", err)
		}
	}
}

func TestPendingRequestCannotChangeNamesOrEnvironment(t *testing.T) {
	credentials(t)
	l := newLaboratory(t)
	root := filepath.Join(t.TempDir(), "state")
	r := request("cloudflare", t.TempDir())
	options := l.options()
	options.After = func(string) error { return errors.New("interrupt") }
	a := app.New(root, options)
	if _, err := a.Issue(context.Background(), r, app.RunOptions{}); err == nil {
		t.Fatal("expected interruption")
	}
	a = app.New(root, l.options())
	r.Certificate.Domains = []string{"other.example.com"}
	if _, err := a.Issue(context.Background(), r, app.RunOptions{}); err == nil {
		t.Fatal("changed pending names accepted")
	}
	if len(l.orders) != 0 {
		t.Fatal("changed pending operation reached ACME")
	}
	r = request("cloudflare", t.TempDir())
	r.ACME.Environment = "production"
	if _, err := a.Issue(context.Background(), r, app.RunOptions{}); err == nil {
		t.Fatal("changed pending environment accepted")
	}
}

func TestIssueToAutomaticDSMEntryAndRecoverWithoutReissuing(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local DSM deployment requires Linux")
	}
	credentials(t)
	lab := newLaboratory(t)
	nas := t.TempDir()
	root := filepath.Join(t.TempDir(), "state")
	archive := filepath.Join(nas, "usr/syno/etc/certificate/_archive")
	if err := os.MkdirAll(filepath.Join(archive, "ABC123"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{filepath.Join(archive, "INFO"): `{"ABC123":{"desc":"existing default","services":[],"extra":{"keep":true}}}`, filepath.Join(archive, "DEFAULT"): "ABC123\n"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := request("cloudflare", t.TempDir())
	r.Certificate.Destinations = append(r.Certificate.Destinations, "nas-main")
	r.Destinations["nas-main"] = config.Destination{Type: "dsm"}
	options := lab.options()
	options.DSMRoot = nas
	options.After = func(point string) error {
		if point == "deploy-dsm-info-published" {
			return errors.New("interrupted DSM registration")
		}
		return nil
	}
	a := app.New(root, options)
	first, err := a.Issue(context.Background(), r, app.RunOptions{Deploy: true})
	if err == nil || first.GenerationID == "" || len(first.Deployments) != 2 || !first.Deployments[0].Completed || first.Deployments[1].Completed {
		t.Fatalf("expected partial deployment with stored generation: %+v, %v", first, err)
	}
	entryID := func() string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(archive, "INFO"))
		if err != nil {
			t.Fatal(err)
		}
		var info map[string]json.RawMessage
		if err := json.Unmarshal(data, &info); err != nil {
			t.Fatal(err)
		}
		if len(info) != 2 {
			t.Fatal("unexpected DSM entry count")
		}
		for id := range info {
			if id != "ABC123" {
				return id
			}
		}
		t.Fatal("missing automatic DSM entry")
		return ""
	}
	id := entryID()
	options.After = nil
	a = app.New(root, options)
	second, err := a.Issue(context.Background(), r, app.RunOptions{Deploy: true})
	if err != nil {
		t.Fatal(err)
	}
	if second.State != "recovered" || second.GenerationID != first.GenerationID || lab.finalizations != 1 || entryID() != id {
		t.Fatal("registration recovery duplicated issuance or DSM entry")
	}
	third, err := a.Issue(context.Background(), r, app.RunOptions{Force: true, Deploy: true})
	if err != nil {
		t.Fatal(err)
	}
	if third.GenerationID == first.GenerationID || lab.finalizations != 2 || entryID() != id {
		t.Fatal("new generation did not reuse the managed DSM entry")
	}
	if data, err := os.ReadFile(filepath.Join(archive, "DEFAULT")); err != nil || string(data) != "ABC123\n" {
		t.Fatal("automatic deployment modified DSM DEFAULT")
	}
}

func TestDNSRateLimitIsPersistedAcrossCommands(t *testing.T) {
	credentials(t)
	l := newLaboratory(t)
	l.limitCreate = true
	root := filepath.Join(t.TempDir(), "state")
	r := request("cloudflare", t.TempDir())
	a := app.New(root, l.options())
	if _, err := a.Issue(context.Background(), r, app.RunOptions{}); err == nil {
		t.Fatal("expected provider rate limit")
	}
	s, err := store.Open(root, false)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Pending("web")
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	if p == nil || !p.RetryAt.Equal(l.now.Add(2*time.Minute)) {
		t.Fatal("provider retry deadline not persisted")
	}
	a = app.New(root, l.options())
	if _, err := a.Issue(context.Background(), r, app.RunOptions{}); err == nil || !strings.Contains(err.Error(), "deferred until") {
		t.Fatalf("retry deadline ignored: %v", err)
	}
	l.now = l.now.Add(2*time.Minute + time.Second)
	if _, err := a.Issue(context.Background(), r, app.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	if l.finalizations != 1 {
		t.Fatal("rate limit recovery duplicated issuance")
	}
	assertClean(t, l)
}

func TestProviderRefusesDeletingExternallyChangedTXT(t *testing.T) {
	for _, kind := range []string{"cloudflare", "ovh"} {
		t.Run(kind, func(t *testing.T) {
			l := newLaboratory(t)
			var p dns.Provider
			if kind == "cloudflare" {
				p = cloudflare.New("fixture-token", "example.com", l.client)
			} else {
				var err error
				p, err = ovh.New("ovh-eu", "fixture-key", "fixture-secret", "fixture-consumer", "example.com", l.client)
				if err != nil {
					t.Fatal(err)
				}
			}
			r, err := p.Create(context.Background(), "_acme-challenge.example.com", "owned-value")
			if err != nil {
				t.Fatal(err)
			}
			l.mu.Lock()
			changed := l.records[r.ID]
			changed.Value = "external-change"
			l.records[r.ID] = changed
			l.mu.Unlock()
			if err := p.Delete(context.Background(), r); err == nil {
				t.Fatal("externally changed record deleted")
			}
			if l.records[r.ID].Value != "external-change" {
				t.Fatal("external record was modified")
			}
		})
	}
}

func TestStoredGenerationIsImmutableAndCorruptionDoesNotIssue(t *testing.T) {
	credentials(t)
	l := newLaboratory(t)
	root := filepath.Join(t.TempDir(), "state")
	r := request("cloudflare", t.TempDir())
	a := app.New(root, l.options())
	if _, err := a.Issue(context.Background(), r, app.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root, true)
	if err != nil {
		t.Fatal(err)
	}
	g, record, err := s.Latest("web", "staging")
	if err != nil {
		t.Fatal(err)
	}
	changed, err := domain.NewGeneration(domain.GenerationInput{ID: g.ID(), CertificateID: g.CertificateID(), Provenance: g.Provenance(), ValidatedAt: g.ValidatedAt(), CertificateDER: g.CertificateDER(), PrivateKeyPKCS8: g.PrivateKeyPKCS8()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveGeneration(changed, record.Request, record.DirectoryURL); err == nil {
		t.Fatal("immutable issuer chain was replaced")
	}
	path := filepath.Join(s.CertDir("web"), "generations", g.ID()+".json")
	record.Input.PrivateKeyPKCS8 = []byte("corrupted material")
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := a.List(""); err == nil {
		t.Fatal("corrupt store shown as a valid inventory")
	}
	if _, err := a.Issue(context.Background(), r, app.RunOptions{}); err == nil {
		t.Fatal("corrupt generation silently ignored")
	}
	if l.finalizations != 1 {
		t.Fatal("store corruption caused a new issuance")
	}
}
