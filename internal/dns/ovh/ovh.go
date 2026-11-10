// Package ovh implements signed, zone-scoped OVH DNS-01 operations.
package ovh

import (
	"context"
	"crypto/sha1" // Required by OVH's AK/AS/CK request-signing protocol.
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/kernaxis/xcertm/internal/dns"
)

type Provider struct {
	base, applicationKey, secret, consumerKey, zone string
	client                                          *http.Client
}

func New(endpoint, ak, secret, ck, zone string, client *http.Client) (*Provider, error) {
	base := "https://eu.api.ovh.com/1.0"
	switch endpoint {
	case "", "ovh-eu":
	case "ovh-ca":
		base = "https://ca.api.ovh.com/1.0"
	case "ovh-us":
		base = "https://api.us.ovhcloud.com/1.0"
	default:
		return nil, errors.New("unsupported OVH endpoint")
	}
	return &Provider{base, ak, secret, ck, zone, client}, nil
}

func (p *Provider) call(ctx context.Context, method, path string, body, out any) (int, error) {
	var timestamp int64
	if _, err := dns.HTTPJSON(ctx, p.client, http.MethodGet, p.base+"/auth/time", nil, nil, &timestamp); err != nil {
		return 0, err
	}
	data := ""
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		data = string(encoded)
	}
	stamp := strconv.FormatInt(timestamp, 10)
	signature := fmt.Sprintf("$1$%x", sha1.Sum([]byte(p.secret+"+"+p.consumerKey+"+"+method+"+"+p.base+path+"+"+data+"+"+stamp)))
	return dns.HTTPJSON(ctx, p.client, method, p.base+path, map[string]string{"X-Ovh-Application": p.applicationKey, "X-Ovh-Consumer": p.consumerKey, "X-Ovh-Timestamp": stamp, "X-Ovh-Signature": signature}, body, out)
}

func (p *Provider) zoneName(ctx context.Context, name string) (string, error) {
	name = dns.CanonicalName(name)
	if p.zone != "" {
		zone := dns.CanonicalName(p.zone)
		if name != zone && !strings.HasSuffix(name, "."+zone) {
			return "", errors.New("DNS name is outside configured OVH zone")
		}
		return zone, nil
	}
	var zones []string
	if _, err := p.call(ctx, http.MethodGet, "/domain/zone", nil, &zones); err != nil {
		return "", err
	}
	best := ""
	for _, zone := range zones {
		zone = dns.CanonicalName(zone)
		if (name == zone || strings.HasSuffix(name, "."+zone)) && len(zone) > len(best) {
			best = zone
		}
	}
	if best == "" {
		return "", errors.New("OVH DNS zone not found")
	}
	return best, nil
}

type record struct {
	ID        int64  `json:"id"`
	FieldType string `json:"fieldType"`
	SubDomain string `json:"subDomain"`
	Target    string `json:"target"`
}

func targetValue(value string) string {
	if decoded, err := strconv.Unquote(value); err == nil {
		return decoded
	}
	return value
}
func subdomain(name, zone string) string {
	return strings.TrimSuffix(strings.TrimSuffix(dns.CanonicalName(name), zone), ".")
}

func (p *Provider) Find(ctx context.Context, name, value string) ([]dns.Record, error) {
	zone, err := p.zoneName(ctx, name)
	if err != nil {
		return nil, err
	}
	path := "/domain/zone/" + url.PathEscape(zone) + "/record"
	var ids []int64
	if _, err := p.call(ctx, http.MethodGet, path+"?fieldType=TXT&subDomain="+url.QueryEscape(subdomain(name, zone)), nil, &ids); err != nil {
		return nil, err
	}
	var found []dns.Record
	for _, id := range ids {
		var r record
		if _, err := p.call(ctx, http.MethodGet, path+"/"+strconv.FormatInt(id, 10), nil, &r); err != nil {
			return nil, err
		}
		if r.FieldType == "TXT" && r.SubDomain == subdomain(name, zone) && targetValue(r.Target) == value {
			found = append(found, dns.Record{ID: strconv.FormatInt(r.ID, 10), Zone: zone, Name: dns.CanonicalName(name), Value: value})
		}
	}
	return found, nil
}

func (p *Provider) Create(ctx context.Context, name, value string) (dns.Record, error) {
	zone, err := p.zoneName(ctx, name)
	if err != nil {
		return dns.Record{}, err
	}
	var r record
	_, err = p.call(ctx, http.MethodPost, "/domain/zone/"+url.PathEscape(zone)+"/record", map[string]any{"fieldType": "TXT", "subDomain": subdomain(name, zone), "target": strconv.Quote(value), "ttl": 60}, &r)
	if err != nil {
		return dns.Record{}, err
	}
	if r.ID <= 0 {
		return dns.Record{}, errors.New("OVH returned an invalid record ID")
	}
	// The caller persists the ID before refreshing the zone, including on retry.
	return dns.Record{ID: strconv.FormatInt(r.ID, 10), Zone: zone, Name: dns.CanonicalName(name), Value: value}, nil
}

func (p *Provider) Refresh(ctx context.Context, zone string) error {
	_, err := p.call(ctx, http.MethodPost, "/domain/zone/"+url.PathEscape(zone)+"/refresh", nil, nil)
	return err
}

func (p *Provider) Delete(ctx context.Context, r dns.Record) error {
	path := "/domain/zone/" + url.PathEscape(r.Zone) + "/record/" + url.PathEscape(r.ID)
	var current record
	code, err := p.call(ctx, http.MethodGet, path, nil, &current)
	if code == http.StatusNotFound {
		return p.Refresh(ctx, r.Zone)
	}
	if err != nil {
		return err
	}
	if strconv.FormatInt(current.ID, 10) != r.ID || current.FieldType != "TXT" || current.SubDomain != subdomain(r.Name, r.Zone) || targetValue(current.Target) != r.Value {
		return errors.New("OVH TXT changed; refusing deletion")
	}
	code, err = p.call(ctx, http.MethodDelete, path, nil, nil)
	if err != nil && code != http.StatusNotFound {
		return err
	}
	return p.Refresh(ctx, r.Zone)
}
