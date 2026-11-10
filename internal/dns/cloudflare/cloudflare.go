// Package cloudflare implements targeted DNS-01 record operations via API v4.
package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kernaxis/xcertm/internal/dns"
)

const baseURL = "https://api.cloudflare.com/client/v4"

type Provider struct {
	token, zone string
	client      *http.Client
}

func New(token, zone string, client *http.Client) *Provider { return &Provider{token, zone, client} }

type record struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
}
type envelope[T any] struct {
	Success bool `json:"success"`
	Result  T    `json:"result"`
	Info    struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (p *Provider) call(ctx context.Context, method, path string, body, out any) (int, error) {
	return dns.HTTPJSON(ctx, p.client, method, baseURL+path, map[string]string{"Authorization": "Bearer " + p.token}, body, out)
}

func (p *Provider) zoneID(ctx context.Context, name string) (string, error) {
	name = dns.CanonicalName(name)
	for candidate := name; candidate != ""; {
		if p.zone != "" {
			candidate = dns.CanonicalName(p.zone)
			if name != candidate && !strings.HasSuffix(name, "."+candidate) {
				return "", errors.New("DNS name is outside configured Cloudflare zone")
			}
		}
		var response envelope[[]struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}]
		_, err := p.call(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(candidate), nil, &response)
		if err != nil {
			return "", err
		}
		if !response.Success {
			return "", errors.New("Cloudflare rejected zone lookup")
		}
		if len(response.Result) > 1 {
			return "", errors.New("ambiguous Cloudflare zone")
		}
		if len(response.Result) == 1 && response.Result[0].ID != "" && dns.CanonicalName(response.Result[0].Name) == candidate {
			return response.Result[0].ID, nil
		}
		if p.zone != "" {
			break
		}
		_, tail, ok := strings.Cut(candidate, ".")
		if !ok {
			break
		}
		candidate = tail
	}
	return "", errors.New("Cloudflare DNS zone not found")
}

func (p *Provider) Find(ctx context.Context, name, value string) ([]dns.Record, error) {
	zone, err := p.zoneID(ctx, name)
	if err != nil {
		return nil, err
	}
	name = dns.CanonicalName(name)
	var found []dns.Record
	for page := 1; page <= 1000; page++ {
		var response envelope[[]record]
		path := fmt.Sprintf("/zones/%s/dns_records?type=TXT&name=%s&per_page=100&page=%d", url.PathEscape(zone), url.QueryEscape(name), page)
		if _, err := p.call(ctx, http.MethodGet, path, nil, &response); err != nil {
			return nil, err
		}
		if !response.Success {
			return nil, errors.New("Cloudflare rejected record lookup")
		}
		for _, r := range response.Result {
			if r.Type == "TXT" && dns.CanonicalName(r.Name) == name && r.Content == value {
				found = append(found, dns.Record{ID: r.ID, Zone: zone, Name: name, Value: value})
			}
		}
		if page >= response.Info.TotalPages {
			return found, nil
		}
	}
	return nil, errors.New("Cloudflare record pagination limit exceeded")
}

func (p *Provider) Create(ctx context.Context, name, value string) (dns.Record, error) {
	zone, err := p.zoneID(ctx, name)
	if err != nil {
		return dns.Record{}, err
	}
	var response envelope[record]
	_, err = p.call(ctx, http.MethodPost, "/zones/"+url.PathEscape(zone)+"/dns_records", map[string]any{"type": "TXT", "name": dns.CanonicalName(name), "content": value, "ttl": 60}, &response)
	if err != nil {
		return dns.Record{}, err
	}
	if !response.Success || response.Result.Type != "TXT" {
		return dns.Record{}, errors.New("Cloudflare rejected record creation")
	}
	r := response.Result
	return dns.Record{ID: r.ID, Zone: zone, Name: dns.CanonicalName(r.Name), Value: r.Content}, nil
}

func (p *Provider) Delete(ctx context.Context, r dns.Record) error {
	path := "/zones/" + url.PathEscape(r.Zone) + "/dns_records/" + url.PathEscape(r.ID)
	var response envelope[record]
	code, err := p.call(ctx, http.MethodGet, path, nil, &response)
	if code == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if !response.Success || response.Result.ID != r.ID || response.Result.Type != "TXT" || dns.CanonicalName(response.Result.Name) != dns.CanonicalName(r.Name) || response.Result.Content != r.Value {
		return errors.New("Cloudflare TXT changed; refusing deletion")
	}
	var deleted envelope[struct {
		ID string `json:"id"`
	}]
	code, err = p.call(ctx, http.MethodDelete, path, nil, &deleted)
	if code == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if !deleted.Success {
		return errors.New("Cloudflare rejected record deletion")
	}
	return nil
}
