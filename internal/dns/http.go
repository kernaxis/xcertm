package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

type RateLimitError struct{ Delay time.Duration }

func (e *RateLimitError) Error() string { return "DNS API returned HTTP 429; retry is deferred" }

// HTTPJSON does not surface response bodies, headers, or credentials in errors.
func HTTPJSON(ctx context.Context, client *http.Client, method, url string, headers map[string]string, body any, out any) (int, error) {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return 0, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("DNS API request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		delay := time.Minute
		if seconds, err := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 32); err == nil && seconds > 0 {
			delay = time.Duration(seconds) * time.Second
		} else if at, err := http.ParseTime(resp.Header.Get("Retry-After")); err == nil && time.Until(at) > 0 {
			delay = time.Until(at)
		}
		return resp.StatusCode, &RateLimitError{Delay: delay}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("DNS API returned HTTP %d", resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("invalid DNS API JSON response")
		}
	}
	return resp.StatusCode, nil
}
