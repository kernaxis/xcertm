// Package update installs published XCertM releases independently of certificate state.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const repository = "https://github.com/kernaxis/xcertm"

var versionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.(0|[1-9][0-9]*))?$`)

type Release struct {
	Version     string
	ArchiveName string
	archiveURL  string
	checksumURL string
}

// Client uses public GitHub releases; it needs neither credentials nor configuration.
type Client struct {
	http         *http.Client
	latestURL    string
	downloadBase string
}

func NewClient() *Client {
	return &Client{
		http: &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 || req.URL.Scheme != "https" {
				return fmt.Errorf("refusing unsafe or excessive download redirects")
			}
			return nil
		}},
		latestURL:    "https://api.github.com/repos/kernaxis/xcertm/releases/latest",
		downloadBase: repository + "/releases/download/",
	}
}

// Compare returns current versus target. Unknown build versions are reported separately.
func Compare(current, target string) (comparison int, known bool) {
	a, b := versionPattern.FindStringSubmatch(current), versionPattern.FindStringSubmatch(target)
	if a == nil || b == nil {
		return 0, false
	}
	compareNumber := func(x, y string) int {
		if len(x) != len(y) {
			if len(x) < len(y) {
				return -1
			}
			return 1
		}
		return strings.Compare(x, y)
	}
	for i := 1; i <= 3; i++ {
		if n := compareNumber(a[i], b[i]); n != 0 {
			return n, true
		}
	}
	if a[4] == "" && b[4] != "" {
		return 1, true
	}
	if a[4] != "" && b[4] == "" {
		return -1, true
	}
	return compareNumber(a[5], b[5]), true
}

func (c *Client) Latest(ctx context.Context) (Release, error) {
	arch := runtime.GOARCH
	if runtime.GOOS != "linux" {
		return Release{}, fmt.Errorf("updates support Linux and Synology DSM only")
	}
	if arch == "arm" {
		arch = "armv7"
	}
	switch arch {
	case "amd64", "386", "armv7", "arm64":
	default:
		return Release{}, fmt.Errorf("no release for architecture %s", arch)
	}
	body, err := c.get(ctx, c.latestURL)
	if err != nil {
		return Release{}, err
	}
	defer body.Close()
	data, err := readLimited(body, 1<<20)
	if err != nil {
		return Release{}, err
	}
	var response struct {
		Tag        string                  `json:"tag_name"`
		Draft      bool                    `json:"draft"`
		Prerelease bool                    `json:"prerelease"`
		Assets     []struct{ Name string } `json:"assets"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return Release{}, fmt.Errorf("invalid release metadata: %w", err)
	}
	if !versionPattern.MatchString(response.Tag) || strings.Contains(response.Tag, "-") || response.Draft || response.Prerelease {
		return Release{}, fmt.Errorf("GitHub did not return a published stable release")
	}
	r := Release{Version: response.Tag}
	r.ArchiveName = "xcertm_" + strings.TrimPrefix(r.Version, "v") + "_linux_" + arch + ".tar.gz"
	assets := map[string]int{}
	for _, asset := range response.Assets {
		assets[asset.Name]++
	}
	if assets[r.ArchiveName] != 1 || assets["SHA256SUMS"] != 1 {
		return Release{}, fmt.Errorf("release %s must contain %s and SHA256SUMS", r.Version, r.ArchiveName)
	}
	// Construct fixed repository URLs rather than trusting URLs from API metadata.
	base := c.downloadBase + r.Version + "/"
	r.archiveURL, r.checksumURL = base+r.ArchiveName, base+"SHA256SUMS"
	return r, nil
}

func (c *Client) get(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "xcertm-updater")
	response, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("release download failed: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		if response.StatusCode == http.StatusNotFound && url == c.latestURL {
			return nil, fmt.Errorf("no published stable release is available")
		}
		return nil, fmt.Errorf("release download failed: HTTP %s", strconv.Itoa(response.StatusCode))
	}
	return response.Body, nil
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err == nil && int64(len(data)) > max {
		err = fmt.Errorf("release data exceeds size limit")
	}
	return data, err
}
