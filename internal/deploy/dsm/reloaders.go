package dsm

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kernaxis/xcertm/internal/state"
)

// assignedService reads the metadata for the recorded target, rather than
// treating a subscriber or the certificate file owner as a systemd unit name.
func (t *target) assignedService(key string) (service, error) {
	journal, err := (&state.Store{Dir: t.stateDir}).Load()
	if err != nil {
		return service{}, err
	}
	if journal == nil {
		return service{}, fmt.Errorf("deployment journal missing before DSM activation")
	}
	info, err := t.readInfo()
	if err != nil {
		return service{}, err
	}
	var found []service
	for _, s := range info[journal.Target].Services {
		if serviceKey(s) == key {
			found = append(found, s)
		}
	}
	if len(found) != 1 {
		return service{}, fmt.Errorf("DSM activation service is missing or ambiguous: %s", key)
	}
	return found[0], nil
}

type packageResource struct {
	Certificate struct {
		Services []struct{ Service string } `json:"services"`
		Reloader string                     `json:"reloader-relpath"`
	} `json:"certificate-config"`
	TLS struct {
		Services []struct {
			Service  string `json:"service"`
			Reloader string `json:"reloader-relpath"`
		} `json:"services"`
	} `json:"tls-profile"`
}

// packageReloader uses DSM's structured package declarations. Certificate
// and TLS service names need not match. A sole declared TLS reloader is
// unambiguous; multiple profiles require an exact service match.
func (t *target) packageReloader(s service) (path, kind string, err error) {
	if !s.IsPackage {
		return "", "", nil
	}
	packageDir := filepath.Join(t.config.Root, "var/packages", s.Subscriber)
	resourcePath := filepath.Join(packageDir, "conf/resource")
	info, err := os.Stat(resourcePath)
	if os.IsNotExist(err) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("cannot inspect DSM package resource: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 1<<20 {
		return "", "", fmt.Errorf("invalid DSM package resource file")
	}
	file, err := os.Open(resourcePath)
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return "", "", err
	}
	if len(data) > 1<<20 {
		return "", "", fmt.Errorf("DSM package resource exceeds size limit")
	}
	var resource packageResource
	if err := json.Unmarshal(data, &resource); err != nil {
		return "", "", fmt.Errorf("invalid DSM package resource JSON")
	}
	declared := false
	for _, certificate := range resource.Certificate.Services {
		declared = declared || certificate.Service == s.Service
	}
	if !declared {
		return "", "", fmt.Errorf("certificate service %s is not declared by its DSM package", serviceKey(s))
	}
	kind = "tls"
	var candidates []string
	if len(resource.TLS.Services) == 0 {
		if resource.Certificate.Reloader == "" {
			return "", "none", nil
		}
		kind = "certificate"
		candidates = append(candidates, resource.Certificate.Reloader)
	}
	for _, profile := range resource.TLS.Services {
		if !safeComponent(profile.Service) {
			return "", "", fmt.Errorf("invalid DSM TLS profile identity")
		}
		if profile.Service == s.Service {
			candidates = append(candidates, profile.Reloader)
		}
	}
	if len(candidates) == 0 && len(resource.TLS.Services) == 1 {
		candidates = append(candidates, resource.TLS.Services[0].Reloader)
	}
	if len(candidates) != 1 {
		return "", "", fmt.Errorf("ambiguous DSM TLS reloader for %s", serviceKey(s))
	}
	relative := candidates[0]
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == "." || relative == ".." || strings.HasPrefix(relative, "../") || strings.ContainsAny(relative, "\\\x00\r\n") {
		return "", "", fmt.Errorf("unsafe DSM reloader path")
	}
	// DSM package targets are normally symlinks into the installed volume.
	// Resolve them, but keep the executable confined to that package target.
	target, err := filepath.EvalSymlinks(filepath.Join(packageDir, "target"))
	if err != nil {
		return "", "", fmt.Errorf("cannot resolve DSM package target: %w", err)
	}
	path, err = filepath.EvalSymlinks(filepath.Join(target, relative))
	if err != nil {
		return "", "", fmt.Errorf("cannot resolve DSM reloader: %w", err)
	}
	within, err := filepath.Rel(target, path)
	if err != nil || within == ".." || strings.HasPrefix(within, "../") {
		return "", "", fmt.Errorf("DSM reloader escapes its package target")
	}
	ok, err := executable(path)
	if err != nil {
		return "", "", err
	}
	if !ok {
		return "", "", fmt.Errorf("declared DSM reloader is unavailable")
	}
	info, err = os.Stat(path)
	if err != nil {
		return "", "", err
	}
	if info.Mode().Perm()&0022 != 0 {
		return "", "", fmt.Errorf("DSM reloader must not be group/world writable")
	}
	return path, kind, nil
}
