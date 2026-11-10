// Package filesystem publishes certificate material in an existing directory.
package filesystem

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kernaxis/xcertm/internal/deploy"
	"github.com/kernaxis/xcertm/internal/domain"
	"github.com/kernaxis/xcertm/internal/state"
)

type Config struct {
	DestinationID   string
	Directory       string
	KeyFile         string
	CertificateFile string
}

type target struct{ config Config }

func Open(stateRoot string, config Config) (*deploy.Session, error) {
	dir, err := filepath.Abs(config.Directory)
	if err != nil {
		return nil, err
	}
	if config.Directory == "" {
		return nil, fmt.Errorf("filesystem directory is required")
	}
	config.Directory = dir
	if config.KeyFile == "" {
		config.KeyFile = "privkey.pem"
	}
	if config.CertificateFile == "" {
		config.CertificateFile = "fullchain.pem"
	}
	for _, name := range []string{config.KeyFile, config.CertificateFile} {
		if name == "." || name == ".." || filepath.Base(name) != name || strings.HasPrefix(name, ".xcertm") || strings.ContainsAny(name, "\\\x00") {
			return nil, fmt.Errorf("invalid filesystem output filename")
		}
	}
	if config.KeyFile == config.CertificateFile {
		return nil, fmt.Errorf("filesystem output filenames must be distinct")
	}
	return deploy.Open(stateRoot, &target{config})
}

func (t *target) Binding() deploy.Binding {
	c := t.config
	return deploy.Binding{DestinationID: c.DestinationID, Kind: "filesystem", Resource: c.Directory, Configuration: state.Digest([]byte(c.KeyFile + "\x00" + c.CertificateFile)), LockName: ".xcertm.lock"}
}

func (t *target) Plan(g domain.Generation) (deploy.Plan, error) {
	m, err := deploy.Render(g)
	if err != nil {
		return deploy.Plan{}, err
	}
	c := t.config
	return deploy.Plan{Target: c.Directory, Batches: []state.Batch{{Name: "files", Files: []state.Content{
		{Path: filepath.Join(c.Directory, c.KeyFile), Data: m.PrivateKey},
		{Path: filepath.Join(c.Directory, c.CertificateFile), Data: m.Fullchain},
	}}}}, nil
}

func (t *target) Validate(j *state.Journal) error {
	c := t.config
	if j.Target != c.Directory || len(j.Groups) != 1 || j.Groups[0].Name != "files" || j.Groups[0].Reload != "" || len(j.Files) != 2 || len(j.Guards) != 0 || len(j.Directories) != 1 || j.Directories[0].Path != c.Directory {
		return fmt.Errorf("invalid filesystem deployment plan")
	}
	for i, name := range []string{c.KeyFile, c.CertificateFile} {
		if j.Files[i].Path != filepath.Join(c.Directory, name) || !j.Files[i].After.Exists || j.Files[i].After.Mode != 0600 {
			return fmt.Errorf("invalid filesystem output or permissions")
		}
	}
	if len(j.Groups[0].Files) != 2 || j.Groups[0].Files[0] != 0 || j.Groups[0].Files[1] != 1 {
		return fmt.Errorf("invalid filesystem file group")
	}
	return nil
}
