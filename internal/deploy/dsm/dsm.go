// Package dsm deploys to local DSM certificate entries and their assigned
// services. With no selector it creates and retains a dedicated entry.
package dsm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kernaxis/xcertm/internal/deploy"
	"github.com/kernaxis/xcertm/internal/domain"
	"github.com/kernaxis/xcertm/internal/state"
)

type Config struct {
	DestinationID string
	CertificateID string
	UseDefault    bool
	// Root defaults to /. An alternate local root permits mounted layouts and
	// integration tests; all certificate paths and scripts are resolved below it.
	Root     string
	Progress func(string)
}

type service struct {
	Subscriber string `json:"subscriber"`
	Service    string `json:"service"`
	IsPackage  bool   `json:"isPkg"`
}
type certInfo struct {
	Services []service `json:"services"`
}
type target struct {
	config   Config
	archive  string
	stateDir string
}

func Open(stateRoot string, config Config) (*deploy.Session, error) {
	if config.UseDefault && config.CertificateID != "" {
		return nil, errors.New("DSM certificate ID and UseDefault are mutually exclusive")
	}
	if config.CertificateID != "" && !safeComponent(config.CertificateID) {
		return nil, errors.New("invalid DSM certificate ID")
	}
	if config.Root == "" {
		config.Root = "/"
	}
	root, err := filepath.Abs(config.Root)
	if err != nil {
		return nil, err
	}
	config.Root = root
	stateRoot, err = filepath.Abs(stateRoot)
	if err != nil {
		return nil, err
	}
	t := &target{config: config, archive: filepath.Join(root, "usr/syno/etc/certificate/_archive"), stateDir: deploy.StateDirectory(stateRoot, config.DestinationID)}
	if err := t.checkCreationOwner(); err != nil {
		return nil, err
	}
	session, err := deploy.Open(stateRoot, t)
	if err != nil {
		return nil, err
	}
	if t.automatic() {
		if err := t.checkAutomaticEntry(); err != nil {
			session.Close()
			return nil, err
		}
	}
	return session, nil
}

func safeComponent(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value && !strings.ContainsAny(value, "\\\x00\r\n")
}

func (t *target) Binding() deploy.Binding {
	selector := "id:" + t.config.CertificateID
	if t.config.UseDefault {
		selector = "default"
	} else if t.automatic() {
		selector = "auto"
	}
	return deploy.Binding{DestinationID: t.config.DestinationID, Kind: "dsm", Resource: t.archive, Configuration: state.Digest([]byte(selector)), LockName: ".xcertm.lock"}
}

func (t *target) readInfo() (map[string]certInfo, error) {
	path := filepath.Join(t.archive, "INFO")
	if _, err := state.Inspect(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var info map[string]certInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("invalid DSM INFO: %w", err)
	}
	if info == nil {
		return nil, errors.New("DSM INFO must be an object")
	}
	return info, nil
}

func (t *target) defaultID() (string, error) {
	path := filepath.Join(t.archive, "DEFAULT")
	if _, err := state.Inspect(path); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if !safeComponent(id) {
		return "", errors.New("invalid DSM default certificate ID")
	}
	return id, nil
}

func serviceKey(s service) string { return s.Subscriber + "/" + s.Service }

func (t *target) servicePath(s service) (string, error) {
	if !safeComponent(s.Subscriber) || !safeComponent(s.Service) {
		return "", errors.New("unsafe DSM service identity")
	}
	for _, base := range []string{"usr/local/etc/certificate", "usr/syno/etc/certificate"} {
		path := filepath.Join(t.config.Root, base, s.Subscriber, s.Service)
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return "", err
		}
		if _, err := state.InspectDirectory(path); err != nil {
			return "", err
		}
		return path, nil
	}
	return "", fmt.Errorf("DSM certificate directory missing for %s", serviceKey(s))
}

func (t *target) Plan(g domain.Generation) (deploy.Plan, error) {
	if err := t.checkCreationOwner(); err != nil {
		return deploy.Plan{}, err
	}
	id, err := t.selectedID(g.CertificateID())
	if err != nil {
		return deploy.Plan{}, err
	}
	info, err := t.readInfo()
	if err != nil {
		return deploy.Plan{}, err
	}
	entry, ok := info[id]
	if !ok {
		return deploy.Plan{}, errors.New("DSM certificate ID is absent from INFO")
	}
	m, err := deploy.Render(g)
	if err != nil {
		return deploy.Plan{}, err
	}
	plan := deploy.Plan{Target: id, AllowExisting: true, Guards: []string{filepath.Join(t.archive, "INFO")}}
	if t.automatic() {
		journal, err := state.Inspect(filepath.Join(t.stateDir, "current.json"))
		if err != nil {
			return deploy.Plan{}, err
		}
		plan.AllowExisting = journal.Exists
	}
	if t.config.UseDefault {
		plan.Guards = append(plan.Guards, filepath.Join(t.archive, "DEFAULT"))
	}
	batch := func(name, dir, reload string) state.Batch {
		return state.Batch{Name: name, Reload: reload, Files: []state.Content{
			{Path: filepath.Join(dir, "privkey.pem"), Data: m.PrivateKey},
			{Path: filepath.Join(dir, "cert.pem"), Data: m.Certificate},
			{Path: filepath.Join(dir, "chain.pem"), Data: m.Chain, Remove: len(m.Chain) == 0},
			{Path: filepath.Join(dir, "fullchain.pem"), Data: m.Fullchain},
		}}
	}
	plan.Batches = append(plan.Batches, batch("archive", filepath.Join(t.archive, id), ""))
	for _, s := range entry.Services {
		dir, err := t.servicePath(s)
		if err != nil {
			return deploy.Plan{}, err
		}
		plan.Batches = append(plan.Batches, batch(serviceKey(s), dir, serviceKey(s)))
	}
	return plan, nil
}

func (t *target) Validate(j *state.Journal) error {
	if err := t.checkCreationOwner(); err != nil {
		return err
	}
	if !safeComponent(j.Target) {
		return errors.New("invalid journal DSM target")
	}
	id, err := t.selectedID(j.CertificateID)
	if err != nil {
		return err
	}
	if j.Target != id {
		return errors.New("DSM target differs from configured ID")
	}
	info, err := t.readInfo()
	if err != nil {
		return err
	}
	entry, ok := info[j.Target]
	if !ok {
		return errors.New("recorded DSM target is absent from INFO")
	}
	if len(j.Groups) != 1+len(entry.Services) || len(j.Files) != 4*len(j.Groups) {
		return errors.New("invalid DSM deployment groups")
	}
	guardCount := 1
	if t.config.UseDefault {
		guardCount = 2
		id, err := t.defaultID()
		if err != nil {
			return err
		}
		if id != j.Target {
			return errors.New("DSM default changed during deployment")
		}
	}
	if len(j.Guards) != guardCount || j.Guards[0].Path != filepath.Join(t.archive, "INFO") {
		return errors.New("invalid DSM configuration guards")
	}
	if guardCount == 2 && j.Guards[1].Path != filepath.Join(t.archive, "DEFAULT") {
		return errors.New("invalid DSM default guard")
	}
	for groupIndex, group := range j.Groups {
		name, dir, reload := "archive", filepath.Join(t.archive, j.Target), ""
		if groupIndex > 0 {
			s := entry.Services[groupIndex-1]
			dir, err = t.servicePath(s)
			if err != nil {
				return err
			}
			name, reload = serviceKey(s), serviceKey(s)
		}
		if group.Name != name || group.Reload != reload || len(group.Files) != 4 {
			return errors.New("invalid DSM service group")
		}
		for i, fileName := range []string{"privkey.pem", "cert.pem", "chain.pem", "fullchain.pem"} {
			index := groupIndex*4 + i
			if group.Files[i] != index || j.Files[index].Path != filepath.Join(dir, fileName) {
				return errors.New("invalid DSM file path")
			}
			if i != 2 && !j.Files[index].After.Exists {
				return errors.New("missing DSM certificate material")
			}
			if i == 0 && j.Files[index].After.Mode&0137 != 0 {
				return errors.New("unsafe DSM private key permissions")
			}
		}
	}
	return nil
}
