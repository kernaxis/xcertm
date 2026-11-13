package dsm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kernaxis/xcertm/internal/state"
)

func executable(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := state.CheckParents(path); err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return false, fmt.Errorf("DSM reload path is not a regular executable: %s", path)
	}
	return true, nil
}

func (t *target) Activate(ctx context.Context, key string) error {
	callerContext := ctx
	if err := t.checkCreationOwner(); err != nil {
		return err
	}
	parts := strings.Split(key, "/")
	if len(parts) != 2 || !safeComponent(parts[0]) || !safeComponent(parts[1]) {
		return fmt.Errorf("invalid DSM activation identity")
	}
	s, err := t.assignedService(key)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	run := func(path string, args ...string) error {
		// No shell interpolation or replay of arbitrary user hooks. Script output
		// is not collected or logged because it may contain sensitive material.
		if err := exec.CommandContext(ctx, path, args...).Run(); err != nil {
			if callerContext.Err() != nil {
				return callerContext.Err()
			}
			return &state.ActivationError{Err: fmt.Errorf("DSM reload script %s: %w", path, err), Attempted: true}
		}
		return nil
	}
	path, kind, err := t.packageReloader(s)
	if err != nil {
		return &state.ActivationError{Err: err}
	}
	if kind == "tls" || kind == "certificate" {
		if t.config.Progress != nil {
			t.config.Progress(fmt.Sprintf("Using declared DSM %s reloader for %s: %s", kind, key, path))
		}
		// The TLS profile replaces the historical certificate hook. Calling
		// both can start an unused package before its safe try-restart handler.
		if kind == "tls" {
			return run(path)
		}
		return run(path, s.Service)
	}
	if t.config.Progress != nil {
		t.config.Progress(fmt.Sprintf("Using legacy DSM activation callbacks for %s", key))
	}
	found := false
	for _, base := range []string{"usr/libexec/certificate.d", "usr/local/libexec/certificate.d", "usr/syno/share/certificate.d", "usr/local/share/certificate.d"} {
		path := filepath.Join(t.config.Root, base, s.Subscriber)
		ok, err := executable(path)
		if err != nil {
			return &state.ActivationError{Err: err}
		}
		if ok {
			if err := run(path, s.Service); err != nil {
				return err
			}
			found = true
			break
		}
	}
	name := s.Subscriber + ".sh"
	if s.Subscriber == "system" && s.Service == "default" {
		name = "dsm.sh"
	}
	path = filepath.Join(t.config.Root, "usr/libexec/security-profile/tls-profile", name)
	ok, err := executable(path)
	if err != nil {
		return &state.ActivationError{Err: err}
	}
	if ok {
		if err := run(path); err != nil {
			return err
		}
		found = true
	}
	if !found {
		if kind == "none" {
			if t.config.Progress != nil {
				t.config.Progress(fmt.Sprintf("No callback declared or available for %s; files published without service activation", key))
			}
			return state.ErrNoActivation
		}
		return &state.ActivationError{Err: fmt.Errorf("no DSM reload script found for %s", key)}
	}
	return nil
}
