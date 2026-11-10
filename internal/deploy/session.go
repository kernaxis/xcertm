package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kernaxis/xcertm/internal/domain"
	"github.com/kernaxis/xcertm/internal/state"
)

// Binding separates a stable destination identity from concrete access/layout.
type Binding struct {
	DestinationID, Kind, Resource, Configuration, LockName string
}

type Plan struct {
	Target        string
	Batches       []state.Batch
	Guards        []string
	AllowExisting bool
}

// Target is consumed by the shared coordinator and implemented by both local
// adapters. Planning is read-only; validation confines persisted effects.
type Target interface {
	Binding() Binding
	Plan(domain.Generation) (Plan, error)
	Validate(*state.Journal) error
}

// Activator is required only for plans that activate services (DSM).
type Activator interface {
	Activate(context.Context, string) error
}

// Initializer is used by DSM to reserve/register an automatically managed
// entry before read-only planning. It owns durable metadata recovery; Session
// holds both locks and supplies the same fault boundaries as file deployment.
type Initializer interface {
	Initialize(context.Context, string, domain.Generation, func(string) error) error
}

// StateDirectory locates coordinator and adapter state for one destination.
func StateDirectory(root, destinationID string) string {
	return filepath.Join(root, "deployments", state.Digest([]byte(destinationID)))
}

type Result struct {
	OperationID, DestinationID, CertificateID, GenerationID string
	Completed                                               bool
}

type owner struct {
	Store       string `json:"store"`
	OperationID string `json:"operation_id"`
}

// Session holds resource and destination locks until Close. Its methods must
// not be called concurrently. No target is touched on the basis of new input
// while a different operation remains pending.
type Session struct {
	// After optionally injects a failure after a durable boundary. Normal
	// callers leave it nil; recovery tests use it to simulate process loss.
	After   func(string) error
	target  Target
	binding Binding
	store   state.Store
	locks   []*os.File
	closed  bool
}

func Open(stateRoot string, target Target) (*Session, error) {
	b := target.Binding()
	if strings.TrimSpace(b.DestinationID) == "" || b.Kind == "" || b.Configuration == "" || b.LockName == "" || filepath.Base(b.LockName) != b.LockName {
		return nil, errors.New("incomplete deployment binding")
	}
	resource, err := filepath.Abs(b.Resource)
	if err != nil {
		return nil, err
	}
	b.Resource = resource
	if _, err := state.InspectDirectory(resource); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(stateRoot)
	if err != nil {
		return nil, err
	}
	if err := state.PrivateDir(root); err != nil {
		return nil, err
	}
	parent := filepath.Join(root, "deployments")
	if err := state.PrivateDir(parent); err != nil {
		return nil, err
	}
	dir := StateDirectory(root, b.DestinationID)
	if err := state.PrivateDir(dir); err != nil {
		return nil, err
	}
	s := &Session{target: target, binding: b, store: state.Store{Dir: dir}}
	s.store.Validate = s.validate
	for _, path := range []string{filepath.Join(resource, b.LockName), filepath.Join(dir, ".lock")} {
		lock, err := state.Lock(path)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.locks = append(s.locks, lock)
	}
	if _, err := s.readOwner(); err != nil {
		s.Close()
		return nil, err
	}
	j, err := s.store.Load()
	if err == nil && j != nil {
		err = s.checkBinding(j)
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Session) Close() error {
	var err error
	for i := len(s.locks) - 1; i >= 0; i-- {
		err = errors.Join(err, s.locks[i].Close())
	}
	s.locks = nil
	s.closed = true
	return err
}

func (s *Session) checkBinding(j *state.Journal) error {
	b := s.binding
	if j.DestinationID != b.DestinationID || j.Kind != b.Kind || j.Resource != b.Resource || j.Configuration != b.Configuration {
		return errors.New("destination configuration differs from recorded deployment; use its original binding")
	}
	return nil
}

func (s *Session) validate(j *state.Journal) error {
	if err := s.checkBinding(j); err != nil {
		return err
	}
	return s.target.Validate(j)
}

func (s *Session) ownerPath() string { return filepath.Join(s.binding.Resource, ".xcertm-pending") }

func (s *Session) readOwner() (*owner, error) {
	snapshot, err := state.Inspect(s.ownerPath())
	if err != nil || !snapshot.Exists {
		return nil, err
	}
	data, err := state.ReadPrivate(s.ownerPath())
	if err != nil {
		return nil, err
	}
	var record owner
	if err := state.Decode(data, &record); err != nil {
		return nil, fmt.Errorf("invalid resource owner marker: %w", err)
	}
	if record.Store != s.store.Dir {
		return nil, fmt.Errorf("resource has an unfinished deployment owned by %s", record.Store)
	}
	if strings.TrimSpace(record.OperationID) == "" {
		return nil, errors.New("resource owner marker lacks operation identity")
	}
	return &record, nil
}

func (s *Session) claim(operationID string) error {
	record, err := s.readOwner()
	if err != nil {
		return err
	}
	if record != nil && record.OperationID != operationID {
		return errors.New("resource marker belongs to another operation")
	}
	data, err := json.Marshal(owner{s.store.Dir, operationID})
	if err != nil {
		return err
	}
	return state.WritePrivate(s.ownerPath(), data)
}

func (s *Session) release(operationID string) error {
	record, err := s.readOwner()
	if err != nil {
		return err
	}
	if record == nil {
		// Also completes a prior marker unlink whose directory sync failed.
		return state.SyncDir(s.binding.Resource)
	}
	if record.OperationID != operationID {
		return errors.New("resource owner changed during deployment")
	}
	if err := os.Remove(s.ownerPath()); err != nil {
		return err
	}
	return state.SyncDir(s.binding.Resource)
}

func result(j *state.Journal) Result {
	if j == nil {
		return Result{}
	}
	return Result{OperationID: j.OperationID, DestinationID: j.DestinationID, CertificateID: j.CertificateID, GenerationID: j.GenerationID}
}

func (s *Session) Recover(ctx context.Context) (Result, error) {
	if s.closed {
		return Result{}, errors.New("deployment session is closed")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	j, err := s.store.Load()
	if err != nil {
		return Result{}, err
	}
	record, err := s.readOwner()
	if err != nil {
		return result(j), err
	}
	if j == nil {
		if record != nil {
			return Result{}, errors.New("resource marker exists without its journal; manual recovery required")
		}
		return Result{}, nil
	}
	if err := s.checkBinding(j); err != nil {
		return result(j), err
	}
	if record != nil && record.OperationID != j.OperationID {
		return result(j), errors.New("resource marker and journal disagree; manual recovery required")
	}
	if !j.Completed() {
		if err := s.claim(j.OperationID); err != nil {
			return result(j), err
		}
	}
	s.configure(ctx)
	if err := s.store.Replay(); err != nil {
		r := result(j)
		r.Completed = false
		return r, err
	}
	if err := s.release(j.OperationID); err != nil {
		return result(j), err
	}
	j, err = s.store.Load()
	r := result(j)
	r.Completed = err == nil && j != nil && j.Completed()
	return r, err
}

func (s *Session) configure(ctx context.Context) {
	s.store.After = func(point string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.After != nil {
			return s.After(point)
		}
		return nil
	}
	s.store.Reload = func(key string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		activator, ok := s.target.(Activator)
		if !ok {
			return errors.New("target does not support service activation")
		}
		return activator.Activate(ctx, key)
	}
}

func (s *Session) Deploy(ctx context.Context, operationID string, generation domain.Generation) (Result, error) {
	if s.closed {
		return Result{}, errors.New("deployment session is closed")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(operationID) == "" {
		return Result{}, errors.New("operation ID is required")
	}
	material, err := Render(generation)
	if err != nil {
		return Result{}, err
	}
	previous, err := s.store.Load()
	if err != nil {
		return Result{}, err
	}
	if previous != nil {
		if err := s.checkBinding(previous); err != nil {
			return result(previous), err
		}
		if previous.OperationID == operationID {
			if !sameGeneration(previous, generation, material.Fingerprint) {
				return result(previous), errors.New("operation ID reused with different generation material")
			}
			return s.Recover(ctx)
		}
		if !previous.Completed() {
			return result(previous), errors.New("another operation is pending; recover it first")
		}
		if previous.CertificateID != generation.CertificateID() {
			return result(previous), errors.New("destination already belongs to another managed certificate")
		}
		if previous.GenerationID == generation.ID() && !sameGeneration(previous, generation, material.Fingerprint) {
			return result(previous), errors.New("generation ID reused with different material")
		}
		if err := s.store.CheckCompleted(previous); err != nil {
			return result(previous), err
		}
	}
	if record, err := s.readOwner(); err != nil {
		return Result{}, err
	} else if record != nil {
		return Result{}, errors.New("resource has a pending marker; recover it first")
	}
	if initializer, ok := s.target.(Initializer); ok {
		boundary := func(point string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if s.After != nil {
				return s.After(point)
			}
			return nil
		}
		if err := initializer.Initialize(ctx, operationID, generation, boundary); err != nil {
			return Result{}, err
		}
	}
	plan, err := s.target.Plan(generation)
	if err != nil {
		return Result{}, err
	}
	j := state.Journal{
		OperationID:         operationID,
		DestinationID:       s.binding.DestinationID,
		CertificateID:       generation.CertificateID(),
		GenerationID:        generation.ID(),
		GenerationSource:    generation.Provenance().Source,
		GenerationReference: generation.Provenance().Reference,
		ValidatedAt:         generation.ValidatedAt(),
		Fingerprint:         material.Fingerprint,
		Kind:                s.binding.Kind,
		Resource:            s.binding.Resource,
		Configuration:       s.binding.Configuration,
		Target:              plan.Target,
	}
	if err := s.claim(operationID); err != nil {
		return Result{}, err
	}
	s.configure(ctx)
	if err := s.store.Prepare(j, plan.Batches, plan.Guards, plan.AllowExisting); err != nil {
		// If publication did not occur, this ordinary error has not touched any
		// target. Retain orphan stages, but release our preparation marker.
		current, loadErr := s.store.Load()
		if loadErr == nil && (current == nil || current.OperationID != operationID) {
			err = errors.Join(err, s.release(operationID))
		}
		return Result{}, err
	}
	if err := s.store.Boundary("prepared"); err != nil {
		return resultFromPrepared(&s.store), err
	}
	return s.Recover(ctx)
}

func resultFromPrepared(store *state.Store) Result { j, _ := store.Load(); return result(j) }

func sameGeneration(j *state.Journal, g domain.Generation, fingerprint string) bool {
	p := g.Provenance()
	return j.GenerationID == g.ID() && j.CertificateID == g.CertificateID() && j.Fingerprint == fingerprint && j.GenerationSource == p.Source && j.GenerationReference == p.Reference && j.ValidatedAt.Equal(g.ValidatedAt())
}
