package deploy

import (
	"context"
	"errors"
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
	Guards        []state.Guard
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
	InitializationPaths(domain.Generation) ([]string, error)
	Initialize(context.Context, string, domain.Generation, func(string) error) error
}

// StateDirectory locates coordinator and adapter state for one destination.
func StateDirectory(root, destinationID string) string {
	return filepath.Join(root, "deployments", state.Digest([]byte(destinationID)))
}

type Result struct {
	OperationID, DestinationID, CertificateID, GenerationID string
	Completed                                               bool
	Services                                                []ServiceResult `json:"services,omitempty"`
	Unchanged                                               bool            `json:"unchanged,omitempty"`
}

// ServiceResult reports file publication and callback execution, not live
// process health or the certificate currently served by an application.
type ServiceResult struct {
	Name           string `json:"name"`
	FilesPublished bool   `json:"files_published"`
	Activation     string `json:"activation"`
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
	if upgrader, ok := target.(interface{ Upgrade(*state.Journal) error }); ok {
		s.store.Upgrade = upgrader.Upgrade
	}
	for _, path := range []string{filepath.Join(resource, b.LockName), filepath.Join(dir, ".lock")} {
		lock, err := state.Lock(path)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.locks = append(s.locks, lock)
	}
	if _, err := s.readOwners(); err != nil {
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

func result(j *state.Journal) Result {
	if j == nil {
		return Result{}
	}
	r := Result{OperationID: j.OperationID, DestinationID: j.DestinationID, CertificateID: j.CertificateID, GenerationID: j.GenerationID}
	for _, group := range j.Groups {
		if group.Reload == "" {
			continue
		}
		activation := group.Activation
		if activation == "" {
			activation = "pending"
			if group.Done {
				activation = "callback-succeeded"
			}
		}
		r.Services = append(r.Services, ServiceResult{group.Name, group.Published || group.Done, activation})
	}
	return r
}

// Inspect reads recorded outcomes without taking deployment locks, creating a
// missing store, or probing/reloading live services.
func Inspect(stateRoot, destinationID string) (Result, error) {
	j, err := (&state.Store{Dir: StateDirectory(stateRoot, destinationID)}).Load()
	if err != nil || j == nil {
		return Result{}, err
	}
	if j.DestinationID != destinationID {
		return Result{}, errors.New("deployment receipt has a different destination identity")
	}
	r := result(j)
	r.Completed = j.Completed()
	return r, nil
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
	owners, err := s.readOwners()
	if err != nil {
		return result(j), err
	}
	if j == nil {
		if owners.forStore(s.store.Dir) != nil {
			return Result{}, errors.New("resource marker exists without its journal; manual recovery required")
		}
		return Result{}, nil
	}
	if err := s.checkBinding(j); err != nil {
		return result(j), err
	}
	record := owners.forStore(s.store.Dir)
	if record != nil && (record.OperationID != j.OperationID || !samePaths(record.Paths, journalPaths(j))) {
		return result(j), errors.New("resource marker and journal disagree; manual recovery required")
	}
	if err := owners.check(s.store.Dir, j.OperationID, journalPaths(j)); err != nil {
		return result(j), err
	}
	if !j.Completed() {
		if err := s.claim(j.OperationID, journalPaths(j)); err != nil {
			return result(j), err
		}
	}
	s.configure(ctx)
	if err := s.store.Replay(); err != nil {
		latest, loadErr := s.store.Load()
		if loadErr != nil {
			latest = j
		}
		r := result(latest)
		r.Completed = false
		return r, errors.Join(err, loadErr)
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
	return s.deploy(ctx, operationID, generation, false)
}

// Republish starts a new, journaled publication from validated stored material.
// It permits overwriting drift, but never abandons a pending operation.
func (s *Session) Republish(ctx context.Context, operationID string, generation domain.Generation) (Result, error) {
	return s.deploy(ctx, operationID, generation, true)
}

func (s *Session) deploy(ctx context.Context, operationID string, generation domain.Generation, force bool) (Result, error) {
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
			r, err := s.Recover(ctx)
			r.Unchanged = err == nil && previous.Completed()
			return r, err
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
		if !force {
			if err := s.store.CheckCompleted(previous); err != nil {
				return result(previous), err
			}
		}
	}
	owners, err := s.readOwners()
	if err != nil {
		return Result{}, err
	}
	if record := owners.forStore(s.store.Dir); record != nil {
		if previous == nil || !previous.Completed() || record.OperationID != previous.OperationID || !samePaths(record.Paths, journalPaths(previous)) {
			return Result{}, errors.New("resource has a pending marker; recover it first")
		}
		// A completed checkpoint can survive a lost marker-release response.
		// Reconcile that receipt before starting another (possibly forced) run.
		if _, err := s.Recover(ctx); err != nil {
			return result(previous), err
		}
		owners, err = s.readOwners()
		if err != nil {
			return Result{}, err
		}
	}
	if initializer, ok := s.target.(Initializer); ok {
		writes, err := initializer.InitializationPaths(generation)
		if err != nil {
			return Result{}, err
		}
		if err := s.checkInitialization(owners, writes); err != nil {
			return Result{}, err
		}
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
	paths := []string{}
	for _, batch := range plan.Batches {
		for _, file := range batch.Files {
			paths = append(paths, file.Path)
		}
	}
	j := state.Journal{
		ForcePublish:        force,
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
	if err := s.claim(operationID, paths); err != nil {
		return Result{}, err
	}
	s.configure(ctx)
	if err := s.store.Prepare(j, plan.Batches, plan.Guards, plan.AllowExisting || force); err != nil {
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
