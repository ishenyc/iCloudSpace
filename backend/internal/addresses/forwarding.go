package addresses

import (
	"context"
	"errors"
)

// CreationOperation keeps one authenticated provider jar across the complete
// preflight/write/readback sequence. Close persists observations, never owns
// or releases the caller's source guard, and never replays a provider write.
type CreationOperation interface {
	Provider
	Close() error
}

type CreationOpener interface {
	OpenCreation(context.Context) (CreationOperation, error)
}

// ForwardingInitializer is used only after a complete empty directory proves
// that the expected destination is an available choice and no target is set.
type ForwardingInitializer interface {
	InitializeForwarding(context.Context, string) error
}

const forwardingUnknown = "forwarding_initialization_unknown"
const forwardingInitialized = "forwarding_initialized_retry_explicit"

func openCreation(ctx context.Context, p Provider) (Provider, func() error, error) {
	if opener, ok := p.(CreationOpener); ok {
		op, err := opener.OpenCreation(ctx)
		if err != nil {
			return nil, nil, err
		}
		if op == nil {
			return nil, nil, ErrProvider
		}
		return op, op.Close, nil
	}
	return p, func() error { return nil }, nil
}

func (s *Service) failedPreflight(ctx context.Context, op Operation, cause error) (Operation, error) {
	if op.State != "reserved" || op.ErrorCode == forwardingUnknown {
		return op, cause
	}
	code := "forwarding_preflight_failed"
	if errors.Is(cause, ErrDirectory) {
		code = "forwarding_target_unverified"
	} else if errors.Is(cause, ErrConflict) {
		code = "source_changed"
	}
	// No generate/reserve/init write was attempted. Preserve the concrete
	// provider/persistence error while recording this known NotCreated result.
	err := s.stage(ctx, &op, "reserved", "failed", nil, code)
	return op, errors.Join(cause, err)
}

func (s *Service) creationPreflight(ctx context.Context, op *Operation, src source, p Provider) error {
	d, err := s.checkedDirectory(ctx, src, p)
	if err != nil {
		return err
	}
	expected, err := expectedForward(src)
	if err != nil {
		return ErrDirectory
	}
	if d.SelectedForward == expected {
		return s.creationSourceCurrent(ctx, src)
	}
	// An existing selection or any remote alias makes changing this global
	// setting unsafe. Directory reconciliation remains independent of it.
	if d.SelectedForward != "" || len(d.Entries) != 0 {
		return ErrDirectory
	}
	available := false
	for _, candidate := range d.ForwardAddresses {
		n, e := NormalizeAddress(candidate)
		available = available || e == nil && n == expected
	}
	initializer, ok := p.(ForwardingInitializer)
	if !available || !ok {
		return ErrDirectory
	}
	if err = s.creationSourceCurrent(ctx, src); err != nil {
		return err
	}
	// The unknown marker is durable before the single global-setting write.
	// A crash before dispatch is deliberately recovered by read-only query.
	if err = s.stage(ctx, op, "reserved", "reserved", nil, forwardingUnknown); err != nil {
		return err
	}
	if err = initializer.InitializeForwarding(ctx, expected); err != nil {
		observed, observedErr := s.providerFailure(ctx, *op, err)
		*op = observed
		return observedErr
	}
	d, err = s.checkedDirectory(ctx, src, p)
	if err != nil {
		return err
	}
	if d.SelectedForward != expected || len(d.Entries) != 0 {
		return ErrDirectory
	}
	return s.creationSourceCurrent(ctx, src)
}

func (s *Service) creationSourceCurrent(ctx context.Context, expected source) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := readSource(ctx, tx, expected.ID)
	if err != nil {
		return err
	}
	if !current.Enabled || !sameSource(current, operationRequest{SourceRevision: expected.Revision, PrincipalRevision: expected.PrincipalRevision, SourceGeneration: expected.Generation}) {
		return ErrConflict
	}
	return nil
}

func (s *Service) queryForwarding(ctx context.Context, op Operation, r operationRequest, p Provider) (Operation, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return op, err
	}
	src, err := readSource(ctx, tx, op.SourceID)
	tx.Rollback()
	if err != nil {
		return op, err
	}
	if !sameSource(src, r) {
		return op, ErrConflict
	}
	d, err := s.checkedDirectory(ctx, src, p)
	if err != nil {
		return op, err
	}
	if d.SelectedForward != r.Forward {
		return op, nil
	}
	if err = s.creationSourceCurrent(ctx, src); err != nil {
		return op, err
	}
	// This old request never generated a candidate. A new, explicit creation
	// request is required; a query cannot turn into an external write.
	err = s.stage(ctx, &op, "reserved", "failed", nil, forwardingInitialized)
	return op, err
}
