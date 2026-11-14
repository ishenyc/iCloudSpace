package providersession

import (
	"bytes"
	"context"
	"errors"

	"icloudspace/internal/provider/apple"
	"icloudspace/internal/sourceguard"
)

// Operation borrows the outer source lease and owns one actual provider jar.
// It is for a single adapter owner, which serializes its Client/Checkpoint/Close
// calls. Client must never escape that adapter or be used after Close.
type Operation struct {
	service   *Service
	gate      *sourceguard.Lease
	src       source
	client    *apple.Client
	ctx       context.Context
	lastPlain []byte
	failed    error
	closed    bool
}

func (s *Service) OpenHeldGuard(ctx context.Context, gate *sourceguard.Lease, id int64) (*Operation, error) {
	src, client, err := s.openClient(ctx, gate, id)
	if err != nil {
		return nil, err
	}
	plain, err := apple.EncodeSession(client.Snapshot())
	if err != nil {
		client.CloseIdleConnections()
		return nil, ErrBinding
	}
	return &Operation{service: s, gate: gate, src: src, client: client, ctx: ctx, lastPlain: plain}, nil
}
func (o *Operation) valid() error {
	if o == nil || o.service == nil || o.closed || !o.gate.ValidFor(o.service.cfg.Registry, o.src.Scope.SourceID) {
		return ErrGuard
	}
	if o.failed != nil {
		return o.failed
	}
	return nil
}
func (o *Operation) Client() (*apple.Client, error) {
	if err := o.valid(); err != nil {
		return nil, err
	}
	if !o.src.Info.Authenticated {
		return nil, ErrLoginRequired
	}
	return o.client, nil
}

// Scope exposes identity generations, never capsule material. The adapter must
// compare its domain snapshot before making any request with this operation.
func (o *Operation) Scope() (Scope, error) {
	if err := o.valid(); err != nil {
		return Scope{}, err
	}
	return o.src.Scope, nil
}

// Checkpoint returns the original provider result when persistence succeeds.
// PersistenceError retains both facts on failure; it does not change an
// observed accepted/rejected RPC receipt. A failure latches against more RPCs.
func (o *Operation) Checkpoint(ctx context.Context, providerErr error) (SessionInfo, error) {
	if err := o.valid(); err != nil {
		return SessionInfo{}, err
	}
	snapshot := o.client.Snapshot()
	authenticated := o.src.Info.Authenticated
	var known *apple.Error
	if errors.As(providerErr, &known) && (known.Kind == apple.AuthenticationRequired || known.Kind == apple.SecondFactorRequired) {
		authenticated = false
	}
	w, err := o.service.repo.encodeSession(o.src, snapshot, authenticated)
	if err == nil {
		persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), o.service.cfg.PersistenceTimeout)
		err = o.service.repo.save(persist, o.gate, w, nil, nil, nil, false)
		cancel()
	}
	if err != nil {
		o.failed = &PersistenceError{Provider: providerErr, Persistence: err}
		return o.src.Info, o.failed
	}
	o.src.Info = w.info
	o.src.SessionExists = true
	o.src.StoredPrincipalRevision = w.info.PrincipalRevision
	o.src.Envelope = append([]byte(nil), w.envelope...)
	if snapshot.ValidatedAtUnixNano != nil && o.src.DSID == "" {
		o.src.DSID = snapshot.Principal.DSID
	}
	o.lastPlain, _ = apple.EncodeSession(snapshot)
	return w.info, providerErr
}

// Close never releases the source gate, retries a failed checkpoint or repeats
// any provider call. An unchanged already-checkpointed jar needs no SQL write.
func (o *Operation) Close() error {
	if o == nil {
		return nil
	}
	if o.closed {
		return o.failed
	}
	defer func() { o.closed = true; o.client.CloseIdleConnections() }()
	if o.failed != nil {
		return o.failed
	}
	if err := o.valid(); err != nil {
		o.failed = err
		return err
	}
	plain, err := apple.EncodeSession(o.client.Snapshot())
	if err != nil {
		o.failed = ErrBinding
		return o.failed
	}
	if bytes.Equal(plain, o.lastPlain) {
		return nil
	}
	_, err = o.Checkpoint(o.ctx, nil)
	return err
}
