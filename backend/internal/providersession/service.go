package providersession

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"icloudspace/internal/addresses"
	"icloudspace/internal/provider/apple"
	"icloudspace/internal/sourceguard"
)

type Service struct {
	repo *Repository
	cfg  Config
}

// SessionInfo reads a narrow metadata projection. It does not open a vault
// envelope, initialize a provider client or expose a cookie/token/document.
func (s *Service) SessionInfo(ctx context.Context, id int64) (SessionInfo, error) {
	if s == nil || id < 1 {
		return SessionInfo{}, ErrInvalid
	}
	var info SessionInfo
	err := s.repo.DB.QueryRowContext(ctx, `SELECT p.source_id,p.revision,coalesce(a.revision,0),coalesce(a.authenticated AND a.principal_revision=p.revision,false),coalesce(a.saved_at,0),a.last_validated_at,a.expires_at
 FROM space.apple_principals p LEFT JOIN space.apple_sessions a ON a.source_id=p.source_id WHERE p.source_id=$1`, id).Scan(&info.SourceID, &info.PrincipalRevision, &info.Revision, &info.Authenticated, &info.SavedAt, &info.LastValidatedAt, &info.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return info, ErrNotFound
	}
	if err != nil {
		return info, err
	}
	if info.ExpiresAt != nil {
		now, e := instant(s.cfg.Clock())
		if e != nil {
			return info, e
		}
		if now >= *info.ExpiresAt {
			info.Authenticated = false
		}
	}
	return info, nil
}
func (s *Service) document(src source, allowNew bool) (apple.SessionDocument, error) {
	if !src.SessionExists || src.StoredPrincipalRevision != src.Scope.PrincipalRevision {
		if !allowNew {
			return apple.SessionDocument{}, ErrLoginRequired
		}
		return apple.NewSession(apple.Principal{AppleID: src.AppleID, Region: src.Region, DSID: src.DSID})
	}
	aad, err := binding(s.cfg.InstallationID, src.Scope)
	if err != nil {
		return apple.SessionDocument{}, ErrBinding
	}
	plain, err := s.cfg.Vault.Open(aad, string(src.Envelope))
	if err != nil {
		return apple.SessionDocument{}, ErrBinding
	}
	document, err := apple.DecodeSession(plain)
	if err != nil || !strings.EqualFold(document.Principal.AppleID, src.AppleID) || document.Principal.Region != src.Region || src.DSID != "" && document.Principal.DSID != src.DSID {
		return apple.SessionDocument{}, ErrBinding
	}
	return document, nil
}

// WithHeldGuard is the sole callback boundary for directory/mailout adapters.
// The callback must finish synchronously and retain no Client. Snapshot is
// persisted after every result, including provider errors and unknown outcomes.
func (s *Service) WithHeldGuard(ctx context.Context, gate *sourceguard.Lease, id int64, operation func(*apple.Client) error) (SessionInfo, error) {
	if operation == nil {
		return SessionInfo{}, ErrInvalid
	}
	op, err := s.OpenHeldGuard(ctx, gate, id)
	if err != nil {
		return SessionInfo{}, err
	}
	defer op.Close()
	client, err := op.Client()
	if err != nil {
		return op.src.Info, err
	}
	return op.Checkpoint(ctx, callOperation(client, operation))
}

func (s *Service) openClient(ctx context.Context, gate *sourceguard.Lease, id int64) (source, *apple.Client, error) {
	if s == nil || id < 1 || !gate.ValidFor(s.cfg.Registry, id) {
		return source{}, nil, ErrGuard
	}
	src, err := s.repo.load(ctx, id)
	if err != nil {
		return src, nil, err
	}
	var writes bool
	if e := s.repo.DB.QueryRowContext(ctx, `SELECT writes_enabled FROM space.installation WHERE singleton AND installation_id=$1`, s.cfg.InstallationID).Scan(&writes); e != nil {
		return src, nil, e
	}
	if !writes {
		return src, nil, ErrReadOnly
	}
	if !src.Enabled || !src.Info.Authenticated {
		return src, nil, ErrLoginRequired
	}
	if src.Info.ExpiresAt != nil {
		now, e := instant(s.cfg.Clock())
		if e != nil {
			return src, nil, e
		}
		if now >= *src.Info.ExpiresAt {
			src.Info.Authenticated = false
			return src, nil, ErrLoginRequired
		}
	}
	document, err := s.document(src, false)
	if err != nil {
		return src, nil, err
	}
	client, err := s.cfg.Factory(document, s.cfg.Options(src.Scope))
	if err != nil {
		return src, nil, err
	}
	if client == nil {
		return src, nil, ErrInvalid
	}
	return src, client, nil
}

func callOperation(client *apple.Client, operation func(*apple.Client) error) (err error) {
	defer func() {
		if recover() != nil {
			err = &apple.Error{Kind: apple.Transport, Operation: "operation_panicked", Unknown: true}
		}
	}()
	return operation(client)
}
func (s *Service) WithSource(ctx context.Context, id int64, operation func(*apple.Client) error) (SessionInfo, error) {
	if s == nil {
		return SessionInfo{}, ErrInvalid
	}
	if held := sourceguard.LeaseFromContext(ctx); held != nil {
		return s.WithHeldGuard(ctx, held, id, operation)
	}
	gate, err := s.cfg.Registry.Acquire(ctx, id)
	if err != nil {
		return SessionInfo{}, err
	}
	defer gate.Close()
	return s.WithHeldGuard(sourceguard.WithLease(ctx, gate), gate, id, operation)
}

// Provider is deliberately lazy: addresses acquires/binds its source lease
// before invoking any method. It cannot recursively acquire the same gate.
func (s *Service) Provider(sourceID int64) addresses.Provider {
	return &directoryAdapter{service: s, sourceID: sourceID}
}

type directoryAdapter struct {
	service  *Service
	sourceID int64
	creation *Operation
}

func (p *directoryAdapter) call(ctx context.Context, operation func(*apple.Client) error) error {
	if p.creation != nil {
		client, err := p.creation.Client()
		if err != nil {
			return err
		}
		_, err = p.creation.Checkpoint(ctx, callOperation(client, operation))
		return err
	}
	_, err := p.service.WithHeldGuard(ctx, sourceguard.LeaseFromContext(ctx), p.sourceID, operation)
	return err
}
func (p *directoryAdapter) OpenCreation(ctx context.Context) (addresses.CreationOperation, error) {
	if p.creation != nil {
		return nil, ErrInvalid
	}
	op, err := p.service.OpenHeldGuard(ctx, sourceguard.LeaseFromContext(ctx), p.sourceID)
	if err != nil {
		return nil, err
	}
	return &directoryAdapter{service: p.service, sourceID: p.sourceID, creation: op}, nil
}
func (p *directoryAdapter) Close() error {
	if p.creation == nil {
		return nil
	}
	return p.creation.Close()
}
func (p *directoryAdapter) InitializeForwarding(ctx context.Context, expected string) error {
	return p.call(ctx, func(client *apple.Client) error { return client.InitializeForwarding(ctx, expected) })
}
func (p *directoryAdapter) Directory(ctx context.Context) (out addresses.Directory, err error) {
	err = p.call(ctx, func(client *apple.Client) error { var e error; out, e = client.Directory(ctx); return e })
	return
}
func (p *directoryAdapter) Generate(ctx context.Context) (out addresses.Candidate, err error) {
	err = p.call(ctx, func(client *apple.Client) error { var e error; out, e = client.Generate(ctx); return e })
	return
}
func (p *directoryAdapter) Reserve(ctx context.Context, c addresses.Candidate, label, nonce string) error {
	return p.call(ctx, func(client *apple.Client) error { return client.Reserve(ctx, c, label, nonce) })
}
func (p *directoryAdapter) Deactivate(ctx context.Context, id string) error {
	return p.call(ctx, func(client *apple.Client) error { return client.Deactivate(ctx, id) })
}
func (p *directoryAdapter) Delete(ctx context.Context, id string) error {
	return p.call(ctx, func(client *apple.Client) error { return client.Delete(ctx, id) })
}
