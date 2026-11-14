package externalregistration

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"icloudspace/internal/addressauth"
	"icloudspace/internal/addresses"
	"icloudspace/internal/operationlog"
	"icloudspace/internal/sourceguard"
)

func (s *Service) Register(ctx context.Context, a Access, input Request) (*Delivery, error) {
	if !s.authorized(a) {
		return nil, ErrUnauthorized
	}
	input, digest, err := canonicalRequest(input)
	if err != nil {
		return nil, err
	}
	gate, err := s.guards.Acquire(ctx, input.SourceID)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			gate.Close()
		}
	}()
	ctx = sourceguard.WithLease(ctx, gate)
	ctx, err = operationlog.WithActor(ctx, operationlog.Actor{Kind: "system", Ref: "external_registration"})
	if err != nil {
		return nil, ErrStorage
	}
	issue, err := s.authority.BeginIssue(ctx)
	if err != nil {
		return nil, err
	}
	defer issue.Close()
	r, _, err := s.prepare(ctx, a, input, digest)
	if err != nil {
		if errors.Is(err, ErrUnknown) {
			_ = issue.MarkSourceUncertain(gate)
			r.State = "unknown"
		}
		if r.OperationKey != "" {
			return &Delivery{Receipt: r.Receipt}, err
		}
		return nil, err
	}
	r, attempted, err := s.issue(ctx, issue, r)
	if err != nil {
		if attempted {
			_ = issue.MarkSourceUncertain(gate)
			r.State = "unknown"
			r.AddressID, r.Generation, r.DeliveryKey = 0, 0, ""
			return &Delivery{Receipt: r.Receipt}, ErrUnknown
		}
		// No COMMIT was attempted. Prove the abandoned transaction ended
		// before releasing the email reservation; a failed proof stays query-only.
		proof, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		settled, settleErr := s.cancelPrepared(proof, a, input.SourceID, input.OperationKey)
		cancel()
		if settleErr == nil {
			r = settled
		} else {
			_ = issue.MarkSourceUncertain(gate)
			r.State = "unknown"
			return &Delivery{Receipt: r.Receipt}, ErrUnknown
		}
		return &Delivery{Receipt: r.Receipt}, err
	}
	reveal, err := issue.TransferReveal()
	if err != nil {
		return &Delivery{Receipt: r.Receipt}, err
	}
	out, err := s.material(ctx, reveal, r)
	if err != nil {
		reveal.Close()
		return nil, err
	}
	out.close = func() { reveal.Close(); gate.Close() }
	transferred = true
	return out, nil
}

func (s *Service) issue(ctx context.Context, scope *addressauth.IssueScope, r registration) (registration, bool, error) {
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return r, false, err
	}
	attempted := false
	defer func() {
		if !attempted {
			tx.Rollback()
		}
	}()
	_, retired, err := lockSource(ctx, tx, r.SourceID)
	if err != nil {
		return r, false, err
	}
	if retired {
		return r, false, ErrNotFound
	}
	fresh, err := scanRegistration(tx.QueryRowContext(ctx, `SELECT `+receiptColumns+` FROM space.external_registrations WHERE operation_key=$1 FOR UPDATE`, r.OperationKey))
	if err != nil {
		return r, false, storage(ctx)
	}
	if fresh.State != "prepared" || fresh.SourceID != r.SourceID || fresh.deliveryOwner != r.deliveryOwner {
		return r, false, ErrConflict
	}
	stage := func(ctx context.Context, tx *sql.Tx, in addresses.IssueRequest) error {
		return scope.Stage(ctx, tx, addressauth.IssueRequest{SourceID: in.SourceID, AddressID: in.AddressID, Generation: in.Generation, Profile: addressauth.Profile(in.Profile), OwnerKey: in.OwnerKey})
	}
	address, err := s.addresses.StageExternalRegistration(ctx, tx, stage, addresses.ExternalRegistrationInput{SourceID: r.SourceID, Address: r.Address, OwnerKey: r.deliveryOwner})
	if err != nil {
		return r, false, err
	}
	var delivery string
	if tx.QueryRowContext(ctx, `SELECT delivery_key FROM space.pending_reveals WHERE source_id=$1 AND address_id=$2 AND auth_generation=$3 AND owner_key=$4 AND acknowledged_at IS NULL`, r.SourceID, address.ID, address.AuthGeneration, r.deliveryOwner).Scan(&delivery) != nil {
		return r, false, ErrStorage
	}
	_, err = tx.ExecContext(ctx, `UPDATE space.external_registrations SET state='committed',address_id=$2,auth_generation=$3,delivery_key=$4,committed_at=$5 WHERE operation_key=$1 AND state='prepared'`, r.OperationKey, address.ID, address.AuthGeneration, delivery, s.clock())
	if err != nil {
		return r, false, storage(ctx)
	}
	r.State, r.AddressID, r.Generation, r.DeliveryKey = "committed", address.ID, address.AuthGeneration, delivery
	attempted = true
	if s.commit(tx) != nil {
		return r, true, ErrUnknown
	}
	return r, true, nil
}

func (s *Service) Query(ctx context.Context, a Access, q Query) (*Delivery, error) {
	if !s.authorized(a) {
		return nil, ErrUnauthorized
	}
	if q.SourceID < 1 || !validKey(q.OperationKey) {
		return nil, ErrInvalid
	}
	gate, err := s.guards.Acquire(ctx, q.SourceID)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			gate.Close()
		}
	}()
	if err = s.authority.ResolveSourceChange(ctx, gate); err != nil {
		return nil, ErrUnknown
	}
	reveal, err := s.authority.BeginReveal(ctx)
	if err != nil {
		return nil, err
	}
	r, err := s.cancelPrepared(ctx, a, q.SourceID, q.OperationKey)
	if err != nil {
		reveal.Close()
		return nil, err
	}
	out, err := s.material(ctx, reveal, r)
	if err != nil {
		reveal.Close()
		return nil, err
	}
	out.close = func() { reveal.Close(); gate.Close() }
	transferred = true
	return out, nil
}

func (s *Service) material(ctx context.Context, reveal *addressauth.RevealScope, r registration) (*Delivery, error) {
	out := &Delivery{Receipt: r.Receipt}
	if r.State != "committed" {
		out.Receipt.UnavailableReason = "not_committed"
		return out, nil
	}
	var generation int64
	var lifecycle string
	var deleted, retired sql.NullInt64
	var enabled, sourceEnabled bool
	err := s.db.QueryRowContext(ctx, `SELECT a.auth_generation,a.lifecycle,a.deleted_at,a.enabled,m.enabled,m.retired_at FROM space.private_addresses a JOIN space.mail_sources m ON m.id=a.source_id WHERE a.source_id=$1 AND a.id=$2`, r.SourceID, r.AddressID).Scan(&generation, &lifecycle, &deleted, &enabled, &sourceEnabled, &retired)
	if errors.Is(err, sql.ErrNoRows) {
		out.Receipt.UnavailableReason = "deleted"
		return out, nil
	}
	if err != nil {
		return nil, storage(ctx)
	}
	if deleted.Valid || lifecycle != "confirmed" || retired.Valid {
		out.Receipt.UnavailableReason = "deleted_or_retired"
		return out, nil
	}
	if generation != r.Generation {
		out.Receipt.UnavailableReason = "rotated"
		return out, nil
	}
	pending, err := reveal.Pending(ctx, r.DeliveryKey, r.deliveryOwner)
	if errors.Is(err, addressauth.ErrUnavailable) {
		out.Receipt.UnavailableReason = "delivery_unavailable"
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if pending.SourceID != r.SourceID || pending.AddressID != r.AddressID || pending.Generation != r.Generation {
		return nil, ErrStorage
	}
	if pending.Acknowledged {
		out.Receipt.UnavailableReason = "acknowledged"
		return out, nil
	}
	if pending.Revoked {
		out.Receipt.UnavailableReason = "rotated"
		return out, nil
	}
	bundle, err := reveal.Bundle(ctx, r.AddressID)
	if errors.Is(err, addressauth.ErrUnavailable) {
		out.Receipt.UnavailableReason = "credentials_unavailable"
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if bundle.API.Key != pending.Secret.APIKey {
		return nil, ErrStorage
	}
	out.Bundle = &bundle
	out.Receipt.Available = true
	out.Receipt.EffectiveEnabled = sourceEnabled && enabled
	return out, nil
}
