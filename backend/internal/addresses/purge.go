package addresses

import "context"

// PurgeArchived is an explicit local retirement of an archived identity. It
// revokes access and hides the address while preserving domain high-water,
// unknown submissions, unacknowledged deliveries and history ownership. Shared
// content reclamation belongs to the archive owner, never this address command.
func (s *Service) PurgeArchived(ctx context.Context, in HMEDeleteInput) (Operation, error) {
	if in.AddressID < 1 || in.ExpectedRevision < 1 || !operationKey(in.RequestKey) || !text(in.OwnerKey, 256, true) {
		return Operation{}, &FieldError{"archive_purge"}
	}
	if existing, r, e := s.operation(ctx, in.RequestKey, "purge", in.OwnerKey); e == nil {
		if r.AddressID != in.AddressID || r.AddressRevision != in.ExpectedRevision || r.ConfirmAddress != in.ConfirmAddress {
			return Operation{}, ErrConflict
		}
		return existing, nil
	} else if e != ErrNotFound {
		return Operation{}, e
	}
	a, err := s.Get(ctx, in.AddressID)
	if err != nil {
		return Operation{}, err
	}
	ctx, release, err := s.enter(ctx, a.SourceID)
	if err != nil {
		return Operation{}, err
	}
	defer release()
	tx, err := s.begin(ctx)
	if err != nil {
		return Operation{}, err
	}
	defer tx.Rollback()
	src, err := readSource(ctx, tx, a.SourceID)
	if err != nil {
		return Operation{}, err
	}
	a, err = scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM space.private_addresses a WHERE a.id=$1 AND a.deleted_at IS NULL FOR UPDATE`, in.AddressID))
	if err != nil {
		return Operation{}, err
	}
	if a.Revision != in.ExpectedRevision || a.Address != in.ConfirmAddress {
		return Operation{}, ErrConflict
	}
	if a.Lifecycle != "archived" {
		return Operation{}, ErrIneligible
	}
	r := operationRequest{Version: 1, SourceRevision: src.Revision, PrincipalRevision: src.PrincipalRevision, SourceGeneration: src.Generation, AddressID: a.ID, AddressRevision: a.Revision, ConfirmAddress: a.Address}
	op, fresh, err := s.claim(ctx, tx, src, in.RequestKey, "purge", in.OwnerKey, &a.ID, r)
	if err != nil {
		return Operation{}, err
	}
	if !fresh {
		return op, nil
	}
	if err = s.tombstone(ctx, tx, a.ID); err != nil {
		return op, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE space.address_operations SET state='confirmed',updated_at=greatest(updated_at+1,$2) WHERE operation_key=$1`, op.Key, s.clock()); err != nil {
		return op, err
	}
	if err = commit(tx); err != nil {
		return op, err
	}
	op.State = "confirmed"
	return op, nil
}
func (s *Service) QueryPurge(ctx context.Context, addressID int64, key, owner string) (Operation, error) {
	if addressID < 1 || !operationKey(key) || !text(owner, 256, true) {
		return Operation{}, &FieldError{"archive_purge_query"}
	}
	op, _, err := s.operation(ctx, key, "purge", owner)
	if err != nil {
		return op, err
	}
	if op.AddressID == nil || *op.AddressID != addressID {
		return Operation{}, ErrConflict
	}
	return op, nil
}
