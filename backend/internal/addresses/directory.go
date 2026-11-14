package addresses

import (
	"context"
	"database/sql"
	"strings"
)

func expectedForward(src source) (string, error) {
	forward, err := NormalizeAddress(src.Forward)
	if err != nil {
		return NormalizeAddress(src.Namespace)
	}
	return forward, nil
}

// ValidateDirectory repeats the adapter's essential identity checks at the
// domain boundary. A zero value or an empty/malformed row is never evidence of
// remote absence. A genuinely complete empty array is valid evidence.
func ValidateDirectory(directory Directory, subject, forward string) (Directory, error) {
	if !directory.Complete || !text(directory.Subject, 128, true) || directory.Subject != subject || subject == "" || directory.Entries == nil {
		return Directory{}, ErrDirectory
	}
	if _, err := NormalizeAddress(forward); err != nil {
		return Directory{}, ErrDirectory
	}
	selected := ""
	var err error
	if directory.SelectedForward != "" {
		selected, err = NormalizeAddress(directory.SelectedForward)
		if err != nil {
			return Directory{}, ErrDirectory
		}
	}
	if len(directory.ForwardAddresses) == 0 {
		return Directory{}, ErrDirectory
	}
	forwardSet := map[string]bool{}
	for _, v := range directory.ForwardAddresses {
		n, e := NormalizeAddress(v)
		if e != nil || forwardSet[n] {
			return Directory{}, ErrDirectory
		}
		forwardSet[n] = true
	}
	if selected != "" && !forwardSet[selected] {
		return Directory{}, ErrDirectory
	}
	ids := map[string]bool{}
	emails := map[string]bool{}
	out := directory
	out.Entries = make([]RemoteAddress, len(directory.Entries))
	for i, r := range directory.Entries {
		r.Address, err = NormalizeAddress(r.Address)
		if err != nil {
			return Directory{}, ErrDirectory
		}
		r.Forward, err = NormalizeAddress(r.Forward)
		if err != nil || !forwardSet[r.Forward] || !text(r.ID, 512, true) || !text(r.Label, 512, false) || ids[r.ID] || emails[r.Address] {
			return Directory{}, ErrDirectory
		}
		ids[r.ID] = true
		emails[r.Address] = true
		out.Entries[i] = r
	}
	out.SelectedForward = selected
	return out, nil
}

// ReconcileDirectory imports only this source's forwarding destinations and
// archives real absence atomically. Archival updates metadata only: UID values,
// grants, bundles, pending delivery, messages and file references are retained.
func (s *Service) ReconcileDirectory(ctx context.Context, sourceID, revision int64, directory Directory, ownerKey, profile string) (Reconciliation, error) {
	if sourceID < 1 || revision < 1 || !text(ownerKey, 256, true) || (profile != "api_key_only" && profile != "mailbox") {
		return Reconciliation{}, &FieldError{"reconcile"}
	}
	ctx, release, err := s.enter(ctx, sourceID)
	if err != nil {
		return Reconciliation{}, err
	}
	defer release()
	issuance, err := s.beginIssue(ctx)
	if err != nil {
		return Reconciliation{}, err
	}
	defer issuance.Close()
	tx, err := s.begin(ctx)
	if err != nil {
		return Reconciliation{}, err
	}
	defer tx.Rollback()
	src, err := readSource(ctx, tx, sourceID)
	if err != nil {
		return Reconciliation{}, err
	}
	if src.Kind == "custom" {
		return Reconciliation{}, ErrIneligible
	}
	if src.Revision != revision {
		return Reconciliation{}, ErrConflict
	}
	forward, err := expectedForward(src)
	if err != nil {
		return Reconciliation{}, ErrDirectory
	}
	directory, err = ValidateDirectory(directory, src.Subject, forward)
	if err != nil {
		return Reconciliation{}, err
	}
	out, err := s.reconcile(ctx, tx, issuance.Stage, src, directory, ownerKey, profile)
	if err != nil {
		return Reconciliation{}, err
	}
	return out, commit(tx)
}
func (s *Service) reconcile(ctx context.Context, tx *sql.Tx, issue Issuer, src source, directory Directory, ownerKey, profile string) (Reconciliation, error) {
	var out Reconciliation
	forward, err := expectedForward(src)
	if err != nil {
		return out, ErrDirectory
	}
	seenID := map[string]bool{}
	seenEmail := map[string]bool{}
	now := s.clock()
	// Lock this source's existing rows in the same ID order as batch grouping.
	locked, err := tx.QueryContext(ctx, `SELECT id FROM space.private_addresses WHERE source_id=$1 ORDER BY id FOR UPDATE`, src.ID)
	if err != nil {
		return Reconciliation{}, err
	}
	for locked.Next() {
		var id int64
		if err = locked.Scan(&id); err != nil {
			locked.Close()
			return Reconciliation{}, err
		}
	}
	err = locked.Err()
	locked.Close()
	if err != nil {
		return Reconciliation{}, err
	}
	occupied, err := occupiedCapacity(ctx, tx, src.ID, "")
	if err != nil {
		return Reconciliation{}, err
	}
	for _, r := range directory.Entries {
		seenID[r.ID] = true
		seenEmail[r.Address] = true
		if r.Active {
			out.Active++
		} else {
			out.Inactive++
		}
		if r.Forward != forward {
			out.SkippedForward++
			continue
		}
		a, err := scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM space.private_addresses a WHERE a.normalized_email=$1 AND a.deleted_at IS NULL`, r.Address))
		if err == ErrNotFound {
			// A directory refresh has no authority to undo a local purge. Only
			// a later explicit command may create a fresh address identity.
			var tombstone bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.private_addresses WHERE source_id=$1 AND normalized_email=$2 AND deleted_at IS NOT NULL)`, src.ID, r.Address).Scan(&tombstone); err != nil {
				return Reconciliation{}, err
			}
			if tombstone {
				out.Conflicts++
				continue
			}
			// An unknown creation already owns this exact candidate and its
			// credential delivery. A directory refresh must not issue a second
			// bundle under a different label, group or management owner.
			var pending bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.address_operations WHERE source_id=$1 AND kind='create' AND candidate_email=$2 AND state NOT IN ('confirmed','failed'))`, src.ID, r.Address).Scan(&pending); err != nil {
				return Reconciliation{}, err
			}
			if pending {
				out.Pending++
				continue
			}
			enabled := r.Active && (s.LocalAppleCapacity == 0 || occupied < s.LocalAppleCapacity)
			_, err = s.insert(ctx, tx, issue, src, CreateInput{Address: r.Address, Label: strings.TrimSpace(r.Label), Enabled: enabled, CredentialProfile: profile, OwnerKey: ownerKey}, "apple", &r)
			if err != nil {
				return Reconciliation{}, err
			}
			out.Imported++
			if enabled {
				occupied++
			}
			continue
		}
		if err != nil {
			return Reconciliation{}, err
		}
		if a.SourceID != src.ID || a.Kind != "apple" || a.DeletedAt != nil || a.ProviderID != nil && *a.ProviderID != r.ID || a.ProviderOwner != nil && *a.ProviderOwner != src.Subject {
			out.Conflicts++
			continue
		}
		// Reappearance removes the archival notice but never restores enabled.
		rediscovered := a.Lifecycle == "archived"
		_, err = tx.ExecContext(ctx, `UPDATE space.private_addresses SET provider_address_id=$2,provider_owner=$3,provider_active=$4,forwarding_email=$5,lifecycle=CASE WHEN lifecycle='archived' THEN 'confirmed' ELSE lifecycle END,archived_at=NULL,archive_reason=NULL,enabled=CASE WHEN lifecycle='archived' THEN false ELSE enabled END,revision=revision+1,updated_at=greatest(updated_at+1,$6) WHERE id=$1`, a.ID, r.ID, src.Subject, r.Active, r.Forward, now)
		if err != nil {
			return Reconciliation{}, err
		}
		out.Existing++
		if rediscovered {
			out.Rediscovered++
		}
	}
	rows, err := tx.QueryContext(ctx, metadataQuery(` FROM space.private_addresses a WHERE a.source_id=$1 AND a.kind='apple' AND a.lifecycle NOT IN ('pending','deletion_pending') AND a.deleted_at IS NULL`), src.ID)
	if err != nil {
		return Reconciliation{}, err
	}
	missing := []int64{}
	for rows.Next() {
		a, e := scan(rows)
		if e != nil {
			rows.Close()
			return Reconciliation{}, e
		}
		present := seenEmail[strings.ToLower(a.Address)]
		if a.ProviderID != nil {
			present = present || seenID[*a.ProviderID]
		}
		if !present && a.Lifecycle != "archived" {
			missing = append(missing, a.ID)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Reconciliation{}, err
	}
	for _, id := range missing {
		_, err = tx.ExecContext(ctx, `UPDATE space.private_addresses SET lifecycle='archived',enabled=false,archived_at=coalesce(archived_at,$2),archive_reason='remote_missing',provider_active=false,revision=revision+1,updated_at=greatest(updated_at+1,$2) WHERE id=$1`, id, now)
		if err != nil {
			return Reconciliation{}, err
		}
		out.Archived++
	}
	return out, nil
}
