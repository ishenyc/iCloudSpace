package addresses

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"

	"icloudspace/internal/addressauth"
)

type credentialExportSelection struct {
	installation string
	filter       Filter
	ids          []int64
	copyFormat   bool
}

// CredentialCopySelection skips deleted or unconfirmed addresses in copy
// output. Credential backup validates every selected address before disclosure.
func (s *Service) CredentialCopySelection(filter *Filter, ids []int64) (addressauth.ExportSelection, error) {
	selection, err := s.CredentialExportSelection(filter, ids)
	if err != nil {
		return nil, err
	}
	selection.(*credentialExportSelection).copyFormat = true
	return selection, nil
}

// CredentialExportSelection carries only validated non-secret selection facts.
// The authority supplies the sole transaction, avoiding nested pool acquisition
// while metadata and credential material share the same snapshot.
func (s *Service) CredentialExportSelection(filter *Filter, ids []int64) (addressauth.ExportSelection, error) {
	if s == nil || (filter == nil) == (ids == nil) {
		return nil, ErrInvalid
	}
	selection := &credentialExportSelection{installation: s.installation}
	if filter != nil {
		normalized, _, err := normalizeFilter(*filter, Page{})
		if err != nil {
			return nil, err
		}
		selection.filter = normalized
	} else {
		if len(ids) < 1 || len(ids) > MaximumLimit {
			return nil, ErrInvalid
		}
		seen := map[int64]bool{}
		for _, id := range ids {
			if id < 1 || seen[id] {
				return nil, ErrInvalid
			}
			seen[id] = true
		}
		selection.ids = append([]int64(nil), ids...)
	}
	return selection, nil
}
func (s *credentialExportSelection) InstallationID() string { return s.installation }
func (s *credentialExportSelection) query() (string, []any) {
	if s.ids != nil {
		raw, _ := json.Marshal(s.ids)
		return ` FROM space.private_addresses a WHERE a.id IN(SELECT value::bigint FROM jsonb_array_elements_text($1::jsonb))`, []any{string(raw)}
	}
	return predicate, filterArgs(s.filter)
}
func (s *credentialExportSelection) Validate(ctx context.Context, tx *sql.Tx) error {
	where, args := s.query()
	var count int64
	var eligible bool
	if err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(bool_and(a.lifecycle='confirmed' AND a.deleted_at IS NULL),true)`+where, args...).Scan(&count, &eligible); err != nil {
		return err
	}
	if s.ids != nil && count != int64(len(s.ids)) {
		return ErrNotFound
	}
	if !eligible && !s.copyFormat {
		return ErrIneligible
	}
	return nil
}
func (s *credentialExportSelection) Next(ctx context.Context, tx *sql.Tx, after int64, limit int) ([]addressauth.ExportAddress, error) {
	where, args := s.query()
	if s.copyFormat {
		where += ` AND a.lifecycle='confirmed' AND a.deleted_at IS NULL`
	}
	afterArg := len(args) + 1
	limitArg := afterArg + 1
	args = append(args, after, limit)
	rows, err := tx.QueryContext(ctx, `SELECT a.source_id,a.id,a.auth_generation,a.email`+where+` AND a.id>$`+strconv.Itoa(afterArg)+` ORDER BY a.id LIMIT $`+strconv.Itoa(limitArg), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]addressauth.ExportAddress, 0, limit)
	for rows.Next() {
		var item addressauth.ExportAddress
		if err := rows.Scan(&item.SourceID, &item.AddressID, &item.Generation, &item.Address); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
