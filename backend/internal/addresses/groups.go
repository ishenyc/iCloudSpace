package addresses

import (
	"context"
	"database/sql"
	"sort"
	"strconv"
	"strings"

	"icloudspace/internal/operationlog"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

func groupName(name string) (string, string, error) {
	name = strings.TrimSpace(name)
	if !text(name, 128, true) {
		return "", "", &FieldError{"name"}
	}
	return name, cases.Fold().String(norm.NFKC.String(name)), nil
}
func (s *Service) Groups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT g.id,g.display_name,g.revision,count(a.id) FROM space.address_groups g LEFT JOIN space.private_addresses a ON a.group_id=g.id AND a.deleted_at IS NULL GROUP BY g.id ORDER BY g.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var g Group
		if err = rows.Scan(&g.ID, &g.Name, &g.Revision, &g.AddressCount); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (s *Service) CreateGroup(ctx context.Context, name string) (Group, error) {
	name, normalized, err := groupName(name)
	if err != nil {
		return Group{}, err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return Group{}, err
	}
	defer tx.Rollback()
	var g Group
	err = tx.QueryRowContext(ctx, `INSERT INTO space.address_groups(display_name,normalized_name,revision,created_at,updated_at) VALUES($1,$2,1,$3,$3) RETURNING id,display_name,revision`, name, normalized, s.clock()).Scan(&g.ID, &g.Name, &g.Revision)
	if err != nil {
		return Group{}, classify(err)
	}
	if err = auditGroupTx(ctx, tx, g.ID, s.clock(), "group.created"); err != nil {
		return Group{}, err
	}
	return g, commit(tx)
}
func (s *Service) RenameGroup(ctx context.Context, id, revision int64, name string) (Group, error) {
	if id < 1 || revision < 1 {
		return Group{}, &FieldError{"revision"}
	}
	name, normalized, err := groupName(name)
	if err != nil {
		return Group{}, err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return Group{}, err
	}
	defer tx.Rollback()
	var g Group
	err = tx.QueryRowContext(ctx, `UPDATE space.address_groups SET display_name=$3,normalized_name=$4,revision=revision+1,updated_at=greatest(updated_at+1,$5) WHERE id=$1 AND revision=$2 RETURNING id,display_name,revision`, id, revision, name, normalized, s.clock()).Scan(&g.ID, &g.Name, &g.Revision)
	if err == sql.ErrNoRows {
		return Group{}, ErrConflict
	}
	if err != nil {
		return Group{}, classify(err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM space.private_addresses WHERE group_id=$1 AND deleted_at IS NULL`, id).Scan(&g.AddressCount); err != nil {
		return Group{}, err
	}
	if err = auditGroupTx(ctx, tx, id, s.clock(), "group.renamed"); err != nil {
		return Group{}, err
	}
	return g, commit(tx)
}
func lockGroup(ctx context.Context, tx *sql.Tx, id *int64) error {
	if id == nil {
		return nil
	}
	if *id < 1 {
		return &FieldError{"group_id"}
	}
	var locked int64
	return classify(tx.QueryRowContext(ctx, `SELECT id FROM space.address_groups WHERE id=$1 FOR UPDATE`, *id).Scan(&locked))
}
func (s *Service) DeleteGroup(ctx context.Context, id, revision int64) error {
	if id < 1 || revision < 1 {
		return &FieldError{"revision"}
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockGroup(ctx, tx, &id); err != nil {
		return err
	}
	var actual int64
	if err = tx.QueryRowContext(ctx, `SELECT revision FROM space.address_groups WHERE id=$1`, id).Scan(&actual); err != nil {
		return classify(err)
	}
	if actual != revision {
		return ErrConflict
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM space.private_addresses WHERE group_id=$1 ORDER BY id FOR UPDATE`, id)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ignored int64
		if err = rows.Scan(&ignored); err != nil {
			rows.Close()
			return err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE space.private_addresses SET group_id=NULL,revision=revision+1,updated_at=greatest(updated_at+1,$2) WHERE group_id=$1`, id, s.clock()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM space.address_groups WHERE id=$1`, id); err != nil {
		return err
	}
	if err = auditGroupTx(ctx, tx, id, s.clock(), "group.deleted"); err != nil {
		return err
	}
	return commit(tx)
}

// Move validates the whole selection before writing. Global groups may span
// sources; only selected address identities/revisions are changed.
func (s *Service) Move(ctx context.Context, selection []Selection, groupID *int64) ([]Metadata, error) {
	if len(selection) < 1 || len(selection) > MaximumLimit || !validID(groupID) {
		return nil, &FieldError{"selection"}
	}
	selection = append([]Selection(nil), selection...)
	sort.Slice(selection, func(i, j int) bool { return selection[i].ID < selection[j].ID })
	for i, x := range selection {
		if x.ID < 1 || x.ExpectedRevision < 1 || i > 0 && selection[i-1].ID == x.ID {
			return nil, &FieldError{"selection"}
		}
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = lockGroup(ctx, tx, groupID); err != nil {
		return nil, err
	}
	out := make([]Metadata, 0, len(selection))
	for _, x := range selection {
		a, e := scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM space.private_addresses a WHERE a.id=$1 AND a.deleted_at IS NULL FOR UPDATE`, x.ID))
		if e != nil {
			return nil, e
		}
		if a.Revision != x.ExpectedRevision {
			return nil, ErrConflict
		}
		out = append(out, a)
	}
	for i := range out {
		a := &out[i]
		err = tx.QueryRowContext(ctx, `UPDATE space.private_addresses SET group_id=$2,revision=revision+1,updated_at=greatest(updated_at+1,$3) WHERE id=$1 RETURNING revision,updated_at`, a.ID, groupID, s.clock()).Scan(&a.Revision, &a.UpdatedAt)
		if err != nil {
			return nil, err
		}
		a.GroupID = groupID
		if err = auditAddressTx(ctx, tx, a.SourceID, a.ID, s.clock(), "address.moved"); err != nil {
			return nil, err
		}
	}
	return out, commit(tx)
}

func auditGroupTx(ctx context.Context, tx *sql.Tx, id, now int64, action string) error {
	return operationlog.RecordAuditTx(ctx, tx, operationlog.ActorRecord(ctx, operationlog.Record{OccurredAt: now, Action: action, ResourceKind: "address_group", ResourceRef: strconv.FormatInt(id, 10), Outcome: "success", Fields: map[string]string{"component": "addresses"}}))
}
