package pgschema

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// UpgradeOneToTwo applies each immutable forward migration to the current
// schema. The caller
// holds the paired installation's exclusive file/database ownership and must
// validate its installation/key identity and disabled writes through verify in
// this transaction. It never initializes an empty target or rewrites row 1.
// A failed COMMIT acknowledgement requires InspectSettled before any retry.
func UpgradeOneToTwo(ctx context.Context, db *sql.DB, verify func(context.Context, *sql.Tx) error) (bool, error) {
	if db == nil || verify == nil {
		return false, errors.New("pgschema: upgrade requires a pool and installation verification")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SET LOCAL search_path TO pg_catalog"); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "SELECT pg_catalog.pg_advisory_xact_lock($1)", initializationLock); err != nil {
		return false, err
	}
	inspection, err := inspectTransaction(ctx, tx)
	if err != nil {
		return false, err
	}
	if inspection.State != UpgradeRequired && inspection.State != Ready {
		return false, inspection.readinessError()
	}
	if err = verify(ctx, tx); err != nil {
		return false, err
	}
	if inspection.State == Ready {
		return false, nil
	}
	for _, migration := range Migrations()[inspection.Version:] {
		if _, err = tx.ExecContext(ctx, migration.SQL); err != nil {
			return false, fmt.Errorf("apply canonical migration %d: %w", migration.Version, err)
		}
		catalog, err := catalogChecksum(ctx, tx)
		if err != nil {
			return false, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO space.schema_migrations(version,name,checksum,catalog_checksum) VALUES ($1,$2,$3,$4)`, migration.Version, migration.Name, migration.SHA256, catalog); err != nil {
			return false, err
		}
	}
	inspection, err = inspectTransaction(ctx, tx)
	if err != nil {
		return false, err
	}
	if err = inspection.readinessError(); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, ErrCommitUnknown
	}
	return true, nil
}
