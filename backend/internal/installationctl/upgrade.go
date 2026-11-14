package installationctl

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"

	"icloudspace/internal/pgschema"
)

// Upgrade applies forward migrations to a known, stopped installation with
// writes disabled. It never creates a lock file, installation, key or receipt.
// An unknown COMMIT stays unknown; QueryUpgrade settles the original before
// the operator decides whether a subsequent explicit attempt is appropriate.
func Upgrade(ctx context.Context, processFile string) (Result, error) {
	o, err := open(ctx, processFile, false)
	if err != nil {
		return Result{}, err
	}
	defer o.close()
	return upgradeOpened(ctx, o)
}

func upgradeOpened(ctx context.Context, o *opened) (Result, error) {
	result := Result{Operation: "upgrade", State: "not_upgraded"}
	guard, err := acquire(ctx, o, false)
	if err != nil {
		return result, err
	}
	defer guard.close()
	upgraded, err := pgschema.UpgradeOneToTwo(ctx, o.db, func(ctx context.Context, tx *sql.Tx) error {
		_, writes, err := upgradeBinding(ctx, tx, o, true)
		if err != nil {
			return err
		}
		if writes {
			return ErrState
		}
		return nil
	})
	if errors.Is(err, pgschema.ErrCommitUnknown) {
		result.State = "unknown"
		return result, ErrUnknown
	}
	if err != nil {
		if errors.Is(err, ErrBinding) || errors.Is(err, ErrState) {
			return result, err
		}
		if errors.Is(err, pgschema.ErrIncompatible) || errors.Is(err, pgschema.ErrPartial) || errors.Is(err, pgschema.ErrForeign) || errors.Is(err, pgschema.ErrUninitialized) || errors.Is(err, pgschema.ErrUnsupportedPG) {
			return result, ErrState
		}
		return result, ErrDatabase
	}
	result.State = "already_upgraded"
	if upgraded {
		result.State = "upgraded"
	}
	result.SchemaVersion = pgschema.CurrentVersion
	migrations := pgschema.Migrations()
	result.SchemaChecksum = migrations[len(migrations)-1].SHA256
	return result, nil
}

// QueryUpgrade is read-only and waits for an original DDL transaction to settle.
// It needs no exclusive application ownership and remains usable while a
// correctly bound application holds its normal process locks.
func QueryUpgrade(ctx context.Context, processFile string) (Result, error) {
	o, err := open(ctx, processFile, true)
	if err != nil {
		return Result{}, err
	}
	defer o.close()
	result := Result{Operation: "query-upgrade", State: "not_upgraded"}
	inspection, err := pgschema.InspectSettled(ctx, o.db)
	if err != nil || inspection.State != pgschema.UpgradeRequired && inspection.State != pgschema.Ready {
		return result, ErrState
	}
	revision, writes, err := upgradeBinding(ctx, o.db, o, false)
	if err != nil {
		return result, err
	}
	result.State = "upgrade_required"
	if inspection.State == pgschema.Ready {
		result.State = "upgraded"
	}
	result.SchemaVersion = inspection.Version
	result.SchemaChecksum = inspection.Ledger[len(inspection.Ledger)-1].Checksum
	result.SchemaCatalogChecksum = inspection.CatalogChecksum
	result.CurrentRevision = decimal(revision)
	result.CurrentWritesEnabled = boolRef(writes)
	return result, nil
}

// The schema owner already checked the actual known catalog. Keep this exact
// binding check independent of the latest-only ordinary startup gate, and lock
// the installation/key rows for a mutating upgrade so writes cannot race it.
func upgradeBinding(ctx context.Context, reader operatorReader, o *opened, lock bool) (int64, bool, error) {
	query := `SELECT i.installation_id,i.configuration_revision,i.writes_enabled,k.proof FROM space.installation i JOIN space.key_binding k USING(singleton) WHERE i.singleton AND k.binding_version=1`
	if lock {
		query += ` FOR UPDATE OF i,k`
	}
	var id string
	var revision int64
	var writes bool
	var proof []byte
	if reader.QueryRowContext(ctx, query).Scan(&id, &revision, &writes, &proof) != nil {
		return 0, false, ErrBinding
	}
	want, err := o.box.Fingerprint(o.process.InstallationID)
	if err != nil || id != o.process.InstallationID || revision < 1 || subtle.ConstantTimeCompare(proof, want[:]) != 1 {
		return 0, false, ErrBinding
	}
	return revision, writes, nil
}
