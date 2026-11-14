// Package pgschema owns only the canonical PostgreSQL layout. It does not open
// pools, discover credentials, read historical formats, or start an application.
package pgschema

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	SchemaName     = "space"
	CurrentVersion = 4
	// This application-specific lock serializes explicit initialization even
	// before the schema exists. It is released with the transaction.
	initializationLock int64 = 0x5370616365536368
)

//go:embed 001_space.sql
var versionOneSQL string

//go:embed 002_address_latest_received.sql
var versionTwoSQL string

//go:embed 003_public_http_settings.sql
var versionThreeSQL string

//go:embed 004_mail_submission_routes.sql
var versionFourSQL string

var (
	ErrUninitialized = errors.New("canonical schema is not initialized")
	ErrForeign       = errors.New("database contains noncanonical user objects")
	ErrPartial       = errors.New("canonical schema is partially initialized")
	ErrIncompatible  = errors.New("canonical schema version or checksum is incompatible")
	ErrUnsupportedPG = errors.New("PostgreSQL 16 or 17 is required")
	ErrCommitUnknown = errors.New("canonical initialization commit acknowledgement unknown")
)

type State string

const (
	Empty           State = "empty"
	Ready           State = "ready"
	Foreign         State = "foreign"
	Partial         State = "partial"
	Incompatible    State = "incompatible"
	UpgradeRequired State = "upgrade_required"
)

// Migration is an immutable build-time specification, not a historical claim.
// SHA256 covers the exact embedded SQL bytes, including comments.
type Migration struct {
	Version int
	Name    string
	SHA256  string
	SQL     string
}

type LedgerEntry struct {
	Version         int
	Name            string
	Checksum        string
	CatalogChecksum string
}

// Inspection reports schema readiness only. A ready layout is not proof that
// installation/key binding, imported data, files, or application readiness pass.
type Inspection struct {
	State           State
	Version         int
	ExpectedVersion int
	ServerVersion   int
	ObjectCount     int64
	CatalogChecksum string
	Ledger          []LedgerEntry
	Reason          string
}

func Migrations() []Migration {
	one := sha256.Sum256([]byte(versionOneSQL))
	two := sha256.Sum256([]byte(versionTwoSQL))
	three := sha256.Sum256([]byte(versionThreeSQL))
	four := sha256.Sum256([]byte(versionFourSQL))
	return []Migration{
		{Version: 1, Name: "canonical_space", SHA256: hex.EncodeToString(one[:]), SQL: versionOneSQL},
		{Version: 2, Name: "address_latest_received", SHA256: hex.EncodeToString(two[:]), SQL: versionTwoSQL},
		{Version: 3, Name: "public_http_settings", SHA256: hex.EncodeToString(three[:]), SQL: versionThreeSQL},
		{Version: 4, Name: "mail_submission_routes", SHA256: hex.EncodeToString(four[:]), SQL: versionFourSQL},
	}
}

// ValidateLedger rejects gaps, unknown versions, changed names or SQL bytes.
// Callers must provide ledger entries in ascending version order.
func ValidateLedger(entries []LedgerEntry) error {
	if len(entries) == 0 {
		return ErrUninitialized
	}
	expected := Migrations()
	if len(entries) != len(expected) {
		return fmt.Errorf("%w: have %d ledger entries, need %d", ErrIncompatible, len(entries), len(expected))
	}
	return validateKnownLedger(entries)
}

// Only the exact original v1 prefix or this build's complete ledger is known.
// A known prefix is insufficient by itself: inspection also matches its actual
// catalog before allowing the explicit one-to-two upgrade.
func validateKnownLedger(entries []LedgerEntry) error {
	expected := Migrations()
	if len(entries) < 1 || len(entries) > len(expected) {
		return ErrIncompatible
	}
	for i, entry := range entries {
		want := expected[i]
		if entry.Version != want.Version || entry.Name != want.Name || entry.Checksum != want.SHA256 {
			return fmt.Errorf("%w: ledger entry %d does not match this build", ErrIncompatible, i+1)
		}
		if !isDigest(entry.CatalogChecksum) {
			return fmt.Errorf("%w: invalid catalog checksum at version %d", ErrIncompatible, entry.Version)
		}
	}
	return nil
}

func isDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, ch := range value {
		if ch < '0' || (ch > '9' && ch < 'a') || ch > 'f' {
			return false
		}
	}
	return true
}

// Inspect takes a read-only, repeatable snapshot. It never initializes,
// migrates, locks an application owner, or repairs a database.
func Inspect(ctx context.Context, db *sql.DB) (Inspection, error) {
	if db == nil {
		return Inspection{}, errors.New("pgschema: nil database pool")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return Inspection{}, fmt.Errorf("inspect canonical schema: %w", err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SET LOCAL search_path TO pg_catalog"); err != nil {
		return Inspection{}, err
	}
	result, err := inspectTransaction(ctx, tx)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

// InspectSettled waits for an original explicit initialization transaction to
// finish before classifying its layout. READ COMMITTED takes the catalog
// snapshot after the wait; an earlier repeatable-read snapshot could falsely
// report Empty while an unacknowledged DDL transaction was still committing.
// The advisory lock changes no data and is released when this read ends.
func InspectSettled(ctx context.Context, db *sql.DB) (Inspection, error) {
	if db == nil {
		return Inspection{}, errors.New("pgschema: nil database pool")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted, ReadOnly: true})
	if err != nil {
		return Inspection{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SET LOCAL search_path TO pg_catalog"); err != nil {
		return Inspection{}, err
	}
	if _, err = tx.ExecContext(ctx, "SELECT pg_catalog.pg_advisory_xact_lock($1)", initializationLock); err != nil {
		return Inspection{}, err
	}
	result, err := inspectTransaction(ctx, tx)
	if err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

// Check is the read-only startup gate for the layout. Binding and application
// readiness checks belong to their own owners and must follow this gate.
func Check(ctx context.Context, db *sql.DB) error {
	result, err := Inspect(ctx, db)
	if err != nil {
		return err
	}
	return result.readinessError()
}

func (result Inspection) readinessError() error {
	var kind error
	switch result.State {
	case Ready:
		return nil
	case Empty:
		kind = ErrUninitialized
	case Foreign:
		kind = ErrForeign
	case Partial:
		kind = ErrPartial
	default:
		kind = ErrIncompatible
	}
	if result.ServerVersion < 160000 || result.ServerVersion >= 180000 {
		return fmt.Errorf("%w: server_version_num=%d", ErrUnsupportedPG, result.ServerVersion)
	}
	return fmt.Errorf("%w: %s", kind, result.Reason)
}

// Initialize is the explicit fresh-layout entry point. It accepts only an empty
// independent database, or an already matching canonical database. It refuses
// an old public layout, extra user schemas, and every partial initialization.
// The caller owns the pool and the explicit decision to initialize this target.
func Initialize(ctx context.Context, db *sql.DB) error {
	_, err := InitializeAtomic(ctx, db, nil)
	return err
}

// InitializeAtomic installs the layout and explicit initial data together.
// A seed runs only for an empty database, under the same transaction/lock as
// the DDL and ledger. A matching existing layout is never reseeded. The caller
// must separately check installation/key binding and any initial-data receipt.
// ErrCommitUnknown requires read-only inspection, never automatic replay.
func InitializeAtomic(ctx context.Context, db *sql.DB, seed func(context.Context, *sql.Tx) error) (bool, error) {
	if db == nil {
		return false, errors.New("pgschema: nil database pool")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return false, fmt.Errorf("initialize canonical schema: %w", err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SET LOCAL search_path TO pg_catalog"); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "SELECT pg_catalog.pg_advisory_xact_lock($1)", initializationLock); err != nil {
		return false, fmt.Errorf("lock canonical initialization: %w", err)
	}
	result, err := inspectTransaction(ctx, tx)
	if err != nil {
		return false, err
	}
	if result.State == Ready {
		return false, nil
	}
	if result.State != Empty {
		return false, result.readinessError()
	}
	for _, migration := range Migrations() {
		if _, err = tx.ExecContext(ctx, migration.SQL); err != nil {
			return false, fmt.Errorf("apply canonical migration %d: %w", migration.Version, err)
		}
		catalog, err := catalogChecksum(ctx, tx)
		if err != nil {
			return false, err
		}
		if _, err = tx.ExecContext(ctx,
			`INSERT INTO space.schema_migrations(version,name,checksum,catalog_checksum) VALUES ($1,$2,$3,$4)`,
			migration.Version, migration.Name, migration.SHA256, catalog); err != nil {
			return false, fmt.Errorf("record canonical migration %d: %w", migration.Version, err)
		}
	}
	if seed != nil {
		if err = seed(ctx, tx); err != nil {
			return false, err
		}
	}
	result, err = inspectTransaction(ctx, tx)
	if err != nil {
		return false, err
	}
	if err = result.readinessError(); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, ErrCommitUnknown
	}
	return true, nil
}

func inspectTransaction(ctx context.Context, tx *sql.Tx) (Inspection, error) {
	result := Inspection{ExpectedVersion: CurrentVersion}
	if err := tx.QueryRowContext(ctx, `SELECT current_setting('server_version_num')::integer`).Scan(&result.ServerVersion); err != nil {
		return result, err
	}
	if result.ServerVersion < 160000 || result.ServerVersion >= 180000 {
		result.State, result.Reason = Incompatible, "unsupported PostgreSQL major version"
		return result, nil
	}
	var exists bool
	var foreign int64
	if err := tx.QueryRowContext(ctx, objectInventorySQL).Scan(&exists, &result.ObjectCount, &foreign); err != nil {
		return result, err
	}
	if foreign != 0 {
		result.State, result.Reason = Foreign, "noncanonical user objects or namespaces exist"
		return result, nil
	}
	if !exists {
		result.State, result.Reason = Empty, "explicit initialization is required"
		return result, nil
	}
	var ledgerShape bool
	if err := tx.QueryRowContext(ctx, ledgerShapeSQL).Scan(&ledgerShape); err != nil {
		return result, err
	}
	if !ledgerShape {
		result.State, result.Reason = Partial, "migration ledger is absent or has an unknown shape"
		return result, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT version,name,checksum,catalog_checksum FROM space.schema_migrations ORDER BY version`)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var entry LedgerEntry
		if err = rows.Scan(&entry.Version, &entry.Name, &entry.Checksum, &entry.CatalogChecksum); err != nil {
			rows.Close()
			return result, err
		}
		result.Ledger = append(result.Ledger, entry)
		result.Version = entry.Version
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	if len(result.Ledger) == 0 {
		result.State, result.Reason = Partial, "schema exists without an applied migration"
		return result, nil
	}
	if err = validateKnownLedger(result.Ledger); err != nil {
		result.State, result.Reason = Incompatible, err.Error()
		return result, nil
	}
	result.CatalogChecksum, err = catalogChecksum(ctx, tx)
	if err != nil {
		return result, err
	}
	if result.CatalogChecksum != result.Ledger[len(result.Ledger)-1].CatalogChecksum {
		result.State, result.Reason = Incompatible, "catalog differs from the applied migration"
		return result, nil
	}
	if result.Version < CurrentVersion {
		result.State, result.Reason = UpgradeRequired, fmt.Sprintf("explicit schema upgrade from version %d to %d is required", result.Version, CurrentVersion)
		return result, nil
	}
	result.State = Ready
	return result, nil
}

const objectInventorySQL = `
WITH user_namespaces AS (
 SELECT oid,nspname FROM pg_catalog.pg_namespace
 WHERE nspname <> 'information_schema' AND nspname !~ '^pg_'
), objects AS (
 SELECT n.nspname FROM pg_catalog.pg_class c JOIN user_namespaces n ON n.oid=c.relnamespace
 UNION ALL SELECT n.nspname FROM pg_catalog.pg_proc p JOIN user_namespaces n ON n.oid=p.pronamespace
 UNION ALL SELECT n.nspname FROM pg_catalog.pg_type t JOIN user_namespaces n ON n.oid=t.typnamespace WHERE t.typtype IN ('d','e','r','m')
 UNION ALL SELECT nspname FROM user_namespaces WHERE nspname NOT IN ('public','space')
)
SELECT EXISTS(SELECT 1 FROM user_namespaces WHERE nspname='space'),
       count(*) FILTER (WHERE nspname='space'),count(*) FILTER (WHERE nspname<>'space') FROM objects`

const ledgerShapeSQL = `
SELECT EXISTS (
 SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='space' AND c.relname='schema_migrations' AND c.relkind='r'
 AND (SELECT string_agg(a.attname||':'||pg_catalog.format_type(a.atttypid,a.atttypmod),',' ORDER BY a.attnum)
      FROM pg_catalog.pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped)
     ='version:integer,name:text,checksum:text,catalog_checksum:text,applied_at:space.instant_ns'
)`

// Catalog identity deliberately excludes row values, statistics, OIDs, sequence
// current values and owners, so explicit-ID import, ANALYZE and cold/logical
// restore do not change it. Structure, constraints, routines and triggers do.
const catalogSQL = `
WITH relations AS (
 SELECT c.* FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='space'
), lines AS (
 SELECT 'relation|'||relname||'|'||relkind::text||'|'||relpersistence::text||'|'||relrowsecurity||'|'||relforcerowsecurity AS line FROM relations
 UNION ALL
 SELECT 'column|'||c.relname||'|'||a.attnum||'|'||a.attname||'|'||pg_catalog.format_type(a.atttypid,a.atttypmod)||'|'||a.attnotnull||'|'||a.attidentity::text||'|'||a.attgenerated::text||'|'||coalesce(pg_catalog.pg_get_expr(d.adbin,d.adrelid),'')
 FROM relations c JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
 LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 WHERE a.attnum>0 AND NOT a.attisdropped AND c.relkind IN ('r','p','v','m','f')
 UNION ALL
 SELECT 'constraint|'||c.relname||'|'||k.conname||'|'||pg_catalog.pg_get_constraintdef(k.oid,false)||'|'||k.convalidated
 FROM relations c JOIN pg_catalog.pg_constraint k ON k.conrelid=c.oid
 UNION ALL
 SELECT 'index|'||c.relname||'|'||pg_catalog.pg_get_indexdef(i.indexrelid)||'|'||i.indisvalid||'|'||i.indisready
 FROM relations c JOIN pg_catalog.pg_index i ON i.indexrelid=c.oid
 UNION ALL
 SELECT 'sequence|'||c.relname||'|'||s.seqstart||'|'||s.seqincrement||'|'||s.seqmax||'|'||s.seqmin||'|'||s.seqcache||'|'||s.seqcycle
 FROM relations c JOIN pg_catalog.pg_sequence s ON s.seqrelid=c.oid
 UNION ALL
 SELECT 'function|'||p.proname||'|'||pg_catalog.pg_get_functiondef(p.oid)
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='space'
 UNION ALL
 SELECT 'trigger|'||c.relname||'|'||pg_catalog.pg_get_triggerdef(t.oid,false)||'|'||t.tgenabled::text
 FROM relations c JOIN pg_catalog.pg_trigger t ON t.tgrelid=c.oid WHERE NOT t.tgisinternal
 UNION ALL
 SELECT 'type|'||t.typname||'|'||t.typtype::text||'|'||pg_catalog.format_type(t.typbasetype,t.typtypmod)||'|'||t.typnotnull||'|'||coalesce(t.typdefault,'')
 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
 WHERE n.nspname='space' AND t.typtype IN ('d','e','r','m')
 UNION ALL
 SELECT 'domain_constraint|'||t.typname||'|'||k.conname||'|'||pg_catalog.pg_get_constraintdef(k.oid,false)||'|'||k.convalidated
 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
 JOIN pg_catalog.pg_constraint k ON k.contypid=t.oid WHERE n.nspname='space'
 UNION ALL
 SELECT 'policy|'||c.relname||'|'||p.polname||'|'||p.polcmd::text||'|'||p.polpermissive||'|'||coalesce(pg_catalog.pg_get_expr(p.polqual,p.polrelid),'')||'|'||coalesce(pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid),'')
 FROM relations c JOIN pg_catalog.pg_policy p ON p.polrelid=c.oid
 UNION ALL
 SELECT 'rule|'||c.relname||'|'||pg_catalog.pg_get_ruledef(r.oid,false)
 FROM relations c JOIN pg_catalog.pg_rewrite r ON r.ev_class=c.oid
)
SELECT line FROM lines ORDER BY line COLLATE "C"`

func catalogChecksum(ctx context.Context, tx *sql.Tx) (string, error) {
	rows, err := tx.QueryContext(ctx, catalogSQL)
	if err != nil {
		return "", fmt.Errorf("read canonical catalog: %w", err)
	}
	defer rows.Close()
	hash := sha256.New()
	for rows.Next() {
		var line string
		if err = rows.Scan(&line); err != nil {
			return "", err
		}
		// Length-prefixing prevents names or routine bodies with delimiters
		// from changing the boundary between catalog records.
		fmt.Fprintf(hash, "%d:", len(line))
		hash.Write([]byte(line))
	}
	if err = rows.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
