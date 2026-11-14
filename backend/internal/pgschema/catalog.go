package pgschema

import (
	"context"
	"database/sql"
	"fmt"
)

// Column describes the import surface without reading application rows.
// DataType "space.instant_ns" always means signed Unix nanoseconds, never a
// PostgreSQL timestamp or a value implicitly converted through time.Time.
// IdentitySequence is the schema-qualified regclass spelling accepted as a
// parameter by setval. Importers must preserve the source's deleted-ID high
// water mark as well as max(id); this cannot be reconstructed from live rows.
type Column struct {
	Name             string
	DataType         string
	Nullable         bool
	Identity         string
	IdentitySequence string
	Default          string
	Generated        string
}

type Table struct {
	Name    string
	Columns []Column
}

// Describe returns the complete column catalog of a checked canonical target.
// The embedded SQL exposed by Migrations is the corresponding offline schema
// specification. No data, ciphertext, current sequence value or key is read.
func Describe(ctx context.Context, db *sql.DB) ([]Table, error) {
	if db == nil {
		return nil, fmt.Errorf("pgschema: nil database pool")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SET LOCAL search_path TO pg_catalog"); err != nil {
		return nil, err
	}
	inspection, err := inspectTransaction(ctx, tx)
	if err != nil {
		return nil, err
	}
	if err = inspection.readinessError(); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `
SELECT c.relname,a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),NOT a.attnotnull,a.attidentity,
       CASE WHEN a.attidentity<>'' THEN pg_catalog.pg_get_serial_sequence('space.'||pg_catalog.quote_ident(c.relname),a.attname) ELSE '' END,
       coalesce(pg_catalog.pg_get_expr(d.adbin,d.adrelid),''),a.attgenerated
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
WHERE n.nspname='space' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
ORDER BY c.relname COLLATE "C",a.attnum`)
	if err != nil {
		return nil, err
	}
	var result []Table
	for rows.Next() {
		var name string
		var column Column
		if err = rows.Scan(&name, &column.Name, &column.DataType, &column.Nullable, &column.Identity, &column.IdentitySequence, &column.Default, &column.Generated); err != nil {
			rows.Close()
			return nil, err
		}
		if len(result) == 0 || result[len(result)-1].Name != name {
			result = append(result, Table{Name: name})
		}
		result[len(result)-1].Columns = append(result[len(result)-1].Columns, column)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
