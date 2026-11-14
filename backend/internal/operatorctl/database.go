package operatorctl

import (
	"database/sql"
	"net/url"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// pgx normally consults PG* variables and HOME-based pass/certificate files.
// This offline tool rejects those environment overrides and supplies explicit
// empty certificate/passfile defaults so only the Process references matter.
func openDatabase(dsn string, readOnly bool) (*sql.DB, error) {
	for _, name := range []string{"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE", "PGAPPNAME", "PGCONNECT_TIMEOUT", "PGSSLMODE", "PGSSLKEY", "PGSSLCERT", "PGSSLSNI", "PGSSLROOTCERT", "PGSSLPASSWORD", "PGSSLNEGOTIATION", "PGTARGETSESSIONATTRS", "PGSERVICE", "PGSERVICEFILE", "PGTZ", "PGOPTIONS", "PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION"} {
		if os.Getenv(name) != "" {
			return nil, ErrAmbient
		}
	}
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil {
		return nil, ErrPrivateFile
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, ErrPrivateFile
	}
	allowed := map[string]bool{"sslmode": true, "sslcert": true, "sslkey": true, "sslrootcert": true, "sslpassword": true, "connect_timeout": true}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 {
			return nil, ErrPrivateFile
		}
	}
	for key, value := range map[string]string{"sslmode": "prefer", "sslcert": "", "sslkey": "", "sslrootcert": "", "sslpassword": "", "connect_timeout": "5"} {
		if !query.Has(key) {
			query.Set(key, value)
		}
	}
	query.Set("passfile", "/dev/null")
	u.RawQuery = query.Encode()
	config, err := pgx.ParseConfig(u.String())
	if err != nil {
		return nil, ErrPrivateFile
	}
	config.RuntimeParams = map[string]string{"application_name": "icloudspace-operator", "timezone": "UTC"}
	if readOnly {
		config.RuntimeParams["default_transaction_read_only"] = "on"
	}
	config.ConnectTimeout = 5 * time.Second
	db := stdlib.OpenDB(*config)
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(0)
	return db, nil
}
