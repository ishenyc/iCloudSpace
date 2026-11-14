package application

import (
	"context"
	"database/sql"

	"icloudspace/internal/blobstore"
)

type archiveQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// A lower incoming limit must not make a previously committed body unreadable.
// This startup-only metadata query does not open/hash every historical file.
func archiveReadBudget(ctx context.Context, db archiveQuery, incoming int64) (int64, error) {
	var historical int64
	if err := db.QueryRowContext(ctx, `SELECT coalesce(max(byte_size),0) FROM space.content_objects`).Scan(&historical); err != nil {
		return 0, ErrStartup
	}
	return max(incoming, blobstore.DefaultMaxBytes, historical), nil
}
