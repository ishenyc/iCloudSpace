package syncengine

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	"icloudspace/internal/intake"
	"icloudspace/internal/rounds"
)

func checkedNow(at time.Time) (int64, error) {
	ns := at.UnixNano()
	if !time.Unix(0, ns).Equal(at) {
		return 0, ErrInvalid
	}
	return ns, nil
}
func (e *Executor) cursor(ctx context.Context, scope rounds.Scope, mailbox string) (intake.Cursor, error) {
	var c intake.Cursor
	err := e.config.Intake.DB.QueryRowContext(ctx, `SELECT uid_validity,committed_uid,observed_uid,revision FROM space.mailbox_cursors WHERE source_id=$1 AND source_generation=$2 AND mailbox_name=$3`, scope.SourceID, scope.Generation, mailbox).Scan(&c.UIDValidity, &c.Committed, &c.Observed, &c.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil
	}
	c.Exists = err == nil
	return c, err
}
func (e *Executor) nextBackfill(ctx context.Context, scope rounds.Scope, mailbox string, frontier *rounds.MailFrontier, after *rounds.BackfillFrontier) (*intake.Backfill, error) {
	var addressID, epoch int64
	if after != nil {
		addressID, epoch = after.AddressID, after.ScanEpoch
	}
	var b intake.Backfill
	err := e.config.Intake.DB.QueryRowContext(ctx, `SELECT b.address_id,b.scan_epoch,b.uid_validity,b.lower_uid,b.captured_upper_uid,b.committed_uid,b.state FROM space.address_backfills b JOIN space.private_addresses a ON a.source_id=b.source_id AND a.id=b.address_id
 WHERE b.source_id=$1 AND b.source_generation=$2 AND b.mailbox_name=$3 AND b.state IN ('pending','scanning') AND b.initialized AND b.uid_validity=$4 AND b.captured_upper_uid<=$5
 AND a.enabled AND a.deleted_at IS NULL AND a.lifecycle='confirmed' AND (b.address_id>$6 OR (b.address_id=$6 AND b.scan_epoch>$7))
 AND b.scan_epoch=(SELECT max(z.scan_epoch) FROM space.address_backfills z WHERE z.address_id=b.address_id AND z.source_generation=b.source_generation AND z.mailbox_name=b.mailbox_name)
 ORDER BY b.address_id,b.scan_epoch LIMIT 1`, scope.SourceID, scope.Generation, mailbox, frontier.UIDValidity, frontier.CapturedUpper, addressID, epoch).Scan(&b.AddressID, &b.ScanEpoch, &b.UIDValidity, &b.Lower, &b.Upper, &b.Committed, &b.State)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// Only the backfill table is written here. Live cursor/checkpoint ownership
// remains with intake. A changed mailbox epoch preserves old work as cancelled
// and starts a new explicit epoch in the newly captured UID coordinate space.
func (e *Executor) prepareBackfills(ctx context.Context, in rounds.StepInput, mailbox string, frontier *rounds.MailFrontier) error {
	if frontier == nil || frontier.Committed != frontier.CapturedUpper {
		return ErrInvalid
	}
	tx, err := e.config.Intake.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var revision, generation, credentials, configuration int64
	var enabled bool
	err = tx.QueryRowContext(ctx, `SELECT revision,source_generation,credential_generation,enabled FROM space.mail_sources WHERE id=$1 FOR UPDATE`, in.Source.Scope.SourceID).Scan(&revision, &generation, &credentials, &enabled)
	if err != nil {
		return err
	}
	if !enabled || revision != in.Source.Scope.Revision || generation != in.Source.Scope.Generation || credentials != in.Source.Scope.CredentialGeneration {
		return rounds.ErrStale
	}
	if err = tx.QueryRowContext(ctx, `SELECT configuration_revision FROM space.installation WHERE singleton FOR SHARE`).Scan(&configuration); err != nil {
		return err
	}
	if configuration != in.Source.Scope.ConfigurationRevision {
		return rounds.ErrStale
	}
	var uidv, committed, upper uint32
	if err = tx.QueryRowContext(ctx, `SELECT uid_validity,committed_uid,observed_uid FROM space.mailbox_cursors WHERE source_id=$1 AND source_generation=$2 AND mailbox_name=$3 FOR UPDATE`, in.Source.Scope.SourceID, generation, mailbox).Scan(&uidv, &committed, &upper); err != nil {
		return err
	}
	if uidv != frontier.UIDValidity || committed != frontier.Committed || upper != frontier.CapturedUpper {
		return rounds.ErrStale
	}
	rows, err := tx.QueryContext(ctx, `SELECT b.address_id,b.scan_epoch,b.uid_validity,b.initialized,b.captured_upper_uid,b.committed_uid,a.revision FROM space.address_backfills b JOIN space.private_addresses a ON a.source_id=b.source_id AND a.id=b.address_id
 WHERE b.source_id=$1 AND b.source_generation=$2 AND b.mailbox_name=$3 AND b.state IN ('pending','scanning') AND (NOT b.initialized OR b.uid_validity<>$4)
 AND a.enabled AND a.deleted_at IS NULL AND a.lifecycle='confirmed'
 AND b.scan_epoch=(SELECT max(z.scan_epoch) FROM space.address_backfills z WHERE z.address_id=b.address_id AND z.source_generation=b.source_generation AND z.mailbox_name=b.mailbox_name)
 ORDER BY b.address_id FOR UPDATE OF b,a`, in.Source.Scope.SourceID, generation, mailbox, uidv)
	if err != nil {
		return err
	}
	type pending struct {
		id, epoch, revision    int64
		uidv, upper, committed uint32
		initialized            bool
	}
	var work []pending
	for rows.Next() {
		var b pending
		if err = rows.Scan(&b.id, &b.epoch, &b.uidv, &b.initialized, &b.upper, &b.committed, &b.revision); err != nil {
			rows.Close()
			return err
		}
		work = append(work, b)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	now, err := checkedNow(e.config.Clock())
	if err != nil {
		return err
	}
	for _, b := range work {
		if b.uidv == uidv {
			if b.upper == 0 && b.committed == 0 {
				_, err = tx.ExecContext(ctx, `UPDATE space.address_backfills SET initialized=true,lower_uid=0,committed_uid=0,captured_upper_uid=$5,updated_at=$6 WHERE source_id=$1 AND address_id=$2 AND source_generation=$3 AND mailbox_name=$4 AND scan_epoch=$7 AND NOT initialized`, in.Source.Scope.SourceID, b.id, generation, mailbox, upper, now, b.epoch)
			} else {
				_, err = tx.ExecContext(ctx, `UPDATE space.address_backfills SET initialized=true,updated_at=$5 WHERE source_id=$1 AND address_id=$2 AND source_generation=$3 AND mailbox_name=$4 AND scan_epoch=$6 AND NOT initialized`, in.Source.Scope.SourceID, b.id, generation, mailbox, now, b.epoch)
			}
			if err != nil {
				return err
			}
			continue
		}
		var latest int64
		if err = tx.QueryRowContext(ctx, `SELECT max(scan_epoch) FROM space.address_backfills WHERE address_id=$1 AND source_generation=$2 AND mailbox_name=$3`, b.id, generation, mailbox).Scan(&latest); err != nil {
			return err
		}
		latest = max(latest, b.revision)
		if latest == math.MaxInt64 {
			return ErrInvalid
		}
		if _, err = tx.ExecContext(ctx, `UPDATE space.address_backfills SET state='cancelled',updated_at=$6 WHERE source_id=$1 AND address_id=$2 AND source_generation=$3 AND mailbox_name=$4 AND scan_epoch=$5 AND uid_validity=$7 AND state IN ('pending','scanning')`, in.Source.Scope.SourceID, b.id, generation, mailbox, b.epoch, now, b.uidv); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO space.address_backfills(source_id,address_id,mailbox_name,source_generation,scan_epoch,uid_validity,lower_uid,captured_upper_uid,committed_uid,state,initialized,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,0,$7,0,'pending',true,$8,$8)`, in.Source.Scope.SourceID, b.id, mailbox, generation, latest+1, uidv, upper, now); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return errors.Join(ErrBackfillUnknown, err)
	}
	return nil
}
