// Package operatorctl provides explicit canonical offline operator operations.
// It has no initializer, provider, mailbox credential or environment fallback.
package operatorctl

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sys/unix"
	"icloudspace/internal/adminauth"
	"icloudspace/internal/installation"
	"icloudspace/internal/operationlog"
)

const ProcessLock int64 = 0x537061636552756e

var (
	ErrInput       = errors.New("operatorctl: invalid explicit input")
	ErrPrivateFile = errors.New("operatorctl: private file unavailable")
	ErrBinding     = errors.New("operatorctl: canonical installation binding rejected")
	ErrDatabase    = errors.New("operatorctl: database operation unavailable")
	ErrRunning     = errors.New("operatorctl: installation has an active process owner")
	ErrReadOnly    = errors.New("operatorctl: installation writes are disabled")
	ErrOperator    = errors.New("operatorctl: selected enabled operator unavailable")
	ErrPassword    = errors.New("operatorctl: password must contain 12 to 72 exact bytes")
	ErrUnknown     = errors.New("operatorctl: recovery commit outcome unknown; do not replay")
	ErrAmbient     = errors.New("operatorctl: ambient PostgreSQL configuration is rejected")
)

type Inspection struct {
	InstallationID        string `json:"installation_id"`
	Schema                string `json:"schema"`
	KeyBound              bool   `json:"key_bound"`
	ConfigurationRevision string `json:"configuration_revision"`
	WritesEnabled         bool   `json:"writes_enabled"`
}
type Recovery struct {
	OperatorID      string `json:"operator_id"`
	OperationID     string `json:"operation_id"`
	Outcome         string `json:"outcome"`
	Epoch           string `json:"epoch,omitempty"`
	ExpectedEpoch   string `json:"expected_epoch,omitempty"`
	RevokedSessions string `json:"revoked_sessions,omitempty"`
}
type opened struct {
	process  installation.Process
	db       *sql.DB
	settings installation.Settings
}

func privateFile(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return nil, ErrPrivateFile
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrPrivateFile
	}
	file := os.NewFile(uintptr(fd), "private-reference")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > limit {
		return nil, ErrPrivateFile
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrPrivateFile
	}
	return raw, nil
}
func GenerateKey(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return ErrInput
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return ErrPrivateFile
	}
	defer clear(key[:])
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrPrivateFile
	}
	defer file.Close()
	if err = file.Chmod(0600); err != nil {
		return ErrPrivateFile
	}
	if _, err = file.Write(key[:]); err != nil {
		return ErrPrivateFile
	}
	if err = file.Sync(); err != nil {
		return ErrPrivateFile
	}
	if err = file.Close(); err != nil {
		return ErrPrivateFile
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return ErrPrivateFile
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return ErrPrivateFile
	}
	return nil
}
func open(ctx context.Context, path string, readOnly bool) (*opened, error) {
	validated, err := privateFile(path, 64<<10)
	if err != nil {
		return nil, ErrInput
	}
	clear(validated)
	p, err := installation.LoadProcess(path)
	if err != nil {
		return nil, ErrInput
	}
	for name, limit := range map[string]int64{p.MasterKeyFile: 32, p.DatabaseDSNFile: 32 << 10} {
		raw, e := privateFile(name, limit)
		if e != nil {
			return nil, ErrPrivateFile
		}
		clear(raw)
	}
	box, err := p.Vault()
	if err != nil {
		return nil, ErrBinding
	}
	dsn, err := p.DatabaseDSN()
	if err != nil {
		return nil, ErrPrivateFile
	}
	db, err := openDatabase(dsn, readOnly)
	if err != nil {
		return nil, err
	}
	if db.PingContext(ctx) != nil {
		db.Close()
		return nil, ErrDatabase
	}
	settings, err := installation.ReadSettings(ctx, db, p.InstallationID, box)
	if err != nil {
		db.Close()
		return nil, ErrBinding
	}
	return &opened{p, db, settings}, nil
}
func Inspect(ctx context.Context, path string) (Inspection, error) {
	o, err := open(ctx, path, true)
	if err != nil {
		return Inspection{}, err
	}
	defer o.db.Close()
	return Inspection{InstallationID: o.settings.ID, Schema: "ready", KeyBound: true, ConfigurationRevision: strconv.FormatInt(o.settings.Revision, 10), WritesEnabled: o.settings.WritesEnabled}, nil
}

type writerLease struct {
	conn *sql.Conn
	file *os.File
}

func acquire(ctx context.Context, o *opened) (*writerLease, error) {
	conn, err := o.db.Conn(ctx)
	if err != nil {
		return nil, ErrDatabase
	}
	lease := &writerLease{conn: conn}
	ok := false
	defer func() {
		if !ok {
			lease.Close()
		}
	}()
	var held bool
	if conn.QueryRowContext(ctx, `SELECT pg_catalog.pg_try_advisory_lock($1)`, ProcessLock).Scan(&held) != nil {
		return nil, ErrDatabase
	}
	if !held {
		return nil, ErrRunning
	}
	dir, err := unix.Open(o.process.BlobDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrPrivateFile
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, ".process-lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrPrivateFile
	}
	lease.file = os.NewFile(uintptr(fd), "paired-process-lock")
	info, err := lease.file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrPrivateFile
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, ErrRunning
	}
	ok = true
	return lease, nil
}
func (l *writerLease) Close() {
	if l == nil {
		return
	}
	if l.conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		var released bool
		err := l.conn.QueryRowContext(ctx, `SELECT pg_catalog.pg_advisory_unlock($1)`, ProcessLock).Scan(&released)
		cancel()
		if err != nil || !released {
			_ = l.conn.Raw(func(any) error { return driver.ErrBadConn })
		}
		_ = l.conn.Close()
		l.conn = nil
	}
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
}
func Recover(ctx context.Context, processFile, operatorID, passwordFile string) (Recovery, error) {
	id, err := strconv.ParseInt(operatorID, 10, 64)
	if err != nil || id < 1 || strconv.FormatInt(id, 10) != operatorID {
		return Recovery{}, ErrInput
	}
	password, err := privateFile(passwordFile, adminauth.MaxLoginPasswordBytes)
	if err != nil {
		return Recovery{}, err
	}
	defer clear(password)
	if len(password) < adminauth.MinNewPasswordBytes || len(password) > adminauth.MaxNewPasswordBytes {
		return Recovery{}, ErrPassword
	}
	o, err := open(ctx, processFile, false)
	if err != nil {
		return Recovery{}, err
	}
	defer o.db.Close()
	return recoverOpened(ctx, o, id, operatorID, password)
}
func recoverOpened(ctx context.Context, o *opened, id int64, operatorID string, password []byte) (Recovery, error) {
	if !o.settings.WritesEnabled {
		return Recovery{}, ErrReadOnly
	}
	lease, err := acquire(ctx, o)
	if err != nil {
		return Recovery{}, err
	}
	defer lease.Close()
	encoded, err := bcrypt.GenerateFromPassword(password, adminauth.PasswordCost)
	if err != nil {
		return Recovery{}, ErrPassword
	}
	defer clear(encoded)
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return Recovery{}, ErrDatabase
	}
	result := Recovery{OperatorID: operatorID, OperationID: "operator_recover_" + hex.EncodeToString(random[:]), Outcome: "not_committed"}
	err = recoverTransaction(ctx, o, lease.conn, id, encoded, &result)
	return result, err
}
func recoverTransaction(ctx context.Context, o *opened, conn *sql.Conn, id int64, encoded []byte, result *Recovery) error {
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ErrDatabase
	}
	defer tx.Rollback()
	var actual string
	var writable bool
	var proof []byte
	if tx.QueryRowContext(ctx, `SELECT i.installation_id,i.writes_enabled,k.proof FROM space.installation i JOIN space.key_binding k USING(singleton) WHERE i.singleton AND k.binding_version=1 FOR SHARE OF i,k`).Scan(&actual, &writable, &proof) != nil {
		return ErrBinding
	}
	box, err := o.process.Vault()
	if err != nil {
		return ErrBinding
	}
	want, err := box.Fingerprint(o.process.InstallationID)
	if err != nil || actual != o.process.InstallationID || subtle.ConstantTimeCompare(proof, want[:]) != 1 {
		return ErrBinding
	}
	if !writable {
		return ErrReadOnly
	}
	var epoch int64
	var enabled bool
	if tx.QueryRowContext(ctx, `SELECT session_epoch,enabled FROM space.operators WHERE id=$1 FOR UPDATE`, id).Scan(&epoch, &enabled) != nil || !enabled || epoch == math.MaxInt64 {
		return ErrOperator
	}
	var now int64
	if tx.QueryRowContext(ctx, `SELECT space.clock_ns()`).Scan(&now) != nil || now <= 0 {
		return ErrDatabase
	}
	if _, err = tx.ExecContext(ctx, `UPDATE space.operators SET password_encoding=$2,session_epoch=$3,updated_at=greatest(updated_at+1,$4) WHERE id=$1`, id, string(encoded), epoch+1, now); err != nil {
		return ErrDatabase
	}
	changed, err := tx.ExecContext(ctx, `UPDATE space.operator_sessions SET revoked_at=coalesce(revoked_at,$2) WHERE operator_id=$1`, id, now)
	if err != nil {
		return ErrDatabase
	}
	count, err := changed.RowsAffected()
	if err != nil {
		return ErrDatabase
	}
	if operationlog.RecordAuditTx(ctx, tx, operationlog.Record{OccurredAt: now, ActorKind: "system", ActorRef: "operatorctl", Action: "management.operator_recovered", ResourceKind: "operator", ResourceRef: strconv.FormatInt(id, 10), Outcome: "success", CorrelationKey: result.OperationID, Origin: "offline_cli", Fields: map[string]string{"component": "operatorctl"}}) != nil {
		return ErrDatabase
	}
	result.ExpectedEpoch = strconv.FormatInt(epoch+1, 10)
	if tx.Commit() != nil {
		result.Outcome = "unknown"
		return ErrUnknown
	}
	result.Outcome = "committed"
	result.Epoch = result.ExpectedEpoch
	result.RevokedSessions = strconv.FormatInt(count, 10)
	return nil
}
