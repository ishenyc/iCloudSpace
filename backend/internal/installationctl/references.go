package installationctl

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/sys/unix"
	"icloudspace/internal/installation"
	"icloudspace/internal/vault"
)

const processLock int64 = 0x537061636552756e

func absolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}
func privateFile(path string, limit int64) ([]byte, error) {
	if !absolute(path) {
		return nil, ErrPrivate
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrPrivate
	}
	file := os.NewFile(uintptr(fd), "private-reference")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > limit {
		return nil, ErrPrivate
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrPrivate
	}
	return raw, nil
}
func readSpec(path string) (Spec, error) {
	raw, err := privateFile(path, 64<<10)
	if err != nil {
		return Spec{}, err
	}
	defer clear(raw)
	if !utf8.Valid(raw) || !oneObject(raw) {
		return Spec{}, ErrInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var spec Spec
	if d.Decode(&spec) != nil || d.Decode(new(any)) != io.EOF || spec.Version != 1 || !absolute(spec.ProcessFile) || !absolute(spec.PasswordFile) || spec.ExpectedDatabase == "" || !validLogin(spec.OperatorLogin) {
		return Spec{}, ErrInput
	}
	return spec, nil
}
func oneObject(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var visit func(int) bool
	visit = func(depth int) bool {
		if depth > 16 {
			return false
		}
		t, e := d.Token()
		if e != nil {
			return false
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok {
					return false
				}
				s = strings.ToLower(s)
				if seen[s] {
					return false
				}
				seen[s] = true
				if !visit(depth + 1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !visit(depth + 1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim(']')
		}
		return false
	}
	if !visit(0) {
		return false
	}
	_, e := d.Token()
	return e == io.EOF
}

type opened struct {
	process  installation.Process
	db       *sql.DB
	box      *vault.Vault
	key      []byte
	database string
}

func open(ctx context.Context, path string, readonly bool) (*opened, error) {
	raw, err := privateFile(path, 64<<10)
	if err != nil {
		return nil, err
	}
	clear(raw)
	p, err := installation.LoadProcess(path)
	if err != nil {
		return nil, ErrBinding
	}
	key, err := privateFile(p.MasterKeyFile, 32)
	if err != nil || len(key) != 32 {
		return nil, ErrPrivate
	}
	box, err := vault.New(key)
	if err != nil {
		clear(key)
		return nil, ErrBinding
	}
	info, err := os.Lstat(p.BlobDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		clear(key)
		return nil, ErrPrivate
	}
	if p.ProxyURLFile != "" {
		data, err := privateFile(p.ProxyURLFile, 16<<10)
		if err != nil {
			clear(key)
			return nil, err
		}
		clear(data)
		if _, err = p.ProxyURL(); err != nil {
			clear(key)
			return nil, ErrBinding
		}
	}
	db, name, err := database(p.DatabaseDSNFile, readonly)
	if err != nil {
		clear(key)
		return nil, err
	}
	var actual string
	if db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&actual) != nil || actual != name {
		clear(key)
		db.Close()
		return nil, ErrBinding
	}
	return &opened{process: p, db: db, box: box, key: key, database: name}, nil
}
func (o *opened) close() { o.db.Close(); clear(o.key) }
func database(path string, readonly bool) (*sql.DB, string, error) {
	for _, name := range []string{"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE", "PGAPPNAME", "PGCONNECT_TIMEOUT", "PGSSLMODE", "PGSSLKEY", "PGSSLCERT", "PGSSLSNI", "PGSSLROOTCERT", "PGSSLPASSWORD", "PGSSLNEGOTIATION", "PGTARGETSESSIONATTRS", "PGSERVICE", "PGSERVICEFILE", "PGTZ", "PGOPTIONS", "PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION"} {
		if os.Getenv(name) != "" {
			return nil, "", ErrAmbient
		}
	}
	raw, err := privateFile(path, 32<<10)
	if err != nil {
		return nil, "", err
	}
	defer clear(raw)
	dsn := strings.TrimSpace(string(raw))
	if strings.ContainsAny(dsn, "\x00\r\n") {
		return nil, "", ErrPrivate
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.User == nil || u.User.Username() == "" || u.Hostname() == "" || strings.TrimPrefix(u.Path, "/") == "" || u.Fragment != "" {
		return nil, "", ErrPrivate
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, "", ErrPrivate
	}
	allowed := map[string]bool{"sslmode": true, "sslcert": true, "sslkey": true, "sslrootcert": true, "sslpassword": true, "connect_timeout": true}
	for k, v := range q {
		if !allowed[k] || len(v) != 1 {
			return nil, "", ErrPrivate
		}
	}
	for k, v := range map[string]string{"sslmode": "prefer", "sslcert": "", "sslkey": "", "sslrootcert": "", "sslpassword": "", "connect_timeout": "5"} {
		if !q.Has(k) {
			q.Set(k, v)
		}
	}
	q.Set("passfile", "/dev/null")
	u.RawQuery = q.Encode()
	c, err := pgx.ParseConfig(u.String())
	if err != nil {
		return nil, "", ErrPrivate
	}
	c.ConnectTimeout = 5 * time.Second
	c.RuntimeParams = map[string]string{"application_name": "icloudspace-install", "timezone": "UTC"}
	if readonly {
		c.RuntimeParams["default_transaction_read_only"] = "on"
	}
	db := stdlib.OpenDB(*c)
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(0)
	return db, c.Database, nil
}

type lease struct {
	db   *sql.DB
	conn *sql.Conn
	file *os.File
}

func acquire(ctx context.Context, o *opened, create bool) (*lease, error) {
	conn, err := o.db.Conn(ctx)
	if err != nil {
		return nil, ErrDatabase
	}
	l := &lease{db: o.db, conn: conn}
	ok := false
	defer func() {
		if !ok {
			l.close()
		}
	}()
	var held bool
	if conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, processLock).Scan(&held) != nil {
		return nil, ErrDatabase
	}
	if !held {
		return nil, ErrRunning
	}
	dir, err := unix.Open(o.process.BlobDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrPrivate
	}
	defer unix.Close(dir)
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if create {
		flags = unix.O_RDWR | unix.O_CREAT | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	}
	fd, err := unix.Openat(dir, ".process-lock", flags, 0600)
	if err != nil {
		return nil, ErrPrivate
	}
	l.file = os.NewFile(uintptr(fd), "paired-process-lock")
	info, err := l.file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, ErrPrivate
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, ErrRunning
	}
	ok = true
	return l, nil
}
func (l *lease) close() {
	if l.conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		var released bool
		err := l.conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, processLock).Scan(&released)
		cancel()
		if err != nil || !released {
			l.conn.Raw(func(any) error { return driver.ErrBadConn })
		}
		l.conn.Close()
		l.conn = nil
	}
	if l.db != nil {
		l.db.Close()
		l.db = nil
	}
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}
}
