package application

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/sys/unix"

	"icloudspace/internal/installation"
	"icloudspace/internal/operationlog"
	"icloudspace/internal/rounds"
)

var (
	ErrStartup  = errors.New("application: matched installation could not be opened")
	ErrRunning  = errors.New("application: another process owns this installation")
	ErrServe    = errors.New("application: a listener or background owner stopped")
	ErrShutdown = errors.New("application: graceful shutdown exhausted its drain budget")
)

// The database contains exactly one installation. Keep this dedicated session
// until all users of the process-local source/credential gates have joined.
const processLock int64 = 0x537061636552756e

func holdProcess(ctx context.Context, db *sql.DB) (*sql.Conn, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, ErrStartup
	}
	var held bool
	if conn.QueryRowContext(ctx, `SELECT pg_catalog.pg_try_advisory_lock($1)`, processLock).Scan(&held) != nil {
		conn.Close()
		return nil, ErrStartup
	}
	if !held {
		conn.Close()
		return nil, ErrRunning
	}
	return conn, nil
}

func releaseProcess(conn *sql.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := conn.ExecContext(ctx, `SELECT pg_catalog.pg_advisory_unlock($1)`, processLock)
	if err != nil {
		// A failed unlock must discard the underlying connection rather than
		// return a still-locked session to the reusable pool.
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	}
	_ = conn.Close()
}

// The paired body volume supplies the process-lifetime exclusion even if a
// database backend disconnects and releases its session advisory lock. This
// descriptor remains open through the last request/worker join.
func holdFiles(directory string) (*os.File, error) {
	file, err := os.OpenFile(filepath.Join(directory, ".process-lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, ErrStartup
	}
	if unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		file.Close()
		return nil, ErrRunning
	}
	return file, nil
}

// Run opens explicit private references and an already bound schema. It has no
// initialization, migration, secret generation or ambient configuration path.
func Run(ctx context.Context, process installation.Process) error {
	dsn, err := process.DatabaseDSN()
	if err != nil {
		return ErrStartup
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return ErrStartup
	}
	defer db.Close()
	db.SetMaxOpenConns(12)
	db.SetMaxIdleConns(12)
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if db.PingContext(startup) != nil {
		return ErrStartup
	}
	lease, err := holdProcess(startup, db)
	if err != nil {
		return err
	}
	defer releaseProcess(lease)
	app, err := New(startup, db, process)
	if err != nil {
		return ErrStartup
	}
	filesLease, err := holdFiles(process.BlobDirectory)
	if err != nil {
		app.Close()
		return err
	}
	defer func() { _ = app.Close(); _ = filesLease.Close() }()
	app.processLease = lease
	poolSize := max(12, 4+2*app.Settings.SyncConcurrency)
	db.SetMaxOpenConns(poolSize)
	// Keep the bounded pool available between concurrent IMAP command bursts.
	// A smaller idle limit otherwise discards and reauthenticates connections
	// after every burst, despite the next command needing the same capacity.
	db.SetMaxIdleConns(poolSize)
	httpListener, err := net.Listen("tcp", app.Settings.HTTPAddress)
	if err != nil {
		return ErrStartup
	}
	defer httpListener.Close()
	imapListener, err := net.Listen("tcp", app.Settings.IMAPSAddress)
	if err != nil {
		return ErrStartup
	}
	defer imapListener.Close()
	return app.Serve(ctx, httpListener, imapListener)
}

type silentHTTPLog struct{}

func (silentHTTPLog) Write(p []byte) (int, error) { return len(p), nil }

type requestDrain struct {
	mu      sync.Mutex
	closing bool
	active  sync.WaitGroup
	next    http.Handler
}

func (app *Assembly) httpServer(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadTimeout: app.budgets.HTTPRead, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second,
		MaxHeaderBytes: 64 << 10, ErrorLog: log.New(silentHTTPLog{}, "", 0)}
}

func (d *requestDrain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	if d.closing {
		d.mu.Unlock()
		http.Error(w, "Service is stopping.", 503)
		return
	}
	d.active.Add(1)
	d.mu.Unlock()
	defer d.active.Done()
	d.next.ServeHTTP(w, r)
}
func (d *requestDrain) stop() { d.mu.Lock(); d.closing = true; d.mu.Unlock() }

// Serve takes ownership of both already-bound listeners. A background owner's
// unexpected exit is observable and shuts admission instead of leaving a
// silently degraded process. Read-only rehearsals start no background work.
func (app *Assembly) Serve(ctx context.Context, httpListener, imapListener net.Listener) error {
	if app == nil || httpListener == nil || imapListener == nil || !app.serving.CompareAndSwap(false, true) {
		return ErrServe
	}
	defer httpListener.Close()
	defer imapListener.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	workers, stop := context.WithCancel(context.Background())
	defer stop()
	if app.Settings.WritesEnabled {
		if err := app.Synchronization.Start(workers); err != nil {
			return ErrStartup
		}
	}
	requests := &requestDrain{next: app.Handler}
	server := app.httpServer(requests)
	finished := make(chan string, 8)
	var group sync.WaitGroup
	app.ready.Store(true)
	defer app.ready.Store(false)
	launch := func(name string, action func() error) {
		group.Add(1)
		go func() {
			defer group.Done()
			_ = action()
			app.ready.Store(false)
			finished <- name
		}()
	}
	launch("http", func() error { return server.Serve(httpListener) })
	launch("imaps", func() error { return app.IMAPS.Serve(imapListener) })
	if app.processLease != nil {
		launch("process_lease", func() error { return app.watchLease(workers) })
	}
	if app.Settings.WritesEnabled {
		launch("creation", func() error { return app.Creation.Run(workers) })
		launch("bodies", func() error { return app.Bodies.Run(workers) })
		launch("local_cleanup", func() error { return app.LocalCleanup.Run(workers) })
		launch("seen", func() error { return app.Seen.Run(workers) })
		launch("synchronization_events", func() error { return app.bridgeRounds(workers) })
	}
	var result error
	select {
	case <-ctx.Done():
	case owner := <-finished:
		app.Logs.Ring().Append(operationlog.Event{Level: "error", ErrorCode: "owner_stopped", Fields: map[string]string{"component": owner}})
		result = ErrServe
	}
	// Stop scheduled work first. In-flight HTTP mutations retain their own
	// contexts through the graceful drain and can persist a final verdict.
	stop()
	app.ready.Store(false)
	requests.stop()
	drain, cancel := context.WithTimeout(context.Background(), app.budgets.Shutdown)
	defer cancel()
	joined := make(chan struct{})
	go func() {
		_ = app.IMAPS.Close()
		_ = app.Synchronization.Shutdown(drain)
		<-app.Synchronization.Done()
		group.Wait()
		requests.active.Wait()
		close(joined)
	}()
	if server.Shutdown(drain) != nil {
		_ = server.Close()
		result = errors.Join(result, ErrShutdown)
	}
	select {
	case <-joined:
	case <-drain.Done():
		result = errors.Join(result, ErrShutdown)
		// All network admission is closed/cancelled. Keep the process/file/DB
		// locks while any owner still runs; never return a live owner to Run's
		// deferred resource and lock release. A forced OS exit closes them all.
		<-joined
	}
	return result
}

func (app *Assembly) watchLease(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			check, cancel := context.WithTimeout(ctx, 2*time.Second)
			err := app.processLease.PingContext(check)
			cancel()
			if err != nil && ctx.Err() == nil {
				app.leaseLost.Store(true)
				return ErrRunning
			}
		}
	}
}

func roundLog(event rounds.Event) operationlog.Event {
	p := event.Progress
	var source *int64
	if p.Source.SourceID > 0 {
		id := p.Source.SourceID
		source = &id
	}
	return operationlog.Event{OccurredAt: event.At, Level: event.Level, SourceID: source,
		RoundKey: p.RoundID, Attempt: p.Attempts, Phase: string(p.Phase), Outcome: event.Outcome, ErrorCode: p.ErrorCode,
		Fields: map[string]string{"component": "synchronization", "stage": event.Name,
			"scope": event.Scope, "recovered": strconv.FormatBool(p.Recovered),
			"automatic": strconv.FormatBool(p.Trigger == rounds.Automatic),
			"stored":    strconv.FormatInt(p.Counters.Archived, 10), "bytes": strconv.FormatInt(p.Counters.Bytes, 10)}}
}

func (app *Assembly) bridgeRounds(ctx context.Context) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var after uint64
	publish := func() {
		batch := app.Synchronization.Events(after)
		if batch.Lost > 0 {
			app.Logs.Ring().Append(operationlog.Event{Level: "warn", ErrorCode: "synchronization_events_evicted", Fields: map[string]string{"skipped": strconv.FormatUint(batch.Lost, 10)}})
		}
		for _, event := range batch.Items {
			app.Logs.Ring().Append(roundLog(event))
		}
		after = batch.LastSequence
	}
	for {
		select {
		case <-ctx.Done():
			publish()
			return ctx.Err()
		case <-ticker.C:
			publish()
		}
	}
}
