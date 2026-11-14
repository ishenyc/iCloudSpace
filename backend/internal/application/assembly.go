// Package application assembles the canonical owners. It never initializes or
// converts a database; a matched installation must already pass startup gates.
package application

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"icloudspace/internal/accessimap"
	"icloudspace/internal/accounts"
	"icloudspace/internal/addressauth"
	"icloudspace/internal/addresses"
	"icloudspace/internal/adminauth"
	"icloudspace/internal/blobstore"
	"icloudspace/internal/bodymaintenance"
	"icloudspace/internal/creationengine"
	"icloudspace/internal/externalregistration"
	"icloudspace/internal/httpapi"
	"icloudspace/internal/installation"
	"icloudspace/internal/installationresources"
	"icloudspace/internal/intake"
	"icloudspace/internal/localcleanup"
	"icloudspace/internal/mailout"
	"icloudspace/internal/mailview"
	"icloudspace/internal/networkroute"
	"icloudspace/internal/operationlog"
	"icloudspace/internal/provider/apple"
	"icloudspace/internal/provider/applemail"
	upstream "icloudspace/internal/provider/imap"
	"icloudspace/internal/providersession"
	"icloudspace/internal/rounds"
	"icloudspace/internal/seenworker"
	"icloudspace/internal/sourceguard"
	"icloudspace/internal/syncengine"
)

type Assembly struct {
	Process               installation.Process
	Settings              installation.Settings
	Handler               http.Handler
	Accounts              *accounts.Service
	Addresses             *addresses.Service
	ExternalRegistrations *externalregistration.Service
	Authority             *addressauth.Authority
	ProviderSessions      *providersession.Service
	Mail                  *mailview.Service
	Mailout               *mailout.Service
	Creation              *creationengine.Engine
	Bodies                *bodymaintenance.Service
	LocalCleanup          *localcleanup.Service
	Synchronization       *rounds.Coordinator
	IMAPS                 *accessimap.Service
	Seen                  *seenworker.Service
	Logs                  *operationlog.Service
	Registry              *sourceguard.Registry
	Slots                 *rounds.Slots
	pool                  *upstream.Pool
	files                 *blobstore.Store
	ui                    *httpapi.ManagementUI
	publicUI              *httpapi.PublicViewerUI
	documentation         *httpapi.PublicDocumentation
	serving               atomic.Bool
	processLease          *sql.Conn
	leaseLost             atomic.Bool
	ready                 atomic.Bool
	budgets               installation.Budgets
}

func New(ctx context.Context, db *sql.DB, process installation.Process) (app *Assembly, err error) {
	budgets, err := process.Budgets()
	if err != nil {
		return nil, err
	}
	box, err := process.Vault()
	if err != nil {
		return nil, err
	}
	settings, err := installation.ReadSettings(ctx, db, process.InstallationID, box)
	if err != nil {
		return nil, err
	}
	app = &Assembly{Process: process, Settings: settings, Registry: sourceguard.New(), budgets: budgets}
	owned := app
	defer func() {
		if err != nil {
			owned.Close()
		}
	}()
	app.Logs, err = operationlog.New(ctx, db, settings.ID, operationlog.Options{Output: os.Stdout})
	if err != nil {
		return nil, err
	}
	logger := slog.New(app.Logs.Ring().Handler())
	app.Slots, err = rounds.NewSlots(app.Registry, settings.SyncConcurrency)
	if err != nil {
		return nil, err
	}
	proxy, err := process.ProxyURL()
	if err != nil {
		return nil, err
	}
	route, err := networkroute.New(proxy, networkroute.Options{})
	if err != nil {
		return nil, err
	}
	archiveBytes, err := archiveReadBudget(ctx, db, budgets.IncomingMessageBytes)
	if err != nil {
		return nil, err
	}
	app.files, err = blobstore.Open(process.BlobDirectory, blobstore.Options{MaxBytes: archiveBytes})
	if err != nil {
		return nil, err
	}
	app.Accounts, err = accounts.NewWithSourceChangeFence(ctx, db, settings.ID, box, app.Registry, nil, accounts.SourceChangeFence{
		Begin: func(ctx context.Context, g *sourceguard.Lease) (accounts.SourceChangeScope, error) {
			return app.Authority.BeginSourceChange(ctx, g)
		},
		Resolve: func(ctx context.Context, g *sourceguard.Lease) error {
			return app.Authority.ResolveSourceChange(ctx, g)
		},
	})
	if err != nil {
		return nil, err
	}
	app.Authority, err = addressauth.NewAuthority(ctx, db, settings.ID, box, app.Registry, nil)
	if err != nil {
		return nil, err
	}
	app.LocalCleanup, err = localcleanup.New(ctx, db, settings.ID, app.files, app.Registry, localcleanup.Options{
		BeginFence: func(ctx context.Context, g *sourceguard.Lease) (localcleanup.Fence, error) {
			return app.Authority.BeginSourceChange(ctx, g)
		},
		ResolveFence: app.Authority.ResolveSourceChange,
	})
	if err != nil {
		return nil, err
	}
	app.Addresses, err = addresses.New(ctx, db, settings.ID, app.Registry, func(ctx context.Context) (addresses.IssueScope, error) {
		scope, err := app.Authority.BeginIssue(ctx)
		if err != nil {
			return addresses.IssueScope{}, err
		}
		return addresses.IssueScope{Close: func() { scope.Close() }, Stage: func(ctx context.Context, tx *sql.Tx, in addresses.IssueRequest) error {
			return scope.Stage(ctx, tx, addressauth.IssueRequest{SourceID: in.SourceID, AddressID: in.AddressID, Generation: in.Generation, Profile: addressauth.Profile(in.Profile), OwnerKey: in.OwnerKey})
		}}, nil
	}, nil)
	if err != nil {
		return nil, err
	}
	app.Addresses.LocalAppleCapacity = 750
	registrationHash, err := process.ExternalRegistrationKeyHash()
	if err != nil {
		return nil, err
	}
	app.ExternalRegistrations, err = externalregistration.New(ctx, externalregistration.Config{DB: db, InstallationID: settings.ID, Addresses: app.Addresses, Authority: app.Authority, Guards: app.Registry, TokenHash: registrationHash})
	if err != nil {
		return nil, err
	}
	app.ProviderSessions, err = providersession.New(ctx, db, providersession.Config{InstallationID: settings.ID, Registry: app.Registry, Vault: box, Options: func(providersession.Scope) apple.Options { return apple.Options{ProxyURL: proxy} }})
	if err != nil {
		return nil, err
	}
	app.pool, err = upstream.NewPool(upstream.Config{MaxIdle: settings.SyncConcurrency, DialContext: route.DialContext, ConnectTimeout: budgets.IMAPDial, TLSHandshakeTimeout: budgets.IMAPTLSHandshake, CommandTimeout: budgets.SyncSegment})
	if err != nil {
		return nil, err
	}
	intakeRepo := intake.NewRepository(db, app.Registry)
	pipeline := intake.New(app.Registry, intakeRepo, app.files, app.pool)
	if err = pipeline.ConfigureLimits(budgets.IncomingMessageBytes, budgets.BodyBytes); err != nil {
		return nil, err
	}
	roundRepo := rounds.NewPostgres(db, app.Registry)
	executor, err := syncengine.New(syncengine.Config{Registry: app.Registry, Slots: app.Slots, Accounts: app.Accounts, Sessions: app.ProviderSessions, Addresses: app.Addresses, Intake: intakeRepo, Pipeline: pipeline, Rounds: roundRepo, MaxPendingSources: process.MaximumSources})
	if err != nil {
		return nil, err
	}
	app.Synchronization, err = rounds.New(rounds.Config{Workers: settings.SyncConcurrency, MaxSources: process.MaximumSources, EventCapacity: 2000, AllowDegradedDirectory: true, StepTimeout: budgets.SyncSegment, RoundTimeout: budgets.SyncRoundActive}, roundRepo, executor, app.Registry, app.Slots)
	if err != nil {
		return nil, err
	}
	readLimits := mailview.DefaultLimits()
	readLimits.BodyBytes = budgets.BodyBytes
	readLimits.MessageBytes = archiveBytes
	app.Mail, err = mailview.New(ctx, db, settings.ID, app.Authority, app.files, mailview.Options{Limits: readLimits, Wake: func(source int64) { app.Synchronization.Wake(source, rounds.Public) }})
	if err != nil {
		return nil, err
	}
	drafts, err := applemail.NewDraftWriter(applemail.DraftConfig{ReadPool: app.pool, Credentials: func(ctx context.Context, mailbox applemail.AppleMailbox) (applemail.DraftEndpoint, error) {
		account, err := app.Accounts.Reveal(ctx, mailbox.SourceID)
		if err != nil || account.Source.Kind != accounts.AppleDirect || account.Source.Apple == nil || account.Source.Apple.Revision != mailbox.PrincipalRevision || !strings.EqualFold(account.Source.Apple.AppleID, mailbox.AppleID) || account.Source.Apple.DSID == nil || *account.Source.Apple.DSID != mailbox.DSID {
			return applemail.DraftEndpoint{}, mailout.ErrIneligible
		}
		endpoint := account.Source.Endpoint
		return applemail.DraftEndpoint{Host: endpoint.Host, Port: uint16(endpoint.Port), Username: endpoint.Username, Password: account.Credentials.IMAPPassword}, nil
	}, AcquireSlot: func(ctx context.Context, gate *sourceguard.Lease) (io.Closer, error) {
		return app.Slots.Acquire(ctx, gate)
	}, DialContext: route.DialContext})
	if err != nil {
		return nil, err
	}
	smtpProxy, err := process.SMTPProxyURL()
	if err != nil {
		return nil, err
	}
	smtpRoute, err := networkroute.New(smtpProxy, networkroute.Options{})
	if err != nil {
		return nil, err
	}
	smtpTransport, err := applemail.NewSMTPTransport(applemail.SMTPConfig{Drafts: drafts, DialContext: smtpRoute.DialContext})
	if err != nil {
		return nil, err
	}
	provider, err := applemail.New(applemail.Config{Sessions: app.ProviderSessions, Drafts: drafts, SMTP: smtpTransport})
	if err != nil {
		return nil, err
	}
	app.Mailout, err = mailout.New(ctx, db, settings.ID, box, app.Registry, provider, mailout.Options{AuthorizeBootstrap: httpapi.AuthorizeMailBootstrap})
	if err != nil {
		return nil, err
	}
	app.Creation, err = creationengine.New(ctx, db, settings.ID, app.Registry, app.Addresses, app.ProviderSessions.Provider, creationengine.Options{Logger: logger})
	if err != nil {
		return nil, err
	}
	app.Bodies, err = bodymaintenance.New(ctx, db, settings.ID, app.files, app.Registry, bodymaintenance.Options{CapacityBytes: settings.ArchiveCapacityBytes})
	if err != nil {
		return nil, err
	}
	app.Seen, err = seenworker.New(ctx, db, settings.ID, box, app.Registry, app.Slots, seenworker.Options{Writer: seenworker.WriterConfig{DialContext: route.DialContext}})
	if err != nil {
		return nil, err
	}
	certificate, err := installationresources.Certificate(settings)
	if err != nil {
		return nil, errors.New("application: installed IMAPS certificate pair could not be loaded")
	}
	app.IMAPS, err = accessimap.New(app.Authority, app.Mail, accessimap.Options{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}})
	if err != nil {
		return nil, err
	}
	app.ui, err = httpapi.NewManagementUIWithRecovery(process.WebDirectory, httpapi.ManagementUIPath, process.PreviousManagementPath, process.RecoveryManagementPath)
	if err != nil {
		return nil, err
	}
	app.publicUI, err = httpapi.NewPublicViewerUI(process.WebDirectory)
	if err != nil {
		return nil, err
	}
	app.documentation, err = httpapi.NewPublicDocumentation(process.WebDirectory)
	if err != nil {
		return nil, err
	}
	app.Handler, err = app.managementHandler(db)
	if err != nil {
		return nil, err
	}
	return app, nil
}

func (app *Assembly) managementHandler(db *sql.DB) (http.Handler, error) {
	process := app.Process
	repository, err := adminauth.NewSQLRepository(db)
	if err != nil {
		return nil, err
	}
	identity, err := adminauth.NewService(repository, time.Duration(process.SessionTTLSeconds)*time.Second)
	if err != nil {
		return nil, err
	}
	auth, err := httpapi.NewManagementAuth(httpapi.AuthOptions{BasePath: httpapi.ManagementUIPath + "/api/control/v1", Identity: identity, TrustedProxies: process.ProxyPrefixes(), SecureCookie: process.ForceSecureCookies})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if !app.ready.Load() || app.leaseLost.Load() || db.PingContext(ctx) != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "{\"status\":\"unavailable\"}\n")
			return
		}
		_, _ = io.WriteString(w, "{\"status\":\"ok\"}\n")
	})
	auth.Register(mux)
	accountHTTP, err := httpapi.NewManagementAccountsWithReadBarrier(auth, app.Accounts, func(ctx context.Context) (io.Closer, error) { return app.Authority.BeginReveal(ctx) })
	if err != nil {
		return nil, err
	}
	accountHTTP.Register(mux)
	cleanupHTTP, err := httpapi.NewManagementLocalCleanup(auth, app.LocalCleanup, identity)
	if err != nil {
		return nil, err
	}
	cleanupHTTP.Register(mux)
	addressHTTP, err := httpapi.NewManagementAddresses(auth, app.Addresses)
	if err != nil {
		return nil, err
	}
	addressHTTP.Register(mux)
	credentialHTTP, err := httpapi.NewManagementCredentials(auth, app.Authority, identity)
	if err != nil {
		return nil, err
	}
	credentialHTTP.Register(mux)
	exportHTTP, err := httpapi.NewManagementCredentialExports(auth, app.Authority, app.Addresses)
	if err != nil {
		return nil, err
	}
	exportHTTP.Register(mux)
	hmeHTTP, err := httpapi.NewManagementHME(auth, app.Addresses, app.Registry, app.ProviderSessions.Provider)
	if err != nil {
		return nil, err
	}
	hmeHTTP.Register(mux)
	providerHTTP, err := httpapi.NewManagementProviderSessions(auth, app.ProviderSessions, app.Registry)
	if err != nil {
		return nil, err
	}
	providerHTTP.Register(mux)
	mailHTTP, err := httpapi.NewMailAccess(app.Authority, app.Mail)
	if err != nil {
		return nil, err
	}
	mailHTTP.RegisterPublic(mux)
	oauthHTTP, err := httpapi.NewOAuthToken(app.Authority)
	if err != nil {
		return nil, err
	}
	oauthHTTP.Register(mux)
	registrationHTTP, err := httpapi.NewExternalRegistration(app.ExternalRegistrations)
	if err != nil {
		return nil, err
	}
	registrationHTTP.Register(mux)
	if err = mailHTTP.RegisterManagement(mux, auth); err != nil {
		return nil, err
	}
	mailoutHTTP, err := httpapi.NewManagementMailout(auth, app.Addresses, app.Mailout, app.Registry, 4)
	if err != nil {
		return nil, err
	}
	mailoutHTTP.Register(mux)
	creationHTTP, err := httpapi.NewManagementCreation(auth, app.Creation, app.Registry)
	if err != nil {
		return nil, err
	}
	creationHTTP.Register(mux)
	synchronizationHTTP, err := httpapi.NewManagementSynchronization(auth, app.Accounts, app.Synchronization)
	if err != nil {
		return nil, err
	}
	synchronizationHTTP.Register(mux)
	eventsHTTP, err := httpapi.NewManagementEvents(auth, app.Logs)
	if err != nil {
		return nil, err
	}
	eventsHTTP.Register(mux)
	app.ui.Register(mux)
	app.publicUI.Register(mux)
	app.documentation.Register(mux)
	return mux, nil
}

// Close only releases owned protocol/file resources. The process runner drains
// HTTP/IMAPS/workers before this point and closes its database pool last.
func (app *Assembly) Close() error {
	if app == nil {
		return nil
	}
	var result error
	if app.IMAPS != nil {
		result = errors.Join(result, app.IMAPS.Close())
	}
	if app.Seen != nil {
		result = errors.Join(result, app.Seen.Close())
	}
	if app.pool != nil {
		result = errors.Join(result, app.pool.Close())
	}
	if app.ui != nil {
		result = errors.Join(result, app.ui.Close())
	}
	if app.publicUI != nil {
		result = errors.Join(result, app.publicUI.Close())
	}
	if app.documentation != nil {
		result = errors.Join(result, app.documentation.Close())
	}
	if app.files != nil {
		result = errors.Join(result, app.files.Close())
	}
	return result
}
