// Package applemail adapts the canonical WebMail primitives to one explicit
// mailout operation. It owns no durable task or automatic retry policy.
package applemail

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"sync"
	"time"

	"icloudspace/internal/mailout"
	"icloudspace/internal/provider/apple"
	"icloudspace/internal/providersession"
)

type Config struct {
	Sessions *providersession.Service
	Clock    func() time.Time
	Drafts   *DraftWriter
	SMTP     *SMTPTransport
}
type Provider struct{ config Config }

func New(config Config) (*Provider, error) {
	if config.Sessions == nil {
		return nil, mailout.ErrInvalid
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if _, err := instant(config.Clock()); err != nil {
		return nil, err
	}
	return &Provider{config: config}, nil
}
func instant(at time.Time) (int64, error) {
	ns := at.UnixNano()
	if !time.Unix(0, ns).Equal(at) {
		return 0, mailout.ErrInvalid
	}
	return ns, nil
}
func address(raw string) (string, error) {
	m, err := mail.ParseAddress(raw)
	if err != nil || m.Address == "" || strings.ContainsAny(m.Address, "\r\n\x00") {
		return "", mailout.ErrInvalid
	}
	return strings.ToLower(m.Address), nil
}
func same(a, b string) bool { return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b)) }
func safe(raw string, max int) bool {
	return raw != "" && len(raw) <= max && !strings.ContainsAny(raw, "\r\n\x00")
}
func (p *Provider) Open(ctx context.Context, scope mailout.Scope) (mailout.Operation, error) {
	if p == nil || scope.Source.ID < 1 || scope.Address.ID < 1 || scope.Gate == nil || scope.Source.Kind == "custom" {
		return nil, mailout.ErrIneligible
	}
	session, err := p.config.Sessions.OpenHeldGuard(ctx, scope.Gate, scope.Source.ID)
	if err != nil {
		return nil, err
	}
	actual, err := session.Scope()
	if err != nil {
		session.Close()
		return nil, err
	}
	expected := providersession.Scope{SourceID: scope.Source.ID, SourceRevision: scope.Source.Revision, SourceGeneration: scope.Source.Generation, CredentialGeneration: scope.Source.CredentialGeneration, PrincipalRevision: scope.Source.PrincipalRevision}
	if actual != expected {
		session.Close()
		return nil, providersession.ErrStale
	}
	return &operation{provider: p, scope: scope, session: session, references: map[string]referenceProof{}, parts: map[string]apple.MailPart{}}, nil
}

type referenceProof struct {
	reference   mailout.Reference
	relay, from string
	wireGUID    string
	bootstrap   bool
	ready       bool
}
type operation struct {
	mu              sync.Mutex
	provider        *Provider
	scope           mailout.Scope
	session         *providersession.Operation
	route           mailout.Route
	references      map[string]referenceProof
	parts           map[string]apple.MailPart
	smtpParts       map[string]smtpPart
	submitted       bool
	submission      mailout.RPCReceipt
	submissionError error
	seeded          bool
	seed            mailout.RPCReceipt
	seedError       error
	appended        bool
	draft           mailout.AppendReceipt
	draftError      error
	closed          bool
	validated       bool
	mailRoutes      []apple.HMEMailRoute
	resolved        *apple.HMEMailRoute
	routeAttempted  bool
	originalFlow    bool
}

func (o *operation) client() (*apple.Client, error) {
	if o.closed {
		return nil, mailout.ErrConflict
	}
	return o.session.Client()
}
func (o *operation) checkpoint(ctx context.Context, err error) error {
	var service *apple.Error
	if errors.As(err, &service) && service.Kind == apple.AuthenticationRequired && strings.HasPrefix(service.Operation, "mail_") && service.Operation != "mail_validate" && service.Operation != "mail_directory" {
		// Setup/HME authentication was checked for this operation. A Mail-only
		// rejection must not revoke that separately validated Apple login.
		_, saved := o.session.Checkpoint(ctx, nil)
		return joined(err, saved)
	}
	_, e := o.session.Checkpoint(ctx, err)
	return e
}
func (o *operation) fresh(ns int64) bool {
	now, err := instant(o.provider.config.Clock())
	return err == nil && ns <= now && uint64(now)-uint64(ns) <= uint64(30*time.Second)
}
func (o *operation) validRoute(route mailout.Route) bool {
	return route == o.route && route.SourceID == o.scope.Source.ID && route.AddressID == o.scope.Address.ID && route.OwnerVerified && route.Active && o.fresh(route.CheckedAt)
}
func (o *operation) ValidateRoute(ctx context.Context, recipient string) (mailout.Route, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	client, err := o.client()
	if err != nil {
		return mailout.Route{}, err
	}
	target, err := address(recipient)
	if err != nil {
		return mailout.Route{}, err
	}
	alias, err := address(o.scope.Address.Email)
	if err != nil {
		return mailout.Route{}, err
	}
	if !o.validated {
		if err = o.checkpoint(ctx, client.ValidateForMail(ctx)); err != nil {
			return mailout.Route{}, err
		}
		o.validated = true
	}
	directory, routes, remote := client.MailDirectory(ctx)
	if err = o.checkpoint(ctx, remote); err != nil {
		return mailout.Route{}, err
	}
	o.mailRoutes = routes
	principal := client.Snapshot().Principal
	if !directory.Complete || directory.Subject == "" || directory.Subject != principal.DSID || o.scope.Address.ProviderOwner != "" && o.scope.Address.ProviderOwner != directory.Subject {
		return mailout.Route{}, mailout.ErrIneligible
	}
	var foundID, from string
	for _, entry := range directory.Entries {
		if !same(entry.Address, alias) {
			continue
		}
		if foundID != "" || !entry.Active || entry.ID == "" || o.scope.Address.ProviderID != "" && entry.ID != o.scope.Address.ProviderID {
			return mailout.Route{}, mailout.ErrIneligible
		}
		foundID = entry.ID
		from, err = address(entry.Forward)
		if err != nil {
			return mailout.Route{}, mailout.ErrIneligible
		}
	}
	if foundID == "" {
		return mailout.Route{}, mailout.ErrIneligible
	}
	at, err := instant(o.provider.config.Clock())
	if err != nil {
		return mailout.Route{}, err
	}
	o.route = mailout.Route{SourceID: o.scope.Source.ID, AddressID: o.scope.Address.ID, Alias: alias, Recipient: target, PrimaryAddress: o.scope.Source.PrimaryAddress, ProviderAddressID: foundID, ProviderFrom: from, OwnerVerified: true, Active: true, CheckedAt: at}
	return o.route, nil
}
func (o *operation) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return o.session.Close()
	}
	o.closed = true
	clear(o.references)
	clear(o.parts)
	for _, part := range o.smtpParts {
		clear(part.body)
	}
	clear(o.smtpParts)
	return o.session.Close()
}
func rpcReceipt(r apple.MailReceipt) mailout.RPCReceipt {
	outcome := mailout.Unknown
	switch r.Outcome {
	case "accepted":
		outcome = mailout.Accepted
	case "rejected":
		outcome = mailout.Rejected
	case "not_sent":
		outcome = mailout.NotSent
	}
	return mailout.RPCReceipt{RPCID: r.RPCID, Outcome: outcome, UpstreamID: r.UpstreamID, Matched: r.Matched || outcome == mailout.NotSent}
}
func joined(provider, local error) error {
	if provider != nil && local != nil {
		return errors.Join(provider, local)
	}
	if provider != nil {
		return provider
	}
	return local
}

var _ mailout.Provider = (*Provider)(nil)
var _ mailout.Operation = (*operation)(nil)
