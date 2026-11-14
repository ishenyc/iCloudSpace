package providersession

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"

	"icloudspace/internal/provider/apple"
	"icloudspace/internal/sourceguard"
)

const challengeProjection = `c.challenge_hash,c.operator_id,c.principal_revision,c.revision,c.session_revision,coalesce(c.request_key,''),c.state,c.attempts,c.created_at,c.expires_at,c.challenge_envelope`

func scanChallenge(row interface{ Scan(...any) error }) (c challenge, err error) {
	err = row.Scan(&c.Hash, &c.OperatorID, &c.PrincipalRevision, &c.Revision, &c.SessionRevision, &c.RequestKey, &c.State, &c.Attempts, &c.CreatedAt, &c.ExpiresAt, &c.Envelope)
	return
}
func (r *Repository) openChallenge(c challenge, sourceID int64) (challenge, error) {
	scope := Scope{SourceID: sourceID, PrincipalRevision: c.PrincipalRevision}
	aad, err := challengeBinding(r.cfg.InstallationID, scope, c.OperatorID, c.Hash)
	if err != nil {
		return c, ErrBinding
	}
	plain, err := r.cfg.Vault.Open(aad, string(c.Envelope))
	if err != nil {
		return c, ErrBinding
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c.Document) != nil {
		return c, ErrBinding
	}
	if _, err = decoder.Token(); err != io.EOF {
		return c, ErrBinding
	}
	if _, err = plainChallenge(c.Document); err != nil || c.Document.Scope.SourceID != sourceID || c.Document.Scope.PrincipalRevision != c.PrincipalRevision || c.Document.SessionRevision != c.SessionRevision {
		return c, ErrBinding
	}
	hash, err := tokenHash(c.Document.Token)
	if err != nil || subtle.ConstantTimeCompare(hash, c.Hash) != 1 {
		return c, ErrBinding
	}
	return c, nil
}
func (r *Repository) sealChallenge(c challenge) (challenge, error) {
	plain, err := plainChallenge(c.Document)
	if err != nil {
		return c, err
	}
	aad, err := challengeBinding(r.cfg.InstallationID, c.Document.Scope, c.OperatorID, c.Hash)
	if err != nil {
		return c, err
	}
	encrypted, err := r.cfg.Vault.Seal(aad, plain)
	if err != nil {
		return c, ErrBinding
	}
	c.Envelope = []byte(encrypted)
	return c, nil
}
func (r *Repository) findChallenge(ctx context.Context, sourceID int64, actor Actor, token, key string) (challenge, error) {
	query := `SELECT ` + challengeProjection + ` FROM space.apple_action_requests r JOIN space.apple_challenges c ON c.challenge_hash=r.challenge_hash AND c.source_id=r.source_id AND c.operator_id=r.operator_id WHERE r.source_id=$1 AND r.operator_id=$2 AND r.request_key=$3`
	var lookup any = key
	if token != "" {
		hash, err := tokenHash(token)
		if err != nil {
			return challenge{}, err
		}
		query = `SELECT ` + challengeProjection + ` FROM space.apple_challenges c WHERE c.source_id=$1 AND c.operator_id=$2 AND c.challenge_hash=$3`
		lookup = hash
	}
	c, err := scanChallenge(r.DB.QueryRowContext(ctx, query, sourceID, actor.OperatorID, lookup))
	if token == "" && errors.Is(err, sql.ErrNoRows) {
		// Canonical capsules written before the action index still expose their
		// original request key. Only that bounded lookup is compatible; receipt
		// recovery must never decrypt and scan every challenge for a source.
		query = `SELECT ` + challengeProjection + ` FROM space.apple_challenges c WHERE c.source_id=$1 AND c.operator_id=$2 AND c.request_key=$3`
		c, err = scanChallenge(r.DB.QueryRowContext(ctx, query, sourceID, actor.OperatorID, key))
	}
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	c, err = r.openChallenge(c, sourceID)
	if err != nil {
		return c, err
	}
	if c.Document.OperatorEpoch != actor.SessionEpoch {
		return c, ErrOwner
	}
	return c, nil
}
func writeChallenge(ctx context.Context, tx *sql.Tx, c challenge, sourceID int64) error {
	result, err := tx.ExecContext(ctx, `INSERT INTO space.apple_challenges AS current(challenge_hash,source_id,operator_id,principal_revision,revision,session_revision,request_key,state,challenge_envelope,attempts,created_at,expires_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(challenge_hash) DO UPDATE SET revision=EXCLUDED.revision,session_revision=EXCLUDED.session_revision,state=EXCLUDED.state,challenge_envelope=EXCLUDED.challenge_envelope,attempts=EXCLUDED.attempts
 WHERE current.source_id=EXCLUDED.source_id AND current.operator_id=EXCLUDED.operator_id AND current.principal_revision=EXCLUDED.principal_revision AND current.revision=EXCLUDED.revision-1`, c.Hash, sourceID, c.OperatorID, c.PrincipalRevision, c.Revision, c.SessionRevision, c.RequestKey, c.State, c.Envelope, c.Attempts, c.CreatedAt, c.ExpiresAt)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrStale
	}
	keys := make([]string, len(c.Document.Receipts))
	for i, r := range c.Document.Receipts {
		keys[i] = r.RequestKey
	}
	result, err = tx.ExecContext(ctx, `INSERT INTO space.apple_action_requests AS current(source_id,operator_id,request_key,challenge_hash)
 SELECT $1,$2,request_key,$3 FROM unnest($4::text[]) AS requests(request_key)
 WHERE NOT EXISTS(SELECT 1 FROM space.apple_challenges previous WHERE previous.source_id=$1 AND previous.operator_id=$2 AND previous.request_key=requests.request_key AND previous.challenge_hash<>$3)
 ON CONFLICT(source_id,operator_id,request_key) DO UPDATE SET challenge_hash=EXCLUDED.challenge_hash
 WHERE current.challenge_hash=EXCLUDED.challenge_hash`, sourceID, c.OperatorID, c.Hash, keys)
	if err != nil {
		return err
	}
	n, err = result.RowsAffected()
	if err != nil {
		return err
	}
	if n != int64(len(keys)) {
		return ErrStale
	}
	return nil
}
func (s *Service) enter(ctx context.Context, id int64) (context.Context, *sourceguard.Lease, func(), error) {
	if s == nil || id < 1 {
		return ctx, nil, nil, ErrInvalid
	}
	if held := sourceguard.LeaseFromContext(ctx); held != nil {
		if !held.ValidFor(s.cfg.Registry, id) {
			return ctx, nil, nil, ErrGuard
		}
		return ctx, held, func() {}, nil
	}
	gate, err := s.cfg.Registry.Acquire(ctx, id)
	if err != nil {
		return ctx, nil, nil, err
	}
	return sourceguard.WithLease(ctx, gate), gate, func() { gate.Close() }, nil
}
func (s *Service) checkActor(ctx context.Context, actor Actor) error {
	if !actorValid(actor) {
		return ErrOwner
	}
	var epoch int64
	var enabled bool
	if err := s.repo.DB.QueryRowContext(ctx, `SELECT session_epoch,enabled FROM space.operators WHERE id=$1`, actor.OperatorID).Scan(&epoch, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrOwner
		}
		return err
	}
	if !enabled || epoch != actor.SessionEpoch {
		return ErrOwner
	}
	return nil
}
func receipt(c challenge, key string) (ActionReceipt, bool) {
	for _, r := range c.Document.Receipts {
		if r.RequestKey == key {
			return r, true
		}
	}
	return ActionReceipt{}, false
}
func unresolved(c challenge) bool {
	for _, r := range c.Document.Receipts {
		if r.Prepared || r.Outcome == Unknown {
			return true
		}
	}
	return false
}
func options(document apple.SessionDocument) *apple.AuthOptions {
	if document.AuthFlow == nil {
		return nil
	}
	flow := document.AuthFlow.Options
	return &flow
}
func (s *Service) result(src source, c challenge, key string) AuthResult {
	r, _ := receipt(c, key)
	out := AuthResult{RequestKey: key, ChallengeToken: c.Document.Token, ChallengeRevision: c.Revision, State: c.State, Session: src.Info, Receipt: r, RequestSessionRevision: c.SessionRevision}
	if document, err := s.document(src, false); err == nil {
		if c.SessionRevision == src.Info.Revision {
			out.Options = options(document)
		}
	}
	if c.State == "complete" || c.State == "failed" || c.State == "expired" {
		return out
	}
	if c.SessionRevision != src.Info.Revision {
		out.State = "expired"
		return out
	}
	if now, err := instant(s.cfg.Clock()); err == nil && now >= c.ExpiresAt {
		out.State = "expired"
		return out
	}
	if src.Info.Authenticated {
		out.State = "complete"
		return out
	}
	if len(c.Document.Receipts) > 0 {
		last := c.Document.Receipts[len(c.Document.Receipts)-1]
		switch last.Action {
		case Login:
			if last.ErrorCode == string(apple.SecondFactorRequired) {
				out.NextAction = LoadChallenge
			} else if last.Outcome == Accepted {
				out.NextAction = ExchangeToken
			}
		case RestoreSession:
			out.NextAction = ValidateSession
		case VerifyDeviceCode, VerifySMS, VerifySecurityKey:
			if last.Outcome == Accepted {
				out.NextAction = TrustBrowser
			}
		case TrustBrowser:
			if last.Outcome == Accepted {
				out.NextAction = ExchangeToken
			}
		}
	}
	return out
}

// Query is only a local receipt read. A prepared/unknown action remains query
// only; it does not rerun SRP, deliver a code, verify one or trust a browser.
func (s *Service) Query(ctx context.Context, id int64, actor Actor, token, key string) (AuthResult, error) {
	if id < 1 || !actorValid(actor) || token == "" && !requestKey(key) {
		return AuthResult{}, ErrInvalid
	}
	if err := s.checkActor(ctx, actor); err != nil {
		return AuthResult{}, err
	}
	c, err := s.repo.findChallenge(ctx, id, actor, token, key)
	if err != nil {
		return AuthResult{}, err
	}
	src, err := s.repo.load(ctx, id)
	if err != nil {
		return AuthResult{}, err
	}
	if src.Scope != c.Document.Scope {
		return AuthResult{}, ErrStale
	}
	if key == "" {
		key = c.Document.Receipts[len(c.Document.Receipts)-1].RequestKey
	}
	if _, exists := receipt(c, key); !exists {
		return AuthResult{}, ErrNotFound
	}
	out := s.result(src, c, key)
	if unresolved(c) {
		return out, ErrRequestUnknown
	}
	return out, nil
}

func (s *Service) newChallenge(src source, actor Actor, key string, action Action) (challenge, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return challenge{}, err
	}
	token := hex.EncodeToString(raw[:])
	hash, _ := tokenHash(token)
	at := s.cfg.Clock()
	now, err := instant(at)
	if err != nil {
		return challenge{}, err
	}
	expires, err := instant(at.Add(s.cfg.ChallengeTTL))
	if err != nil {
		return challenge{}, err
	}
	c := challenge{Hash: hash, OperatorID: actor.OperatorID, PrincipalRevision: src.Scope.PrincipalRevision, Revision: 1, RequestKey: key, State: "password", Attempts: 1, CreatedAt: now, ExpiresAt: expires}
	c.Document = challengeDocument{Version: 1, Scope: src.Scope, OperatorEpoch: actor.SessionEpoch, Token: token, Receipts: []ActionReceipt{{RequestKey: key, Action: action, Outcome: Unknown, Prepared: true, StartedAt: now}}}
	return c, nil
}
func (s *Service) saveAuth(ctx context.Context, gate *sourceguard.Lease, w sessionWrite, actor Actor, before *challenge, after challenge, expire, observed bool) (challenge, error) {
	after.SessionRevision = w.info.Revision
	after.Document.SessionRevision = w.info.Revision
	sealed, err := s.repo.sealChallenge(after)
	if err != nil {
		return after, err
	}
	err = s.repo.save(ctx, gate, w, &actor, before, &sealed, expire)
	if observed && errors.Is(err, ErrOwner) {
		// Revocation forbids granting authenticated access, but rotated source
		// state is still preserved. The revoked challenge remains expired and
		// query-only; no provider operation is repeated.
		w.info.Authenticated = false
		sealed.State = "expired"
		persistErr := s.repo.save(ctx, gate, w, nil, before, &sealed, expire)
		if persistErr != nil {
			return sealed, &PersistenceError{Provider: ErrOwner, Persistence: persistErr}
		}
		return sealed, ErrOwner
	}
	return sealed, err
}

// Start is explicit. Its request key is claimed before SRP and never reused to
// restart a failed/unknown login. Password is never stored in a document/receipt.
func (s *Service) Start(ctx context.Context, id int64, actor Actor, key, password string) (AuthResult, error) {
	if id < 1 || !actorValid(actor) || !requestKey(key) || len(password) == 0 || len(password) > 4096 {
		return AuthResult{}, ErrInvalid
	}
	if err := s.checkActor(ctx, actor); err != nil {
		return AuthResult{}, err
	}
	ctx, gate, close, err := s.enter(ctx, id)
	if err != nil {
		return AuthResult{}, err
	}
	defer close()
	if old, e := s.repo.findChallenge(ctx, id, actor, "", key); e == nil {
		if previous, exists := receipt(old, key); !exists || previous.Action != Login {
			return AuthResult{}, ErrStale
		}
		src, e := s.repo.load(ctx, id)
		if e != nil {
			return AuthResult{}, e
		}
		if src.Scope != old.Document.Scope {
			return AuthResult{}, ErrStale
		}
		out := s.result(src, old, key)
		if out.Receipt.Prepared || out.Receipt.Outcome == Unknown {
			return out, ErrRequestUnknown
		}
		return out, nil
	} else if !errors.Is(e, ErrNotFound) {
		return AuthResult{}, e
	}
	src, err := s.repo.load(ctx, id)
	if err != nil {
		return AuthResult{}, err
	}
	document, err := s.document(src, true)
	if err != nil {
		return AuthResult{}, err
	}
	c, err := s.newChallenge(src, actor, key, Login)
	if err != nil {
		return AuthResult{}, err
	}
	w, err := s.repo.encodeSession(src, document, false)
	if err != nil {
		return AuthResult{}, err
	}
	c, err = s.saveAuth(ctx, gate, w, actor, nil, c, true, false)
	if err != nil {
		return s.result(src, c, key), err
	}
	prepared, err := s.repo.load(ctx, id)
	if err != nil {
		return AuthResult{}, err
	}
	return s.runAuth(ctx, gate, prepared, c, actor, key, Login, func(client *apple.Client) error {
		if _, e := client.AuthorizeShell(ctx); e != nil {
			return e
		}
		loginErr := client.Login(ctx, password)
		var failure *apple.Error
		if errors.As(loginErr, &failure) && failure.Kind == apple.SecondFactorRequired {
			_, _ = client.AuthorizeShell(ctx)
		}
		return loginErr
	})
}

func (s *Service) runAuth(ctx context.Context, gate *sourceguard.Lease, src source, c challenge, actor Actor, key string, action Action, operation func(*apple.Client) error) (AuthResult, error) {
	document, err := s.document(src, false)
	if err != nil {
		return s.result(src, c, key), err
	}
	client, err := s.cfg.Factory(document, s.cfg.Options(src.Scope))
	providerErr := err
	snapshot := document
	outcome := NotSent
	if err == nil && client != nil {
		defer client.CloseIdleConnections()
		providerErr = callOperation(client, operation)
		snapshot = client.Snapshot()
		outcome = actionOutcome(providerErr)
	} else if err == nil {
		providerErr = ErrInvalid
	}
	before := c
	c.Revision++
	if c.Revision <= 0 {
		return AuthResult{}, ErrStale
	}
	now, err := instant(s.cfg.Clock())
	if err != nil {
		return s.result(src, c, key), err
	}
	for i := range c.Document.Receipts {
		if c.Document.Receipts[i].RequestKey == key {
			c.Document.Receipts[i].Prepared = false
			c.Document.Receipts[i].Outcome = outcome
			c.Document.Receipts[i].ErrorCode = safeCode(providerErr)
			c.Document.Receipts[i].FinishedAt = &now
		}
	}
	authenticated := false
	if providerErr == nil && (action == ExchangeToken || action == ValidateSession) {
		authenticated = snapshot.Principal.DSID != "" && !snapshot.Assurance.HSAChallengeRequired
	}
	var provider *apple.Error
	if errors.As(providerErr, &provider) && provider.Kind == apple.SecondFactorRequired {
		c.State = "mfa"
	} else if authenticated {
		c.State = "complete"
	} else if action == Login && outcome == Rejected {
		c.State = "failed"
	}
	w, err := s.repo.encodeSession(src, snapshot, authenticated)
	if err != nil {
		return s.result(src, c, key), &PersistenceError{Provider: providerErr, Persistence: err}
	}
	persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.PersistenceTimeout)
	defer cancel()
	c, err = s.saveAuth(persist, gate, w, actor, &before, c, false, true)
	current, e := s.repo.load(persist, src.Scope.SourceID)
	if e != nil {
		current = src
	}
	out := s.result(current, c, key)
	if err != nil {
		return out, &PersistenceError{Provider: providerErr, Persistence: err}
	}
	if outcome == Unknown {
		return out, ErrRequestUnknown
	}
	if errors.As(providerErr, &provider) && provider.Kind == apple.SecondFactorRequired {
		return out, nil
	}
	return out, providerErr
}

func sixDigits(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func (s *Service) Perform(ctx context.Context, in AuthInput) (AuthResult, error) {
	if in.SourceID < 1 || !actorValid(in.Actor) || !requestKey(in.RequestKey) || in.ChallengeToken == "" {
		return AuthResult{}, ErrInvalid
	}
	if len(in.PhoneID) > 64 || len(in.Mode) > 16 {
		return AuthResult{}, ErrInvalid
	}
	switch in.Action {
	case LoadChallenge, SendDeviceCode, TrustBrowser, ExchangeToken, ValidateSession:
	case VerifyDeviceCode, VerifySMS:
		if !sixDigits(in.Code) {
			return AuthResult{}, ErrInvalid
		}
	case SendSMS:
	case VerifySecurityKey:
		if in.Assertion == nil {
			return AuthResult{}, ErrInvalid
		}
	default:
		return AuthResult{}, ErrInvalid
	}
	if err := s.checkActor(ctx, in.Actor); err != nil {
		return AuthResult{}, err
	}
	ctx, gate, close, err := s.enter(ctx, in.SourceID)
	if err != nil {
		return AuthResult{}, err
	}
	defer close()
	c, err := s.repo.findChallenge(ctx, in.SourceID, in.Actor, in.ChallengeToken, "")
	if err != nil {
		return AuthResult{}, err
	}
	src, err := s.repo.load(ctx, in.SourceID)
	if err != nil {
		return AuthResult{}, err
	}
	if src.Scope != c.Document.Scope {
		return AuthResult{}, ErrStale
	}
	if old, exists := receipt(c, in.RequestKey); exists {
		if old.Action != in.Action || old.Target != in.PhoneID || old.Mode != in.Mode {
			return AuthResult{}, ErrStale
		}
		out := s.result(src, c, in.RequestKey)
		if old.Prepared || old.Outcome == Unknown {
			return out, ErrRequestUnknown
		}
		return out, nil
	}
	now, err := instant(s.cfg.Clock())
	if err != nil {
		return AuthResult{}, err
	}
	if now >= c.ExpiresAt {
		return s.result(src, c, in.RequestKey), ErrExpired
	}
	if c.State == "complete" || c.State == "failed" || c.State == "expired" {
		return AuthResult{}, ErrExpired
	}
	if c.SessionRevision != src.Info.Revision || unresolved(c) {
		return s.result(src, c, in.RequestKey), ErrRequestUnknown
	}
	if c.Attempts >= s.cfg.MaxChallengeAttempts || len(c.Document.Receipts) >= 24 {
		return s.result(src, c, in.RequestKey), ErrAttempts
	}
	if c.Revision == math.MaxInt64 {
		return AuthResult{}, ErrStale
	}
	before := c
	c.Revision++
	c.Attempts++
	c.Document.Receipts = append(append([]ActionReceipt(nil), c.Document.Receipts...), ActionReceipt{RequestKey: in.RequestKey, Action: in.Action, Target: in.PhoneID, Mode: in.Mode, Outcome: Unknown, Prepared: true, StartedAt: now})
	document, err := s.document(src, false)
	if err != nil {
		return AuthResult{}, err
	}
	w, err := s.repo.encodeSession(src, document, false)
	if err != nil {
		return AuthResult{}, err
	}
	c, err = s.saveAuth(ctx, gate, w, in.Actor, &before, c, false, false)
	if err != nil {
		return s.result(src, c, in.RequestKey), err
	}
	prepared, err := s.repo.load(ctx, in.SourceID)
	if err != nil {
		return AuthResult{}, err
	}
	return s.runAuth(ctx, gate, prepared, c, in.Actor, in.RequestKey, in.Action, func(client *apple.Client) error {
		switch in.Action {
		case LoadChallenge:
			_, e := client.AuthorizeShell(ctx)
			return e
		case SendDeviceCode:
			return client.RequestDeviceCode(ctx)
		case VerifyDeviceCode:
			return client.VerifyTrustedDeviceCode(ctx, in.Code)
		case SendSMS:
			return client.RequestPhoneCode(ctx, in.PhoneID, in.Mode)
		case VerifySMS:
			return client.VerifyPhoneCode(ctx, in.PhoneID, in.Mode, in.Code)
		case VerifySecurityKey:
			return client.VerifySecurityKey(ctx, *in.Assertion)
		case TrustBrowser:
			return client.TrustSession(ctx)
		case ExchangeToken:
			return client.ExchangeToken(ctx)
		case ValidateSession:
			return client.Validate(ctx)
		}
		return ErrInvalid
	})
}
