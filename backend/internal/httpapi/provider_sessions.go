package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"icloudspace/internal/provider/apple"
	"icloudspace/internal/providersession"
	"icloudspace/internal/sourceguard"
)

type ManagementProviderSessions struct {
	identity *ManagementAuth
	sessions *providersession.Service
	guards   *sourceguard.Registry
}

func NewManagementProviderSessions(identity *ManagementAuth, sessions *providersession.Service, guards *sourceguard.Registry) (*ManagementProviderSessions, error) {
	if identity == nil || sessions == nil || guards == nil {
		return nil, errors.New("httpapi: management identity, provider owner and source registry are required")
	}
	return &ManagementProviderSessions{identity, sessions, guards}, nil
}
func (a *ManagementProviderSessions) Register(mux *http.ServeMux) {
	base := a.identity.basePath + "/accounts/{source_id}/provider-session"
	for pattern, handler := range map[string]http.HandlerFunc{
		"GET " + base:                a.status,
		"POST " + base + "/login":    a.login,
		"POST " + base + "/actions":  a.action,
		"POST " + base + "/query":    a.query,
		"POST " + base + "/restore":  a.restore,
		"POST " + base + "/validate": a.validate,
		"POST " + base + "/clear":    a.clear,
	} {
		mux.Handle(pattern, a.identity.RequireSession(handler))
	}
}

type providerSessionView struct {
	SourceID          string  `json:"source_id"`
	PrincipalRevision string  `json:"principal_revision"`
	Revision          *string `json:"revision"`
	Authenticated     bool    `json:"authenticated"`
	SavedAt           *string `json:"saved_at"`
	LastValidatedAt   *string `json:"last_validated_at"`
	ExpiresAt         *string `json:"expires_at"`
}

func presentProviderSession(info providersession.SessionInfo) providerSessionView {
	view := providerSessionView{SourceID: decimal(info.SourceID), PrincipalRevision: decimal(info.PrincipalRevision), Authenticated: info.Authenticated, LastValidatedAt: optionalInstant(info.LastValidatedAt), ExpiresAt: optionalInstant(info.ExpiresAt)}
	if info.Revision > 0 {
		view.Revision = optionalDecimal(&info.Revision)
		view.SavedAt = optionalInstant(&info.SavedAt)
	}
	return view
}

type providerReceiptView struct {
	Key          string                  `json:"request_key"`
	Action       providersession.Action  `json:"action"`
	Outcome      providersession.Outcome `json:"outcome"`
	ErrorCode    string                  `json:"error_code"`
	HTTPStatus   int                     `json:"http_status,omitempty"`
	ProviderCode string                  `json:"provider_code,omitempty"`
	Prepared     bool                    `json:"prepared"`
	StartedAt    string                  `json:"started_at"`
	FinishedAt   *string                 `json:"finished_at"`
}
type providerAuthView struct {
	Key               string                 `json:"request_key"`
	ChallengeToken    string                 `json:"challenge_token"`
	ChallengeRevision *string                `json:"challenge_revision"`
	State             string                 `json:"state"`
	Session           *providerSessionView   `json:"session"`
	Receipt           *providerReceiptView   `json:"receipt"`
	Options           *apple.AuthOptions     `json:"options"`
	NextAction        providersession.Action `json:"next_action"`
	Durable           bool                   `json:"durable"`
}

func presentProviderAuth(result providersession.AuthResult, durable bool) providerAuthView {
	view := providerAuthView{Key: result.RequestKey, ChallengeToken: result.ChallengeToken, State: result.State, Options: result.Options, NextAction: result.NextAction, Durable: durable}
	if result.ChallengeRevision > 0 {
		view.ChallengeRevision = optionalDecimal(&result.ChallengeRevision)
	}
	if result.Session.SourceID > 0 {
		session := presentProviderSession(result.Session)
		view.Session = &session
	}
	if result.Receipt.RequestKey != "" {
		view.Receipt = &providerReceiptView{Key: result.Receipt.RequestKey, Action: result.Receipt.Action,
			Outcome: result.Receipt.Outcome, ErrorCode: result.Receipt.ErrorCode, HTTPStatus: result.ProviderStatus,
			ProviderCode: result.ProviderCode, Prepared: result.Receipt.Prepared,
			StartedAt: instant(result.Receipt.StartedAt), FinishedAt: optionalInstant(result.Receipt.FinishedAt)}
	}
	return view
}
func (a *ManagementProviderSessions) fail(w http.ResponseWriter, r *http.Request, err error, key string) {
	status, problem := 500, internalProblem()
	switch {
	case errors.Is(err, providersession.ErrInvalid):
		status, problem = 400, Problem{Kind: "invalid_request", Code: "PROVIDER_INPUT_INVALID", Message: "Check the provider request and challenge.", Outcome: NotSent}
	case errors.Is(err, providersession.ErrNotFound):
		status, problem = 404, Problem{Kind: "not_found", Code: "PROVIDER_REQUEST_NOT_FOUND", Message: "The source or original provider request is unavailable."}
	case errors.Is(err, providersession.ErrStale), errors.Is(err, providersession.ErrBinding):
		status, problem = 409, Problem{Kind: "conflict", Code: "PROVIDER_SCOPE_CHANGED", Message: "The source identity or provider session has changed."}
	case errors.Is(err, providersession.ErrOwner):
		status, problem = 403, Problem{Kind: "authorization", Code: "PROVIDER_OWNER_CHANGED", Message: "Sign in again before continuing this provider request."}
	case errors.Is(err, providersession.ErrExpired):
		status, problem = 410, Problem{Kind: "expiry", Code: "PROVIDER_CHALLENGE_EXPIRED", Message: "The provider challenge has expired.", Outcome: NotSent}
	case errors.Is(err, providersession.ErrAttempts):
		status, problem = 429, Problem{Kind: "rate_limit", Code: "PROVIDER_ATTEMPTS_EXHAUSTED", Message: "The challenge attempt limit has been reached.", Outcome: NotSent}
	case errors.Is(err, providersession.ErrLoginRequired):
		status, problem = 409, Problem{Kind: "authentication", Code: "PROVIDER_LOGIN_REQUIRED", Message: "Sign in to the provider before this operation."}
	case errors.Is(err, providersession.ErrReadOnly):
		status, problem = 503, Problem{Kind: "maintenance", Code: "INSTALLATION_READ_ONLY", Message: "The installation is currently read-only.", Outcome: NotSent}
	case errors.Is(err, providersession.ErrUnknown), errors.Is(err, providersession.ErrRequestUnknown):
		status, problem = 503, Problem{Kind: "persistence", Code: "PROVIDER_REQUEST_UNKNOWN", Message: "Query the same request; do not repeat the provider action.", Outcome: Unknown, SubmissionKey: key}
	}
	WriteProblem(w, status, currentMeta(w), problem)
}
func (a *ManagementProviderSessions) result(w http.ResponseWriter, r *http.Request, result providersession.AuthResult, err error) {
	if result.RequestKey != "" && result.State != "" && result.Receipt.RequestKey != "" {
		durable := !errors.Is(err, providersession.ErrUnknown)
		var persistence *providersession.PersistenceError
		if errors.As(err, &persistence) {
			durable = false
		}
		status := 200
		if err != nil || result.Receipt.Outcome == providersession.Unknown {
			status = 202
		}
		WriteResult(w, status, currentMeta(w), presentProviderAuth(result, durable))
		return
	}
	if err != nil {
		a.fail(w, r, err, result.RequestKey)
		return
	}
	WriteResult(w, 200, currentMeta(w), presentProviderAuth(result, true))
}
func (a *ManagementProviderSessions) status(w http.ResponseWriter, r *http.Request) {
	id, ok := accountID(w, r)
	if !ok {
		return
	}
	info, err := a.sessions.SessionInfo(r.Context(), id)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	WriteResult(w, 200, currentMeta(w), presentProviderSession(info))
}

// The HTTP owner borrows the source gate into the provider service and checks
// the actual management session after that wait. Actor epoch alone cannot prove
// that the browser's individual session has not expired while queued.
func (a *ManagementProviderSessions) enter(w http.ResponseWriter, r *http.Request) (*http.Request, int64, providersession.Actor, func(), bool) {
	id, ok := accountID(w, r)
	if !ok {
		return r, 0, providersession.Actor{}, nil, false
	}
	gate, err := a.guards.Acquire(r.Context(), id)
	if err != nil {
		a.fail(w, r, err, "")
		return r, 0, providersession.Actor{}, nil, false
	}
	session, err := a.identity.identity.Authenticate(r.Context(), cookieValue(r, sessionCookie))
	if err != nil {
		gate.Close()
		a.identity.writeAuthError(w, currentMeta(w), err)
		return r, 0, providersession.Actor{}, nil, false
	}
	if session.Epoch() < 1 {
		gate.Close()
		a.fail(w, r, providersession.ErrOwner, "")
		return r, 0, providersession.Actor{}, nil, false
	}
	actor := providersession.Actor{OperatorID: session.Operator.ID, SessionEpoch: session.Epoch()}
	return r.WithContext(sourceguard.WithLease(r.Context(), gate)), id, actor, func() { gate.Close() }, true
}
func (a *ManagementProviderSessions) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Key      string `json:"request_key"`
		Password string `json:"password"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	r, id, actor, close, ok := a.enter(w, r)
	if !ok {
		return
	}
	defer close()
	result, err := a.sessions.Start(r.Context(), id, actor, input.Key, input.Password)
	a.result(w, r, result, err)
}
func (a *ManagementProviderSessions) action(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Key          string                      `json:"request_key"`
		Token        string                      `json:"challenge_token"`
		Action       providersession.Action      `json:"action"`
		ConfirmTrust bool                        `json:"confirm_browser_trust"`
		Code         string                      `json:"code"`
		PhoneID      string                      `json:"phone_id"`
		Mode         string                      `json:"mode"`
		Assertion    *apple.SecurityKeyAssertion `json:"assertion"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	if (input.Action == providersession.TrustBrowser) != input.ConfirmTrust {
		WriteProblem(w, http.StatusBadRequest, currentMeta(w), Problem{Kind: "invalid_request", Code: "PROVIDER_TRUST_CHOICE_REQUIRED", Message: "Choose whether to trust this browser.", Outcome: NotSent})
		return
	}
	r, id, actor, close, ok := a.enter(w, r)
	if !ok {
		return
	}
	defer close()
	result, err := a.sessions.Perform(r.Context(), providersession.AuthInput{SourceID: id, Actor: actor, RequestKey: input.Key, ChallengeToken: input.Token, Action: input.Action, Code: input.Code, PhoneID: input.PhoneID, Mode: input.Mode, Assertion: input.Assertion})
	a.result(w, r, result, err)
}
func (a *ManagementProviderSessions) query(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Key   string `json:"request_key"`
		Token string `json:"challenge_token"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	id, ok := accountID(w, r)
	if !ok {
		return
	}
	session, ok := AuthenticatedSession(r.Context())
	if !ok {
		a.fail(w, r, providersession.ErrOwner, "")
		return
	}
	result, err := a.sessions.Query(r.Context(), id, providersession.Actor{OperatorID: session.Operator.ID, SessionEpoch: session.Epoch()}, input.Token, input.Key)
	a.result(w, r, result, err)
}
func (a *ManagementProviderSessions) restore(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Key          string          `json:"request_key"`
		Document     json.RawMessage `json:"document"`
		DocumentJSON *string         `json:"document_json"`
	}
	// A textual capsule avoids JavaScript rounding signed Unix nanoseconds.
	// JSON string escaping can expand the bounded original by up to six times.
	if problem := DecodeJSON(w, r, &input, (6<<20)+4096); problem != nil {
		WriteProblem(w, 400, currentMeta(w), *problem)
		return
	}
	if input.DocumentJSON != nil {
		if len(input.Document) != 0 {
			a.fail(w, r, providersession.ErrInvalid, "")
			return
		}
		input.Document = json.RawMessage(*input.DocumentJSON)
	}
	document, err := apple.DecodeSession(input.Document)
	if err != nil {
		a.fail(w, r, providersession.ErrInvalid, "")
		return
	}
	r, id, actor, close, ok := a.enter(w, r)
	if !ok {
		return
	}
	defer close()
	result, err := a.sessions.Restore(r.Context(), id, actor, input.Key, document)
	a.result(w, r, result, err)
}
func (a *ManagementProviderSessions) validate(w http.ResponseWriter, r *http.Request) {
	a.local(w, r, false)
}
func (a *ManagementProviderSessions) clear(w http.ResponseWriter, r *http.Request) {
	a.local(w, r, true)
}
func (a *ManagementProviderSessions) local(w http.ResponseWriter, r *http.Request, clear bool) {
	var input struct {
		Key string `json:"request_key"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	r, id, actor, close, ok := a.enter(w, r)
	if !ok {
		return
	}
	defer close()
	var result providersession.AuthResult
	var err error
	if clear {
		result, err = a.sessions.ClearAuth(r.Context(), id, actor, input.Key)
	} else {
		result, err = a.sessions.Validate(r.Context(), id, actor, input.Key)
	}
	a.result(w, r, result, err)
}
