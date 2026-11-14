package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"icloudspace/internal/adminauth"
	"icloudspace/internal/operationlog"
	"icloudspace/internal/sourceguard"
)

const (
	sessionCookie = "space_session"
	csrfCookie    = "space_csrf"
)

// ManagementIdentity is the transport's authentication port. Its implementation
// owns passwords and persistence; this boundary owns HTTP request policy.
type ManagementIdentity interface {
	Login(context.Context, string, string) (adminauth.IssuedSession, error)
	Authenticate(context.Context, string) (adminauth.Session, error)
	ValidateCSRF(adminauth.Session, string) bool
	Logout(context.Context, string) error
	ChangePassword(context.Context, string, string, string, string) error
}

type AuthOptions struct {
	// BasePath is the complete installed management API path, without a
	// trailing slash. The management UI entry remains a separate resource.
	BasePath     string
	Identity     ManagementIdentity
	SecureCookie bool
	// Empty means forwarded headers have no authority. Only the actual peer
	// matching one of these explicit ranges may supply proxy information.
	TrustedProxies []netip.Prefix
}

type ManagementAuth struct {
	basePath string
	identity ManagementIdentity
	secure   bool
	login    *loginAdmission
	// Global management lock precedes account gates and upstream slots.
	// Revocation/password changes exclude sensitive management operations;
	// those operations reauthenticate after waiting for this lock.
	credentialGate sync.RWMutex
	trustedProxies []netip.Prefix
}

func NewManagementAuth(options AuthOptions) (*ManagementAuth, error) {
	path := options.BasePath
	if options.Identity == nil || path == "" || path[0] != '/' || strings.HasSuffix(path, "/") ||
		strings.ContainsAny(path, "?#%\\\r\n\t ") || strings.Contains(path, "//") {
		return nil, errors.New("httpapi: identity and canonical management API base are required")
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return nil, errors.New("httpapi: management API base contains a relative segment")
		}
	}
	for _, prefix := range options.TrustedProxies {
		if !prefix.IsValid() {
			return nil, errors.New("httpapi: trusted proxy prefix is invalid")
		}
	}
	return &ManagementAuth{
		basePath: path, identity: options.Identity, secure: options.SecureCookie,
		login:          newLoginAdmission(),
		trustedProxies: append([]netip.Prefix(nil), options.TrustedProxies...),
	}, nil
}

// Register adds only canonical authentication endpoints. It installs no old
// URL fallback and does not initialize an operator or database.
func (a *ManagementAuth) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+a.basePath+"/session", a.readSession)
	mux.HandleFunc("POST "+a.basePath+"/session", a.createSession)
	mux.Handle("DELETE "+a.basePath+"/session", a.RequireSession(http.HandlerFunc(a.deleteSession)))
	mux.Handle("PUT "+a.basePath+"/password", a.RequireSession(http.HandlerFunc(a.changePassword)))
}

type sessionContextKey struct{}

func AuthenticatedSession(ctx context.Context) (adminauth.Session, bool) {
	session, ok := ctx.Value(sessionContextKey{}).(adminauth.Session)
	return session, ok
}

// RequireSession authenticates each request. A separate account/credential
// write gate must authenticate again after any lock wait before its mutation.
func (a *ManagementAuth) RequireSession(next http.Handler) http.Handler {
	return a.requireSession(next, false)
}

// RequireLocalCommand defers the final session check until the local owner has
// acquired its source/credential admission. It is not used for provider work or
// finalizing a mutation that the remote service may already have accepted.
func (a *ManagementAuth) RequireLocalCommand(next http.Handler) http.Handler {
	return a.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := sourceguard.WithLocalMutationCheck(r.Context(), func(ctx context.Context) error {
			_, err := a.identity.Authenticate(ctx, cookieValue(r, sessionCookie))
			return err
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	}))
}

// Sensitive GET responses participate in password/logout revocation just like
// explicit reveals. Ordinary metadata GETs need no long management read lease.
func (a *ManagementAuth) RequireSensitiveRead(next http.Handler) http.Handler {
	return a.requireSession(next, true)
}

func (a *ManagementAuth) requireSession(next http.Handler, sensitiveRead bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta, ok := requestMeta(w)
		if !ok {
			return
		}
		if !a.sameOrigin(r, unsafeMethod(r.Method)) {
			WriteProblem(w, http.StatusForbidden, meta, originProblem())
			return
		}
		if unsafeMethod(r.Method) || sensitiveRead {
			exclusive := r.Method == http.MethodPut && r.URL.Path == a.basePath+"/password" ||
				r.Method == http.MethodDelete && r.URL.Path == a.basePath+"/session" ||
				r.Method == http.MethodPost && r.URL.Path == a.basePath+"/credential-rotations"
			if exclusive {
				a.credentialGate.Lock()
				defer a.credentialGate.Unlock()
			} else {
				a.credentialGate.RLock()
				defer a.credentialGate.RUnlock()
			}
		}
		session, err := a.identity.Authenticate(r.Context(), cookieValue(r, sessionCookie))
		if err != nil {
			a.writeAuthError(w, meta, err)
			return
		}
		if unsafeMethod(r.Method) && !a.identity.ValidateCSRF(session, r.Header.Get("X-CSRF-Token")) {
			WriteProblem(w, http.StatusForbidden, meta, Problem{Kind: "authorization", Code: "CSRF_INVALID", Message: "Refresh the management session before making changes."})
			return
		}
		actorContext, err := operationlog.WithActor(r.Context(), operationlog.Actor{Kind: "operator", Ref: strconv.FormatInt(session.Operator.ID, 10), Origin: a.clientAddress(r), RequestID: meta.RequestID})
		if err != nil {
			WriteProblem(w, 500, meta, internalProblem())
			return
		}
		r = r.WithContext(context.WithValue(actorContext, sessionContextKey{}, session))
		next.ServeHTTP(w, r)
	})
}

type operatorView struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type sessionView struct {
	Authenticated bool          `json:"authenticated"`
	Operator      *operatorView `json:"operator,omitempty"`
	CSRFToken     string        `json:"csrf_token,omitempty"`
	ExpiresAt     string        `json:"expires_at,omitempty"`
}

func (a *ManagementAuth) readSession(w http.ResponseWriter, r *http.Request) {
	meta, ok := requestMeta(w)
	if !ok {
		return
	}
	if !a.sameOrigin(r, false) {
		WriteProblem(w, http.StatusForbidden, meta, originProblem())
		return
	}
	session, err := a.identity.Authenticate(r.Context(), cookieValue(r, sessionCookie))
	if errors.Is(err, adminauth.ErrUnauthenticated) {
		a.clearCookies(w, r)
		WriteResult(w, http.StatusOK, meta, sessionView{})
		return
	}
	if err != nil {
		a.writeAuthError(w, meta, err)
		return
	}
	csrf := cookieValue(r, csrfCookie)
	if !a.identity.ValidateCSRF(session, csrf) {
		// Hash-only storage cannot reconstruct a missing browser CSRF token.
		// Reauthentication is explicit rather than silently issuing a token
		// in response to a safe request.
		WriteProblem(w, http.StatusUnauthorized, meta, Problem{Kind: "authentication", Code: "SESSION_REAUTHENTICATION_REQUIRED", Message: "Sign in again to restore the management session."})
		return
	}
	WriteResult(w, http.StatusOK, meta, sessionView{
		Authenticated: true,
		Operator:      &operatorView{ID: strconv.FormatInt(session.Operator.ID, 10), Username: session.Operator.Username},
		CSRFToken:     csrf,
		ExpiresAt:     session.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
}

func (a *ManagementAuth) createSession(w http.ResponseWriter, r *http.Request) {
	meta, ok := requestMeta(w)
	if !ok {
		return
	}
	if !a.sameOrigin(r, true) {
		WriteProblem(w, http.StatusForbidden, meta, originProblem())
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if problem := DecodeJSON(w, r, &input, 8<<10); problem != nil {
		problem.Outcome = NotSent
		WriteProblem(w, http.StatusBadRequest, meta, *problem)
		return
	}
	if !a.login.enter(a.clientAddress(r), time.Now()) {
		w.Header().Set("Retry-After", "15")
		WriteProblem(w, http.StatusTooManyRequests, meta, Problem{Kind: "rate_limit", Code: "LOGIN_THROTTLED", Message: "Wait briefly before signing in again."})
		return
	}
	defer a.login.leave()
	actorContext, err := operationlog.WithActor(r.Context(), operationlog.Actor{Kind: "system", Ref: "anonymous", Origin: a.clientAddress(r), RequestID: meta.RequestID})
	if err != nil {
		WriteProblem(w, 500, meta, internalProblem())
		return
	}
	issued, err := a.identity.Login(actorContext, input.Username, input.Password)
	if err != nil {
		a.writeAuthError(w, meta, err)
		return
	}
	a.setCookie(w, r, sessionCookie, issued.SessionToken, issued.ExpiresAt)
	a.setCookie(w, r, csrfCookie, issued.CSRFToken, issued.ExpiresAt)
	WriteResult(w, http.StatusCreated, meta, sessionView{
		Authenticated: true,
		Operator:      &operatorView{ID: strconv.FormatInt(issued.Operator.ID, 10), Username: issued.Operator.Username},
		CSRFToken:     issued.CSRFToken,
		ExpiresAt:     issued.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
}

func (a *ManagementAuth) deleteSession(w http.ResponseWriter, r *http.Request) {
	meta := Meta{RequestID: w.Header().Get("X-Request-ID")}
	if err := a.identity.Logout(r.Context(), cookieValue(r, sessionCookie)); err != nil {
		a.writeAuthError(w, meta, err)
		return
	}
	a.clearCookies(w, r)
	WriteResult(w, http.StatusOK, meta, nil)
}

func (a *ManagementAuth) changePassword(w http.ResponseWriter, r *http.Request) {
	meta := Meta{RequestID: w.Header().Get("X-Request-ID")}
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		Confirmation    string `json:"confirmation"`
	}
	if problem := DecodeJSON(w, r, &input, 8<<10); problem != nil {
		problem.Outcome = NotSent
		WriteProblem(w, http.StatusBadRequest, meta, *problem)
		return
	}
	// Password changes perform bcrypt as well. Share the bounded admission
	// slots with login so authenticated callers cannot create unbounded work.
	if !a.login.enter(a.clientAddress(r), time.Now()) {
		w.Header().Set("Retry-After", "15")
		WriteProblem(w, http.StatusTooManyRequests, meta, Problem{Kind: "rate_limit", Code: "LOGIN_THROTTLED", Message: "Wait briefly before changing credentials again.", Outcome: NotSent})
		return
	}
	defer a.login.leave()
	err := a.identity.ChangePassword(r.Context(), cookieValue(r, sessionCookie), input.CurrentPassword, input.NewPassword, input.Confirmation)
	if err != nil {
		switch {
		case errors.Is(err, adminauth.ErrInvalidCredentials):
			WriteProblem(w, http.StatusForbidden, meta, Problem{Kind: "invalid_request", Code: "CURRENT_PASSWORD_INVALID", Message: "The current password does not match. The session is unchanged.", Outcome: NotSent})
			return
		case errors.Is(err, adminauth.ErrPasswordPolicy), errors.Is(err, adminauth.ErrInvalidInput):
			WriteProblem(w, http.StatusBadRequest, meta, Problem{Kind: "invalid_request", Code: "PASSWORD_POLICY", Message: "Use 12 to 72 password bytes and matching confirmation.", Outcome: NotSent})
			return
		}
		a.writeAuthError(w, meta, err)
		return
	}
	a.clearCookies(w, r)
	WriteResult(w, http.StatusOK, meta, nil)
}

func (a *ManagementAuth) writeAuthError(w http.ResponseWriter, meta Meta, err error) {
	status := http.StatusInternalServerError
	p := internalProblem()
	switch {
	case errors.Is(err, adminauth.ErrInvalidCredentials):
		status, p = http.StatusUnauthorized, Problem{Kind: "authentication", Code: "CREDENTIALS_INVALID", Message: "The management credentials are invalid."}
	case errors.Is(err, adminauth.ErrUnauthenticated):
		status, p = http.StatusUnauthorized, Problem{Kind: "authentication", Code: "SESSION_REQUIRED", Message: "Sign in to continue."}
	case errors.Is(err, adminauth.ErrInvalidInput):
		status, p = http.StatusBadRequest, Problem{Kind: "invalid_request", Code: "AUTH_INPUT_INVALID", Message: "The authentication input is invalid."}
	case errors.Is(err, adminauth.ErrPasswordPolicy):
		status, p = http.StatusBadRequest, Problem{Kind: "invalid_request", Code: "PASSWORD_POLICY", Message: "Use 12 to 72 password bytes and matching confirmation."}
	case errors.Is(err, adminauth.ErrConflict):
		status, p = http.StatusConflict, Problem{Kind: "conflict", Code: "CREDENTIALS_CHANGED", Message: "Credentials changed concurrently; sign in again."}
	case errors.Is(err, adminauth.ErrOutcomeUnknown):
		status, p = http.StatusServiceUnavailable, Problem{Kind: "persistence", Code: "AUTH_COMMIT_UNKNOWN", Message: "The change could not be confirmed. Check the current session or sign in explicitly.", Outcome: Unknown}
	}
	WriteProblem(w, status, meta, p)
}

func requestMeta(w http.ResponseWriter) (Meta, bool) {
	id, err := RequestID()
	if err != nil {
		WriteProblem(w, http.StatusInternalServerError, Meta{}, internalProblem())
		return Meta{}, false
	}
	w.Header().Set("X-Request-ID", id)
	return Meta{RequestID: id}, true
}

func (a *ManagementAuth) sameOrigin(r *http.Request, required bool) bool {
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return false
	}
	values := r.Header.Values("Origin")
	if len(values) == 0 {
		return !required
	}
	if len(values) != 1 {
		return false
	}
	origin, err := url.Parse(values[0])
	if err != nil || origin.Opaque != "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return false
	}
	peer := a.requestSource(r)
	if a.secure {
		peer.scheme = "https"
	}
	return origin.Scheme == peer.scheme && strings.EqualFold(origin.Host, peer.host) && origin.Host != ""
}

func unsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func originProblem() Problem {
	return Problem{Kind: "authorization", Code: "ORIGIN_REJECTED", Message: "Use the installed management site for this request."}
}

func cookieValue(r *http.Request, name string) string {
	cookies := r.CookiesNamed(name)
	if len(cookies) != 1 {
		return ""
	}
	return cookies[0].Value
}

func (a *ManagementAuth) setCookie(w http.ResponseWriter, r *http.Request, name, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: a.basePath, Expires: expires,
		HttpOnly: true, Secure: a.cookieSecure(r), SameSite: http.SameSiteStrictMode,
	})
}

func (a *ManagementAuth) clearCookies(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{sessionCookie, csrfCookie} {
		http.SetCookie(w, &http.Cookie{Name: name, Path: a.basePath, MaxAge: -1, HttpOnly: true, Secure: a.cookieSecure(r), SameSite: http.SameSiteStrictMode})
	}
}

type loginClient struct {
	tokens float64
	seen   time.Time
}

// One bounded process-local limiter protects password hashing. It is not a
// public mailbox quota, nor a substitute for the stored session epoch.
type loginAdmission struct {
	mu      sync.Mutex
	clients map[string]loginClient
	active  int
}

func newLoginAdmission() *loginAdmission {
	return &loginAdmission{clients: make(map[string]loginClient)}
}

func (l *loginAdmission) enter(client string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active >= 4 {
		return false
	}
	state, found := l.clients[client]
	if !found {
		if len(l.clients) >= 1024 {
			// Refuse new identities while all tracked identities are recent.
			// This bounds memory without evicting active throttling records.
			for key, candidate := range l.clients {
				if now.Sub(candidate.seen) >= 5*time.Minute {
					delete(l.clients, key)
				}
			}
			if len(l.clients) >= 1024 {
				return false
			}
		}
		state = loginClient{tokens: 5, seen: now}
	}
	state.tokens = min(5, state.tokens+max(0, now.Sub(state.seen).Seconds())/15)
	state.seen = now
	if state.tokens < 1 {
		l.clients[client] = state
		return false
	}
	state.tokens--
	l.clients[client] = state
	l.active++
	return true
}

func (l *loginAdmission) leave() {
	l.mu.Lock()
	l.active--
	l.mu.Unlock()
}
