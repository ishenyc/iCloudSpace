package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"icloudspace/internal/addresses"
	"icloudspace/internal/provider/apple"
	"icloudspace/internal/providersession"
	"icloudspace/internal/sourceguard"
)

// ManagementHME binds the browser session, source gate and address lifecycle.
// The provider factory is lazy: the domain borrows the held gate for every
// provider call. Creation/deletion recovery is an explicit, read-only query of
// the original operation; neither endpoint retries an upstream mutation.
type ManagementHME struct {
	identity  *ManagementAuth
	addresses *addresses.Service
	guards    *sourceguard.Registry
	provider  func(int64) addresses.Provider
}

func NewManagementHME(identity *ManagementAuth, owner *addresses.Service, guards *sourceguard.Registry, provider func(int64) addresses.Provider) (*ManagementHME, error) {
	if identity == nil || owner == nil || guards == nil || provider == nil {
		return nil, errors.New("httpapi: management identity, address owner, source registry and provider factory are required")
	}
	return &ManagementHME{identity, owner, guards, provider}, nil
}

func (a *ManagementHME) Register(mux *http.ServeMux) {
	base := a.identity.basePath + "/accounts/{source_id}/hme"
	for pattern, handler := range map[string]http.HandlerFunc{
		"POST " + base + "/creations":                             a.create,
		"POST " + base + "/creations/query":                       a.queryCreate,
		"POST " + base + "/directory/reconcile":                   a.reconcile,
		"POST " + base + "/addresses/{address_id}/deletion":       a.delete,
		"POST " + base + "/addresses/{address_id}/deletion/query": a.queryDelete,
	} {
		mux.Handle(pattern, a.identity.RequireSession(handler))
	}
}

func (a *ManagementHME) enter(w http.ResponseWriter, r *http.Request) (*http.Request, int64, func(), bool) {
	id, ok := accountID(w, r)
	if !ok {
		return r, 0, nil, false
	}
	gate, err := a.guards.Acquire(r.Context(), id)
	if err != nil {
		writeAddressError(w, r, err, nil)
		return r, 0, nil, false
	}
	if _, err := a.identity.identity.Authenticate(r.Context(), cookieValue(r, sessionCookie)); err != nil {
		gate.Close()
		a.identity.writeAuthError(w, currentMeta(w), err)
		return r, 0, nil, false
	}
	return r.WithContext(sourceguard.WithLease(r.Context(), gate)), id, func() { gate.Close() }, true
}

type providerFailureView struct {
	Kind              string `json:"kind"`
	Code              string `json:"code"`
	HTTPStatus        int    `json:"http_status"`
	Unknown           bool   `json:"unknown"`
	RetryAfterSeconds int64  `json:"retry_after_seconds"`
}
type hmeOperationView struct {
	Operation        addressOperationView `json:"operation"`
	CandidateAddress *string              `json:"candidate_address"`
	Warning          *Problem             `json:"warning"`
	ProviderFailure  *providerFailureView `json:"provider_failure"`
}

func (a *ManagementHME) result(w http.ResponseWriter, r *http.Request, op addresses.Operation, err error) {
	if op.Key == "" {
		if err == nil {
			err = addresses.ErrConflict
		}
		writeAddressError(w, r, err, nil)
		return
	}
	view := hmeOperationView{Operation: presentAddressOperation(op), CandidateAddress: op.CandidateAddress}
	if err != nil || op.State == "failed" || op.ErrorCode == "forwarding_initialization_unknown" {
		view.Warning = &Problem{Kind: "provider", Code: "HME_OPERATION_UNSETTLED", Message: "The original operation remains recorded. Query it before making another change.", Outcome: Unknown, SubmissionKey: op.Key, Resource: addressReference(valueID(op.AddressID))}
		if op.State == "failed" {
			view.Warning.Code = "HME_OPERATION_REJECTED"
			view.Warning.Message = "The provider explicitly rejected this operation. Its original result remains recorded."
			view.Warning.Outcome = Rejected
		}
		if op.State == "failed" {
			switch op.ErrorCode {
			case "forwarding_target_unverified", "forwarding_preflight_failed", "source_changed":
				view.Warning.Code = "HME_CREATION_NOT_STARTED"
				view.Warning.Message = "Creation stopped before any address generation or reservation. Check the forwarding destination and source state."
				view.Warning.Outcome = NotSent
			case "forwarding_initialized_retry_explicit":
				view.Warning.Code = "HME_FORWARDING_INITIALIZED"
				view.Warning.Message = "Forwarding initialization is confirmed. No address was generated; a new explicit creation request is required."
				view.Warning.Outcome = NotSent
			}
			if view.Warning.Outcome == NotSent {
				switch {
				case errors.Is(err, providersession.ErrLoginRequired):
					view.Warning.Code = "HME_LOGIN_REQUIRED"
					view.Warning.Message = "Authenticate the provider before making a new explicit creation request."
				case errors.Is(err, providersession.ErrReadOnly), errors.Is(err, addresses.ErrReadOnly):
					view.Warning.Code = "INSTALLATION_READ_ONLY"
					view.Warning.Message = "The installation is currently read-only. No address creation was attempted."
				}
			}
		}
		var remote *apple.Error
		if errors.As(err, &remote) {
			wait := int64(0)
			if remote.RetryAfter > 0 {
				wait = int64((remote.RetryAfter + time.Second - 1) / time.Second)
			}
			view.ProviderFailure = &providerFailureView{string(remote.Kind), remote.Code, remote.Status, remote.Unknown, wait}
		}
	}
	status := http.StatusAccepted
	if op.State == "failed" || err == nil && op.State == "confirmed" {
		status = http.StatusOK
	}
	WriteResult(w, status, currentMeta(w), view)
}

func valueID(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

func (a *ManagementHME) create(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Key      string  `json:"operation_key"`
		Revision string  `json:"expected_revision"`
		Label    string  `json:"label"`
		GroupID  *string `json:"group_id"`
		Profile  string  `json:"credential_profile"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	revision, valid := positiveDecimal(input.Revision)
	group, err := optionalID(input.GroupID)
	if !valid || err != nil {
		writeAddressError(w, r, addresses.ErrInvalid, nil)
		return
	}
	r, id, close, ok := a.enter(w, r)
	if !ok {
		return
	}
	defer close()
	op, err := a.addresses.CreateHME(r.Context(), addresses.HMECreateInput{SourceID: id, RequestKey: input.Key, ExpectedRevision: revision, Label: input.Label, GroupID: group, OwnerKey: managementOwner(r), CredentialProfile: input.Profile}, a.provider(id))
	a.result(w, r, op, err)
}

func (a *ManagementHME) queryCreate(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Key string `json:"operation_key"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	r, id, close, ok := a.enter(w, r)
	if !ok {
		return
	}
	defer close()
	op, err := a.addresses.QueryCreate(r.Context(), id, input.Key, managementOwner(r), a.provider(id))
	a.result(w, r, op, err)
}

func (a *ManagementHME) target(w http.ResponseWriter, r *http.Request, source int64) (int64, bool) {
	id, ok := pathID(w, r, "address_id")
	if !ok {
		return 0, false
	}
	item, err := a.addresses.Get(r.Context(), id)
	if err == nil && item.SourceID != source {
		err = addresses.ErrNotFound
	}
	if err != nil {
		writeAddressError(w, r, err, addressReference(id))
		return 0, false
	}
	return id, true
}

func (a *ManagementHME) delete(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Key      string `json:"operation_key"`
		Revision string `json:"expected_revision"`
		Confirm  string `json:"confirm_address"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	revision, valid := positiveDecimal(input.Revision)
	if !valid {
		writeAddressError(w, r, addresses.ErrInvalid, nil)
		return
	}
	r, source, close, ok := a.enter(w, r)
	if !ok {
		return
	}
	defer close()
	id, ok := a.target(w, r, source)
	if !ok {
		return
	}
	op, err := a.addresses.DeleteHME(r.Context(), addresses.HMEDeleteInput{AddressID: id, RequestKey: input.Key, ExpectedRevision: revision, ConfirmAddress: input.Confirm, OwnerKey: managementOwner(r)}, a.provider(source))
	a.result(w, r, op, err)
}

func (a *ManagementHME) queryDelete(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Key string `json:"operation_key"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	r, source, close, ok := a.enter(w, r)
	if !ok {
		return
	}
	defer close()
	// The retained operation remains queryable after an explicit local purge.
	// QueryDelete binds its immutable source/address/owner before any provider
	// call; the borrowed source gate rejects a mismatched path source.
	id, ok := pathID(w, r, "address_id")
	if !ok {
		return
	}
	op, err := a.addresses.QueryDelete(r.Context(), id, input.Key, managementOwner(r), a.provider(source))
	if op.SourceID > 0 && op.SourceID != source {
		writeAddressError(w, r, addresses.ErrNotFound, addressReference(id))
		return
	}
	a.result(w, r, op, err)
}

func (a *ManagementHME) reconcile(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Revision string `json:"expected_revision"`
		Profile  string `json:"credential_profile"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	revision, valid := positiveDecimal(input.Revision)
	if !valid || input.Profile != "api_key_only" && input.Profile != "mailbox" {
		writeAddressError(w, r, addresses.ErrInvalid, nil)
		return
	}
	r, source, close, ok := a.enter(w, r)
	if !ok {
		return
	}
	defer close()
	provider := a.provider(source)
	if provider == nil {
		writeDirectoryReadError(w, r, addresses.ErrProvider)
		return
	}
	directory, err := provider.Directory(r.Context())
	if err != nil {
		writeDirectoryReadError(w, r, err)
		return
	}
	result, err := a.addresses.ReconcileDirectory(r.Context(), source, revision, directory, managementOwner(r), input.Profile)
	if err != nil {
		if errors.Is(err, addresses.ErrDirectory) && !errors.Is(err, addresses.ErrCommitUnknown) {
			writeDirectoryReadError(w, r, err)
			return
		}
		writeAddressError(w, r, err, nil)
		return
	}
	WriteResult(w, 200, currentMeta(w), struct {
		Imported       int `json:"imported"`
		Existing       int `json:"existing"`
		Archived       int `json:"archived"`
		Rediscovered   int `json:"rediscovered"`
		Active         int `json:"active"`
		Inactive       int `json:"inactive"`
		SkippedForward int `json:"skipped_forward"`
		Conflicts      int `json:"conflicts"`
		Pending        int `json:"pending"`
	}{result.Imported, result.Existing, result.Archived, result.Rediscovered, result.Active, result.Inactive, result.SkippedForward, result.Conflicts, result.Pending})
}

// This endpoint has not submitted a directory import when its provider read
// fails. Uncertain database commits use the separate address error path.
func writeDirectoryReadError(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusBadGateway
	problem := Problem{Kind: "provider", Code: "HME_DIRECTORY_READ_FAILED", Message: "The Apple directory could not be read. No addresses were reconciled.", Outcome: NotSent}
	var remote *apple.Error
	var persist *providersession.PersistenceError
	errors.As(err, &remote)
	switch {
	case errors.As(err, &persist):
		status, problem.Code, problem.Message = http.StatusServiceUnavailable, "HME_DIRECTORY_SESSION_CHECKPOINT", "The provider session checkpoint could not be confirmed. No addresses were reconciled."
	case errors.Is(err, providersession.ErrLoginRequired) || remote != nil && (remote.Kind == apple.AuthenticationRequired || remote.Kind == apple.SecondFactorRequired):
		status, problem.Code, problem.Message = http.StatusConflict, "HME_LOGIN_REQUIRED", "Sign in to Apple to read the directory."
	case errors.Is(err, context.DeadlineExceeded) || remote != nil && remote.Kind == apple.Timeout:
		status, problem.Code, problem.Message = http.StatusGatewayTimeout, "HME_DIRECTORY_READ_TIMEOUT", "The Apple directory read timed out before reconciliation."
	case remote != nil && remote.Kind == apple.RateLimited:
		status, problem.Code, problem.Message = http.StatusTooManyRequests, "HME_DIRECTORY_RATE_LIMITED", "Apple rate-limited the directory read before reconciliation."
	case errors.Is(err, addresses.ErrDirectory) || remote != nil && (remote.Kind == apple.ResponseBudget || remote.Kind == apple.MalformedResponse):
		problem.Code, problem.Message = "DIRECTORY_INCOMPLETE", "The returned Apple directory could not be verified. No addresses were reconciled."
	}
	WriteProblem(w, status, currentMeta(w), problem)
}
