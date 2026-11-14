package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"icloudspace/internal/addressauth"
	"icloudspace/internal/adminauth"
	"icloudspace/internal/localcleanup"
)

// LocalCleanupAuthorization verifies the same session/operator/CSRF inside
// the owner's transaction after SourceGuard and Authority EX have been waited.
// It must neither open another pool connection nor commit this transaction.
type LocalCleanupAuthorization interface {
	VerifyLocalMutationTx(context.Context, *sql.Tx, string, string, int64) error
}
type ManagementLocalCleanup struct {
	identity  *ManagementAuth
	owner     *localcleanup.Service
	authorize LocalCleanupAuthorization
}

func NewManagementLocalCleanup(identity *ManagementAuth, owner *localcleanup.Service, authorize LocalCleanupAuthorization) (*ManagementLocalCleanup, error) {
	if identity == nil || owner == nil || authorize == nil {
		return nil, errors.New("httpapi: cleanup owner and same-transaction authorization are required")
	}
	return &ManagementLocalCleanup{identity: identity, owner: owner, authorize: authorize}, nil
}
func (a *ManagementLocalCleanup) Register(mux *http.ServeMux) {
	for pattern, handler := range map[string]http.HandlerFunc{
		"POST " + a.identity.basePath + "/accounts/{source_id}/retirements":          a.retire,
		"POST " + a.identity.basePath + "/addresses/{address_id}/local-purges":       a.purge,
		"POST " + a.identity.basePath + "/accounts/{source_id}/local-cleanups/query": a.query,
	} {
		mux.Handle(pattern, a.identity.RequireSession(handler))
	}
}

type localCleanupInput struct {
	OperationKey     string `json:"operation_key"`
	ExpectedRevision string `json:"expected_revision"`
	Confirmation     string `json:"confirmation"`
}
type localCleanupCounts struct {
	Objects              string `json:"objects"`
	Pending              string `json:"pending"`
	Collected            string `json:"collected"`
	Absent               string `json:"absent"`
	Shared               string `json:"shared"`
	Protected            string `json:"protected"`
	NeedsReview          string `json:"needs_review"`
	Unacknowledged       string `json:"unacknowledged"`
	UnresolvedOperations string `json:"unresolved_operations"`
}
type localCleanupView struct {
	OperationKey      string             `json:"operation_key"`
	Kind              string             `json:"kind"`
	SourceID          string             `json:"source_id"`
	AddressID         *string            `json:"address_id"`
	State             string             `json:"state"`
	QueryOnly         bool               `json:"query_only"`
	PayloadScrubbed   bool               `json:"payload_scrubbed"`
	InventoryComplete bool               `json:"inventory_complete"`
	LastErrorCode     string             `json:"last_error_code"`
	Counts            localCleanupCounts `json:"counts"`
}

func cleanupKey(key string) bool {
	if key == "" || len(key) > 128 {
		return false
	}
	for _, c := range key {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func cleanupCommand(input localCleanupInput) (int64, bool) {
	revision, ok := positiveDecimal(input.ExpectedRevision)
	return revision, ok && cleanupKey(input.OperationKey) && input.Confirmation != "" && len(input.Confirmation) <= 1024 && !strings.ContainsAny(input.Confirmation, "\r\n\x00")
}
func (a *ManagementLocalCleanup) fresh(r *http.Request) (localcleanup.FreshAuthorization, bool) {
	session, ok := AuthenticatedSession(r.Context())
	if !ok || session.Operator.ID < 1 {
		return nil, false
	}
	raw, csrf, operator := cookieValue(r, sessionCookie), r.Header.Get("X-CSRF-Token"), session.Operator.ID
	return func(ctx context.Context, tx *sql.Tx) error {
		return a.authorize.VerifyLocalMutationTx(ctx, tx, raw, csrf, operator)
	}, true
}
func (a *ManagementLocalCleanup) retire(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "source_id")
	if !ok {
		return
	}
	resource := &ResourceRef{Kind: "account", ID: decimal(id)}
	var input localCleanupInput
	if p := DecodeJSON(w, r, &input, 4096); p != nil {
		p.Outcome = NotSent
		p.Resource = resource
		WriteProblem(w, 400, currentMeta(w), *p)
		return
	}
	revision, ok := cleanupCommand(input)
	if !ok {
		a.fail(w, r, localcleanup.ErrInvalid, input.OperationKey, resource)
		return
	}
	fresh, ok := a.fresh(r)
	if !ok {
		a.identity.writeAuthError(w, currentMeta(w), adminauth.ErrUnauthenticated)
		return
	}
	result, e := a.owner.DeleteSource(r.Context(), localcleanup.SourceDeleteRequest{OperationKey: input.OperationKey, OwnerKey: managementOwner(r), SourceID: id, ExpectedRevision: revision, ConfirmNamespace: input.Confirmation}, fresh)
	if e != nil {
		a.fail(w, r, e, input.OperationKey, resource)
		return
	}
	a.write(w, r, result, resource)
}
func (a *ManagementLocalCleanup) purge(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "address_id")
	if !ok {
		return
	}
	resource := addressReference(id)
	var input struct {
		SourceID         string `json:"source_id"`
		OperationKey     string `json:"operation_key"`
		ExpectedRevision string `json:"expected_revision"`
		Confirmation     string `json:"confirmation"`
	}
	if p := DecodeJSON(w, r, &input, 4096); p != nil {
		p.Outcome = NotSent
		p.Resource = resource
		WriteProblem(w, 400, currentMeta(w), *p)
		return
	}
	revision, valid := cleanupCommand(localCleanupInput{OperationKey: input.OperationKey, ExpectedRevision: input.ExpectedRevision, Confirmation: input.Confirmation})
	source, sourceOK := positiveDecimal(input.SourceID)
	if !valid || !sourceOK {
		a.fail(w, r, localcleanup.ErrInvalid, input.OperationKey, resource)
		return
	}
	fresh, ok := a.fresh(r)
	if !ok {
		a.identity.writeAuthError(w, currentMeta(w), adminauth.ErrUnauthenticated)
		return
	}
	result, e := a.owner.PurgeAddress(r.Context(), localcleanup.AddressPurgeRequest{OperationKey: input.OperationKey, OwnerKey: managementOwner(r), AddressID: id, ExpectedSourceID: source, ExpectedRevision: revision, ConfirmAddress: input.Confirmation}, fresh)
	if e != nil {
		a.fail(w, r, e, input.OperationKey, resource)
		return
	}
	a.write(w, r, result, resource)
}
func (a *ManagementLocalCleanup) query(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "source_id")
	if !ok {
		return
	}
	resource := &ResourceRef{Kind: "account", ID: decimal(id)}
	var input struct {
		OperationKey string `json:"operation_key"`
	}
	if p := DecodeJSON(w, r, &input, 1024); p != nil {
		p.Outcome = NotSent
		p.Resource = resource
		WriteProblem(w, 400, currentMeta(w), *p)
		return
	}
	if !cleanupKey(input.OperationKey) {
		a.fail(w, r, localcleanup.ErrInvalid, input.OperationKey, resource)
		return
	}
	result, e := a.owner.Query(r.Context(), id, input.OperationKey, managementOwner(r))
	// Query has returned and released its transaction before this ordinary
	// pool read; it cannot self-deadlock even with MaxOpenConns=1. No mutation
	// is authorized by this read, and expired sessions receive no late receipt.
	current, authErr := a.identity.identity.Authenticate(r.Context(), cookieValue(r, sessionCookie))
	original, verified := AuthenticatedSession(r.Context())
	if authErr != nil || !verified || current.Operator.ID != original.Operator.ID {
		if authErr == nil {
			authErr = adminauth.ErrUnauthenticated
		}
		a.identity.writeAuthError(w, currentMeta(w), authErr)
		return
	}
	if !a.identity.identity.ValidateCSRF(current, r.Header.Get("X-CSRF-Token")) {
		WriteProblem(w, 403, currentMeta(w), Problem{Kind: "authorization", Code: "CSRF_INVALID", Message: "Refresh the management session before querying cleanup."})
		return
	}
	if e != nil {
		a.fail(w, r, e, input.OperationKey, resource)
		return
	}
	a.write(w, r, result, resource)
}
func (a *ManagementLocalCleanup) write(w http.ResponseWriter, r *http.Request, receipt localcleanup.Receipt, resource *ResourceRef) {
	pending := receipt.Objects
	for _, count := range []int64{receipt.Collected, receipt.Absent, receipt.Shared, receipt.Protected, receipt.NeedsReview} {
		if count < 0 || count > pending {
			a.fail(w, r, localcleanup.ErrUnknown, receipt.OperationKey, resource)
			return
		}
		pending -= count
	}
	if receipt.SourceID < 1 || receipt.Objects < 0 || receipt.Unacknowledged < 0 || receipt.UnresolvedOperations < 0 || !cleanupKey(receipt.OperationKey) || !(receipt.Kind == "source_delete" && receipt.AddressID == nil || receipt.Kind == "address_purge" && receipt.AddressID != nil && *receipt.AddressID > 0) {
		a.fail(w, r, localcleanup.ErrUnknown, receipt.OperationKey, resource)
		return
	}
	if receipt.State != "retired" && receipt.State != "cleaning" && receipt.State != "blocked" && receipt.State != "complete" {
		a.fail(w, r, localcleanup.ErrUnknown, receipt.OperationKey, resource)
		return
	}
	if receipt.State == "complete" && (!receipt.PayloadScrubbed || !receipt.InventoryComplete || pending != 0 || receipt.Protected != 0 || receipt.NeedsReview != 0) {
		a.fail(w, r, localcleanup.ErrUnknown, receipt.OperationKey, resource)
		return
	}
	var address *string
	if receipt.AddressID != nil {
		value := decimal(*receipt.AddressID)
		address = &value
	}
	WriteResult(w, 200, currentMeta(w), localCleanupView{OperationKey: receipt.OperationKey, Kind: receipt.Kind, SourceID: decimal(receipt.SourceID), AddressID: address, State: receipt.State, QueryOnly: true, PayloadScrubbed: receipt.PayloadScrubbed, InventoryComplete: receipt.InventoryComplete, LastErrorCode: receipt.LastErrorCode, Counts: localCleanupCounts{Objects: decimal(receipt.Objects), Pending: decimal(pending), Collected: decimal(receipt.Collected), Absent: decimal(receipt.Absent), Shared: decimal(receipt.Shared), Protected: decimal(receipt.Protected), NeedsReview: decimal(receipt.NeedsReview), Unacknowledged: decimal(receipt.Unacknowledged), UnresolvedOperations: decimal(receipt.UnresolvedOperations)}})
}
func (a *ManagementLocalCleanup) fail(w http.ResponseWriter, r *http.Request, e error, key string, resource *ResourceRef) {
	if errors.Is(e, adminauth.ErrUnauthenticated) || errors.Is(e, adminauth.ErrInvalidCredentials) || errors.Is(e, adminauth.ErrInvalidInput) || errors.Is(e, adminauth.ErrConflict) {
		a.identity.writeAuthError(w, currentMeta(w), e)
		return
	}
	status, p := 500, Problem{Kind: "persistence", Code: "LOCAL_CLEANUP_UNCONFIRMED", Message: "Query the original cleanup operation before another command.", Outcome: Unknown, Resource: resource}
	switch {
	case errors.Is(e, localcleanup.ErrInvalid):
		status, p = 400, Problem{Kind: "invalid_request", Code: "LOCAL_CLEANUP_INPUT_INVALID", Message: "Check the exact identity, revision, operation key and confirmation.", Outcome: NotSent, Resource: resource}
	case errors.Is(e, localcleanup.ErrConflict):
		status, p = 409, Problem{Kind: "conflict", Code: "LOCAL_CLEANUP_CONFLICT", Message: "The scope or original request differs. Refresh metadata and query the original operation.", Outcome: NotSent, Resource: resource}
	case errors.Is(e, localcleanup.ErrNotFound):
		status, p = 404, Problem{Kind: "not_found", Code: "LOCAL_CLEANUP_NOT_FOUND", Message: "No matching committed cleanup operation or identity was found.", Outcome: NotSent, Resource: resource}
	case errors.Is(e, localcleanup.ErrReadOnly):
		status, p = 503, Problem{Kind: "maintenance", Code: "INSTALLATION_READ_ONLY", Message: "The installation is read-only.", Outcome: NotSent, Resource: resource}
	case errors.Is(e, localcleanup.ErrUnknown), errors.Is(e, addressauth.ErrOutcomeUnknown):
		status, p = 503, Problem{Kind: "persistence", Code: "LOCAL_CLEANUP_COMMIT_UNKNOWN", Message: "Query this original operation key; do not repeat retirement or purge.", Outcome: Unknown, Resource: resource}
	}
	if cleanupKey(key) {
		p.SubmissionKey = key
	}
	WriteProblem(w, status, currentMeta(w), p)
}
