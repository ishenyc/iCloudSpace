package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"icloudspace/internal/addressauth"
	"icloudspace/internal/adminauth"
)

type RotationAuthorization interface {
	RevokeForCredentialRotation(context.Context, *sql.Tx, string, string) error
}

type ManagementCredentials struct {
	identity  *ManagementAuth
	authority *addressauth.Authority
	authorize RotationAuthorization
}

func NewManagementCredentials(identity *ManagementAuth, authority *addressauth.Authority, authorize RotationAuthorization) (*ManagementCredentials, error) {
	if identity == nil || authority == nil || authorize == nil {
		return nil, errors.New("httpapi: credential authority and fresh rotation authorization are required")
	}
	return &ManagementCredentials{identity, authority, authorize}, nil
}
func (a *ManagementCredentials) Register(mux *http.ServeMux) {
	base := a.identity.basePath
	local := map[string]bool{
		"POST " + base + "/addresses/{address_id}/credential-rotations":                                true,
		"POST " + base + "/accounts/{source_id}/credential-deliveries/{delivery_key}/complete-mailbox": true,
		"DELETE " + base + "/accounts/{source_id}/credential-deliveries":                               true,
		"POST " + base + "/credential-rotations/{operation_key}/cancel":                                true,
	}
	for pattern, handler := range map[string]http.HandlerFunc{
		"POST " + base + "/addresses/{address_id}/credential-bundle/reveal":                            a.reveal,
		"POST " + base + "/addresses/{address_id}/api-key/reveal":                                      a.revealAPIKey,
		"GET " + base + "/addresses/{address_id}/credential-scope":                                     a.addressScope,
		"POST " + base + "/addresses/{address_id}/credential-rotations":                                a.rotateOne,
		"GET " + base + "/credential-rotation-scope":                                                   a.scope,
		"POST " + base + "/credential-rotations":                                                       a.rotateAll,
		"GET " + base + "/credential-rotations/{operation_key}":                                        a.queryRotation,
		"POST " + base + "/credential-rotations/{operation_key}/cancel":                                a.cancelRotation,
		"GET " + base + "/accounts/{source_id}/credential-deliveries":                                  a.pending,
		"GET " + base + "/accounts/{source_id}/credential-deliveries/{delivery_key}":                   a.delivery,
		"POST " + base + "/accounts/{source_id}/credential-deliveries/{delivery_key}/reveal":           a.revealPending,
		"POST " + base + "/accounts/{source_id}/credential-deliveries/{delivery_key}/reveal-bundle":    a.revealPendingBundle,
		"POST " + base + "/accounts/{source_id}/credential-deliveries/{delivery_key}/complete-mailbox": a.completePending,
		"DELETE " + base + "/accounts/{source_id}/credential-deliveries":                               a.acknowledge,
	} {
		if local[pattern] {
			mux.Handle(pattern, a.identity.RequireLocalCommand(handler))
		} else {
			mux.Handle(pattern, a.identity.RequireSession(handler))
		}
	}
}

func (a *ManagementCredentials) fail(w http.ResponseWriter, r *http.Request, err error, key string) {
	if errors.Is(err, adminauth.ErrInvalidCredentials) || errors.Is(err, adminauth.ErrUnauthenticated) || errors.Is(err, adminauth.ErrInvalidInput) || errors.Is(err, adminauth.ErrConflict) {
		a.identity.writeAuthError(w, currentMeta(w), err)
		return
	}
	status, problem := 500, internalProblem()
	switch {
	case errors.Is(err, addressauth.ErrInvalid):
		status, problem = 400, Problem{Kind: "invalid_request", Code: "CREDENTIAL_INPUT_INVALID", Message: "Check the credential command and explicit confirmation.", Outcome: NotSent}
	case errors.Is(err, addressauth.ErrConflict):
		status, problem = 409, Problem{Kind: "conflict", Code: "CREDENTIAL_SCOPE_CHANGED", Message: "Refresh the credential scope before another change.", Outcome: NotSent}
	case errors.Is(err, addressauth.ErrUnavailable), errors.Is(err, sql.ErrNoRows):
		status, problem = 404, Problem{Kind: "not_found", Code: "CREDENTIAL_MATERIAL_UNAVAILABLE", Message: "The requested credential material is unavailable.", Outcome: NotSent}
	case errors.Is(err, addressauth.ErrReadOnly):
		status, problem = 503, Problem{Kind: "maintenance", Code: "INSTALLATION_READ_ONLY", Message: "The installation is currently read-only.", Outcome: NotSent}
	case errors.Is(err, addressauth.ErrOutcomeUnknown):
		status, problem = 503, Problem{Kind: "persistence", Code: "CREDENTIAL_COMMIT_UNKNOWN", Message: "Query the original operation or delivery; do not repeat the command.", Outcome: Unknown, SubmissionKey: key}
	}
	WriteProblem(w, status, currentMeta(w), problem)
}

func (a *ManagementCredentials) reveal(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "address_id")
	if !ok {
		return
	}
	var empty struct{}
	if !addressBody(w, r, &empty) {
		return
	}
	scope, err := a.authority.BeginReveal(r.Context())
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	defer scope.Close()
	if _, err = a.identity.identity.Authenticate(r.Context(), cookieValue(r, sessionCookie)); err != nil {
		a.identity.writeAuthError(w, currentMeta(w), err)
		return
	}
	bundle, err := scope.Bundle(r.Context(), id)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	WriteResult(w, 200, currentMeta(w), struct {
		AddressID string             `json:"address_id"`
		Bundle    addressauth.Bundle `json:"bundle"`
	}{decimal(id), bundle})
}

func (a *ManagementCredentials) revealAPIKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "address_id")
	if !ok {
		return
	}
	var input struct{}
	if !addressBody(w, r, &input) {
		return
	}
	scope, err := a.authority.BeginReveal(r.Context())
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	defer scope.Close()
	// A queued credential writer can hold this gate past the browser session's
	// expiry. Verify the current cookie after admission before reading secrets.
	if _, err = a.identity.identity.Authenticate(r.Context(), cookieValue(r, sessionCookie)); err != nil {
		a.identity.writeAuthError(w, currentMeta(w), err)
		return
	}
	material, err := scope.APIKey(r.Context(), id)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	WriteResult(w, 200, currentMeta(w), struct {
		AddressID string                     `json:"address_id"`
		API       addressauth.APIKeyMaterial `json:"api"`
	}{decimal(id), material})
}

func writeCredentialScope(w http.ResponseWriter, r *http.Request, state addressauth.ScopeState) {
	WriteResult(w, 200, currentMeta(w), struct {
		Digest        string `json:"digest"`
		AddressCount  string `json:"address_count"`
		EligibleCount string `json:"eligible_count"`
	}{state.Digest, decimal(int64(state.AddressCount)), decimal(int64(state.EligibleCount))})
}
func (a *ManagementCredentials) addressScope(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "address_id")
	if !ok {
		return
	}
	state, err := a.authority.AddressScope(r.Context(), id)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	writeCredentialScope(w, r, state)
}
func (a *ManagementCredentials) scope(w http.ResponseWriter, r *http.Request) {
	state, err := a.authority.Scope(r.Context())
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	writeCredentialScope(w, r, state)
}

type rotationView struct {
	Key         string             `json:"operation_key"`
	Kind        string             `json:"kind"`
	State       string             `json:"state"`
	ScopeDigest string             `json:"scope_digest"`
	Items       []rotationItemView `json:"items"`
}
type rotationItemView struct {
	SourceID            string `json:"source_id"`
	AddressID           string `json:"address_id"`
	PreviousGeneration  string `json:"previous_generation"`
	Generation          string `json:"generation"`
	DeliveryKey         string `json:"delivery_key"`
	PreviousUIDValidity string `json:"previous_uid_validity"`
	UIDValidity         string `json:"uid_validity"`
	Upgraded            bool   `json:"upgraded"`
}

func presentRotation(result addressauth.RotationResult) rotationView {
	view := rotationView{Key: result.OperationKey, Kind: result.Kind, State: result.State, ScopeDigest: result.ScopeDigest, Items: []rotationItemView{}}
	for _, item := range result.Items {
		view.Items = append(view.Items, rotationItemView{decimal(item.SourceID), decimal(item.AddressID), decimal(item.PreviousGeneration), decimal(item.Generation), item.DeliveryKey, decimal(item.PreviousUIDValidity), decimal(item.UIDValidity), item.Upgraded})
	}
	return view
}
func (a *ManagementCredentials) rotateOne(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "address_id")
	if !ok {
		return
	}
	var input struct {
		Kind                string `json:"kind"`
		OperationKey        string `json:"operation_key"`
		ExpectedGeneration  string `json:"expected_generation"`
		ExpectedScopeDigest string `json:"expected_scope_digest"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	generation, ok := positiveDecimal(input.ExpectedGeneration)
	if !ok || input.Kind != "api_key" && input.Kind != "bundle" {
		a.fail(w, r, addressauth.ErrInvalid, "")
		return
	}
	command := addressauth.RotationRequest{OperationKey: input.OperationKey, OwnerKey: managementOwner(r), AddressID: id, ExpectedGeneration: generation, ExpectedScopeDigest: input.ExpectedScopeDigest}
	var result addressauth.RotationResult
	var err error
	if input.Kind == "api_key" {
		result, err = a.authority.RotateKey(r.Context(), command)
	} else {
		result, err = a.authority.RotateBundle(r.Context(), command)
	}
	if err != nil {
		a.fail(w, r, err, input.OperationKey)
		return
	}
	WriteResult(w, 200, currentMeta(w), presentRotation(result))
}
func (a *ManagementCredentials) rotateAll(w http.ResponseWriter, r *http.Request) {
	var input struct {
		OperationKey        string `json:"operation_key"`
		ExpectedScopeDigest string `json:"expected_scope_digest"`
		Confirmation        string `json:"confirmation"`
		CurrentPassword     string `json:"current_password"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	if input.Confirmation != "rotate-all-address-credentials" || input.CurrentPassword == "" {
		a.fail(w, r, addressauth.ErrInvalid, "")
		return
	}
	if !a.identity.login.enter(a.identity.clientAddress(r), time.Now()) {
		w.Header().Set("Retry-After", "15")
		WriteProblem(w, 429, currentMeta(w), Problem{Kind: "rate_limit", Code: "CREDENTIAL_ROTATION_THROTTLED", Message: "Wait before another credential rotation.", Outcome: NotSent})
		return
	}
	defer a.identity.login.leave()
	session, _ := AuthenticatedSession(r.Context())
	result, err := a.authority.RotateAll(r.Context(), addressauth.RotationRequest{OperationKey: input.OperationKey, OwnerKey: managementOwner(r), ExpectedScopeDigest: input.ExpectedScopeDigest}, func(ctx context.Context, tx *sql.Tx) error {
		if err := a.authorize.RevokeForCredentialRotation(ctx, tx, cookieValue(r, sessionCookie), input.CurrentPassword); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO space.audit_records(occurred_at,actor_kind,actor_ref,actor_display,action,resource_kind,resource_ref,outcome,correlation_key,origin,detail) VALUES(space.clock_ns(),'operator',$1,$2,'credentials.rotate_all','installation','current','success',$3,'management','Explicit credential rotation')`, decimal(session.Operator.ID), session.Operator.Username, input.OperationKey)
		return err
	})
	if err != nil {
		if errors.Is(err, adminauth.ErrInvalidCredentials) {
			WriteProblem(w, http.StatusForbidden, currentMeta(w), Problem{Kind: "invalid_request", Code: "CURRENT_PASSWORD_INVALID", Message: "The current password does not match. No credential rotation occurred.", Outcome: NotSent})
			return
		}
		a.fail(w, r, err, input.OperationKey)
		return
	}
	a.identity.clearCookies(w, r)
	WriteResult(w, 200, currentMeta(w), presentRotation(result))
}
func (a *ManagementCredentials) queryRotation(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("operation_key")
	result, err := a.authority.QueryRotation(r.Context(), key)
	if err != nil {
		a.fail(w, r, err, key)
		return
	}
	WriteResult(w, 200, currentMeta(w), presentRotation(result))
}
func (a *ManagementCredentials) cancelRotation(w http.ResponseWriter, r *http.Request) {
	var empty struct{}
	if !addressBody(w, r, &empty) {
		return
	}
	key := r.PathValue("operation_key")
	result, err := a.authority.CancelRotation(r.Context(), key)
	if err != nil {
		a.fail(w, r, err, key)
		return
	}
	WriteResult(w, 200, currentMeta(w), presentRotation(result))
}

type deliveryView struct {
	ID              string  `json:"id"`
	SourceID        string  `json:"source_id"`
	AddressID       string  `json:"address_id"`
	Generation      string  `json:"generation"`
	Key             string  `json:"delivery_key"`
	CreatedAt       string  `json:"created_at"`
	AcknowledgedAt  *string `json:"acknowledged_at"`
	Address         string  `json:"address"`
	Label           string  `json:"label"`
	SourceLabel     string  `json:"source_label"`
	Lifecycle       string  `json:"lifecycle"`
	Deleted         bool    `json:"deleted"`
	Enabled         bool    `json:"enabled"`
	Current         bool    `json:"current"`
	BundleAvailable bool    `json:"bundle_available"`
}

func presentDelivery(item addressauth.DeliveryRef) deliveryView {
	return deliveryView{decimal(item.ID), decimal(item.SourceID), decimal(item.AddressID), decimal(item.Generation), item.Key, instant(item.CreatedAt), optionalInstant(item.AcknowledgedAt), item.Address, item.Label, item.SourceLabel, item.Lifecycle, item.Deleted, item.Enabled, item.Current, item.BundleAvailable}
}
func (a *ManagementCredentials) pending(w http.ResponseWriter, r *http.Request) {
	source, ok := pathID(w, r, "source_id")
	if !ok {
		return
	}
	after, limit := int64(0), 20
	for name, values := range r.URL.Query() {
		if len(values) != 1 {
			a.fail(w, r, addressauth.ErrInvalid, "")
			return
		}
		if name == "after_id" {
			value, valid := positiveDecimal(values[0])
			if !valid {
				a.fail(w, r, addressauth.ErrInvalid, "")
				return
			}
			after = value
		} else if name == "limit" {
			value, err := strconv.ParseInt(values[0], 10, 32)
			if err != nil || value < 1 || value > 1000 {
				a.fail(w, r, addressauth.ErrInvalid, "")
				return
			}
			limit = int(value)
		} else {
			a.fail(w, r, addressauth.ErrInvalid, "")
			return
		}
	}
	items, err := a.authority.PendingDeliveries(r.Context(), source, after, limit)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	views := make([]deliveryView, len(items))
	for i, item := range items {
		views[i] = presentDelivery(item)
	}
	var next *string
	if len(items) == limit {
		next = optionalDecimal(&items[len(items)-1].ID)
	}
	WriteResult(w, 200, currentMeta(w), struct {
		Items       []deliveryView `json:"items"`
		NextAfterID *string        `json:"next_after_id"`
	}{views, next})
}
func (a *ManagementCredentials) lookupDelivery(w http.ResponseWriter, r *http.Request) (addressauth.DeliveryRef, bool) {
	source, ok := pathID(w, r, "source_id")
	if !ok {
		return addressauth.DeliveryRef{}, false
	}
	ref, err := a.authority.Delivery(r.Context(), source, r.PathValue("delivery_key"))
	if err != nil {
		a.fail(w, r, err, "")
		return addressauth.DeliveryRef{}, false
	}
	return ref, true
}
func (a *ManagementCredentials) delivery(w http.ResponseWriter, r *http.Request) {
	ref, ok := a.lookupDelivery(w, r)
	if !ok {
		return
	}
	WriteResult(w, 200, currentMeta(w), presentDelivery(ref))
}
func (a *ManagementCredentials) revealPending(w http.ResponseWriter, r *http.Request) {
	var empty struct{}
	if !addressBody(w, r, &empty) {
		return
	}
	ref, ok := a.lookupDelivery(w, r)
	if !ok {
		return
	}
	scope, err := a.authority.BeginReveal(r.Context())
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	defer scope.Close()
	if _, err = a.identity.identity.Authenticate(r.Context(), cookieValue(r, sessionCookie)); err != nil {
		a.identity.writeAuthError(w, currentMeta(w), err)
		return
	}
	item, err := scope.Pending(r.Context(), ref.Key, ref.OwnerKey)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	links, err := a.pendingCopyLinks(item)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	WriteResult(w, 200, currentMeta(w), struct {
		Delivery deliveryView         `json:"delivery"`
		Revoked  bool                 `json:"revoked"`
		Secret   addressauth.Pending  `json:"secret"`
		Links    *credentialCopyLinks `json:"links"`
	}{presentDelivery(ref), item.Revoked, item.Secret, links})
}

func (a *ManagementCredentials) pendingCopyLinks(item addressauth.PendingDelivery) (*credentialCopyLinks, error) {
	if item.Revoked || !item.CanCopyOTP {
		return nil, nil
	}
	otp, err := a.authority.CompatibilityOTPToken(item.AddressID, item.Secret.APIKey)
	if err != nil {
		return nil, err
	}
	recent, err := a.authority.CompatibilityRecentToken(item.AddressID, item.Secret.APIKey)
	if err != nil {
		return nil, err
	}
	base := "/api/v1/otp?token=" + url.QueryEscape(otp)
	return &credentialCopyLinks{OTP: base + "&latest_only=true&otp_only=true", Recent: "/api/v1/mail/recent?api_key=" + url.QueryEscape(recent), Raw: base + "&raw_mail=true&latest_only=false"}, nil
}

// This explicit reveal only reads an already-issued bundle bound to the exact
// delivery. It does not run the complete-mailbox command or acknowledge it.
func (a *ManagementCredentials) revealPendingBundle(w http.ResponseWriter, r *http.Request) {
	var empty struct{}
	if !addressBody(w, r, &empty) {
		return
	}
	scope, err := a.authority.BeginReveal(r.Context())
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	defer scope.Close()
	if _, err = a.identity.identity.Authenticate(r.Context(), cookieValue(r, sessionCookie)); err != nil {
		a.identity.writeAuthError(w, currentMeta(w), err)
		return
	}
	ref, ok := a.lookupDelivery(w, r)
	if !ok {
		return
	}
	bundle, err := scope.PendingBundle(r.Context(), ref.SourceID, ref.Key, ref.OwnerKey)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	item, err := scope.Pending(r.Context(), ref.Key, ref.OwnerKey)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	links, err := a.pendingCopyLinks(item)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	WriteResult(w, 200, currentMeta(w), struct {
		Delivery deliveryView         `json:"delivery"`
		Bundle   addressauth.Bundle   `json:"bundle"`
		Links    *credentialCopyLinks `json:"links"`
	}{presentDelivery(ref), bundle, links})
}
func (a *ManagementCredentials) completePending(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ExpectedGeneration string `json:"expected_generation"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	generation, ok := positiveDecimal(input.ExpectedGeneration)
	if !ok {
		a.fail(w, r, addressauth.ErrInvalid, "")
		return
	}
	ref, ok := a.lookupDelivery(w, r)
	if !ok {
		return
	}
	_, err := a.authority.EnsurePendingBundle(r.Context(), addressauth.EnsurePendingRequest{AddressID: ref.AddressID, Generation: generation, DeliveryKey: ref.Key, OwnerKey: ref.OwnerKey})
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	// Completion returns only the original delivery reference; obtaining the
	// supplemented tuple still requires the separate explicit reveal action.
	ref, err = a.authority.Delivery(r.Context(), ref.SourceID, ref.Key)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	WriteResult(w, 200, currentMeta(w), presentDelivery(ref))
}
func (a *ManagementCredentials) acknowledge(w http.ResponseWriter, r *http.Request) {
	source, ok := pathID(w, r, "source_id")
	if !ok {
		return
	}
	var input struct {
		Keys []string `json:"delivery_keys"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	if err := a.authority.AcknowledgeDeliveries(r.Context(), source, input.Keys); err != nil {
		a.fail(w, r, err, "")
		return
	}
	WriteResult(w, 200, currentMeta(w), nil)
}
