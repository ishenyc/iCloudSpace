package httpapi

import (
	"errors"
	"net/http"
	"net/url"

	"icloudspace/internal/creationengine"
	"icloudspace/internal/sourceguard"
)

// ManagementCreation exposes policy changes and original-attempt inspection.
// Running or recovering the scheduler is an installation responsibility.
type ManagementCreation struct {
	identity *ManagementAuth
	engine   *creationengine.Engine
	guards   *sourceguard.Registry
}

func NewManagementCreation(identity *ManagementAuth, engine *creationengine.Engine, guards *sourceguard.Registry) (*ManagementCreation, error) {
	if identity == nil || engine == nil || guards == nil {
		return nil, errors.New("httpapi: management identity, creation owner and source registry are required")
	}
	return &ManagementCreation{identity, engine, guards}, nil
}

func (a *ManagementCreation) Register(mux *http.ServeMux) {
	base := a.identity.basePath + "/accounts/{source_id}/creation-policy"
	for pattern, handler := range map[string]http.HandlerFunc{
		"GET " + base:                                     a.get,
		"PUT " + base:                                     a.set,
		"POST " + base + "/enable":                        a.enable,
		"POST " + base + "/disable":                       a.disable,
		"GET " + base + "/attempts":                       a.attempts,
		"GET " + base + "/attempts/{attempt_id}":          a.attempt,
		"POST " + base + "/attempts/{attempt_id}/resolve": a.resolve,
	} {
		mux.Handle(pattern, a.identity.RequireSession(handler))
	}
}

type creationSlotView struct {
	SourceID       string `json:"source_id"`
	PolicyRevision string `json:"policy_revision"`
	ScheduledFor   string `json:"scheduled_for"`
	State          string `json:"state"`
}
type creationAttemptView struct {
	ID             string  `json:"id"`
	SourceID       string  `json:"source_id"`
	PolicyRevision string  `json:"policy_revision"`
	ScheduledFor   string  `json:"scheduled_for"`
	Ordinal        int     `json:"ordinal"`
	State          string  `json:"state"`
	OperationKey   *string `json:"operation_key"`
	ClaimedAt      *string `json:"claimed_at"`
	FinishedAt     *string `json:"finished_at"`
	ErrorCode      string  `json:"error_code"`
	CreatedAt      string  `json:"created_at"`
	OperationState *string `json:"operation_state"`
	AddressID      *string `json:"address_id"`
	QueryOnly      bool    `json:"query_only"`
}
type creationPolicyView struct {
	SourceID             string               `json:"source_id"`
	Revision             string               `json:"revision"`
	Enabled              bool                 `json:"enabled"`
	ScheduleKind         string               `json:"schedule_kind"`
	IntervalMilliseconds *string              `json:"interval_milliseconds"`
	MaximumAddresses     int                  `json:"maximum_addresses"`
	AttemptsPerRound     int                  `json:"attempts_per_round"`
	CooldownUntil        *string              `json:"cooldown_until"`
	LastAttemptedAt      *string              `json:"last_attempted_at"`
	LastConfirmedAt      *string              `json:"last_confirmed_at"`
	PausedReason         string               `json:"paused_reason"`
	LastAddress          string               `json:"last_address"`
	LastErrorDetail      string               `json:"last_error_detail"`
	CreatedAt            string               `json:"created_at"`
	UpdatedAt            string               `json:"updated_at"`
	Slots                []creationSlotView   `json:"slots"`
	PendingAttempt       *creationAttemptView `json:"pending_attempt"`
}

func creationText(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
func presentCreationAttempt(item creationengine.Attempt) creationAttemptView {
	return creationAttemptView{ID: decimal(item.ID), SourceID: decimal(item.SourceID), PolicyRevision: decimal(item.PolicyRevision), ScheduledFor: instant(item.ScheduledFor), Ordinal: item.Ordinal, State: item.State, OperationKey: creationText(item.OperationKey), ClaimedAt: optionalInstant(item.ClaimedAt), FinishedAt: optionalInstant(item.FinishedAt), ErrorCode: item.ErrorCode, CreatedAt: instant(item.CreatedAt), OperationState: creationText(item.OperationState), AddressID: optionalDecimal(item.AddressID), QueryOnly: true}
}
func presentCreationPolicy(item creationengine.Policy) creationPolicyView {
	view := creationPolicyView{SourceID: decimal(item.SourceID), Revision: decimal(item.Revision), Enabled: item.Enabled, ScheduleKind: item.ScheduleKind, IntervalMilliseconds: optionalDecimal(item.IntervalMilliseconds), MaximumAddresses: item.MaximumAddresses, AttemptsPerRound: item.AttemptsPerRound, CooldownUntil: optionalInstant(item.CooldownUntil), LastAttemptedAt: optionalInstant(item.LastAttemptedAt), LastConfirmedAt: optionalInstant(item.LastConfirmedAt), PausedReason: item.PausedReason, LastAddress: item.LastAddress, LastErrorDetail: item.LastErrorDetail, CreatedAt: instant(item.CreatedAt), UpdatedAt: instant(item.UpdatedAt), Slots: make([]creationSlotView, 0, len(item.Slots))}
	for _, slot := range item.Slots {
		view.Slots = append(view.Slots, creationSlotView{decimal(slot.SourceID), decimal(slot.PolicyRevision), instant(slot.ScheduledFor), slot.State})
	}
	if item.PendingAttempt != nil {
		pending := presentCreationAttempt(*item.PendingAttempt)
		view.PendingAttempt = &pending
	}
	return view
}

func (a *ManagementCreation) fail(w http.ResponseWriter, r *http.Request, source int64, err error) {
	status, problem := 500, internalProblem()
	switch {
	case errors.Is(err, creationengine.ErrInvalid):
		status, problem = 400, Problem{Kind: "invalid_request", Code: "CREATION_INPUT_INVALID", Message: "Check the policy, revision and attempt cursor.", Outcome: NotSent}
	case errors.Is(err, creationengine.ErrNotFound):
		status, problem = 404, Problem{Kind: "not_found", Code: "CREATION_RESOURCE_NOT_FOUND", Message: "The source policy or original attempt is unavailable.", Outcome: NotSent}
	case errors.Is(err, creationengine.ErrConflict):
		status, problem = 409, Problem{Kind: "conflict", Code: "CREATION_REVISION_CHANGED", Message: "Read the current policy before changing it.", Outcome: NotSent}
	case errors.Is(err, creationengine.ErrIneligible), errors.Is(err, creationengine.ErrCapacity):
		status, problem = 409, Problem{Kind: "conflict", Code: "CREATION_SOURCE_INELIGIBLE", Message: "The source or configured address maximum does not permit automatic creation.", Outcome: NotSent}
	case errors.Is(err, creationengine.ErrUnresolved):
		status, problem = 409, Problem{Kind: "conflict", Code: "CREATION_REVIEW_REQUIRED", Message: "Inspect the original attempt. Its unresolved provider operation cannot be repeated.", Outcome: NotSent}
	case errors.Is(err, creationengine.ErrReadOnly):
		status, problem = 503, Problem{Kind: "maintenance", Code: "INSTALLATION_READ_ONLY", Message: "The installation is currently read-only.", Outcome: NotSent}
	case errors.Is(err, creationengine.ErrUnknown):
		status, problem = 503, Problem{Kind: "persistence", Code: "CREATION_RESULT_UNKNOWN", Message: "Query the current policy or original attempt before making another change.", Outcome: Unknown}
	}
	if source > 0 {
		problem.Resource = &ResourceRef{Kind: "account", ID: decimal(source)}
	}
	WriteProblem(w, status, currentMeta(w), problem)
}

func (a *ManagementCreation) enter(w http.ResponseWriter, r *http.Request) (*http.Request, int64, func(), bool) {
	id, ok := accountID(w, r)
	if !ok {
		return r, 0, nil, false
	}
	gate, err := a.guards.Acquire(r.Context(), id)
	if err != nil {
		a.fail(w, r, id, err)
		return r, 0, nil, false
	}
	if _, err = a.identity.identity.Authenticate(r.Context(), cookieValue(r, sessionCookie)); err != nil {
		gate.Close()
		a.identity.writeAuthError(w, currentMeta(w), err)
		return r, 0, nil, false
	}
	return r.WithContext(sourceguard.WithLease(r.Context(), gate)), id, func() { gate.Close() }, true
}

func (a *ManagementCreation) get(w http.ResponseWriter, r *http.Request) {
	id, ok := accountID(w, r)
	if !ok {
		return
	}
	policy, err := a.engine.Get(r.Context(), id)
	if err != nil {
		a.fail(w, r, id, err)
		return
	}
	WriteResult(w, 200, currentMeta(w), presentCreationPolicy(policy))
}

func creationRevision(value string) (int64, bool) {
	if value == "0" {
		return 0, true
	}
	return positiveDecimal(value)
}
func (a *ManagementCreation) set(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Revision string `json:"expected_revision"`
		Maximum  *int   `json:"maximum_addresses"`
		Attempts *int   `json:"attempts_per_round"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	revision, ok := creationRevision(input.Revision)
	if !ok || input.Maximum == nil || input.Attempts == nil || *input.Maximum < 0 || int64(*input.Maximum) > 2147483647 || *input.Attempts < 1 || *input.Attempts > creationengine.MaximumAttempts {
		a.fail(w, r, 0, creationengine.ErrInvalid)
		return
	}
	r, id, close, ok := a.enter(w, r)
	if !ok {
		return
	}
	defer close()
	policy, err := a.engine.Set(r.Context(), id, revision, creationengine.Settings{MaximumAddresses: *input.Maximum, AttemptsPerRound: *input.Attempts})
	if err != nil {
		a.fail(w, r, id, err)
		return
	}
	WriteResult(w, 200, currentMeta(w), presentCreationPolicy(policy))
}

func (a *ManagementCreation) enable(w http.ResponseWriter, r *http.Request)  { a.toggle(w, r, true) }
func (a *ManagementCreation) disable(w http.ResponseWriter, r *http.Request) { a.toggle(w, r, false) }
func (a *ManagementCreation) toggle(w http.ResponseWriter, r *http.Request, enabled bool) {
	var input struct {
		Revision string `json:"expected_revision"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	revision, ok := creationRevision(input.Revision)
	if !ok {
		a.fail(w, r, 0, creationengine.ErrInvalid)
		return
	}
	r, id, close, ok := a.enter(w, r)
	if !ok {
		return
	}
	defer close()
	var policy creationengine.Policy
	var err error
	if enabled {
		policy, err = a.engine.Enable(r.Context(), id, revision)
	} else {
		policy, err = a.engine.Disable(r.Context(), id, revision)
	}
	if err != nil {
		a.fail(w, r, id, err)
		return
	}
	WriteResult(w, 200, currentMeta(w), presentCreationPolicy(policy))
}

type creationAttemptPage struct {
	SourceID    string                `json:"source_id"`
	AfterID     string                `json:"after_id"`
	Limit       int                   `json:"limit"`
	NextAfterID *string               `json:"next_after_id"`
	Items       []creationAttemptView `json:"items"`
}

func (a *ManagementCreation) attempts(w http.ResponseWriter, r *http.Request) {
	id, ok := accountID(w, r)
	if !ok {
		return
	}
	after, limit := int64(0), 50
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		a.fail(w, r, id, creationengine.ErrInvalid)
		return
	}
	for name, values := range query {
		if len(values) != 1 || name != "after_id" && name != "limit" {
			a.fail(w, r, id, creationengine.ErrInvalid)
			return
		}
		if name == "after_id" {
			after, ok = creationRevision(values[0])
		} else {
			var parsed int64
			parsed, ok = positiveDecimal(values[0])
			if parsed > 100 {
				ok = false
			}
			limit = int(parsed)
		}
		if !ok {
			a.fail(w, r, id, creationengine.ErrInvalid)
			return
		}
	}
	if _, err := a.engine.Get(r.Context(), id); err != nil {
		a.fail(w, r, id, err)
		return
	}
	items, err := a.engine.Attempts(r.Context(), id, after, limit+1)
	if err != nil {
		a.fail(w, r, id, err)
		return
	}
	page := creationAttemptPage{SourceID: decimal(id), AfterID: decimal(after), Limit: limit, Items: make([]creationAttemptView, 0, limit)}
	if len(items) > limit {
		next := decimal(items[limit-1].ID)
		page.NextAfterID = &next
		items = items[:limit]
	}
	for _, item := range items {
		page.Items = append(page.Items, presentCreationAttempt(item))
	}
	WriteResult(w, 200, currentMeta(w), page)
}
func (a *ManagementCreation) attempt(w http.ResponseWriter, r *http.Request) {
	source, ok := accountID(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "attempt_id")
	if !ok {
		return
	}
	item, err := a.engine.Attempt(r.Context(), source, id)
	if err != nil {
		a.fail(w, r, source, err)
		return
	}
	WriteResult(w, 200, currentMeta(w), presentCreationAttempt(item))
}
func (a *ManagementCreation) resolve(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !addressBody(w, r, &input) {
		return
	}
	id, ok := pathID(w, r, "attempt_id")
	if !ok {
		return
	}
	r, source, close, ok := a.enter(w, r)
	if !ok {
		return
	}
	defer close()
	item, err := a.engine.Resolve(r.Context(), source, id)
	if err != nil {
		a.fail(w, r, source, err)
		return
	}
	WriteResult(w, 200, currentMeta(w), presentCreationAttempt(item))
}
