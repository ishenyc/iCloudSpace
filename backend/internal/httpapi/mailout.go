package httpapi

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"icloudspace/internal/addresses"
	"icloudspace/internal/content"
	"icloudspace/internal/mailout"
	"icloudspace/internal/sourceguard"
)

type ManagementMailout struct {
	identity  *ManagementAuth
	addresses *addresses.Service
	owner     *mailout.Service
	guards    *sourceguard.Registry
	drafts    chan struct{}
}

func NewManagementMailout(identity *ManagementAuth, addresses *addresses.Service, owner *mailout.Service, guards *sourceguard.Registry, concurrentDrafts int) (*ManagementMailout, error) {
	if identity == nil || addresses == nil || owner == nil || guards == nil || concurrentDrafts < 1 || concurrentDrafts > 64 {
		return nil, errors.New("httpapi: mail owner, authority boundary and bounded draft concurrency are required")
	}
	return &ManagementMailout{identity, addresses, owner, guards, make(chan struct{}, concurrentDrafts)}, nil
}

func (a *ManagementMailout) Register(mux *http.ServeMux) {
	base := a.identity.basePath + "/addresses/{address_id}"
	for pattern, handler := range map[string]http.HandlerFunc{
		"POST " + base + "/mail-preview":             a.preview,
		"POST " + base + "/send-submissions":         a.send,
		"POST " + base + "/send-submissions/query":   a.query,
		"POST " + base + "/compose-contexts":         a.prepareContext,
		"POST " + base + "/compose-contexts/query":   a.queryContext,
		"POST " + base + "/compose-contexts/refresh": a.refreshContext,
	} {
		mux.Handle(pattern, a.identity.RequireSession(handler))
	}
}

type mailDraftInput struct {
	Recipient string `json:"recipient"`
	Subject   string `json:"subject"`
	Body      struct {
		Format content.BodyFormat `json:"format"`
		Source string             `json:"source"`
	} `json:"body"`
	Attachments []struct {
		Filename  string `json:"filename"`
		MediaType string `json:"media_type"`
		ContentID string `json:"content_id"`
		Inline    bool   `json:"inline"`
		Bytes     []byte `json:"bytes"`
	} `json:"attachments"`
}

func (in mailDraftInput) draft() content.Draft {
	out := content.Draft{Recipient: in.Recipient, Subject: in.Subject, Body: content.Body{Format: in.Body.Format, Source: in.Body.Source}}
	for _, file := range in.Attachments {
		out.Attachments = append(out.Attachments, content.DraftAttachment{Filename: file.Filename, MediaType: file.MediaType, ContentID: file.ContentID, Inline: file.Inline, Bytes: file.Bytes})
	}
	return out
}
func (a *ManagementMailout) admit(w http.ResponseWriter) (func(), bool) {
	select {
	case a.drafts <- struct{}{}:
		return func() { <-a.drafts }, true
	default:
		w.Header().Set("Retry-After", "1")
		WriteProblem(w, 503, currentMeta(w), Problem{Kind: "capacity", Code: "MAIL_DRAFT_BUSY", Message: "The mail preparation capacity is busy. This request was not submitted.", Outcome: NotSent})
		return nil, false
	}
}
func (a *ManagementMailout) enter(w http.ResponseWriter, r *http.Request) (*http.Request, int64, func(), bool) {
	id, ok := pathID(w, r, "address_id")
	if !ok {
		return r, 0, nil, false
	}
	item, err := a.addresses.Get(r.Context(), id)
	if err != nil {
		writeAddressError(w, r, err, addressReference(id))
		return r, 0, nil, false
	}
	gate, err := a.guards.Acquire(r.Context(), item.SourceID)
	if err != nil {
		a.fail(w, r, err, "", id)
		return r, 0, nil, false
	}
	if _, err := a.identity.identity.Authenticate(r.Context(), cookieValue(r, sessionCookie)); err != nil {
		gate.Close()
		a.identity.writeAuthError(w, currentMeta(w), err)
		return r, 0, nil, false
	}
	return r.WithContext(sourceguard.WithLease(r.Context(), gate)), id, func() { gate.Close() }, true
}
func (a *ManagementMailout) fail(w http.ResponseWriter, r *http.Request, err error, key string, id int64) {
	status, p := 500, internalProblem()
	switch {
	case errors.Is(err, mailout.ErrInvalid), errors.Is(err, content.ErrDraft), errors.Is(err, content.ErrLimits):
		status, p = 400, Problem{Kind: "invalid_request", Code: "MAIL_INPUT_INVALID", Message: "Check the recipient, content and attachments.", Outcome: NotSent}
	case errors.Is(err, mailout.ErrIneligible):
		status, p = 409, Problem{Kind: "eligibility", Code: "MAIL_SEND_INELIGIBLE", Message: "This address is not eligible for sending.", Outcome: NotSent}
	case errors.Is(err, mailout.ErrConflict):
		status, p = 409, Problem{Kind: "conflict", Code: "MAIL_REQUEST_CONFLICT", Message: "The request differs from its recorded original.", Outcome: NotSent}
	case errors.Is(err, mailout.ErrNotFound):
		status, p = 404, Problem{Kind: "not_found", Code: "MAIL_REQUEST_NOT_FOUND", Message: "The original mail request is unavailable."}
	case errors.Is(err, mailout.ErrReadOnly):
		status, p = 503, Problem{Kind: "maintenance", Code: "INSTALLATION_READ_ONLY", Message: "The installation is currently read-only.", Outcome: NotSent}
	case errors.Is(err, mailout.ErrBudget):
		status, p = 409, Problem{Kind: "authorization", Code: "MAIL_BOOTSTRAP_PERMISSION_REQUIRED", Message: "An explicit draft and seed permission is required.", Outcome: NotSent}
	case errors.Is(err, mailout.ErrReference):
		status, p = 409, Problem{Kind: "provider", Code: "MAIL_REFERENCE_PENDING", Message: "Refresh the same compose context before submitting.", Outcome: NotSent}
	case errors.Is(err, mailout.ErrProvider):
		status, p = 502, Problem{Kind: "provider", Code: "MAIL_PROVIDER_UNAVAILABLE", Message: "The provider proof could not be verified."}
	case errors.Is(err, mailout.ErrUnknown):
		status, p = 503, Problem{Kind: "persistence", Code: "MAIL_REQUEST_UNKNOWN", Message: "Query the original request. Do not resubmit it.", Outcome: Unknown, SubmissionKey: key, Resource: addressReference(id)}
	}
	var budget *content.BudgetError
	if errors.As(err, &budget) {
		status, p = 413, Problem{Kind: "request_budget", Code: "MAIL_INPUT_BUDGET", Message: "The mail content or attachments exceed their limit.", Outcome: NotSent}
	}
	WriteProblem(w, status, currentMeta(w), p)
}
func (a *ManagementMailout) preview(w http.ResponseWriter, r *http.Request) {
	if _, ok := pathID(w, r, "address_id"); !ok {
		return
	}
	release, ok := a.admit(w)
	if !ok {
		return
	}
	defer release()
	var input mailDraftInput
	if problem := DecodeJSON(w, r, &input, 20<<20); problem != nil {
		WriteProblem(w, 400, currentMeta(w), *problem)
		return
	}
	result, err := a.owner.Preview(input.draft())
	if err != nil {
		a.fail(w, r, err, "", 0)
		return
	}
	WriteResult(w, 200, currentMeta(w), result)
}
func (a *ManagementMailout) submission(w http.ResponseWriter, r *http.Request, result mailout.Result, err error) {
	if result.Key == "" {
		a.fail(w, r, err, "", result.AddressID)
		return
	}
	// A recorded RPC result survives a later session/SQL acknowledgement error.
	// Unknown remains query-only and never becomes a transport retry hint.
	status := 200
	if result.Outcome == mailout.Unknown || err != nil {
		status = 202
	}
	result.QueryOnly = result.QueryOnly || result.Outcome == mailout.Unknown
	WriteResult(w, status, currentMeta(w), result)
}
func (a *ManagementMailout) send(w http.ResponseWriter, r *http.Request) {
	release, ok := a.admit(w)
	if !ok {
		return
	}
	defer release()
	var input struct {
		Key   string         `json:"request_key"`
		Draft mailDraftInput `json:"draft"`
	}
	if problem := DecodeJSON(w, r, &input, 20<<20); problem != nil {
		WriteProblem(w, 400, currentMeta(w), *problem)
		return
	}
	r, id, close, ok := a.enter(w, r)
	if !ok {
		return
	}
	defer close()
	permission := &bootstrapPermission{address: id, submission: input.Key, stages: map[mailout.BootstrapStage]bool{mailout.AppendStage: true, mailout.SeedStage: true}}
	r = r.WithContext(context.WithValue(r.Context(), bootstrapPermissionKey{}, permission))
	result, err := a.owner.Send(r.Context(), mailout.Request{Key: input.Key, AddressID: id, Draft: input.Draft.draft()})
	if result.Key == "" {
		a.fail(w, r, err, input.Key, id)
		return
	}
	a.submission(w, r, result, err)
}
func (a *ManagementMailout) query(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "address_id")
	if !ok {
		return
	}
	var input struct {
		Key string `json:"request_key"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	result, err := a.owner.Query(r.Context(), id, input.Key)
	if err != nil {
		a.fail(w, r, err, input.Key, id)
		return
	}
	a.submission(w, r, result, nil)
}

type composeContextView struct {
	Key                  string                 `json:"context_key"`
	RequestKey           string                 `json:"request_key,omitempty"`
	AddressID            string                 `json:"address_id"`
	Recipient            string                 `json:"recipient"`
	State                string                 `json:"state"`
	Ready                bool                   `json:"ready"`
	QueryOnly            bool                   `json:"query_only"`
	CandidateID          *string                `json:"candidate_id"`
	CandidateUIDValidity *string                `json:"candidate_uid_validity"`
	SeedID               *string                `json:"seed_id"`
	AppendOutcome        *mailout.Outcome       `json:"append_outcome"`
	SeedOutcome          *mailout.Outcome       `json:"seed_outcome"`
	ReferenceID          *string                `json:"reference_id"`
	ReferenceKind        *mailout.ReferenceKind `json:"reference_kind"`
	Code                 string                 `json:"code"`
	Diagnostic           *mailout.Diagnostic    `json:"diagnostic,omitempty"`
}

func presentComposeContext(id int64, result mailout.ContextStatus) composeContextView {
	e := result.Evidence
	view := composeContextView{Key: e.ContextKey, AddressID: decimal(id), Recipient: e.Recipient, State: e.State, Ready: result.Ready, QueryOnly: result.ReadOnly, CandidateID: optionalText(e.CandidateID), SeedID: optionalText(e.SeedID), AppendOutcome: e.AppendOutcome, SeedOutcome: e.SeedOutcome, ReferenceID: optionalText(e.ReferenceID), Code: result.Code,Diagnostic:result.Diagnostic}
	view.QueryOnly = view.QueryOnly || e.State == "preparing" || e.State == "candidate_unknown" || e.State == "seed_unknown"
	if e.CandidateUIDValidity > 0 {
		value := int64(e.CandidateUIDValidity)
		view.CandidateUIDValidity = optionalDecimal(&value)
	}
	if result.Reference != nil {
		view.ReferenceID = optionalText(result.Reference.ID)
		kind := result.Reference.Kind
		view.ReferenceKind = &kind
	}
	return view
}
func optionalText(text string) *string {
	if text == "" {
		return nil
	}
	return &text
}
func (a *ManagementMailout) contextResult(w http.ResponseWriter, r *http.Request, id int64, requestedKey string, result mailout.ContextStatus, err error) {
	if err != nil {
		a.fail(w, r, err, requestedKey, id)
		return
	}
	status := 200
	if !result.Ready {
		status = 202
	}
	view := presentComposeContext(id, result)
	view.RequestKey = requestedKey
	WriteResult(w, status, currentMeta(w), view)
}

type bootstrapPermissionKey struct{}
type bootstrapPermission struct {
	mu         sync.Mutex
	address    int64
	key        string
	submission string
	stages     map[mailout.BootstrapStage]bool
}

// AuthorizeMailBootstrap is the mail owner's injected permission callback.
// Only a new authenticated Send grants one append and one seed for its bound
// address/context. The owner deduplicates the submission before consuming it.
func AuthorizeMailBootstrap(ctx context.Context, scope mailout.Scope, key string, stage mailout.BootstrapStage) error {
	p, ok := ctx.Value(bootstrapPermissionKey{}).(*bootstrapPermission)
	if !ok || p.address != scope.Address.ID || key == "" || p.submission == "" {
		return mailout.ErrBudget
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key != "" && p.key != key {
		return mailout.ErrBudget
	}
	if p.stages[stage] {
		p.key = key
		delete(p.stages, stage)
		return nil
	}
	return mailout.ErrBudget
}
func (a *ManagementMailout) prepareContext(w http.ResponseWriter, r *http.Request) {
	WriteProblem(w, 410, currentMeta(w), Problem{Kind: "conflict", Code: "MAIL_PREPARATION_RETIRED", Message: "Write the message and use Send. Original preparation records remain queryable.", Outcome: NotSent})
}
func (a *ManagementMailout) queryContext(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "address_id")
	if !ok {
		return
	}
	var input struct {
		Key string `json:"context_key"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	result, err := a.owner.QueryContext(r.Context(), id, input.Key)
	a.contextResult(w, r, id, input.Key, result, err)
}
func (a *ManagementMailout) refreshContext(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Key string `json:"context_key"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	r, id, close, ok := a.enter(w, r)
	if !ok {
		return
	}
	defer close()
	result, err := a.owner.RefreshContext(r.Context(), id, input.Key)
	a.contextResult(w, r, id, input.Key, result, err)
}
