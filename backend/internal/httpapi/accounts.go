package httpapi

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"icloudspace/internal/accounts"
	"icloudspace/internal/adminauth"
)

type ManagementAccounts struct {
	identity    *ManagementAuth
	accounts    *accounts.Service
	readBarrier func(context.Context) (io.Closer, error)
}

func NewManagementAccounts(identity *ManagementAuth, service *accounts.Service) (*ManagementAccounts, error) {
	return NewManagementAccountsWithReadBarrier(identity, service, nil)
}

func NewManagementAccountsWithReadBarrier(identity *ManagementAuth, service *accounts.Service, barrier func(context.Context) (io.Closer, error)) (*ManagementAccounts, error) {
	if identity == nil || service == nil {
		return nil, errors.New("httpapi: management identity and account owner are required")
	}
	return &ManagementAccounts{identity: identity, accounts: service, readBarrier: barrier}, nil
}

func (a *ManagementAccounts) Register(mux *http.ServeMux) {
	base := a.identity.basePath
	for pattern, handler := range map[string]http.HandlerFunc{
		"GET " + base + "/accounts":                     a.list,
		"POST " + base + "/accounts":                    a.create,
		"GET " + base + "/accounts/{source_id}":         a.get,
		"PATCH " + base + "/accounts/{source_id}":       a.patch,
		"DELETE " + base + "/accounts/{source_id}":      a.delete,
		"POST " + base + "/accounts/{source_id}/reveal": a.reveal,
		"POST " + base + "/accounts/export":             a.export,
	} {
		if strings.HasPrefix(pattern, "PATCH ") || strings.HasPrefix(pattern, "DELETE ") || pattern == "POST "+base+"/accounts" {
			mux.Handle(pattern, a.identity.RequireLocalCommand(handler))
		} else {
			mux.Handle(pattern, a.identity.RequireSession(handler))
		}
	}
}

type principalView struct {
	AppleID  string  `json:"apple_id"`
	Region   string  `json:"region"`
	DSID     *string `json:"dsid,omitempty"`
	Revision string  `json:"revision"`
}

// Wire integers with identity/version meaning are decimal strings. Instants
// are RFC3339Nano strings, preserving nanoseconds through JavaScript clients.
type sourceView struct {
	ID                   string            `json:"id"`
	Kind                 accounts.Kind     `json:"kind"`
	DisplayName          string            `json:"display_name"`
	AddressNamespace     string            `json:"address_namespace"`
	Endpoint             accounts.Endpoint `json:"endpoint"`
	AddressSuffix        string            `json:"address_suffix"`
	Enabled              bool              `json:"enabled"`
	AddressCount         string            `json:"address_count"`
	Revision             string            `json:"revision"`
	SourceGeneration     string            `json:"source_generation"`
	CredentialGeneration string            `json:"credential_generation"`
	AutomaticSyncAfter   *string           `json:"automatic_sync_after,omitempty"`
	LastTerminalSyncAt   *string           `json:"last_terminal_sync_at,omitempty"`
	LastSyncState        string            `json:"last_sync_state"`
	LastSyncError        string            `json:"last_sync_error"`
	LastSyncedAt         *string           `json:"last_synced_at"`
	CreatedAt            string            `json:"created_at"`
	UpdatedAt            string            `json:"updated_at"`
	Apple                *principalView    `json:"apple,omitempty"`
}

func presentSource(item accounts.Metadata) sourceView {
	view := sourceView{
		ID: decimal(item.ID), Kind: item.Kind, DisplayName: item.DisplayName,
		AddressNamespace: item.AddressNamespace, Endpoint: item.Endpoint,
		AddressSuffix: item.AddressSuffix, Enabled: item.Enabled, AddressCount: decimal(item.AddressCount),
		Revision: decimal(item.Revision), SourceGeneration: decimal(item.SourceGeneration),
		CredentialGeneration: decimal(item.CredentialGeneration),
		AutomaticSyncAfter:   optionalInstant(item.AutomaticSyncAfter),
		LastTerminalSyncAt:   optionalInstant(item.LastTerminalSyncAt),
		LastSyncState:        accounts.SafeSyncState(item.LastSyncState), LastSyncError: accounts.SafeSyncErrorCode(item.LastSyncError), LastSyncedAt: optionalInstant(item.LastSyncedAt),
		CreatedAt: instant(item.CreatedAt), UpdatedAt: instant(item.UpdatedAt),
	}
	if item.Apple != nil {
		view.Apple = &principalView{AppleID: item.Apple.AppleID, Region: item.Apple.Region, DSID: item.Apple.DSID, Revision: decimal(item.Apple.Revision)}
	}
	return view
}

func decimal(value int64) string { return strconv.FormatInt(value, 10) }
func instant(value int64) string { return time.Unix(0, value).UTC().Format(time.RFC3339Nano) }
func optionalInstant(value *int64) *string {
	if value == nil {
		return nil
	}
	formatted := instant(*value)
	return &formatted
}

func currentMeta(w http.ResponseWriter) Meta { return Meta{RequestID: w.Header().Get("X-Request-ID")} }

func (a *ManagementAccounts) list(w http.ResponseWriter, r *http.Request) {
	meta := currentMeta(w)
	filter, page, size, err := parseAccountQuery(r)
	if err != nil {
		writeAccountError(w, meta, err, 0)
		return
	}
	result, err := a.accounts.List(r.Context(), filter, accounts.Page{Limit: size, Offset: int64(page-1) * int64(size)})
	if err != nil {
		writeAccountError(w, meta, err, 0)
		return
	}
	if result.Total > 1<<53-1 {
		WriteProblem(w, http.StatusInternalServerError, meta, internalProblem())
		return
	}
	items := make([]sourceView, len(result.Items))
	for i, item := range result.Items {
		items[i] = presentSource(item)
	}
	WriteResult(w, http.StatusOK, meta, struct {
		Items    []sourceView `json:"items"`
		Total    int64        `json:"total"`
		Page     int          `json:"page"`
		PageSize int          `json:"page_size"`
	}{items, result.Total, page, size})
}

func parseAccountQuery(r *http.Request) (accounts.Filter, int, int, error) {
	query := r.URL.Query()
	for name, values := range query {
		if len(values) != 1 || name != "query" && name != "kind" && name != "enabled" && name != "page" && name != "page_size" {
			return accounts.Filter{}, 0, 0, accounts.ErrInvalid
		}
	}
	filter := accounts.Filter{Query: query.Get("query"), Kind: accounts.Kind(query.Get("kind"))}
	if value, present := query["enabled"]; present {
		if value[0] != "true" && value[0] != "false" {
			return filter, 0, 0, accounts.ErrInvalid
		}
		boolean := value[0] == "true"
		filter.Enabled = &boolean
	}
	page, size := 1, accounts.DefaultLimit
	if _, present := query["page"]; present {
		parsed, err := strconv.ParseUint(query.Get("page"), 10, 31)
		if err != nil || parsed < 1 {
			return filter, 0, 0, accounts.ErrInvalid
		}
		page = int(parsed)
	}
	if _, present := query["page_size"]; present {
		parsed, err := strconv.ParseUint(query.Get("page_size"), 10, 16)
		if err != nil || parsed < 1 || parsed > accounts.MaximumLimit {
			return filter, 0, 0, accounts.ErrInvalid
		}
		size = int(parsed)
	}
	return filter, page, size, nil
}

func positiveDecimal(value string) (int64, bool) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil && parsed > 0 && strconv.FormatInt(parsed, 10) == value
}

func accountID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, ok := positiveDecimal(r.PathValue("source_id"))
	if !ok {
		writeAccountError(w, currentMeta(w), accounts.ErrInvalid, 0)
	}
	return id, ok
}

func (a *ManagementAccounts) get(w http.ResponseWriter, r *http.Request) {
	id, ok := accountID(w, r)
	if !ok {
		return
	}
	result, err := a.accounts.Get(r.Context(), id)
	if err != nil {
		writeAccountError(w, currentMeta(w), err, id)
		return
	}
	WriteResult(w, http.StatusOK, currentMeta(w), presentSource(result))
}

func (a *ManagementAccounts) create(w http.ResponseWriter, r *http.Request) {
	var input accounts.CreateInput
	if p := DecodeJSON(w, r, &input, 128<<10); p != nil {
		WriteProblem(w, http.StatusBadRequest, currentMeta(w), *p)
		return
	}
	result, err := a.accounts.Create(r.Context(), input)
	if err != nil {
		writeAccountError(w, currentMeta(w), err, result.ID)
		return
	}
	WriteResult(w, http.StatusCreated, currentMeta(w), presentSource(result))
}

func (a *ManagementAccounts) patch(w http.ResponseWriter, r *http.Request) {
	id, ok := accountID(w, r)
	if !ok {
		return
	}
	var input struct {
		ExpectedRevision string `json:"expected_revision"`
		accounts.Patch
	}
	if p := DecodeJSON(w, r, &input, 128<<10); p != nil {
		WriteProblem(w, http.StatusBadRequest, currentMeta(w), *p)
		return
	}
	revision, valid := positiveDecimal(input.ExpectedRevision)
	if !valid {
		writeAccountError(w, currentMeta(w), accounts.ErrInvalid, id)
		return
	}
	result, err := a.accounts.Patch(r.Context(), id, revision, input.Patch)
	if err != nil {
		writeAccountError(w, currentMeta(w), err, id)
		return
	}
	WriteResult(w, http.StatusOK, currentMeta(w), struct {
		Source                   sourceView `json:"source"`
		SourceChanged            bool       `json:"source_changed"`
		CredentialsChanged       bool       `json:"credentials_changed"`
		PreviousSourceGeneration string     `json:"previous_source_generation"`
	}{presentSource(result.Source), result.SourceChanged, result.CredentialsChanged, decimal(result.PreviousSourceGeneration)})
}

func (a *ManagementAccounts) reveal(w http.ResponseWriter, r *http.Request) {
	id, ok := accountID(w, r)
	if !ok {
		return
	}
	var command struct{}
	if p := DecodeJSON(w, r, &command, 1024); p != nil {
		WriteProblem(w, http.StatusBadRequest, currentMeta(w), *p)
		return
	}
	close, ok := a.beginSourceRead(w, r)
	if !ok {
		return
	}
	defer close()
	result, err := a.accounts.Reveal(r.Context(), id)
	if err != nil {
		writeAccountError(w, currentMeta(w), err, id)
		return
	}
	WriteResult(w, http.StatusOK, currentMeta(w), struct {
		Source      sourceView           `json:"source"`
		Credentials accounts.Credentials `json:"credentials"`
	}{presentSource(result.Source), result.Credentials})
}

func (a *ManagementAccounts) delete(w http.ResponseWriter, r *http.Request) {
	id, ok := accountID(w, r)
	if !ok {
		return
	}
	var command struct {
		ExpectedRevision string `json:"expected_revision"`
		OperationKey     string `json:"operation_key"`
	}
	if p := DecodeJSON(w, r, &command, 2048); p != nil {
		WriteProblem(w, http.StatusBadRequest, currentMeta(w), *p)
		return
	}
	revision, valid := positiveDecimal(command.ExpectedRevision)
	if !valid {
		writeAccountError(w, currentMeta(w), accounts.ErrInvalid, id)
		return
	}
	result, err := a.accounts.Delete(r.Context(), id, revision, command.OperationKey)
	if err != nil {
		writeAccountError(w, currentMeta(w), err, id)
		return
	}
	WriteResult(w, http.StatusOK, currentMeta(w), struct {
		OperationKey string `json:"operation_key"`
		SourceID     string `json:"source_id"`
		Deleted      bool   `json:"deleted"`
	}{result.OperationKey, decimal(result.SourceID), result.Deleted})
}

func writeAccountError(w http.ResponseWriter, meta Meta, err error, candidateID int64) {
	status, p := http.StatusInternalServerError, internalProblem()
	switch {
	case errors.Is(err, adminauth.ErrUnauthenticated):
		status, p = http.StatusUnauthorized, Problem{Kind: "authentication", Code: "SESSION_REAUTHENTICATION_REQUIRED", Message: "Sign in again before continuing.", Outcome: NotSent}
	case errors.Is(err, accounts.ErrSourceChangeFence):
		status, p = http.StatusServiceUnavailable, Problem{Kind: "admission", Code: "ACCOUNT_SOURCE_CHANGE_UNAVAILABLE", Message: "The source change barrier is unavailable. No change was started.", Outcome: NotSent}
	case errors.Is(err, accounts.ErrInvalid):
		status, p = http.StatusBadRequest, Problem{Kind: "invalid_request", Code: "ACCOUNT_INPUT_INVALID", Message: "Check the account fields and pagination.", Outcome: NotSent}
	case errors.Is(err, accounts.ErrNotFound):
		status, p = http.StatusNotFound, Problem{Kind: "not_found", Code: "ACCOUNT_NOT_FOUND", Message: "The account does not exist.", Outcome: NotSent}
	case errors.Is(err, accounts.ErrConflict):
		status, p = http.StatusConflict, Problem{Kind: "conflict", Code: "ACCOUNT_REVISION_CONFLICT", Message: "Refresh the account before making further changes.", Outcome: NotSent}
	case errors.Is(err, accounts.ErrIdentityLocked):
		status, p = http.StatusConflict, Problem{Kind: "conflict", Code: "ACCOUNT_IDENTITY_IN_USE", Message: "The account identity is in use by existing addresses.", Outcome: NotSent}
	case errors.Is(err, accounts.ErrSourceChangeRequired):
		status, p = http.StatusConflict, Problem{Kind: "confirmation", Code: "ACCOUNT_SOURCE_CHANGE_REQUIRED", Message: "Explicitly confirm that the incoming mail source will change.", Outcome: NotSent}
	case errors.Is(err, accounts.ErrCredentials):
		status, p = http.StatusConflict, Problem{Kind: "credentials", Code: "ACCOUNT_CREDENTIALS_UNAVAILABLE", Message: "Account credentials could not be opened.", Outcome: NotSent}
	case errors.Is(err, accounts.ErrDependentState):
		status, p = http.StatusConflict, Problem{Kind: "conflict", Code: "ACCOUNT_HAS_DEPENDENT_STATE", Message: "Use the account retirement workflow to preserve dependent state.", Outcome: NotSent}
	case errors.Is(err, accounts.ErrReadOnly):
		status, p = http.StatusServiceUnavailable, Problem{Kind: "maintenance", Code: "INSTALLATION_READ_ONLY", Message: "The installation is currently read-only.", Outcome: NotSent}
	case errors.Is(err, accounts.ErrCommitUnknown):
		status, p = http.StatusServiceUnavailable, Problem{Kind: "persistence", Code: "ACCOUNT_COMMIT_UNKNOWN", Message: "Query the candidate account before making another change.", Outcome: Unknown}
		if candidateID > 0 {
			p.Resource = &ResourceRef{Kind: "account", ID: decimal(candidateID)}
		}
	}
	WriteProblem(w, status, meta, p)
}

func (a *ManagementAccounts) export(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Format string          `json:"format"`
		Filter accounts.Filter `json:"filter"`
	}
	if p := DecodeJSON(w, r, &input, 4096); p != nil {
		WriteProblem(w, http.StatusBadRequest, currentMeta(w), *p)
		return
	}
	if input.Format != "csv" && input.Format != "jsonl" {
		writeAccountError(w, currentMeta(w), accounts.ErrInvalid, 0)
		return
	}
	close, ok := a.beginSourceRead(w, r)
	if !ok {
		return
	}
	defer close()
	started := false
	var csvOutput *csv.Writer
	start := func() {
		if started {
			return
		}
		started = true
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="accounts.%s"`, input.Format))
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		if input.Format == "csv" {
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			csvOutput = csv.NewWriter(w)
			_ = csvOutput.Write([]string{"source_json", "credentials_json"})
		}
	}
	encoder := json.NewEncoder(w)
	err := a.accounts.Export(r.Context(), input.Filter, func(item accounts.Revealed) error {
		start()
		source := presentSource(item.Source)
		if input.Format == "jsonl" {
			return encoder.Encode(struct {
				Source      sourceView           `json:"source"`
				Credentials accounts.Credentials `json:"credentials"`
			}{source, item.Credentials})
		}
		// Each CSV cell is a JSON object, so a spreadsheet never interprets an
		// untrusted label or exact password as a formula. Decoding the cell
		// recovers the original value without trimming or prefixing secrets.
		sourceJSON, marshalErr := json.Marshal(source)
		if marshalErr != nil {
			return marshalErr
		}
		credentialsJSON, marshalErr := json.Marshal(item.Credentials)
		if marshalErr != nil {
			return marshalErr
		}
		return csvOutput.Write([]string{string(sourceJSON), string(credentialsJSON)})
	})
	if err != nil {
		if started {
			// A partial sensitive export must fail its stream, not turn into a
			// successful truncated download or append a JSON error to CSV.
			panic(http.ErrAbortHandler)
		}
		writeAccountError(w, currentMeta(w), err, 0)
		return
	}
	start()
	if csvOutput != nil {
		csvOutput.Flush()
		if csvOutput.Error() != nil {
			panic(http.ErrAbortHandler)
		}
	}
}

// Parent mailbox passwords participate in the same read barrier as mailbox
// credentials. Hold it through the complete response before a source change.
func (a *ManagementAccounts) beginSourceRead(w http.ResponseWriter, r *http.Request) (func(), bool) {
	var scope io.Closer
	if a.readBarrier != nil {
		var err error
		scope, err = a.readBarrier(r.Context())
		if err != nil {
			WriteProblem(w, 503, currentMeta(w), Problem{Kind: "admission", Code: "SOURCE_CREDENTIAL_READ_UNAVAILABLE", Message: "Source credentials are not currently available."})
			return nil, false
		}
	}
	close := func() {
		if scope != nil {
			_ = scope.Close()
		}
	}
	if _, err := a.identity.identity.Authenticate(r.Context(), cookieValue(r, sessionCookie)); err != nil {
		close()
		a.identity.writeAuthError(w, currentMeta(w), err)
		return nil, false
	}
	return close, true
}
