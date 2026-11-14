package httpapi

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"icloudspace/internal/addressauth"
	"icloudspace/internal/addresses"
)

type ManagementCredentialExports struct {
	identity  *ManagementAuth
	authority *addressauth.Authority
	addresses *addresses.Service
}

func NewManagementCredentialExports(identity *ManagementAuth, authority *addressauth.Authority, owner *addresses.Service) (*ManagementCredentialExports, error) {
	if identity == nil || authority == nil || owner == nil {
		return nil, errors.New("httpapi: credential export owners required")
	}
	return &ManagementCredentialExports{identity, authority, owner}, nil
}
func (a *ManagementCredentialExports) Register(mux *http.ServeMux) {
	mux.Handle("POST "+a.identity.basePath+"/addresses/credential-exports", a.identity.RequireSession(http.HandlerFunc(a.export)))
}

type credentialExportRecord struct {
	Type       string                      `json:"type"`
	Version    int                         `json:"version"`
	Kind       string                      `json:"kind"`
	AddressID  string                      `json:"address_id,omitempty"`
	SourceID   string                      `json:"source_id,omitempty"`
	Address    string                      `json:"address,omitempty"`
	Generation string                      `json:"generation,omitempty"`
	API        *addressauth.APIKeyMaterial `json:"api,omitempty"`
	Bundle     *addressauth.Bundle         `json:"bundle,omitempty"`
	Count      *string                     `json:"count,omitempty"`
	Links      *credentialCopyLinks        `json:"links,omitempty"`
}

type credentialCopyLinks struct {
	OTP    string `json:"otp"`
	Recent string `json:"recent"`
	Raw    string `json:"raw"`
}

func (a *ManagementCredentialExports) fail(w http.ResponseWriter, r *http.Request, e error) {
	if errors.Is(e, addressauth.ErrInvalid) || errors.Is(e, addresses.ErrInvalid) {
		WriteProblem(w, 400, currentMeta(w), Problem{Kind: "invalid_request", Code: "CREDENTIAL_EXPORT_INPUT_INVALID", Message: "Check the credential export kind, format and explicit selection."})
		return
	}
	if errors.Is(e, addresses.ErrIneligible) || errors.Is(e, addresses.ErrNotFound) {
		WriteProblem(w, 409, currentMeta(w), Problem{Kind: "eligibility", Code: "CREDENTIAL_EXPORT_SELECTION_INELIGIBLE", Message: "Every selected address must exist and be confirmed without deletion."})
		return
	}
	if errors.Is(e, addressauth.ErrUnavailable) || errors.Is(e, addressauth.ErrCredentials) {
		WriteProblem(w, 409, currentMeta(w), Problem{Kind: "material", Code: "CREDENTIAL_MATERIAL_UNAVAILABLE", Message: "Original current credential material could not be verified."})
		return
	}
	WriteProblem(w, 500, currentMeta(w), internalProblem())
}
func (a *ManagementCredentialExports) export(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Kind        string              `json:"kind"`
		Format      string              `json:"format"`
		Filter      *addressFilterInput `json:"filter"`
		SelectedIDs []string            `json:"selected_ids"`
		CopyFormat  bool                `json:"copy_format"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	if input.Kind != "api_key" && input.Kind != "mailbox" || input.Format != "jsonl" && input.Format != "csv" || (input.Filter == nil) == (input.SelectedIDs == nil) {
		a.fail(w, r, addressauth.ErrInvalid)
		return
	}
	var filter addresses.Filter
	var ids []int64
	var e error
	if input.Filter != nil {
		filter, e = input.Filter.filter()
	} else {
		if len(input.SelectedIDs) < 1 || len(input.SelectedIDs) > addresses.MaximumLimit {
			e = addresses.ErrInvalid
		}
		for _, raw := range input.SelectedIDs {
			id, ok := positiveDecimal(raw)
			if !ok {
				e = addresses.ErrInvalid
				break
			}
			ids = append(ids, id)
		}
	}
	if e != nil {
		a.fail(w, r, e)
		return
	}
	var selectedFilter *addresses.Filter
	selectionMode := "selection"
	if input.Filter != nil {
		selectedFilter = &filter
		selectionMode = "filter"
	}
	selection, e := a.addresses.CredentialExportSelection(selectedFilter, ids)
	if input.CopyFormat {
		selection, e = a.addresses.CredentialCopySelection(selectedFilter, ids)
	}
	if e != nil {
		a.fail(w, r, e)
		return
	}
	scope, e := a.authority.BeginReveal(r.Context())
	if e != nil {
		a.fail(w, r, e)
		return
	}
	defer scope.Close()
	// Natural session expiry may occur while waiting behind Authority EX. The
	// management read gate is already held, so no nested credential gate occurs.
	session, e := a.identity.identity.Authenticate(r.Context(), cookieValue(r, sessionCookie))
	if e != nil {
		a.identity.writeAuthError(w, currentMeta(w), e)
		return
	}
	if !a.identity.identity.ValidateCSRF(session, r.Header.Get("X-CSRF-Token")) {
		WriteProblem(w, 403, currentMeta(w), Problem{Kind: "authorization", Code: "CSRF_INVALID", Message: "Refresh the management session before exporting credentials."})
		return
	}
	audit := addressauth.ExportAudit{Kind: input.Kind, Format: input.Format, Selection: selectionMode, SessionEpoch: session.Epoch()}
	recordAudit := func(stage, outcome, reason string, count uint64, detached bool) error {
		ctx := r.Context()
		if detached {
			ctx = context.WithoutCancel(ctx)
		}
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		value := audit
		value.Stage = stage
		value.Outcome = outcome
		value.Reason = reason
		value.Count = count
		return scope.RecordExportAudit(ctx, value)
	}
	warn := func(code string, count uint64) {
		slog.WarnContext(r.Context(), "credential_export", "component", "credential_export", "request_id", currentMeta(w).RequestID, "reason_code", code, "stored", strconv.FormatUint(count, 10))
	}
	// These are phase facts for the canonical streaming representation. The
	// first audit means authorized, not all material prepared or delivered. The
	// second confirms complete preparation before publishing the terminal proof.
	if e = recordAudit("authorized", "success", "", 0, false); e != nil {
		a.fail(w, r, e)
		return
	}
	started := false
	var output *csv.Writer
	start := func() error {
		if started {
			return nil
		}
		started = true
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Space-Credential-Export", "1")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="address-credentials.%s"`, input.Format))
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		if input.Format == "csv" {
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			output = csv.NewWriter(w)
			return output.Write([]string{"credential_record_json"})
		}
		return nil
	}
	write := func(record credentialExportRecord) error {
		if e := start(); e != nil {
			return e
		}
		if output == nil {
			return json.NewEncoder(w).Encode(record)
		}
		data, e := json.Marshal(record)
		if e != nil {
			return e
		}
		if e = output.Write([]string{string(data)}); e != nil {
			return e
		}
		output.Flush()
		return output.Error()
	}
	writeFailed := false
	export := scope.Export
	if input.CopyFormat {
		export = scope.ExportForCopy
	}
	count, e := export(r.Context(), input.Kind, selection, func(item addressauth.ExportCredential) error {
		record := credentialExportRecord{Type: "credential", Version: 1, Kind: input.Kind, AddressID: decimal(item.AddressID), SourceID: decimal(item.SourceID), Address: item.Address, Generation: decimal(item.Generation), API: item.API, Bundle: item.Bundle}
		if input.CopyFormat && input.Kind == "api_key" {
			otp, err := a.authority.CompatibilityOTPToken(item.AddressID, item.API.Key)
			if err != nil {
				return err
			}
			recent, err := a.authority.CompatibilityRecentToken(item.AddressID, item.API.Key)
			if err != nil {
				return err
			}
			base := "/api/v1/otp?token=" + url.QueryEscape(otp)
			record.Links = &credentialCopyLinks{OTP: base + "&latest_only=true&otp_only=true", Recent: "/api/v1/mail/recent?api_key=" + url.QueryEscape(recent), Raw: base + "&raw_mail=true&latest_only=false"}
		}
		err := write(record)
		if err != nil {
			writeFailed = true
		}
		return err
	})
	if e != nil {
		reason := "material_unavailable"
		if writeFailed {
			reason = "stream_write_failed"
		} else if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
			reason = "cancelled"
		}
		if auditErr := recordAudit("failed", "failure", reason, count, true); auditErr != nil {
			warn("export_audit_unconfirmed", count)
		}
		if started {
			warn(reason, count)
			panic(http.ErrAbortHandler)
		}
		a.fail(w, r, e)
		return
	}
	if e = recordAudit("prepared", "success", "", count, false); e != nil {
		warn("export_audit_unconfirmed", count)
		if started {
			panic(http.ErrAbortHandler)
		}
		a.fail(w, r, e)
		return
	}
	completeCount := strconv.FormatUint(count, 10)
	if e = write(credentialExportRecord{Type: "complete", Version: 1, Kind: input.Kind, Count: &completeCount}); e != nil {
		warn("stream_write_failed", count)
		panic(http.ErrAbortHandler)
	}
	// The terminal record is emitted only after the metadata transaction also
	// completed. A truncated HTTP200 is not a completed downloadable export.
	if e := http.NewResponseController(w).Flush(); e != nil && !errors.Is(e, http.ErrNotSupported) {
		warn("stream_flush_failed", count)
		panic(http.ErrAbortHandler)
	}
}
