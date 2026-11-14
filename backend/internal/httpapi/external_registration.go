package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"icloudspace/internal/addressauth"
	"icloudspace/internal/addresses"
	"icloudspace/internal/externalregistration"
)

const ExternalRegistrationBase = "/api/external-registrations/v1"

type ExternalRegistration struct{ owner *externalregistration.Service }

func NewExternalRegistration(owner *externalregistration.Service) (*ExternalRegistration, error) {
	if owner == nil {
		return nil, errors.New("httpapi: external registration owner required")
	}
	return &ExternalRegistration{owner}, nil
}
func (a *ExternalRegistration) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+ExternalRegistrationBase, a.register)
	mux.HandleFunc("POST "+ExternalRegistrationBase+"/query", a.query)
	mux.HandleFunc("POST /api/v1/aliases", a.compatibleRegister)
	mux.HandleFunc("POST /api/v1/aliases/{$}", a.compatibleRegister)
}

func (a *ExternalRegistration) access(w http.ResponseWriter, r *http.Request) (externalregistration.Access, bool) {
	if _, ok := requestMeta(w); !ok {
		return externalregistration.Access{}, false
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	values := r.Header.Values("Authorization")
	if len(values) == 1 {
		scheme, raw, ok := strings.Cut(values[0], " ")
		if ok && strings.EqualFold(scheme, "Bearer") {
			if access, err := a.owner.Authenticate(raw); err == nil {
				return access, true
			}
		}
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="external-registration"`)
	WriteProblem(w, 401, currentMeta(w), Problem{Kind: "authentication", Code: "EXTERNAL_REGISTRATION_UNAUTHORIZED", Message: "Deployment registration authorization is required."})
	return externalregistration.Access{}, false
}

func externalRegistrationBody(w http.ResponseWriter, r *http.Request, query bool) (map[string]string, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil || len(raw) > 4096 || !utf8.Valid(raw) {
		return nil, false
	}
	defer clear(raw)
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, false
	}
	fields := map[string]string{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, exists := fields[name]; exists {
			return nil, false
		}
		if name != "source_id" && name != "operation_key" && (query || name != "address") {
			return nil, false
		}
		var value string
		if d.Decode(&value) != nil {
			return nil, false
		}
		fields[name] = value
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return nil, false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, false
	}
	want := 3
	if query {
		want = 2
	}
	return fields, len(fields) == want
}

type externalRegistrationView struct {
	OperationKey      string              `json:"operation_key"`
	SourceID          string              `json:"source_id"`
	Address           string              `json:"address"`
	State             string              `json:"state"`
	AddressID         *string             `json:"address_id"`
	Generation        *string             `json:"generation"`
	DeliveryKey       *string             `json:"delivery_key"`
	QueryOnly         bool                `json:"query_only"`
	Available         bool                `json:"available"`
	UnavailableReason *string             `json:"unavailable_reason"`
	EffectiveEnabled  bool                `json:"effective_enabled"`
	Bundle            *addressauth.Bundle `json:"bundle,omitempty"`
}

func externalView(d *externalregistration.Delivery) externalRegistrationView {
	r := d.Receipt
	out := externalRegistrationView{OperationKey: r.OperationKey, SourceID: strconv.FormatInt(r.SourceID, 10), Address: r.Address, State: r.State, QueryOnly: true, Available: r.Available, EffectiveEnabled: r.EffectiveEnabled, Bundle: d.Bundle}
	if r.AddressID > 0 {
		x := strconv.FormatInt(r.AddressID, 10)
		out.AddressID = &x
	}
	if r.Generation > 0 {
		x := strconv.FormatInt(r.Generation, 10)
		out.Generation = &x
	}
	if r.DeliveryKey != "" {
		x := r.DeliveryKey
		out.DeliveryKey = &x
	}
	if r.UnavailableReason != "" {
		x := r.UnavailableReason
		out.UnavailableReason = &x
	}
	return out
}
func (a *ExternalRegistration) fail(w http.ResponseWriter, err error, source, key string) {
	status, code, message := 500, "EXTERNAL_REGISTRATION_FAILED", "The local registration could not be completed."
	switch {
	case errors.Is(err, externalregistration.ErrUnauthorized):
		status, code, message = 401, "EXTERNAL_REGISTRATION_UNAUTHORIZED", "Deployment registration authorization is required."
	case errors.Is(err, externalregistration.ErrInvalid) || errors.Is(err, addresses.ErrInvalid):
		status, code, message = 400, "EXTERNAL_REGISTRATION_INPUT_INVALID", "Check the source, address and original operation key."
	case errors.Is(err, externalregistration.ErrNotFound) || errors.Is(err, addresses.ErrNotFound):
		status, code, message = 404, "EXTERNAL_REGISTRATION_NOT_FOUND", "The requested registration resource is unavailable."
	case errors.Is(err, externalregistration.ErrUnknown) || errors.Is(err, addressauth.ErrOutcomeUnknown):
		status, code, message = 503, "EXTERNAL_REGISTRATION_UNKNOWN", "Query the original source and operation key; do not register again."
	case errors.Is(err, externalregistration.ErrReadOnly) || errors.Is(err, addressauth.ErrReadOnly):
		status, code, message = 503, "EXTERNAL_REGISTRATION_READ_ONLY", "Local registration writes are currently disabled."
	case errors.Is(err, addresses.ErrCapacity):
		status, code, message = 409, "EXTERNAL_REGISTRATION_CAPACITY", "The source's enabled and pending registration capacity is full."
	case errors.Is(err, externalregistration.ErrQueryOnly):
		status, code, message = 409, "EXTERNAL_REGISTRATION_QUERY_ONLY", "Query the original registration operation."
	case errors.Is(err, externalregistration.ErrConflict) || errors.Is(err, addresses.ErrConflict):
		status, code, message = 409, "EXTERNAL_REGISTRATION_CONFLICT", "The address or original operation conflicts with current state."
	}
	p := Problem{Kind: "registration", Code: code, Message: message}
	if source != "" && key != "" {
		p.SubmissionKey = key
		p.Resource = &ResourceRef{Kind: "external_registration", ID: source + ":" + key}
		if status == 503 && code == "EXTERNAL_REGISTRATION_UNKNOWN" {
			p.Outcome = Unknown
		}
	}
	WriteProblem(w, status, currentMeta(w), p)
}
func (a *ExternalRegistration) register(w http.ResponseWriter, r *http.Request) {
	access, ok := a.access(w, r)
	if !ok {
		return
	}
	fields, ok := externalRegistrationBody(w, r, false)
	if !ok {
		a.fail(w, externalregistration.ErrInvalid, "", "")
		return
	}
	source, ok := positiveDecimal(fields["source_id"])
	if !ok {
		a.fail(w, externalregistration.ErrInvalid, "", "")
		return
	}
	delivery, err := a.owner.Register(r.Context(), access, externalregistration.Request{SourceID: source, Address: fields["address"], OperationKey: fields["operation_key"]})
	if delivery != nil {
		defer delivery.Close()
	}
	if err != nil {
		a.fail(w, err, fields["source_id"], fields["operation_key"])
		return
	}
	WriteResult(w, 201, currentMeta(w), externalView(delivery))
}
func (a *ExternalRegistration) query(w http.ResponseWriter, r *http.Request) {
	access, ok := a.access(w, r)
	if !ok {
		return
	}
	fields, ok := externalRegistrationBody(w, r, true)
	if !ok {
		a.fail(w, externalregistration.ErrInvalid, "", "")
		return
	}
	source, ok := positiveDecimal(fields["source_id"])
	if !ok {
		a.fail(w, externalregistration.ErrInvalid, "", "")
		return
	}
	delivery, err := a.owner.Query(r.Context(), access, externalregistration.Query{SourceID: source, OperationKey: fields["operation_key"]})
	if delivery != nil {
		defer delivery.Close()
	}
	if err != nil {
		a.fail(w, err, fields["source_id"], fields["operation_key"])
		return
	}
	WriteResult(w, 200, currentMeta(w), externalView(delivery))
}
