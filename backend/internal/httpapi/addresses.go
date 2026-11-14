package httpapi

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"icloudspace/internal/addresses"
	"icloudspace/internal/adminauth"
)

// ManagementAddresses exposes metadata by default. Credential delivery is a
// separate authority boundary and never piggybacks on an address listing.
type ManagementAddresses struct {
	identity  *ManagementAuth
	addresses *addresses.Service
}

func NewManagementAddresses(identity *ManagementAuth, service *addresses.Service) (*ManagementAddresses, error) {
	if identity == nil || service == nil {
		return nil, errors.New("httpapi: management identity and address owner are required")
	}
	return &ManagementAddresses{identity: identity, addresses: service}, nil
}

func (a *ManagementAddresses) Register(mux *http.ServeMux) {
	base := a.identity.basePath
	local := map[string]bool{
		"POST " + base + "/addresses":                    true,
		"POST " + base + "/addresses/random":             true,
		"POST " + base + "/addresses/move":               true,
		"PATCH " + base + "/addresses/{address_id}":      true,
		"DELETE " + base + "/addresses/{address_id}":     true,
		"POST " + base + "/addresses/{address_id}/purge": true,
		"POST " + base + "/address-groups":               true,
		"PATCH " + base + "/address-groups/{group_id}":   true,
		"DELETE " + base + "/address-groups/{group_id}":  true,
	}
	for pattern, handler := range map[string]http.HandlerFunc{
		"GET " + base + "/addresses":                                     a.list,
		"GET " + base + "/addresses/historical-removals":                 a.historicalRemovals,
		"POST " + base + "/addresses":                                    a.create,
		"POST " + base + "/addresses/random":                             a.random,
		"POST " + base + "/addresses/export":                             a.export,
		"POST " + base + "/addresses/move":                               a.move,
		"GET " + base + "/addresses/{address_id}":                        a.get,
		"PATCH " + base + "/addresses/{address_id}":                      a.patch,
		"DELETE " + base + "/addresses/{address_id}":                     a.deleteLocal,
		"POST " + base + "/addresses/{address_id}/purge":                 a.purge,
		"GET " + base + "/addresses/{address_id}/purges/{operation_key}": a.queryPurge,
		"GET " + base + "/address-groups":                                a.groups,
		"POST " + base + "/address-groups":                               a.createGroup,
		"PATCH " + base + "/address-groups/{group_id}":                   a.renameGroup,
		"DELETE " + base + "/address-groups/{group_id}":                  a.deleteGroup,
	} {
		if local[pattern] {
			mux.Handle(pattern, a.identity.RequireLocalCommand(handler))
		} else {
			mux.Handle(pattern, a.identity.RequireSession(handler))
		}
	}
}

type archiveNoticeView struct {
	Reason     string `json:"reason"`
	ArchivedAt string `json:"archived_at"`
}

type addressView struct {
	ID                   string             `json:"id"`
	SourceID             string             `json:"source_id"`
	SourceLabel          string             `json:"source_label"`
	SourceKind           string             `json:"source_kind"`
	Address              string             `json:"address"`
	Kind                 string             `json:"kind"`
	Label                string             `json:"label"`
	GroupID              *string            `json:"group_id"`
	Lifecycle            string             `json:"lifecycle"`
	Enabled              bool               `json:"enabled"`
	Revision             string             `json:"revision"`
	AuthGeneration       string             `json:"auth_generation"`
	UIDValidity          string             `json:"uid_validity"`
	UIDNext              string             `json:"uid_next"`
	HasMail              bool               `json:"has_mail"`
	CredentialProfile    string             `json:"credential_profile"`
	RegistrationBanned   bool               `json:"registration_banned"`
	RegistrationBannedAt *string            `json:"registration_banned_at"`
	LatestReceivedAt     *string            `json:"latest_received_at"`
	Capabilities         []string           `json:"capabilities"`
	ArchiveNotice        *archiveNoticeView `json:"archive_notice"`
	LastSyncState        string             `json:"last_sync_state"`
	LastSyncError        string             `json:"last_sync_error"`
	LastSyncedAt         *string            `json:"last_synced_at"`
	LastAccessedAt       *string            `json:"last_accessed_at"`
	CreatedAt            string             `json:"created_at"`
	UpdatedAt            string             `json:"updated_at"`
}

func optionalDecimal(value *int64) *string {
	if value == nil {
		return nil
	}
	text := decimal(*value)
	return &text
}

func presentAddress(item addresses.Metadata) addressView {
	view := addressView{
		ID: decimal(item.ID), SourceID: decimal(item.SourceID), SourceLabel: item.SourceLabel, SourceKind: item.SourceKind, Address: item.Address,
		Kind: item.Kind, Label: item.Label, GroupID: optionalDecimal(item.GroupID),
		Lifecycle: item.Lifecycle, Enabled: item.Enabled, Revision: decimal(item.Revision),
		AuthGeneration: decimal(item.AuthGeneration), UIDValidity: decimal(item.UIDValidity),
		UIDNext: decimal(item.UIDNext), HasMail: item.HasMail,
		CredentialProfile: item.CredentialProfile, RegistrationBanned: item.RegistrationBanned,
		RegistrationBannedAt: optionalInstant(item.RegistrationBannedAt), LatestReceivedAt: optionalInstant(item.LatestReceivedAt),
		Capabilities:  append([]string{}, item.Capabilities...),
		LastSyncState: item.LastSyncState, LastSyncError: item.LastSyncError,
		LastSyncedAt: optionalInstant(item.LastSyncedAt), LastAccessedAt: optionalInstant(item.LastAccessedAt),
		CreatedAt: instant(item.CreatedAt), UpdatedAt: instant(item.UpdatedAt),
	}
	if item.Lifecycle == "archived" && item.ArchivedAt != nil && item.ArchiveReason != nil {
		view.ArchiveNotice = &archiveNoticeView{Reason: *item.ArchiveReason, ArchivedAt: instant(*item.ArchivedAt)}
	}
	return view
}

type addressFilterInput struct {
	SourceID  *string `json:"source_id"`
	GroupID   *string `json:"group_id"`
	Ungrouped bool    `json:"ungrouped"`
	Query     string  `json:"query"`
	Enabled   *bool   `json:"enabled"`
	HasMail   *bool   `json:"has_mail"`
	Archive   string  `json:"archive"`
}

func optionalID(value *string) (*int64, error) {
	if value == nil {
		return nil, nil
	}
	id, ok := positiveDecimal(*value)
	if !ok {
		return nil, addresses.ErrInvalid
	}
	return &id, nil
}

func (input addressFilterInput) filter() (addresses.Filter, error) {
	source, err := optionalID(input.SourceID)
	if err != nil {
		return addresses.Filter{}, err
	}
	group, err := optionalID(input.GroupID)
	return addresses.Filter{SourceID: source, GroupID: group, Ungrouped: input.Ungrouped, Query: input.Query,
		Enabled: input.Enabled, HasMail: input.HasMail, Archive: input.Archive}, err
}

func parseAddressQuery(r *http.Request) (addresses.Filter, int, int, error) {
	q := r.URL.Query()
	input := addressFilterInput{Query: q.Get("query"), Archive: q.Get("archive")}
	page, size := 1, addresses.DefaultLimit
	for name, values := range q {
		if len(values) != 1 {
			return addresses.Filter{}, 0, 0, addresses.ErrInvalid
		}
		switch name {
		case "source_id":
			input.SourceID = &values[0]
		case "group_id":
			input.GroupID = &values[0]
		case "query", "archive":
		case "ungrouped", "enabled", "has_mail":
			if values[0] != "true" && values[0] != "false" {
				return addresses.Filter{}, 0, 0, addresses.ErrInvalid
			}
			v := values[0] == "true"
			switch name {
			case "ungrouped":
				input.Ungrouped = v
			case "enabled":
				input.Enabled = &v
			case "has_mail":
				input.HasMail = &v
			}
		case "page", "page_size":
			v, err := strconv.ParseUint(values[0], 10, 31)
			if err != nil || v < 1 || name == "page_size" && v > addresses.MaximumLimit {
				return addresses.Filter{}, 0, 0, addresses.ErrInvalid
			}
			if name == "page" {
				page = int(v)
			} else {
				size = int(v)
			}
		default:
			return addresses.Filter{}, 0, 0, addresses.ErrInvalid
		}
	}
	filter, err := input.filter()
	return filter, page, size, err
}

func (a *ManagementAddresses) list(w http.ResponseWriter, r *http.Request) {
	filter, page, size, err := parseAddressQuery(r)
	if err != nil {
		writeAddressError(w, r, err, nil)
		return
	}
	result, err := a.addresses.List(r.Context(), filter, addresses.Page{Limit: size, Offset: int64(page-1) * int64(size)})
	if err != nil {
		writeAddressError(w, r, err, nil)
		return
	}
	if result.Total > 1<<53-1 {
		WriteProblem(w, 500, currentMeta(w), internalProblem())
		return
	}
	items := make([]addressView, len(result.Items))
	for i, item := range result.Items {
		items[i] = presentAddress(item)
	}
	WriteResult(w, 200, currentMeta(w), struct {
		Items    []addressView `json:"items"`
		Total    int64         `json:"total"`
		Page     int           `json:"page"`
		PageSize int           `json:"page_size"`
	}{items, result.Total, page, size})
}

func pathID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, ok := positiveDecimal(r.PathValue(name))
	if !ok {
		writeAddressError(w, r, addresses.ErrInvalid, nil)
	}
	return id, ok
}

func addressReference(id int64) *ResourceRef {
	if id < 1 {
		return nil
	}
	return &ResourceRef{Kind: "address", ID: decimal(id)}
}

func managementOwner(r *http.Request) string {
	session, ok := AuthenticatedSession(r.Context())
	if !ok {
		return ""
	}
	return "operator:" + decimal(session.Operator.ID)
}

func (a *ManagementAddresses) get(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "address_id")
	if !ok {
		return
	}
	item, err := a.addresses.Get(r.Context(), id)
	if err != nil {
		writeAddressError(w, r, err, addressReference(id))
		return
	}
	WriteResult(w, 200, currentMeta(w), presentAddress(item))
}

func addressBody(w http.ResponseWriter, r *http.Request, input any) bool {
	if problem := DecodeJSON(w, r, input, 128<<10); problem != nil {
		WriteProblem(w, 400, currentMeta(w), *problem)
		return false
	}
	return true
}

func (a *ManagementAddresses) create(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SourceID          string  `json:"source_id"`
		Address           string  `json:"address"`
		Label             string  `json:"label"`
		GroupID           *string `json:"group_id"`
		Enabled           bool    `json:"enabled"`
		CredentialProfile string  `json:"credential_profile"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	source, ok := positiveDecimal(input.SourceID)
	group, err := optionalID(input.GroupID)
	if !ok || err != nil {
		writeAddressError(w, r, addresses.ErrInvalid, nil)
		return
	}
	item, err := a.addresses.CreateLocal(r.Context(), addresses.CreateInput{SourceID: source, Address: input.Address,
		Label: input.Label, GroupID: group, Enabled: input.Enabled, CredentialProfile: input.CredentialProfile, OwnerKey: managementOwner(r)})
	if err != nil {
		writeAddressError(w, r, err, addressReference(item.ID))
		return
	}
	WriteResult(w, 201, currentMeta(w), presentAddress(item))
}

func (a *ManagementAddresses) random(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SourceID          string  `json:"source_id"`
		Count             int     `json:"count"`
		Label             string  `json:"label"`
		GroupID           *string `json:"group_id"`
		CredentialProfile string  `json:"credential_profile"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	source, ok := positiveDecimal(input.SourceID)
	group, err := optionalID(input.GroupID)
	if !ok || err != nil {
		writeAddressError(w, r, addresses.ErrInvalid, nil)
		return
	}
	items, err := a.addresses.CreateRandom(r.Context(), addresses.RandomInput{SourceID: source, Count: input.Count,
		Label: input.Label, GroupID: group, CredentialProfile: input.CredentialProfile, OwnerKey: managementOwner(r)})
	if err != nil {
		writeAddressError(w, r, err, nil)
		return
	}
	views := make([]addressView, len(items))
	for i, item := range items {
		views[i] = presentAddress(item)
	}
	WriteResult(w, 201, currentMeta(w), views)
}

func (a *ManagementAddresses) patch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "address_id")
	if !ok {
		return
	}
	var input struct {
		ExpectedRevision string          `json:"expected_revision"`
		Label            *string         `json:"label"`
		Enabled          *bool           `json:"enabled"`
		GroupID          json.RawMessage `json:"group_id"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	revision, ok := positiveDecimal(input.ExpectedRevision)
	var group *string
	if len(input.GroupID) != 0 && json.Unmarshal(input.GroupID, &group) != nil {
		ok = false
	}
	groupID, err := optionalID(group)
	if !ok || err != nil {
		writeAddressError(w, r, addresses.ErrInvalid, nil)
		return
	}
	item, err := a.addresses.Patch(r.Context(), id, addresses.PatchInput{ExpectedRevision: revision,
		Label: input.Label, Enabled: input.Enabled, Group: addresses.GroupChange{Set: len(input.GroupID) != 0, ID: groupID}})
	if err != nil {
		writeAddressError(w, r, err, addressReference(id))
		return
	}
	WriteResult(w, 200, currentMeta(w), presentAddress(item))
}

func (a *ManagementAddresses) deleteLocal(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "address_id")
	if !ok {
		return
	}
	var input struct {
		ExpectedRevision string `json:"expected_revision"`
		ConfirmAddress   string `json:"confirm_address"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	revision, ok := positiveDecimal(input.ExpectedRevision)
	if !ok {
		writeAddressError(w, r, addresses.ErrInvalid, nil)
		return
	}
	if err := a.addresses.DeleteLocal(r.Context(), id, revision, input.ConfirmAddress); err != nil {
		writeAddressError(w, r, err, addressReference(id))
		return
	}
	WriteResult(w, 200, currentMeta(w), struct {
		ID       string `json:"id"`
		Archived bool   `json:"archived"`
	}{decimal(id), true})
}

func (a *ManagementAddresses) historicalRemovals(w http.ResponseWriter, r *http.Request) {
	for name := range r.URL.Query() {
		if name != "source_id" && name != "query" && name != "page" && name != "page_size" {
			writeAddressError(w, r, addresses.ErrInvalid, nil)
			return
		}
	}
	filter, page, size, err := parseAddressQuery(r)
	if err != nil {
		writeAddressError(w, r, err, nil)
		return
	}
	result, err := a.addresses.HistoricalRemovals(r.Context(), filter.SourceID, filter.Query, addresses.Page{Limit: size, Offset: int64(page-1) * int64(size)})
	if err != nil {
		writeAddressError(w, r, err, nil)
		return
	}
	type item struct {
		ID          string `json:"id"`
		SourceID    string `json:"source_id"`
		SourceLabel string `json:"source_label"`
		Address     string `json:"address"`
		Kind        string `json:"kind"`
		Revision    string `json:"revision"`
		DeletedAt   string `json:"deleted_at"`
	}
	items := make([]item, len(result.Items))
	for i, entry := range result.Items {
		items[i] = item{decimal(entry.ID), decimal(entry.SourceID), entry.SourceLabel, entry.Address, entry.Kind, decimal(entry.Revision), instant(entry.DeletedAt)}
	}
	WriteResult(w, 200, currentMeta(w), struct {
		Items    []item `json:"items"`
		Total    int64  `json:"total"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
	}{items, result.Total, page, size})
}

type groupView struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Revision     string `json:"revision"`
	AddressCount string `json:"address_count"`
}

func presentGroup(item addresses.Group) groupView {
	return groupView{decimal(item.ID), item.Name, decimal(item.Revision), decimal(item.AddressCount)}
}

func (a *ManagementAddresses) groups(w http.ResponseWriter, r *http.Request) {
	items, err := a.addresses.Groups(r.Context())
	if err != nil {
		writeAddressError(w, r, err, nil)
		return
	}
	views := make([]groupView, len(items))
	for i, item := range items {
		views[i] = presentGroup(item)
	}
	WriteResult(w, 200, currentMeta(w), views)
}
func (a *ManagementAddresses) createGroup(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name string `json:"name"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	item, err := a.addresses.CreateGroup(r.Context(), input.Name)
	if err != nil {
		var ref *ResourceRef
		if item.ID > 0 {
			ref = &ResourceRef{Kind: "address_group", ID: decimal(item.ID)}
		}
		writeAddressError(w, r, err, ref)
		return
	}
	WriteResult(w, 201, currentMeta(w), presentGroup(item))
}
func (a *ManagementAddresses) renameGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "group_id")
	if !ok {
		return
	}
	var input struct {
		ExpectedRevision string `json:"expected_revision"`
		Name             string `json:"name"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	revision, ok := positiveDecimal(input.ExpectedRevision)
	if !ok {
		writeAddressError(w, r, addresses.ErrInvalid, nil)
		return
	}
	item, err := a.addresses.RenameGroup(r.Context(), id, revision, input.Name)
	if err != nil {
		writeAddressError(w, r, err, &ResourceRef{Kind: "address_group", ID: decimal(id)})
		return
	}
	WriteResult(w, 200, currentMeta(w), presentGroup(item))
}
func (a *ManagementAddresses) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "group_id")
	if !ok {
		return
	}
	var input struct {
		ExpectedRevision string `json:"expected_revision"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	revision, ok := positiveDecimal(input.ExpectedRevision)
	if !ok {
		writeAddressError(w, r, addresses.ErrInvalid, nil)
		return
	}
	if err := a.addresses.DeleteGroup(r.Context(), id, revision); err != nil {
		writeAddressError(w, r, err, &ResourceRef{Kind: "address_group", ID: decimal(id)})
		return
	}
	WriteResult(w, 200, currentMeta(w), struct {
		ID      string `json:"id"`
		Deleted bool   `json:"deleted"`
	}{decimal(id), true})
}

func (a *ManagementAddresses) move(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Selection []struct {
			ID               string `json:"id"`
			ExpectedRevision string `json:"expected_revision"`
		} `json:"selection"`
		GroupID *string `json:"group_id"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	group, err := optionalID(input.GroupID)
	selection := make([]addresses.Selection, len(input.Selection))
	for i, item := range input.Selection {
		id, validID := positiveDecimal(item.ID)
		revision, validRevision := positiveDecimal(item.ExpectedRevision)
		if !validID || !validRevision {
			err = addresses.ErrInvalid
		}
		selection[i] = addresses.Selection{ID: id, ExpectedRevision: revision}
	}
	if err != nil {
		writeAddressError(w, r, err, nil)
		return
	}
	items, err := a.addresses.Move(r.Context(), selection, group)
	if err != nil {
		writeAddressError(w, r, err, nil)
		return
	}
	views := make([]addressView, len(items))
	for i, item := range items {
		views[i] = presentAddress(item)
	}
	WriteResult(w, 200, currentMeta(w), views)
}

type addressOperationView struct {
	Key       string  `json:"operation_key"`
	SourceID  string  `json:"source_id"`
	AddressID *string `json:"address_id"`
	Kind      string  `json:"kind"`
	State     string  `json:"state"`
	ErrorCode string  `json:"error_code"`
	QueryOnly bool    `json:"query_only"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
}

func presentAddressOperation(item addresses.Operation) addressOperationView {
	return addressOperationView{item.Key, decimal(item.SourceID), optionalDecimal(item.AddressID), item.Kind, item.State,
		item.ErrorCode, item.QueryOnly, instant(item.CreatedAt), instant(item.UpdatedAt)}
}
func (a *ManagementAddresses) purge(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "address_id")
	if !ok {
		return
	}
	var input struct {
		ExpectedRevision string `json:"expected_revision"`
		OperationKey     string `json:"operation_key"`
		ConfirmAddress   string `json:"confirm_address"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	revision, ok := positiveDecimal(input.ExpectedRevision)
	if !ok {
		writeAddressError(w, r, addresses.ErrInvalid, nil)
		return
	}
	op, err := a.addresses.PurgeArchived(r.Context(), addresses.HMEDeleteInput{AddressID: id, RequestKey: input.OperationKey,
		ExpectedRevision: revision, ConfirmAddress: input.ConfirmAddress, OwnerKey: managementOwner(r)})
	if err != nil {
		writeAddressError(w, r, err, addressReference(id))
		return
	}
	WriteResult(w, 200, currentMeta(w), presentAddressOperation(op))
}
func (a *ManagementAddresses) queryPurge(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "address_id")
	if !ok {
		return
	}
	op, err := a.addresses.QueryPurge(r.Context(), id, r.PathValue("operation_key"), managementOwner(r))
	if err != nil {
		writeAddressError(w, r, err, addressReference(id))
		return
	}
	WriteResult(w, 200, currentMeta(w), presentAddressOperation(op))
}

func (a *ManagementAddresses) export(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Format string             `json:"format"`
		Filter addressFilterInput `json:"filter"`
	}
	if !addressBody(w, r, &input) {
		return
	}
	filter, err := input.Filter.filter()
	if err != nil || input.Format != "jsonl" && input.Format != "csv" {
		writeAddressError(w, r, addresses.ErrInvalid, nil)
		return
	}
	started := false
	var csvOutput *csv.Writer
	start := func() {
		if started {
			return
		}
		started = true
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Disposition", `attachment; filename="addresses.`+input.Format+`"`)
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		if input.Format == "csv" {
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			csvOutput = csv.NewWriter(w)
			_ = csvOutput.Write([]string{"address_json"})
		}
	}
	encoder := json.NewEncoder(w)
	err = a.addresses.ExportMetadata(r.Context(), filter, func(item addresses.Metadata) error {
		start()
		view := presentAddress(item)
		if csvOutput == nil {
			return encoder.Encode(view)
		}
		data, err := json.Marshal(view)
		if err != nil {
			return err
		}
		return csvOutput.Write([]string{string(data)})
	})
	if err != nil {
		if started {
			panic(http.ErrAbortHandler)
		}
		writeAddressError(w, r, err, nil)
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

func writeAddressError(w http.ResponseWriter, r *http.Request, err error, ref *ResourceRef) {
	status, p := 500, internalProblem()
	switch {
	case errors.Is(err, adminauth.ErrUnauthenticated):
		status, p = 401, Problem{Kind: "authentication", Code: "SESSION_REQUIRED", Message: "Sign in to continue.", Outcome: NotSent}
	case errors.Is(err, adminauth.ErrInvalidCredentials):
		status, p = 401, Problem{Kind: "authentication", Code: "CREDENTIALS_INVALID", Message: "The management credentials are invalid.", Outcome: NotSent}
	case errors.Is(err, addresses.ErrInvalid):
		status, p = 400, Problem{Kind: "invalid_request", Code: "ADDRESS_INPUT_INVALID", Message: "Check the address fields and selection.", Outcome: NotSent}
	case errors.Is(err, addresses.ErrNotFound):
		status, p = 404, Problem{Kind: "not_found", Code: "ADDRESS_NOT_FOUND", Message: "The address or group does not exist.", Outcome: NotSent}
	case errors.Is(err, addresses.ErrConflict):
		status, p = 409, Problem{Kind: "conflict", Code: "ADDRESS_REVISION_CONFLICT", Message: "Refresh the address or group before changing it.", Outcome: NotSent}
	case errors.Is(err, addresses.ErrIneligible):
		status, p = 409, Problem{Kind: "eligibility", Code: "ADDRESS_INELIGIBLE", Message: "The address is not eligible for this operation.", Outcome: NotSent}
	case errors.Is(err, addresses.ErrCapacity):
		status, p = 409, Problem{Kind: "capacity", Code: "ADDRESS_LOCAL_CAPACITY", Message: "The configured local address capacity has been reached.", Outcome: NotSent}
	case errors.Is(err, addresses.ErrReadOnly):
		status, p = 503, Problem{Kind: "maintenance", Code: "INSTALLATION_READ_ONLY", Message: "The installation is currently read-only.", Outcome: NotSent}
	case errors.Is(err, addresses.ErrCommitUnknown):
		status, p = 503, Problem{Kind: "persistence", Code: "ADDRESS_COMMIT_UNKNOWN", Message: "Query the original resource before making another change.", Outcome: Unknown, Resource: ref}
	case errors.Is(err, addresses.ErrDirectory):
		status, p = 502, Problem{Kind: "provider", Code: "DIRECTORY_INCOMPLETE", Message: "The provider directory could not be verified as complete."}
	case errors.Is(err, addresses.ErrProvider):
		status, p = 502, Problem{Kind: "provider", Code: "ADDRESS_PROVIDER_UNAVAILABLE", Message: "The provider operation could not be completed."}
	}
	WriteProblem(w, status, currentMeta(w), p)
}
