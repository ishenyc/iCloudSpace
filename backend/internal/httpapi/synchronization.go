package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"icloudspace/internal/accounts"
	"icloudspace/internal/rounds"
)

// ManagementSynchronization admits manual wakes and reads coordinator metadata.
// It never waits for a source gate, runs a step, or changes automatic cooldown.
type ManagementSynchronization struct {
	identity *ManagementAuth
	accounts *accounts.Service
	rounds   *rounds.Coordinator
}

func NewManagementSynchronization(auth *ManagementAuth, sources *accounts.Service, coordinator *rounds.Coordinator) (*ManagementSynchronization, error) {
	if auth == nil || sources == nil || coordinator == nil {
		return nil, errors.New("httpapi: synchronization identity, sources and coordinator are required")
	}
	return &ManagementSynchronization{auth, sources, coordinator}, nil
}
func (a *ManagementSynchronization) Register(mux *http.ServeMux) {
	base := a.identity.basePath
	for pattern, handler := range map[string]http.HandlerFunc{
		"POST " + base + "/accounts/{source_id}/synchronization":       a.wake,
		"GET " + base + "/accounts/{source_id}/synchronization":        a.get,
		"GET " + base + "/accounts/{source_id}/synchronization/events": a.events,
		"GET " + base + "/synchronization-statistics":                  a.statistics,
		"GET " + base + "/synchronization/progress":                    a.batchProgress,
	} {
		mux.Handle(pattern, a.identity.RequireSession(handler))
	}
}

type synchronizationScope struct {
	SourceID              string `json:"source_id"`
	Revision              string `json:"revision"`
	Generation            string `json:"generation"`
	CredentialGeneration  string `json:"credential_generation"`
	ConfigurationRevision string `json:"configuration_revision"`
}
type synchronizationBackfill struct {
	AddressID     string `json:"address_id"`
	ScanEpoch     string `json:"scan_epoch"`
	UIDValidity   string `json:"uid_validity"`
	CapturedUpper string `json:"captured_upper"`
	Committed     string `json:"committed"`
}
type synchronizationFrontier struct {
	UIDValidity   string                   `json:"uid_validity"`
	CapturedUpper string                   `json:"captured_upper"`
	Committed     string                   `json:"committed"`
	Backfill      *synchronizationBackfill `json:"backfill"`
}
type synchronizationCounters struct {
	Discovered string `json:"discovered"`
	Archived   string `json:"archived"`
	Links      string `json:"links"`
	Bytes      string `json:"bytes"`
}
type synchronizationProgress struct {
	Source             synchronizationScope     `json:"source"`
	RoundID            string                   `json:"round_id"`
	Trigger            rounds.Trigger           `json:"trigger"`
	Phase              rounds.Phase             `json:"phase"`
	State              rounds.State             `json:"state"`
	Outcome            *string                  `json:"outcome"`
	QueuedAt           string                   `json:"queued_at"`
	StartedAt          *string                  `json:"started_at"`
	FinishedAt         *string                  `json:"finished_at"`
	ReadyAt            *string                  `json:"ready_at"`
	Attempts           string                   `json:"attempts"`
	FailedAttempts     string                   `json:"failed_attempts"`
	Segments           string                   `json:"segments"`
	Retries            string                   `json:"retries"`
	AdmissionWaits     string                   `json:"admission_waits"`
	AdmissionErrors    string                   `json:"admission_errors"`
	ActiveNanoseconds  string                   `json:"active_nanoseconds"`
	Recovered          bool                     `json:"recovered"`
	ErrorCode          string                   `json:"error_code"`
	DirectoryErrorCode string                   `json:"directory_error_code"`
	Frontier           *synchronizationFrontier `json:"frontier"`
	Counters           synchronizationCounters  `json:"counters"`
	WaitingManual      bool                     `json:"waiting_manual"`
}
type synchronizationView struct {
	SourceID       string                   `json:"source_id"`
	AutomaticAfter *string                  `json:"automatic_after"`
	LastTerminalAt *string                  `json:"last_terminal_at"`
	Progress       *synchronizationProgress `json:"progress"`
}
type synchronizationWake struct {
	SourceID    string             `json:"source_id"`
	Disposition rounds.Disposition `json:"disposition"`
	RoundID     *string            `json:"round_id"`
	FollowUp    bool               `json:"follow_up"`
}
type synchronizationStatistics struct {
	Sources          string `json:"sources"`
	Ready            string `json:"ready"`
	InFlight         string `json:"in_flight"`
	Slots            string `json:"slots"`
	Closing          bool   `json:"closing"`
	CatalogErrors    string `json:"catalog_errors"`
	CatalogReloads   string `json:"catalog_reloads"`
	CatalogErrorCode string `json:"catalog_error_code"`
}
type synchronizationBatchItem struct {
	SourceID string                   `json:"source_id"`
	Progress *synchronizationProgress `json:"progress"`
}
type synchronizationBatch struct {
	Items      []synchronizationBatchItem `json:"items"`
	Statistics synchronizationStatistics  `json:"statistics"`
}
type synchronizationEvent struct {
	Sequence string                  `json:"sequence"`
	At       string                  `json:"at"`
	Level    string                  `json:"level"`
	Scope    string                  `json:"scope"`
	Name     string                  `json:"name"`
	Outcome  *string                 `json:"outcome"`
	Progress synchronizationProgress `json:"progress"`
}
type synchronizationEvents struct {
	SourceID     string                 `json:"source_id"`
	RoundID      *string                `json:"round_id"`
	After        string                 `json:"after_sequence"`
	LastSequence string                 `json:"last_sequence"`
	Lost         string                 `json:"lost"`
	Items        []synchronizationEvent `json:"items"`
}

var synchronizationToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`)
var synchronizationCode = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,96}$`)

func synchronizationText(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
func synchronizationInstant(value int64) *string {
	if value == 0 {
		return nil
	}
	return synchronizationText(instant(value))
}
func synchronizationSafeCode(value string) string {
	if value == "" || synchronizationCode.MatchString(value) {
		return value
	}
	return "operation_failed"
}
func presentSynchronization(p rounds.Progress) synchronizationProgress {
	v := synchronizationProgress{
		Source:  synchronizationScope{decimal(p.Source.SourceID), decimal(p.Source.Revision), decimal(p.Source.Generation), decimal(p.Source.CredentialGeneration), decimal(p.Source.ConfigurationRevision)},
		RoundID: p.RoundID, Trigger: p.Trigger, Phase: p.Phase, State: p.State, Outcome: synchronizationText(string(p.Outcome)),
		QueuedAt: instant(p.QueuedAt), StartedAt: synchronizationInstant(p.StartedAt), FinishedAt: synchronizationInstant(p.FinishedAt), ReadyAt: synchronizationInstant(p.ReadyAt),
		Attempts: decimal(int64(p.Attempts)), FailedAttempts: decimal(int64(p.FailedAttempts)), Segments: decimal(int64(p.Segments)), Retries: decimal(int64(p.Retries)),
		AdmissionWaits: decimal(int64(p.AdmissionWaits)), AdmissionErrors: decimal(int64(p.AdmissionErrors)), ActiveNanoseconds: decimal(int64(p.ActiveTime)), Recovered: p.Recovered,
		ErrorCode: synchronizationSafeCode(p.ErrorCode), DirectoryErrorCode: synchronizationSafeCode(p.DirectoryErrorCode), WaitingManual: p.WaitingManual,
		Counters: synchronizationCounters{decimal(p.Counters.Discovered), decimal(p.Counters.Archived), decimal(p.Counters.Links), decimal(p.Counters.Bytes)},
	}
	if p.Frontier != nil {
		f := p.Frontier
		v.Frontier = &synchronizationFrontier{decimal(int64(f.UIDValidity)), decimal(int64(f.CapturedUpper)), decimal(int64(f.Committed)), nil}
		if b := f.Backfill; b != nil {
			v.Frontier.Backfill = &synchronizationBackfill{decimal(b.AddressID), decimal(b.ScanEpoch), decimal(int64(b.UIDValidity)), decimal(int64(b.CapturedUpper)), decimal(int64(b.Committed))}
		}
	}
	return v
}
func (a *ManagementSynchronization) fail(w http.ResponseWriter, r *http.Request, id int64, status int, kind, code, message string) {
	p := Problem{Kind: kind, Code: code, Message: message, Outcome: NotSent}
	if id > 0 {
		p.Resource = &ResourceRef{Kind: "account", ID: decimal(id)}
	}
	WriteProblem(w, status, currentMeta(w), p)
}
func (a *ManagementSynchronization) source(w http.ResponseWriter, r *http.Request) (accounts.Metadata, bool) {
	id, ok := accountID(w, r)
	if !ok {
		return accounts.Metadata{}, false
	}
	s, err := a.accounts.Get(r.Context(), id)
	if errors.Is(err, accounts.ErrNotFound) {
		a.fail(w, r, id, 404, "not_found", "SYNCHRONIZATION_SOURCE_NOT_FOUND", "The account does not exist.")
		return s, false
	}
	if err != nil {
		a.fail(w, r, id, 500, "internal", "SYNCHRONIZATION_UNAVAILABLE", "Synchronization metadata is unavailable.")
		return s, false
	}
	return s, true
}
func (a *ManagementSynchronization) wake(w http.ResponseWriter, r *http.Request) {
	var command struct{}
	if p := DecodeJSON(w, r, &command, 1024); p != nil {
		WriteProblem(w, 400, currentMeta(w), *p)
		return
	}
	if r.URL.RawQuery != "" {
		a.fail(w, r, 0, 400, "invalid_request", "SYNCHRONIZATION_INPUT_INVALID", "Use the account synchronization command without query fields.")
		return
	}
	s, ok := a.source(w, r)
	if !ok {
		return
	}
	if !s.Enabled {
		a.fail(w, r, s.ID, 409, "conflict", "SYNCHRONIZATION_SOURCE_DISABLED", "Enable the account before requesting synchronization.")
		return
	}
	result := a.rounds.Wake(s.ID, rounds.Manual)
	switch result.Disposition {
	case rounds.WakeQueued, rounds.WakeCoalesced:
		WriteResult(w, http.StatusAccepted, currentMeta(w), synchronizationWake{decimal(s.ID), result.Disposition, synchronizationText(result.RoundID), result.FollowUp})
	case rounds.WakeDisabled:
		a.fail(w, r, s.ID, 409, "conflict", "SYNCHRONIZATION_SOURCE_DISABLED", "Enable the account before requesting synchronization.")
	default:
		a.fail(w, r, s.ID, 503, "unavailable", "SYNCHRONIZATION_COORDINATOR_UNAVAILABLE", "The synchronization coordinator is not accepting this account.")
	}
}
func (a *ManagementSynchronization) get(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		a.fail(w, r, 0, 400, "invalid_request", "SYNCHRONIZATION_INPUT_INVALID", "The synchronization metadata route accepts no query fields.")
		return
	}
	s, ok := a.source(w, r)
	if !ok {
		return
	}
	v := synchronizationView{SourceID: decimal(s.ID), AutomaticAfter: optionalInstant(s.AutomaticSyncAfter), LastTerminalAt: optionalInstant(s.LastTerminalSyncAt)}
	if p, exists := a.rounds.Progress(s.ID); exists {
		view := presentSynchronization(p)
		v.Progress = &view
	}
	WriteResult(w, 200, currentMeta(w), v)
}
func (a *ManagementSynchronization) statistics(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		a.fail(w, r, 0, 400, "invalid_request", "SYNCHRONIZATION_INPUT_INVALID", "The scheduler statistics route accepts no query fields.")
		return
	}
	WriteResult(w, 200, currentMeta(w), presentSynchronizationStatistics(a.rounds.Statistics()))
}
func presentSynchronizationStatistics(s rounds.Statistics) synchronizationStatistics {
	return synchronizationStatistics{decimal(int64(s.Sources)), decimal(int64(s.Ready)), decimal(int64(s.InFlight)), decimal(int64(s.Slots)), s.Closing, strconv.FormatUint(s.CatalogErrors, 10), strconv.FormatUint(s.CatalogReloads, 10), synchronizationSafeCode(s.CatalogErrorCode)}
}

// Explicit IDs preserve the metadata page's order. This path deliberately does
// not consult Accounts/Get, reload the catalog, or admit any scheduler work.
func (a *ManagementSynchronization) batchProgress(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	ids := query["source_id"]
	if err != nil || len(query) != 1 || len(ids) < 1 || len(ids) > 1000 {
		a.fail(w, r, 0, 400, "invalid_request", "SYNCHRONIZATION_INPUT_INVALID", "Supply between one and 1000 unique canonical source identifiers.")
		return
	}
	parsed := make([]int64, len(ids))
	seen := make(map[int64]bool, len(ids))
	for index, raw := range ids {
		id, ok := positiveDecimal(raw)
		if !ok || seen[id] {
			a.fail(w, r, 0, 400, "invalid_request", "SYNCHRONIZATION_INPUT_INVALID", "Supply between one and 1000 unique canonical source identifiers.")
			return
		}
		parsed[index], seen[id] = id, true
	}
	result := synchronizationBatch{Items: make([]synchronizationBatchItem, 0, len(ids)), Statistics: presentSynchronizationStatistics(a.rounds.Statistics())}
	for index, id := range parsed {
		item := synchronizationBatchItem{SourceID: ids[index]}
		if progress, exists := a.rounds.Progress(id); exists {
			view := presentSynchronization(progress)
			item.Progress = &view
		}
		result.Items = append(result.Items, item)
	}
	WriteResult(w, 200, currentMeta(w), result)
}
func (a *ManagementSynchronization) events(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	var after uint64
	var roundID string
	if err == nil {
		for key, values := range query {
			if len(values) != 1 {
				err = rounds.ErrInvalid
				break
			}
			switch key {
			case "after_sequence":
				after, err = strconv.ParseUint(values[0], 10, 64)
				if err == nil && strconv.FormatUint(after, 10) != values[0] {
					err = rounds.ErrInvalid
				}
			case "round_id":
				roundID = values[0]
				if !synchronizationToken.MatchString(roundID) {
					err = rounds.ErrInvalid
				}
			default:
				err = rounds.ErrInvalid
			}
			if err != nil {
				break
			}
		}
	}
	if err != nil {
		a.fail(w, r, 0, 400, "invalid_request", "SYNCHRONIZATION_INPUT_INVALID", "Check the event sequence and original round identifier.")
		return
	}
	s, ok := a.source(w, r)
	if !ok {
		return
	}
	page := a.rounds.Events(after)
	v := synchronizationEvents{SourceID: decimal(s.ID), RoundID: synchronizationText(roundID), After: strconv.FormatUint(after, 10), LastSequence: strconv.FormatUint(page.LastSequence, 10), Lost: strconv.FormatUint(page.Lost, 10), Items: make([]synchronizationEvent, 0)}
	for _, event := range page.Items {
		if event.Progress.Source.SourceID == s.ID && (roundID == "" || event.Progress.RoundID == roundID) {
			v.Items = append(v.Items, synchronizationEvent{strconv.FormatUint(event.Sequence, 10), instant(event.At), event.Level, event.Scope, event.Name, synchronizationText(event.Outcome), presentSynchronization(event.Progress)})
		}
	}
	WriteResult(w, 200, currentMeta(w), v)
}
