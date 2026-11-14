package httpapi

import (
	"errors"
	"math"
	"net/http"
	"net/url"

	"icloudspace/internal/operationlog"
)

type ManagementEvents struct {
	identity *ManagementAuth
	logs     *operationlog.Service
}

func NewManagementEvents(identity *ManagementAuth, logs *operationlog.Service) (*ManagementEvents, error) {
	if identity == nil || logs == nil {
		return nil, errors.New("httpapi: management identity and operation log owner are required")
	}
	return &ManagementEvents{identity, logs}, nil
}
func (a *ManagementEvents) Register(mux *http.ServeMux) {
	mux.Handle("GET "+a.identity.basePath+"/runtime-events", a.identity.RequireSession(http.HandlerFunc(a.runtime)))
	mux.Handle("GET "+a.identity.basePath+"/audit-records", a.identity.RequireSession(http.HandlerFunc(a.audits)))
}

type runtimeEventView struct {
	ID         string            `json:"id"`
	OccurredAt string            `json:"occurred_at"`
	Level      string            `json:"level"`
	SourceID   *string           `json:"source_id"`
	RoundKey   string            `json:"round_key"`
	Attempt    int               `json:"attempt"`
	Phase      string            `json:"phase"`
	Outcome    string            `json:"outcome"`
	ErrorCode  string            `json:"error_code"`
	Message    string            `json:"message"`
	Fields     map[string]string `json:"fields"`
}
type runtimeEventPageView struct {
	Stream       string             `json:"stream"`
	Generation   *string            `json:"generation"`
	Items        []runtimeEventView `json:"items"`
	Limit        int                `json:"limit"`
	BeforeID     *string            `json:"before_id"`
	AfterID      *string            `json:"after_id"`
	NextBeforeID *string            `json:"next_before_id"`
	EarliestID   *string            `json:"earliest_id"`
	LatestID     *string            `json:"latest_id"`
	Evicted      bool               `json:"evicted"`
	Total        int64              `json:"total"`
}
type auditRecordView struct {
	ID             string            `json:"id"`
	OccurredAt     string            `json:"occurred_at"`
	ActorKind      string            `json:"actor_kind"`
	ActorRef       string            `json:"actor_ref"`
	ActorDisplay   string            `json:"actor_display"`
	Action         string            `json:"action"`
	ResourceKind   string            `json:"resource_kind"`
	ResourceRef    string            `json:"resource_ref"`
	Outcome        string            `json:"outcome"`
	SourceID       *string           `json:"source_id"`
	CorrelationKey string            `json:"correlation_key"`
	Origin         string            `json:"origin"`
	Detail         string            `json:"detail"`
	Fields         map[string]string `json:"fields"`
}

func eventPage(result operationlog.RuntimePage) runtimeEventPageView {
	view := runtimeEventPageView{Stream: result.Stream, Items: make([]runtimeEventView, 0, len(result.Items)), Limit: result.Limit, BeforeID: optionalDecimal(result.BeforeID), AfterID: optionalDecimal(result.AfterID), NextBeforeID: optionalDecimal(result.NextBeforeID), EarliestID: optionalDecimal(result.EarliestID), LatestID: optionalDecimal(result.LatestID), Evicted: result.Evicted, Total: result.Total}
	if result.Generation != "" {
		view.Generation = &result.Generation
	}
	for _, item := range result.Items {
		view.Items = append(view.Items, runtimeEventView{decimal(item.ID), instant(item.OccurredAt), item.Level, optionalDecimal(item.SourceID), item.RoundKey, item.Attempt, item.Phase, item.Outcome, item.ErrorCode, item.Message, item.Fields})
	}
	return view
}
func (a *ManagementEvents) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, problem := 500, internalProblem()
	if errors.Is(err, operationlog.ErrInvalid) {
		status, problem = 400, Problem{Kind: "invalid_request", Code: "EVENT_QUERY_INVALID", Message: "Check the event filters and pagination."}
	}
	WriteProblem(w, status, currentMeta(w), problem)
}
func eventQuery(r *http.Request, allowed map[string]bool) (url.Values, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, operationlog.ErrInvalid
	}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 {
			return nil, operationlog.ErrInvalid
		}
	}
	return query, nil
}
func eventOptionalID(query url.Values, key string) (*int64, error) {
	if values, present := query[key]; present {
		value, ok := positiveDecimal(values[0])
		if !ok {
			return nil, operationlog.ErrInvalid
		}
		return &value, nil
	}
	return nil, nil
}
func eventNumber(query url.Values, key string, defaultValue, maximum int64) (int64, error) {
	if values, present := query[key]; present {
		value, ok := positiveDecimal(values[0])
		if !ok || value > maximum {
			return 0, operationlog.ErrInvalid
		}
		return value, nil
	}
	return defaultValue, nil
}
func (a *ManagementEvents) runtime(w http.ResponseWriter, r *http.Request) {
	query, err := eventQuery(r, map[string]bool{"stream": true, "before_id": true, "after_id": true, "limit": true, "level": true, "query": true, "source_id": true, "round_key": true})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	stream := query.Get("stream")
	if _, present := query["stream"]; !present {
		stream = "live"
	}
	before, err := eventOptionalID(query, "before_id")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	after, err := eventOptionalID(query, "after_id")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	source, err := eventOptionalID(query, "source_id")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	limit, err := eventNumber(query, "limit", 100, 200)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	result, err := a.logs.Runtime(r.Context(), stream, operationlog.Filter{Level: query.Get("level"), Query: query.Get("query"), SourceID: source, RoundKey: query.Get("round_key")}, operationlog.Cursor{BeforeID: before, AfterID: after, Limit: int(limit)})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if result.Total > 1<<53-1 {
		a.fail(w, r, operationlog.ErrStorage)
		return
	}
	WriteResult(w, 200, currentMeta(w), eventPage(result))
}
func (a *ManagementEvents) audits(w http.ResponseWriter, r *http.Request) {
	query, err := eventQuery(r, map[string]bool{"page": true, "page_size": true, "query": true, "source_id": true, "action": true, "outcome": true})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	source, err := eventOptionalID(query, "source_id")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	page, err := eventNumber(query, "page", 1, 1<<53-1)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	size, err := eventNumber(query, "page_size", 50, 100)
	if err != nil || page-1 > (math.MaxInt64-size)/size {
		a.fail(w, r, operationlog.ErrInvalid)
		return
	}
	result, err := a.logs.Audits(r.Context(), operationlog.AuditFilter{Query: query.Get("query"), Action: query.Get("action"), Outcome: query.Get("outcome"), SourceID: source}, operationlog.Page{Limit: int(size), Offset: (page - 1) * size})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if result.Total > 1<<53-1 {
		a.fail(w, r, operationlog.ErrStorage)
		return
	}
	items := make([]auditRecordView, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, auditRecordView{decimal(item.ID), instant(item.OccurredAt), item.ActorKind, item.ActorRef, item.ActorDisplay, item.Action, item.ResourceKind, item.ResourceRef, item.Outcome, optionalDecimal(item.SourceID), item.CorrelationKey, item.Origin, item.Detail, item.Fields})
	}
	WriteResult(w, 200, currentMeta(w), struct {
		Items    []auditRecordView `json:"items"`
		Total    int64             `json:"total"`
		Page     int64             `json:"page"`
		PageSize int64             `json:"page_size"`
	}{items, result.Total, page, size})
}
