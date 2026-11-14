package operationlog

import (
	"context"
	"log/slog"
	"strconv"
)

type safeHandler struct {
	ring    *Ring
	base    Event
	grouped bool
}

func (r *Ring) Handler() slog.Handler {
	return &safeHandler{ring: r, base: Event{Fields: map[string]string{}}}
}
func (*safeHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *safeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	copy := &safeHandler{ring: h.ring, grouped: h.grouped, base: clone(Entry{Event: h.base}).Event}
	if !h.grouped {
		for _, attr := range attrs {
			apply(&copy.base, attr)
		}
	}
	return copy
}
func (h *safeHandler) WithGroup(name string) slog.Handler {
	return &safeHandler{ring: h.ring, base: clone(Entry{Event: h.base}).Event, grouped: h.grouped || name != ""}
}
func apply(e *Event, attr slog.Attr) {
	var value string
	switch attr.Value.Kind() {
	case slog.KindString:
		value = attr.Value.String()
	case slog.KindInt64:
		value = strconv.FormatInt(attr.Value.Int64(), 10)
	case slog.KindUint64:
		value = strconv.FormatUint(attr.Value.Uint64(), 10)
	case slog.KindBool:
		value = strconv.FormatBool(attr.Value.Bool())
	default:
		return
	}
	switch attr.Key {
	case "source_id":
		if id, err := strconv.ParseInt(value, 10, 64); err == nil && id > 0 {
			e.SourceID = &id
		}
	case "round_key":
		e.RoundKey = token(value, 128)
	case "attempt":
		if n, err := strconv.ParseInt(value, 10, 32); err == nil && n >= 0 {
			e.Attempt = int(n)
		}
	case "phase":
		e.Phase = token(value, 80)
	case "outcome":
		e.Outcome = token(value, 80)
	case "error_code":
		e.ErrorCode = token(value, 80)
		if value != "" && e.ErrorCode == "" {
			e.ErrorCode = "redacted_error"
		}
	default:
		if _, exists := e.Fields[attr.Key]; !exists && len(e.Fields) >= MaximumFields {
			return
		}
		for key, value := range metadataFields(map[string]string{attr.Key: value}) {
			e.Fields[key] = value
		}
	}
}
func (h *safeHandler) Handle(_ context.Context, record slog.Record) error {
	e := clone(Entry{Event: h.base}).Event
	e.OccurredAt, e.Level = record.Time.UnixNano(), record.Level.String()
	if !h.grouped {
		record.Attrs(func(attr slog.Attr) bool { apply(&e, attr); return true })
	}
	h.ring.Append(e)
	return nil
}
