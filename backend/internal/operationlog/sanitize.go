package operationlog

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Identifier-shaped metadata is distinct from free text. Unknown attributes,
// objects and error values are discarded rather than stringified/redacted late.
func token(value string, maximum int) string {
	if value == "" || len(value) > maximum {
		return ""
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:-", c)) {
			return ""
		}
	}
	lower := strings.ToLower(value)
	for _, forbidden := range []string{"password", "secret", "authorization", "bearer", "cookie", "csrf", "access_token", "refresh_token", "session_token", "private_key"} {
		if strings.Contains(lower, forbidden) {
			return ""
		}
	}
	return strings.Clone(value)
}
func level(value string) string {
	switch strings.ToLower(value) {
	case "trace", "debug":
		return "debug"
	case "info", "information":
		return "info"
	case "warn", "warning":
		return "warn"
	default:
		return "error"
	}
}
func validLevel(value string) bool {
	return value == "" || value == "debug" || value == "info" || value == "warn" || value == "error"
}
func validOutcome(value string) bool {
	return value == "success" || value == "rejected" || value == "unknown" || value == "failure"
}
func validActor(value string) bool {
	return value == "operator" || value == "address" || value == "system" || value == "historical"
}
func source(value *int64) *int64 {
	if value == nil || *value < 1 {
		return nil
	}
	copy := *value
	return &copy
}
func metadataFields(fields map[string]string) map[string]string {
	result := map[string]string{}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(result) == MaximumFields {
			break
		}
		value := fields[key]
		if len(value) > MaximumFieldBytes {
			continue
		}
		switch key {
		case "component", "request_id", "operation_kind", "reason_code", "stage", "scope":
			if value = token(value, MaximumFieldBytes); value != "" {
				result[strings.Clone(key)] = value
			}
		case "duration_ms", "fetched", "stored", "duplicates", "messages", "bytes", "wait_ms", "retry", "uid", "active", "pending", "skipped", "archived", "imported", "errors", "attempts":
			if number, err := strconv.ParseUint(value, 10, 64); err == nil && strconv.FormatUint(number, 10) == value {
				result[strings.Clone(key)] = strings.Clone(value)
			}
		case "recovered", "automatic":
			if value == "true" || value == "false" {
				result[strings.Clone(key)] = strings.Clone(value)
			}
		}
	}
	return result
}
func cleanEvent(raw Event, now int64) Event {
	e := Event{OccurredAt: raw.OccurredAt, Level: level(raw.Level), SourceID: source(raw.SourceID), RoundKey: token(raw.RoundKey, 128), Attempt: raw.Attempt, Phase: token(raw.Phase, 80), Outcome: token(raw.Outcome, 80), ErrorCode: token(raw.ErrorCode, 80), Fields: metadataFields(raw.Fields)}
	if e.OccurredAt <= 0 {
		e.OccurredAt = now
	}
	if e.Attempt < 0 {
		e.Attempt = 0
	}
	if e.Phase == "" {
		e.Phase = "runtime_event"
	}
	if e.Outcome == "" {
		e.Outcome = "unspecified"
	}
	if raw.ErrorCode != "" && e.ErrorCode == "" {
		e.ErrorCode = "redacted_error"
	}
	e.Message = e.Phase + ": " + e.Outcome
	if e.ErrorCode != "" {
		e.Message += " (" + e.ErrorCode + ")"
	}
	return e
}
func cleanRecord(raw Record) Record {
	r := Record{OccurredAt: raw.OccurredAt, ActorKind: raw.ActorKind, ActorRef: token(raw.ActorRef, 128), Action: token(raw.Action, 80), ResourceKind: token(raw.ResourceKind, 80), ResourceRef: token(raw.ResourceRef, 128), Outcome: raw.Outcome, SourceID: source(raw.SourceID), CorrelationKey: token(raw.CorrelationKey, 128), Origin: token(raw.Origin, 128), Fields: metadataFields(raw.Fields)}
	if !validActor(r.ActorKind) {
		r.ActorKind = "historical"
	}
	if !validOutcome(r.Outcome) {
		r.Outcome = "unknown"
	}
	if r.ActorRef == "" {
		r.ActorRef = "redacted"
	}
	if r.Action == "" {
		r.Action = "historical_action"
	}
	if r.ResourceKind == "" {
		r.ResourceKind = "resource"
	}
	if r.ResourceRef == "" {
		r.ResourceRef = "redacted"
	}
	if ip, err := netip.ParseAddr(raw.Origin); err == nil {
		r.Origin = ip.String()
	}
	return r
}
func presentAudit(id int64, raw Record) Audit {
	r := cleanRecord(raw)
	return Audit{ID: id, Record: r, ActorDisplay: r.ActorKind + " " + r.ActorRef, Detail: r.Action + " " + r.ResourceKind + ":" + r.ResourceRef + " — " + r.Outcome}
}
func encodedFields(fields map[string]string) string {
	data, _ := json.Marshal(metadataFields(fields))
	return string(data)
}
func validText(value string, maximum int) bool {
	return utf8.ValidString(value) && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}
func validateFilter(f Filter, c Cursor) bool {
	return validLevel(f.Level) && validText(f.Query, 200) && (f.SourceID == nil || *f.SourceID > 0) && (f.RoundKey == "" || token(f.RoundKey, 128) == f.RoundKey) && c.Limit >= 1 && c.Limit <= 200 && !(c.BeforeID != nil && c.AfterID != nil) && (c.BeforeID == nil || *c.BeforeID > 0) && (c.AfterID == nil || *c.AfterID > 0)
}
func matches(e Event, f Filter) bool {
	if f.Level != "" && e.Level != f.Level || f.SourceID != nil && (e.SourceID == nil || *e.SourceID != *f.SourceID) || f.RoundKey != "" && e.RoundKey != f.RoundKey {
		return false
	}
	query := strings.ToLower(f.Query)
	if query == "" {
		return true
	}
	if strings.Contains(strings.ToLower(e.Message), query) || strings.Contains(strings.ToLower(e.RoundKey), query) {
		return true
	}
	for key, value := range e.Fields {
		if strings.Contains(strings.ToLower(key+" "+value), query) {
			return true
		}
	}
	return false
}
