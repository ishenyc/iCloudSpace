// Package httpapi defines the canonical HTTP boundary shared by feature handlers.
// It has no account, provider, SQL, session-storage, or historical API dependency.
package httpapi

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

// Meta is also returned for errors, so a failed operation can be correlated
// without reflecting its URL, body, or credentials into diagnostics.
type Meta struct {
	RequestID string `json:"request_id"`
}

type Outcome string

const (
	Accepted Outcome = "accepted"
	Rejected Outcome = "rejected"
	NotSent  Outcome = "not_sent"
	Unknown  Outcome = "unknown"
)

// Problem contains public, controlled descriptions. Feature adapters map their
// internal failures here; decoder, database, and provider error strings do not
// belong in Message. A network failure does not grant permission to replay.
type Problem struct {
	Kind          string       `json:"kind"`
	Code          string       `json:"code"`
	Message       string       `json:"message"`
	SubmissionKey string       `json:"submission_key,omitempty"`
	Outcome       Outcome      `json:"outcome,omitempty"`
	Resource      *ResourceRef `json:"resource,omitempty"`
}

// ResourceRef identifies a known candidate after a lost local commit
// acknowledgement. It grants no retry and contains no bearer credential.
type ResourceRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

func (p *Problem) Error() string { return p.Kind + ":" + p.Code }

type success struct {
	Result any  `json:"result"`
	Meta   Meta `json:"meta"`
}

type failure struct {
	Error Problem `json:"error"`
	Meta  Meta    `json:"meta"`
}

// RequestID makes a fresh correlation identifier. It is not an authentication
// token and is independent of a caller's durable submission key.
func RequestID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

// WriteResult encodes before publishing a status, preventing a programmer's
// unsupported result type from producing a partial success response. JSON
// commands return an envelope even for a nil result; empty 204s use raw HTTP.
func WriteResult(w http.ResponseWriter, status int, meta Meta, result any) {
	if status < 200 || status > 299 || status == http.StatusNoContent {
		WriteProblem(w, http.StatusInternalServerError, meta, internalProblem())
		return
	}
	var payload bytes.Buffer
	if err := json.NewEncoder(&payload).Encode(success{Result: result, Meta: meta}); err != nil {
		WriteProblem(w, http.StatusInternalServerError, meta, internalProblem())
		return
	}
	writeEncoded(w, status, meta, payload.Bytes())
}

// WriteProblem never includes an underlying error. Invalid HTTP status is a
// handler bug, represented as a normal controlled internal failure.
func WriteProblem(w http.ResponseWriter, status int, meta Meta, problem Problem) {
	if status < 400 || status > 599 {
		status, problem = http.StatusInternalServerError, internalProblem()
	}
	payload, err := json.Marshal(failure{Error: problem, Meta: meta})
	if err != nil {
		// The fixed fields contain no custom encoders or arbitrary values.
		panic("httpapi: impossible problem encoding")
	}
	writeEncoded(w, status, meta, append(payload, '\n'))
}

func writeEncoded(w http.ResponseWriter, status int, meta Meta, payload []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if meta.RequestID != "" {
		w.Header().Set("X-Request-ID", meta.RequestID)
	}
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func internalProblem() Problem {
	return Problem{Kind: "internal", Code: "INTERNAL_ERROR", Message: "The request could not be completed."}
}

// DecodeJSON is the input boundary, before any feature can claim or execute a
// mutation. Limits are supplied by that feature (small commands versus message
// bodies), rather than applying one oversized body budget to every endpoint.
func DecodeJSON(w http.ResponseWriter, r *http.Request, target any, limit int64) *Problem {
	if limit <= 0 {
		p := internalProblem()
		return &p
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return &Problem{Kind: "invalid_request", Code: "JSON_REQUIRED", Message: "A JSON request body is required.", Outcome: NotSent}
	}
	reader := http.MaxBytesReader(w, r.Body, limit)
	defer reader.Close()
	buffered := bufio.NewReader(reader)
	for {
		first, err := buffered.ReadByte()
		if err != nil {
			return decodeProblem(err)
		}
		if first == ' ' || first == '\t' || first == '\r' || first == '\n' {
			continue
		}
		if first != '{' {
			return &Problem{Kind: "invalid_request", Code: "OBJECT_REQUIRED", Message: "A JSON object is required.", Outcome: NotSent}
		}
		_ = buffered.UnreadByte()
		break
	}
	decoder := json.NewDecoder(buffered)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return decodeProblem(err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return decodeProblem(err)
		}
		return &Problem{Kind: "invalid_request", Code: "ONE_DOCUMENT_REQUIRED", Message: "Exactly one JSON document is required.", Outcome: NotSent}
	}
	return nil
}

func decodeProblem(err error) *Problem {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return &Problem{Kind: "invalid_request", Code: "BODY_TOO_LARGE", Message: "The request body exceeds the endpoint budget.", Outcome: NotSent}
	}
	var invalidTarget *json.InvalidUnmarshalError
	if errors.As(err, &invalidTarget) {
		p := internalProblem()
		return &p
	}
	return &Problem{Kind: "invalid_request", Code: "INVALID_JSON", Message: "The request body does not match the endpoint schema.", Outcome: NotSent}
}
