// Package operationlog projects operational facts into bounded, safe metadata.
// Arbitrary messages, provider causes, documents and headers are never copied.
package operationlog

import (
	"database/sql"
	"errors"
	"io"
	"sync"
)

var (
	ErrInvalid = errors.New("operationlog: invalid metadata or cursor")
	ErrStorage = errors.New("operationlog: storage unavailable")
	ErrBinding = errors.New("operationlog: installation mismatch")
)

const (
	MaximumEntries    = 2000
	MaximumBytes      = 32 << 20
	MaximumFields     = 16
	MaximumFieldBytes = 256
)

type Options struct {
	Clock          func() int64
	MaximumEntries int
	MaximumBytes   int
	// Output receives only the same sanitized JSON metadata held by the ring.
	// It is never a second handler wrapping the original slog.Record.
	Output io.Writer
}
type Event struct {
	OccurredAt                int64
	Level                     string
	SourceID                  *int64
	RoundKey                  string
	Attempt                   int
	Phase, Outcome, ErrorCode string
	// Message and unknown fields are deliberately ignored by the projection.
	Message string
	Fields  map[string]string
}
type Entry struct {
	ID int64
	Event
}
type Filter struct {
	Level, Query string
	SourceID     *int64
	RoundKey     string
}
type Cursor struct {
	BeforeID, AfterID *int64
	Limit             int
}
type RuntimePage struct {
	Stream, Generation              string
	Items                           []Entry
	Limit                           int
	BeforeID, AfterID, NextBeforeID *int64
	EarliestID, LatestID            *int64
	Evicted                         bool
	Total                           int64
}
type Record struct {
	OccurredAt                         int64
	ActorKind, ActorRef, Action        string
	ResourceKind, ResourceRef, Outcome string
	SourceID                           *int64
	CorrelationKey, Origin             string
	Fields                             map[string]string
}
type Audit struct {
	ID int64
	Record
	ActorDisplay, Detail string
}
type AuditFilter struct {
	Query, Action, Outcome string
	SourceID               *int64
}
type Page struct {
	Limit  int
	Offset int64
}
type AuditPage struct {
	Items []Audit
	Total int64
}

type Service struct {
	db           *sql.DB
	installation string
	ring         *Ring
}
type stored struct {
	entry Entry
	bytes int
}
type Ring struct {
	mu                           sync.RWMutex
	clock                        func() int64
	maximumEntries, maximumBytes int
	entries                      []stored
	head, count, bytes           int
	next                         int64
	generation                   string
	evicted                      bool
	output                       io.Writer
	outputMu                     sync.Mutex
}
