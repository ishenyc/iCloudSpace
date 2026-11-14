package operationlog

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math"
	"time"
)

func NewRing(options Options) (*Ring, error) {
	if options.MaximumEntries == 0 {
		options.MaximumEntries = MaximumEntries
	}
	if options.MaximumBytes == 0 {
		options.MaximumBytes = MaximumBytes
	}
	if options.MaximumEntries < 1 || options.MaximumEntries > MaximumEntries || options.MaximumBytes < 1 || options.MaximumBytes > MaximumBytes {
		return nil, ErrInvalid
	}
	if options.Clock == nil {
		options.Clock = func() int64 { return time.Now().UnixNano() }
	}
	var generation [16]byte
	if _, err := rand.Read(generation[:]); err != nil {
		return nil, ErrStorage
	}
	return &Ring{clock: options.Clock, maximumEntries: options.MaximumEntries, maximumBytes: options.MaximumBytes, entries: make([]stored, options.MaximumEntries), generation: hex.EncodeToString(generation[:]), output: options.Output}, nil
}
func clone(e Entry) Entry {
	e.SourceID = source(e.SourceID)
	fields := make(map[string]string, len(e.Fields))
	for key, value := range e.Fields {
		fields[key] = value
	}
	e.Fields = fields
	return e
}

// Append keeps only projected metadata. It has no database or provider IO and
// never serializes an arbitrary slog.Any/error value.
func (r *Ring) Append(raw Event) (Entry, bool) {
	if r == nil {
		return Entry{}, false
	}
	e := Entry{Event: cleanEvent(raw, r.clock())}
	r.mu.Lock()
	if r.next == math.MaxInt64 {
		r.mu.Unlock()
		return Entry{}, false
	}
	e.ID = r.next + 1
	wire, err := json.Marshal(e)
	// Account for stored strings, maps and slot overhead, rather than only the
	// wire payload. Small substrings are cloned before the ring retains them.
	cost := len(wire) + 512 + len(e.Fields)*96
	if err != nil || cost > r.maximumBytes {
		r.evicted = true
		r.mu.Unlock()
		return Entry{}, false
	}
	for r.count > 0 && (r.count == r.maximumEntries || r.bytes+cost > r.maximumBytes) {
		r.bytes -= r.entries[r.head].bytes
		r.entries[r.head] = stored{}
		r.head = (r.head + 1) % r.maximumEntries
		r.count--
		r.evicted = true
	}
	r.entries[(r.head+r.count)%r.maximumEntries] = stored{e, cost}
	r.count++
	r.bytes += cost
	r.next = e.ID
	r.mu.Unlock()
	if r.output != nil {
		r.outputMu.Lock()
		_, _ = r.output.Write(append(wire, '\n'))
		r.outputMu.Unlock()
	}
	return clone(e), true
}
func (r *Ring) List(filter Filter, cursor Cursor) (RuntimePage, error) {
	if r == nil || !validateFilter(filter, cursor) {
		return RuntimePage{}, ErrInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	page := RuntimePage{Stream: "live", Generation: r.generation, Items: []Entry{}, Limit: cursor.Limit, BeforeID: cursor.BeforeID, AfterID: cursor.AfterID, Evicted: r.evicted}
	if r.count > 0 {
		earliest, latest := r.entries[r.head].entry.ID, r.entries[(r.head+r.count-1)%r.maximumEntries].entry.ID
		page.EarliestID, page.LatestID = &earliest, &latest
	}
	for i := r.count - 1; i >= 0; i-- {
		e := r.entries[(r.head+i)%r.maximumEntries].entry
		if !matches(e.Event, filter) {
			continue
		}
		page.Total++
		if cursor.BeforeID != nil && e.ID >= *cursor.BeforeID || cursor.AfterID != nil && e.ID <= *cursor.AfterID {
			continue
		}
		if len(page.Items) < cursor.Limit {
			page.Items = append(page.Items, clone(e))
		} else if page.NextBeforeID == nil {
			next := page.Items[len(page.Items)-1].ID
			page.NextBeforeID = &next
		}
	}
	return page, nil
}
func (r *Ring) Size() (entries, bytes int) {
	if r == nil {
		return 0, 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.count, r.bytes
}
