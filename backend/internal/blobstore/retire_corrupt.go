package blobstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// CorruptBody is an observed complete byte stream under an exact valid claim
// and manifest. It grants no deletion authority; the SQL owner must persist it
// before RetireCorrupt. Expected receipt fields are never replaced by these.
type CorruptBody struct {
	ByteSize int64  `json:"byte_size"`
	SHA256   string `json:"sha256"`
}

func (CorruptBody) String() string   { return "blobstore: private damaged-body observation" }
func (CorruptBody) GoString() string { return "blobstore: private damaged-body observation" }

type corruptRetirement struct {
	Version  int         `json:"version"`
	Receipt  Receipt     `json:"receipt"`
	Observed CorruptBody `json:"observed"`
}

func validCorrupt(c CorruptBody) bool { return validExpected(Expected(c)) }
func observeActual(ctx context.Context, root *os.Root, name string) (CorruptBody, error) {
	f, e := openRegular(root, name, os.O_RDONLY)
	if e != nil {
		return CorruptBody{}, e
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		return CorruptBody{}, ErrIO
	}
	h := sha256.New()
	var size int64
	buf := make([]byte, 32<<10)
	for {
		if e = ctx.Err(); e != nil {
			return CorruptBody{}, e
		}
		n, re := f.Read(buf)
		if n > 0 {
			size += int64(n)
			h.Write(buf[:n])
		}
		if re == io.EOF {
			break
		}
		if re != nil {
			return CorruptBody{}, ErrIO
		}
	}
	after, e := f.Stat()
	pathInfo, pe := root.Lstat(name)
	if e != nil || pe != nil || !os.SameFile(before, after) || !os.SameFile(after, pathInfo) || size != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return CorruptBody{}, ErrIntegrity
	}
	return CorruptBody{ByteSize: size, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// ObserveCorrupt never creates a claim, replaces a manifest, repairs or removes
// bytes. Symlinks/invalid claims/ambiguous bodies remain unresolved.
func (s *Store) ObserveCorrupt(ctx context.Context, r Receipt) (CorruptBody, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out CorruptBody
	e := s.withReceipt(ctx, r, func(root *os.Root, m *manifest) error {
		name, e := bodyName(root)
		if e != nil {
			return e
		}
		if name == "" {
			return ErrIncomplete
		}
		out, e = observeActual(ctx, root, name)
		if e != nil {
			return e
		}
		if out.ByteSize == r.ByteSize && out.SHA256 == r.SHA256 {
			return ErrConflict
		}
		return nil
	})
	return out, e
}

// RetireCorrupt requires the unchanged original receipt plus a separately
// persisted actual-byte observation. It rehashes the exact generation under
// the blobstore lock, durably records both expectations, then persists the
// monotonic collection tombstone before unlink. It never removes a tree.
func (s *Store) RetireCorrupt(ctx context.Context, r Receipt, observed CorruptBody) error {
	if !validCorrupt(observed) || observed.ByteSize == r.ByteSize && observed.SHA256 == r.SHA256 {
		return ErrIdentity
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.withReceipt(ctx, r, func(root *os.Root, m *manifest) error {
		name, e := bodyName(root)
		if e != nil {
			return e
		}
		if name == "" {
			if m.State == Collected {
				return nil
			}
			return ErrIncomplete
		}
		actual, e := observeActual(ctx, root, name)
		if e != nil {
			return e
		}
		if actual != observed {
			return ErrConflict
		}
		doc := corruptRetirement{Version: 1, Receipt: r, Observed: observed}
		doc.Receipt.Reused = false
		data, _ := json.Marshal(doc)
		if e = s.expectedDocument(root, "corrupt-retirement.json", data); e != nil {
			return e
		}
		if e = s.writeManifest(root, manifest{Version: ManifestVersion, State: Collected, Receipt: m.Receipt}); e != nil {
			return e
		}
		// A last path identity/hash observation closes replacement by an actor
		// that does not cooperate with this generation's advisory lock.
		check, e := observeActual(ctx, root, name)
		if e != nil {
			return e
		}
		if check != observed {
			return ErrConflict
		}
		if e = root.Remove(name); e != nil {
			return ErrIO
		}
		return s.syncDir(root)
	})
}

// VerifyRetired checks the exact generation after collection. A recovery
// scratch stream is still owned payload even though it is not a published
// body. Unknown partial claims are not erased or reported as complete.
func (s *Store) VerifyRetired(ctx context.Context, r Receipt) (State, error) {
	if !validReceipt(r) {
		return Partial, ErrIdentity
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.root == nil {
		return Partial, ErrClosed
	}
	if e := ctx.Err(); e != nil {
		return Partial, e
	}
	root, e := s.objectRoot(r.Identity, false)
	if errors.Is(e, os.ErrNotExist) {
		return Absent, nil
	}
	if e != nil {
		return Partial, e
	}
	defer root.Close()
	lock, e := s.lock(ctx, root)
	if e != nil {
		return Partial, e
	}
	defer unlock(lock)
	_, m, e := load(root, r.Identity)
	if e != nil {
		return Partial, e
	}
	if m == nil || !sameReceipt(m.Receipt, r) {
		return Partial, ErrConflict
	}
	if m.State != Collected {
		return Partial, ErrIncomplete
	}
	for _, name := range []string{"body.partial", "body.staged", "body.eml", "body.recovery"} {
		if _, e := root.Lstat(name); !errors.Is(e, os.ErrNotExist) {
			return Collected, ErrIncomplete
		}
	}
	return Collected, nil
}
