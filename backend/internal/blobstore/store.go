// Package blobstore owns immutable original-message files. It does not perform
// SQL operations or decide whether a business operation should be retried.
package blobstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ManifestVersion = 1
	DefaultMaxBytes = int64(100 << 20)
	metadataLimit   = 16 << 10
)

var (
	ErrIdentity   = errors.New("blobstore: invalid identity")
	ErrConflict   = errors.New("blobstore: identity conflict")
	ErrIncomplete = errors.New("blobstore: incomplete publication")
	ErrIntegrity  = errors.New("blobstore: integrity check failed")
	ErrTooLarge   = errors.New("blobstore: byte budget exceeded")
	ErrCollected  = errors.New("blobstore: generation collected")
	ErrClosed     = errors.New("blobstore: closed")
	ErrIO         = errors.New("blobstore: file operation failed")
)

// Identity must be chosen and durably recorded by the caller before reading a
// source literal. Generations are positive SQL bigint values. Keys are opaque
// ASCII tokens, not paths, account identifiers or remote UIDs.
type Identity struct {
	ObjectKey  string `json:"object_key"`
	Generation int64  `json:"generation"`
	OwnerKey   string `json:"owner_key"`
}

// Receipt is the versioned durable file fact used by the SQL owner. SHA256 is
// lowercase hexadecimal. Reused is transient: when true Stage did not read the
// supplied reader; an IMAP owner must account for that unread literal itself.
// A receipt makes no assertion about a SQL commit or its acknowledgement.
type Receipt struct {
	Version    int      `json:"version"`
	Identity   Identity `json:"identity"`
	ReceiptKey string   `json:"receipt_key"`
	StagingRef string   `json:"staging_ref"`
	StorageRef string   `json:"storage_ref"`
	ByteSize   int64    `json:"byte_size"`
	SHA256     string   `json:"sha256"`
	Reused     bool     `json:"-"`
}

type State string

const (
	Absent    State = "absent"
	Partial   State = "partial"
	Staged    State = "staged"
	Published State = "published"
	Collected State = "collected"
)

type Inspection struct {
	State   State
	Receipt *Receipt
}

type Options struct {
	// Zero selects DefaultMaxBytes. Negative limits are invalid.
	MaxBytes int64
}

// Store pins its filesystem boundary with os.Root. Private directories and
// no-follow file opens also prevent a symlink from aliasing another object.
// Close waits for active methods. Returned files belong to their callers.
type Store struct {
	mu       sync.RWMutex
	root     *os.Root
	maxBytes int64
	ops      fileOps
}

// These narrow seams exercise real-file error handling without a fake storage
// platform. Production always uses ordinary os.File/os.Root operations.
type fileOps struct {
	read   func(*os.File, []byte) (int, error)
	write  func(*os.File, []byte) (int, error)
	sync   func(*os.File) error
	close  func(*os.File) error
	chmod  func(*os.File, os.FileMode) error
	rename func(*os.Root, string, string) error
}

func Open(directory string, options Options) (*Store, error) {
	if directory == "" || options.MaxBytes < 0 {
		return nil, ErrIdentity
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, ErrIO
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrIntegrity
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, ErrIO
	}
	f, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, ErrIO
	}
	opened, statErr := f.Stat()
	chmodErr := f.Chmod(0o700)
	closeErr := f.Close()
	if statErr != nil || !os.SameFile(info, opened) || chmodErr != nil || closeErr != nil {
		root.Close()
		return nil, ErrIntegrity
	}
	limit := options.MaxBytes
	if limit == 0 {
		limit = DefaultMaxBytes
	}
	return &Store{root: root, maxBytes: limit, ops: fileOps{
		read: (*os.File).Read, write: (*os.File).Write, sync: (*os.File).Sync, close: (*os.File).Close, chmod: (*os.File).Chmod,
		rename: (*os.Root).Rename,
	}}, nil
}

type claim struct {
	Version    int      `json:"version"`
	Identity   Identity `json:"identity"`
	ReceiptKey string   `json:"receipt_key"`
}

type manifest struct {
	Version int     `json:"version"`
	State   State   `json:"state"`
	Receipt Receipt `json:"receipt"`
}

func token(s string) bool {
	if len(s) == 0 || len(s) > 256 || s == "." || s == ".." {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._:-", rune(c))) {
			return false
		}
	}
	return true
}

func validIdentity(id Identity) bool {
	return id.Generation > 0 && token(id.ObjectKey) && token(id.OwnerKey)
}

func directoryFor(id Identity) string {
	h := sha256.Sum256([]byte(id.ObjectKey))
	key := hex.EncodeToString(h[:])
	return path.Join("v1", "objects", key[:2], key, "g"+strconv.FormatInt(id.Generation, 10))
}

func claimFor(id Identity) claim {
	data, _ := json.Marshal(id)
	h := sha256.Sum256(append([]byte("icloudspace.blob.receipt.v1\x00"), data...))
	return claim{Version: ManifestVersion, Identity: id, ReceiptKey: hex.EncodeToString(h[:])}
}

func receiptFor(id Identity, size int64, digest string) Receipt {
	refs, _ := Describe(id)
	return Receipt{Version: ManifestVersion, Identity: id, ReceiptKey: refs.ReceiptKey,
		StagingRef: refs.StagingRef, StorageRef: refs.StorageRef,
		ByteSize: size, SHA256: digest}
}

func validReceipt(r Receipt) bool {
	if !validIdentity(r.Identity) || r.Version != ManifestVersion || r.ByteSize < 0 || len(r.SHA256) != 64 {
		return false
	}
	digest, err := hex.DecodeString(r.SHA256)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != r.SHA256 {
		return false
	}
	expected := receiptFor(r.Identity, r.ByteSize, r.SHA256)
	r.Reused = false
	return r == expected
}

func sameReceipt(a, b Receipt) bool {
	a.Reused, b.Reused = false, false
	return validReceipt(a) && a == b
}

// child pins and checks every directory component. Comparing the opened inode
// closes the Lstat/OpenRoot substitution window, including in-root symlinks.
func child(parent *os.Root, name string, create bool) (*os.Root, error) {
	if create {
		if err := parent.Mkdir(name, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, ErrIO
		}
	}
	before, err := parent.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, ErrIntegrity
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, ErrIntegrity
	}
	f, err := parent.OpenFile(name, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, ErrIntegrity
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.IsDir() || !os.SameFile(before, info) {
		return nil, ErrIntegrity
	}
	if create && f.Chmod(0o700) != nil {
		return nil, ErrIO
	}
	next, err := parent.OpenRoot(name)
	if err != nil {
		return nil, ErrIntegrity
	}
	opened, err := next.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		next.Close()
		return nil, ErrIntegrity
	}
	if create {
		// Make each new ancestor durable before publishing anything below it.
		p, err := parent.Open(".")
		if err != nil {
			next.Close()
			return nil, ErrIO
		}
		syncErr := p.Sync()
		closeErr := p.Close()
		if syncErr != nil || closeErr != nil {
			next.Close()
			return nil, ErrIO
		}
	}
	return next, nil
}

func (s *Store) objectRoot(id Identity, create bool) (*os.Root, error) {
	current := s.root
	for _, segment := range strings.Split(directoryFor(id), "/") {
		next, err := child(current, segment, create)
		if current != s.root {
			current.Close()
		}
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

func openRegular(root *os.Root, name string, flags int) (*os.File, error) {
	before, statErr := root.Lstat(name)
	if statErr == nil && !before.Mode().IsRegular() {
		return nil, ErrIntegrity
	}
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, ErrIO
	}
	f, err := root.OpenFile(name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		if errors.Is(err, os.ErrExist) {
			return nil, os.ErrExist
		}
		return nil, ErrIO
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || before != nil && !os.SameFile(before, info) {
		f.Close()
		return nil, ErrIntegrity
	}
	return f, nil
}

func (s *Store) lock(ctx context.Context, root *os.Root) (*os.File, error) {
	f, err := openRegular(root, "lock", os.O_CREATE|os.O_EXCL|os.O_RDWR)
	if errors.Is(err, os.ErrExist) {
		f, err = openRegular(root, "lock", os.O_RDWR)
	}
	if err != nil {
		return nil, err
	}
	if s.ops.chmod(f, 0o600) != nil {
		f.Close()
		return nil, ErrIO
	}
	for {
		if err := ctx.Err(); err != nil {
			f.Close()
			return nil, err
		}
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			f.Close()
			return nil, ErrIO
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func unlock(f *os.File) {
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	_ = f.Close()
}

func readJSON(root *os.Root, name string, out any) error {
	f, err := openRegular(root, name, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, metadataLimit+1))
	if err != nil || len(data) > metadataLimit {
		return ErrIntegrity
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrIntegrity
	}
	return nil
}

func (s *Store) syncDir(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return ErrIO
	}
	err = s.ops.sync(f)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrIO
	}
	return nil
}

func (s *Store) writeNew(root *os.Root, name string, data []byte) error {
	f, err := openRegular(root, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	return s.writeOpened(root, f, data)
}

func (s *Store) writeOpened(root *os.Root, f *os.File, data []byte) error {
	defer f.Close()
	if s.ops.chmod(f, 0o600) != nil {
		return ErrIO
	}
	n, err := s.ops.write(f, data)
	if err != nil || n != len(data) {
		return ErrIO
	}
	if s.ops.sync(f) != nil {
		return ErrIO
	}
	if s.ops.close(f) != nil {
		return ErrIO
	}
	return s.syncDir(root)
}

func (s *Store) writeManifest(root *os.Root, m manifest) error {
	if !validManifest(m, m.Receipt.Identity) {
		return ErrIntegrity
	}
	var c claim
	if err := readJSON(root, "identity.json", &c); err != nil || c != claimFor(m.Receipt.Identity) {
		return ErrConflict
	}
	// A valid committed manifest anchors replacement of a torn metadata write.
	// The stream's expected bytes/hash never come from the temporary document.
	var committed manifest
	anchorErr := readJSON(root, "manifest.json", &committed)
	hasAnchor := anchorErr == nil
	if hasAnchor {
		if !validManifest(committed, m.Receipt.Identity) || !sameReceipt(committed.Receipt, m.Receipt) {
			return ErrConflict
		}
		if stateRank(m.State) < stateRank(committed.State) {
			if committed.State == Collected {
				return ErrCollected
			}
			return ErrConflict
		}
	} else if !errors.Is(anchorErr, os.ErrNotExist) {
		return anchorErr
	}
	data, _ := json.Marshal(m)
	err := s.writeNew(root, "manifest.next", data)
	if errors.Is(err, os.ErrExist) {
		f, openErr := openRegular(root, "manifest.next", os.O_RDWR)
		if openErr != nil {
			return openErr
		}
		defer f.Close()
		prior, readErr := io.ReadAll(io.LimitReader(f, metadataLimit+1))
		if readErr != nil || len(prior) > metadataLimit {
			return ErrIntegrity
		}
		if !bytes.Equal(prior, data) {
			if !hasAnchor {
				return ErrIncomplete
			}
			// Only a prefix of this generation's exact canonical metadata is
			// scratch space. Foreign or noncanonical documents are preserved.
			matched := false
			for _, state := range []State{Staged, Published, Collected} {
				candidate := manifest{Version: ManifestVersion, State: state, Receipt: committed.Receipt}
				encoded, _ := json.Marshal(candidate)
				if stateRank(state) < stateRank(committed.State) || !bytes.HasPrefix(encoded, prior) {
					continue
				}
				if len(prior) == len(encoded) && stateRank(state) > stateRank(m.State) {
					if state == Collected {
						return ErrCollected
					}
					return ErrConflict
				}
				matched = true
			}
			if !matched {
				return ErrIncomplete
			}
			if f.Truncate(0) != nil {
				return ErrIO
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return ErrIO
			}
			if err := s.writeOpened(root, f, data); err != nil {
				return err
			}
		} else {
			err = s.ops.sync(f)
			closeErr := s.ops.close(f)
			if err != nil || closeErr != nil {
				return ErrIO
			}
		}
	} else if err != nil {
		return err
	}
	if s.ops.rename(root, "manifest.next", "manifest.json") != nil {
		return ErrIO
	}
	return s.syncDir(root)
}

func stateRank(state State) int {
	switch state {
	case Staged:
		return 1
	case Published:
		return 2
	case Collected:
		return 3
	default:
		return 0
	}
}

func validManifest(m manifest, id Identity) bool {
	return m.Version == ManifestVersion && validReceipt(m.Receipt) && m.Receipt.Identity == id &&
		m.Receipt.ReceiptKey == claimFor(id).ReceiptKey && stateRank(m.State) > 0
}

func load(root *os.Root, id Identity) (claim, *manifest, error) {
	var c claim
	if err := readJSON(root, "identity.json", &c); err != nil {
		return c, nil, err
	}
	if c != claimFor(id) {
		return c, nil, ErrConflict
	}
	var m manifest
	err := readJSON(root, "manifest.json", &m)
	if errors.Is(err, os.ErrNotExist) {
		// A fully synced manifest.next may survive before the atomic rename.
		// Inspection exposes it; only an explicit mutation finishes the move.
		err = readJSON(root, "manifest.next", &m)
		if errors.Is(err, os.ErrNotExist) {
			return c, nil, nil
		}
	}
	if err != nil {
		return c, nil, err
	}
	if !validManifest(m, id) {
		return c, nil, ErrIntegrity
	}
	// A complete same-receipt collection decision is monotonic, including when
	// the last rename/acknowledgement was lost. Publish must not overwrite it.
	var next manifest
	if readJSON(root, "manifest.next", &next) == nil && next.State == Collected {
		if !validManifest(next, id) || !sameReceipt(next.Receipt, m.Receipt) {
			return c, nil, ErrConflict
		}
		m = next
	}
	return c, &m, nil
}

func bodyName(root *os.Root) (string, error) {
	found := ""
	for _, name := range []string{"body.partial", "body.staged", "body.eml"} {
		info, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || found != "" {
			return "", ErrIntegrity
		}
		found = name
	}
	return found, nil
}

func (s *Store) verify(ctx context.Context, root *os.Root, name string, r Receipt) (*os.File, error) {
	f, err := openRegular(root, name, os.O_RDONLY)
	if err != nil {
		return nil, ErrIntegrity
	}
	fail := func(err error) (*os.File, error) { f.Close(); return nil, err }
	info, err := f.Stat()
	if err != nil || info.Size() != r.ByteSize {
		return fail(ErrIntegrity)
	}
	h := sha256.New()
	buf := make([]byte, 32<<10)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		n, readErr := s.ops.read(f, buf)
		if n > 0 {
			size += int64(n)
			if size > r.ByteSize {
				return fail(ErrIntegrity)
			}
			h.Write(buf[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fail(ErrIO)
		}
	}
	after, err := f.Stat()
	if err != nil || size != r.ByteSize || hex.EncodeToString(h.Sum(nil)) != r.SHA256 || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return fail(ErrIntegrity)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fail(ErrIO)
	}
	return f, nil
}

func (s *Store) inspect(ctx context.Context, root *os.Root, id Identity) (Inspection, error) {
	_, m, err := load(root, id)
	if errors.Is(err, os.ErrNotExist) {
		name, bodyErr := bodyName(root)
		if bodyErr != nil || name != "" {
			return Inspection{State: Partial}, ErrIntegrity
		}
		for _, metadata := range []string{"manifest.json", "manifest.next"} {
			if _, err := root.Lstat(metadata); !errors.Is(err, os.ErrNotExist) {
				return Inspection{State: Partial}, ErrIntegrity
			}
		}
		return Inspection{State: Absent}, nil
	}
	if err != nil {
		return Inspection{State: Partial}, err
	}
	if m == nil {
		return Inspection{State: Partial}, nil
	}
	r := m.Receipt
	out := Inspection{State: Partial, Receipt: &r}
	name, err := bodyName(root)
	if err != nil {
		return out, err
	}
	if m.State == Collected {
		out.State = Collected
		if name != "" {
			return out, ErrIncomplete
		}
		return out, nil
	}
	if name == "" {
		return out, ErrIntegrity
	}
	f, err := s.verify(ctx, root, name, r)
	if err != nil {
		return out, err
	}
	f.Close()
	if m.State == Staged && name == "body.staged" {
		out.State = Staged
	} else if m.State == Published && name == "body.eml" {
		out.State = Published
	}
	return out, nil
}

// Inspect recovers durable file facts only. Partial with a Receipt identifies a
// complete byte stream interrupted during a filesystem transition. It is not a
// SQL recovery result; the caller must decide whether to explicitly Publish.
func (s *Store) Inspect(ctx context.Context, id Identity) (Inspection, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !validIdentity(id) {
		return Inspection{}, ErrIdentity
	}
	if s.root == nil {
		return Inspection{}, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return Inspection{}, err
	}
	root, err := s.objectRoot(id, false)
	if errors.Is(err, os.ErrNotExist) {
		return Inspection{State: Absent}, nil
	}
	if err != nil {
		return Inspection{}, err
	}
	defer root.Close()
	l, err := s.lock(ctx, root)
	if err != nil {
		return Inspection{}, err
	}
	defer unlock(l)
	return s.inspect(ctx, root, id)
}

// Stage streams the original bytes once. It never reencodes MIME and never
// silently resumes an unproven partial stream. Cancellation is checked between
// Reader calls; the source owner must close a reader blocked on remote input.
// On a transition error a nonzero receipt may be returned for explicit recovery.
func (s *Store) Stage(ctx context.Context, id Identity, reader io.Reader) (Receipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !validIdentity(id) || reader == nil {
		return Receipt{}, ErrIdentity
	}
	if s.root == nil {
		return Receipt{}, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	root, err := s.objectRoot(id, true)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: stage directory", err)
	}
	defer root.Close()
	l, err := s.lock(ctx, root)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: stage lock", err)
	}
	defer unlock(l)
	current, err := s.inspect(ctx, root, id)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: stage inspect", err)
	}
	if current.State == Staged || current.State == Published {
		r := *current.Receipt
		r.Reused = true
		return r, nil
	}
	if current.State == Collected {
		return Receipt{}, ErrCollected
	}
	if current.State == Partial {
		if current.Receipt != nil {
			return *current.Receipt, ErrIncomplete
		}
		return Receipt{}, ErrIncomplete
	}
	data, _ := json.Marshal(claimFor(id))
	if err := s.writeNew(root, "identity.json", data); err != nil {
		return Receipt{}, fmt.Errorf("%w: stage claim", err)
	}
	f, err := openRegular(root, "body.partial", os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: stage partial", err)
	}
	defer f.Close()
	if s.ops.chmod(f, 0o600) != nil {
		return Receipt{}, ErrIO
	}
	h := sha256.New()
	buf := make([]byte, 32<<10)
	var size int64
	emptyReads := 0
	for {
		if err := ctx.Err(); err != nil {
			return Receipt{}, err
		}
		// Read at most one byte beyond the budget, even for a large literal.
		want := int64(len(buf))
		if remaining := s.maxBytes - size; remaining < want {
			want = remaining + 1
		}
		n, readErr := reader.Read(buf[:int(want)])
		if n < 0 || n > int(want) {
			return Receipt{}, ErrIO
		}
		if int64(n) > s.maxBytes-size {
			return Receipt{}, ErrTooLarge
		}
		if n > 0 {
			written, writeErr := s.ops.write(f, buf[:n])
			if writeErr != nil || written != n {
				return Receipt{}, ErrIO
			}
			h.Write(buf[:n])
			size += int64(n)
			emptyReads = 0
		} else if readErr == nil {
			emptyReads++
			if emptyReads >= 100 {
				return Receipt{}, ErrIO
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return Receipt{}, ErrIO
		}
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if s.ops.sync(f) != nil || f.Close() != nil {
		return Receipt{}, ErrIO
	}
	r := receiptFor(id, size, hex.EncodeToString(h.Sum(nil)))
	// A durable completed receipt precedes moving the completed byte stream.
	if err := s.writeManifest(root, manifest{Version: ManifestVersion, State: Staged, Receipt: r}); err != nil {
		return r, err
	}
	if s.ops.rename(root, "body.partial", "body.staged") != nil {
		return r, ErrIO
	}
	if err := s.syncDir(root); err != nil {
		return r, err
	}
	return r, nil
}

func (s *Store) withReceipt(ctx context.Context, r Receipt, action func(*os.Root, *manifest) error) error {
	if !validReceipt(r) {
		return ErrIdentity
	}
	if s.root == nil {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := s.objectRoot(r.Identity, false)
	if err != nil {
		return ErrIntegrity
	}
	defer root.Close()
	l, err := s.lock(ctx, root)
	if err != nil {
		return err
	}
	defer unlock(l)
	_, m, err := load(root, r.Identity)
	if err != nil {
		return err
	}
	if m == nil {
		return ErrIncomplete
	}
	if !sameReceipt(r, m.Receipt) {
		return ErrConflict
	}
	return action(root, m)
}

// Publish makes a verified staged stream available. Repeating it with the exact
// same receipt is safe, including after a lost acknowledgement. No SQL state is
// changed, and no compensation is performed on an error.
func (s *Store) Publish(ctx context.Context, r Receipt) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.withReceipt(ctx, r, func(root *os.Root, m *manifest) error {
		if m.State == Collected {
			return ErrCollected
		}
		name, err := bodyName(root)
		if err != nil || name == "" {
			return ErrIntegrity
		}
		if m.State == Published && name != "body.eml" {
			return ErrIntegrity
		}
		f, err := s.verify(ctx, root, name, r)
		if err != nil {
			return err
		}
		f.Close()
		if _, err := root.Lstat("manifest.json"); errors.Is(err, os.ErrNotExist) {
			if err := s.writeManifest(root, *m); err != nil {
				return err
			}
		}
		if name != "body.eml" {
			if s.ops.rename(root, name, "body.eml") != nil {
				return ErrIO
			}
		}
		if err := s.syncDir(root); err != nil {
			return err
		}
		if m.State == Published {
			return nil
		}
		return s.writeManifest(root, manifest{Version: ManifestVersion, State: Published, Receipt: m.Receipt})
	})
}

// OpenVerified hashes, checks the size of, and rewinds the same regular-file
// descriptor it returns. One IMAP command can share it through SectionReaders;
// it is never closed and reopened between validation and use.
func (s *Store) OpenVerified(ctx context.Context, r Receipt) (*os.File, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var f *os.File
	err := s.withReceipt(ctx, r, func(root *os.Root, m *manifest) error {
		if m.State == Collected {
			return ErrCollected
		}
		if m.State != Published {
			return ErrIncomplete
		}
		var err error
		f, err = s.verify(ctx, root, "body.eml", r)
		return err
	})
	return f, err
}

// Collect removes only an exact, verified generation. The SQL owner must first
// establish that it is safe to collect; an unknown SQL outcome is no authority
// to call this method. The claim, receipt and lock are retained as a tombstone,
// so a stale collector cannot destroy a replacement under the same generation.
func (s *Store) Collect(ctx context.Context, r Receipt) error {
	_, err := s.collect(ctx, r, false)
	return err
}

// CollectVerified combines the Inspect+Collect state checks under one file
// lease and hashes the same original only once. It reports false for an already
// complete tombstone, while an interrupted unlink is verified and completed.
// The caller must still hold the source guard and an acknowledged SQL proof.
func (s *Store) CollectVerified(ctx context.Context, r Receipt) (bool, error) {
	return s.collect(ctx, r, true)
}

func (s *Store) collect(ctx context.Context, r Receipt, inspectState bool) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	collected := false
	err := s.withReceipt(ctx, r, func(root *os.Root, m *manifest) error {
		name, err := bodyName(root)
		if err != nil {
			return err
		}
		if inspectState {
			if m.State == Collected && name == "" {
				return nil
			}
			if m.State != Collected && !(m.State == Published && name == "body.eml" || m.State == Staged && name == "body.staged") {
				return ErrIncomplete
			}
		}
		if name != "" {
			f, err := s.verify(ctx, root, name, r)
			if err != nil {
				return err
			}
			f.Close()
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		// Persist the irreversible local collection decision before deleting
		// bytes. A torn temporary document leaves the verified body intact;
		// a complete tombstone prevents every stale Publish from reviving it.
		if err := s.writeManifest(root, manifest{Version: ManifestVersion, State: Collected, Receipt: m.Receipt}); err != nil {
			return err
		}
		if name != "" {
			if root.Remove(name) != nil {
				return ErrIO
			}
		}
		if err := s.syncDir(root); err != nil {
			return err
		}
		collected = true
		return nil
	})
	return collected, err
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return nil
	}
	err := s.root.Close()
	s.root = nil
	if err != nil {
		return fmt.Errorf("%w: close", ErrIO)
	}
	return nil
}
