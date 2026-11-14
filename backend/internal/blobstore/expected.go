package blobstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
)

// References describes locations and an identity key, without asserting that
// files, a completed receipt, or a publication exist.
type References struct {
	ReceiptKey string `json:"receipt_key"`
	StagingRef string `json:"staging_ref"`
	StorageRef string `json:"storage_ref"`
}

// Describe is pure: it performs no filesystem access and creates no Receipt.
func Describe(id Identity) (References, error) {
	if !validIdentity(id) {
		return References{}, ErrIdentity
	}
	base := directoryFor(id)
	return References{ReceiptKey: claimFor(id).ReceiptKey,
		StagingRef: path.Join(base, "body.staged"), StorageRef: path.Join(base, "body.eml")}, nil
}

// Expected is a caller's explicit, trusted size/digest authorization. A
// converter must persist it together with Identity before opening source bytes.
// It is not a statement that those bytes have been copied or made available.
type Expected struct {
	ByteSize int64  `json:"byte_size"`
	SHA256   string `json:"sha256"`
}

type expectedIntent struct {
	Version    int      `json:"version"`
	Identity   Identity `json:"identity"`
	ReceiptKey string   `json:"receipt_key"`
	Expected   Expected `json:"expected"`
}

func validExpected(expected Expected) bool {
	digest, err := hex.DecodeString(expected.SHA256)
	return expected.ByteSize >= 0 && err == nil && len(digest) == sha256.Size &&
		hex.EncodeToString(digest) == expected.SHA256
}

// expectedDocument may complete only a canonical prefix of the caller's exact
// expected document. It preserves noncanonical/foreign files. The generation
// claim and explicit expected intent are checked by StageExpected first.
func (s *Store) expectedDocument(root *os.Root, name string, data []byte) error {
	err := s.writeNew(root, name, data)
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	f, err := openRegular(root, name, os.O_RDWR)
	if err != nil {
		return err
	}
	defer f.Close()
	prior, err := io.ReadAll(io.LimitReader(f, metadataLimit+1))
	if err != nil || len(prior) > metadataLimit {
		return ErrIntegrity
	}
	if !bytes.HasPrefix(data, prior) {
		return ErrConflict
	}
	if bytes.Equal(data, prior) {
		if s.ops.sync(f) != nil || s.ops.close(f) != nil {
			return ErrIO
		}
		return s.syncDir(root)
	}
	if f.Truncate(0) != nil {
		return ErrIO
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return ErrIO
	}
	return s.writeOpened(root, f, data)
}

func expectedNextPrefix(root *os.Root, data []byte) bool {
	f, err := openRegular(root, "manifest.next", os.O_RDONLY)
	if err != nil {
		return false
	}
	defer f.Close()
	prior, err := io.ReadAll(io.LimitReader(f, metadataLimit+1))
	return err == nil && len(prior) < len(data) && bytes.HasPrefix(data, prior)
}

func (s *Store) expectedClaim(root *os.Root, id Identity) error {
	var c claim
	err := readJSON(root, "identity.json", &c)
	if err == nil {
		if c != claimFor(id) {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, name := range []string{"body.partial", "body.staged", "body.eml", "body.recovery", "expected.json", "manifest.json", "manifest.next"} {
		if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return ErrIntegrity
		}
	}
	data, _ := json.Marshal(claimFor(id))
	return s.writeNew(root, "identity.json", data)
}

func (s *Store) syncVerified(ctx context.Context, root *os.Root, name string, r Receipt) error {
	f, err := s.verify(ctx, root, name, r)
	if err != nil {
		return err
	}
	defer f.Close()
	if s.ops.sync(f) != nil || s.ops.close(f) != nil {
		return ErrIO
	}
	return s.syncDir(root)
}

// expectedStream owns only body.recovery. The original body.partial remains
// untouched until this complete replacement has passed size/hash and fsync.
func (s *Store) expectedStream(ctx context.Context, root *os.Root, r Receipt, reader io.Reader) (bool, error) {
	f, err := openRegular(root, "body.recovery", os.O_CREATE|os.O_EXCL|os.O_RDWR)
	if errors.Is(err, os.ErrExist) {
		f, err = openRegular(root, "body.recovery", os.O_RDWR)
		if err != nil {
			return false, err
		}
		// The matching durable expected intent owns this recovery scratch file.
		// A complete earlier replacement can be reused without reading source.
		verifyErr := s.syncVerified(ctx, root, "body.recovery", r)
		if verifyErr == nil {
			f.Close()
			return true, nil
		}
		if !errors.Is(verifyErr, ErrIntegrity) {
			f.Close()
			return false, verifyErr
		}
		if f.Truncate(0) != nil {
			f.Close()
			return false, ErrIO
		}
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	if s.ops.chmod(f, 0o600) != nil {
		return false, ErrIO
	}
	h := sha256.New()
	buf := make([]byte, 32<<10)
	var size int64
	emptyReads := 0
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		want := int64(len(buf))
		if remaining := r.ByteSize - size; remaining < want {
			want = remaining + 1
		}
		n, readErr := reader.Read(buf[:int(want)])
		if n < 0 || n > int(want) {
			return false, ErrIO
		}
		if int64(n) > r.ByteSize-size {
			return false, ErrIntegrity
		}
		if n > 0 {
			written, writeErr := s.ops.write(f, buf[:n])
			if writeErr != nil || written != n {
				return false, ErrIO
			}
			h.Write(buf[:n])
			size += int64(n)
			emptyReads = 0
		} else if readErr == nil {
			emptyReads++
			if emptyReads >= 100 {
				return false, ErrIO
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return false, ErrIO
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if size != r.ByteSize || hex.EncodeToString(h.Sum(nil)) != r.SHA256 {
		return false, ErrIntegrity
	}
	if s.ops.sync(f) != nil || s.ops.close(f) != nil {
		return false, ErrIO
	}
	return false, s.syncDir(root)
}

func (s *Store) finishExpected(root *os.Root) error {
	if s.ops.rename(root, "body.recovery", "body.partial") != nil {
		return ErrIO
	}
	if err := s.syncDir(root); err != nil {
		return err
	}
	if s.ops.rename(root, "body.partial", "body.staged") != nil {
		return ErrIO
	}
	return s.syncDir(root)
}

// StageExpected is an explicit caller-authorized conversion/recovery operation,
// not an automatic retry policy. It requires a trusted journaled Expected and
// exact durable identity claim. Incomplete recovery scratch files may be
// rewritten only under that matching expected intent. Original unknown partial
// bytes are atomically replaced only after a complete, verified, synced new
// stream and its receipt are durable. Publish remains a separate decision.
func (s *Store) StageExpected(ctx context.Context, id Identity, expected Expected, reader io.Reader) (Receipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !validIdentity(id) || !validExpected(expected) || reader == nil {
		return Receipt{}, ErrIdentity
	}
	if s.root == nil {
		return Receipt{}, ErrClosed
	}
	if expected.ByteSize > s.maxBytes {
		return Receipt{}, ErrTooLarge
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	root, err := s.objectRoot(id, true)
	if err != nil {
		return Receipt{}, err
	}
	defer root.Close()
	l, err := s.lock(ctx, root)
	if err != nil {
		return Receipt{}, err
	}
	defer unlock(l)
	if err := s.expectedClaim(root, id); err != nil {
		return Receipt{}, err
	}
	r := receiptFor(id, expected.ByteSize, expected.SHA256)
	staged := manifest{Version: ManifestVersion, State: Staged, Receipt: r}
	stagedData, _ := json.Marshal(staged)
	_, m, err := load(root, id)
	if err != nil {
		// Only this explicit expected path can coordinate its own interrupted
		// first staged-manifest write, after verifying a full replacement below.
		_, currentErr := root.Lstat("manifest.json")
		if !errors.Is(currentErr, os.ErrNotExist) || !expectedNextPrefix(root, stagedData) {
			return Receipt{}, err
		}
		m = nil
	}
	if m != nil {
		if !sameReceipt(r, m.Receipt) {
			return Receipt{}, ErrConflict
		}
		if m.State == Collected {
			return Receipt{}, ErrCollected
		}
	}
	intent := expectedIntent{Version: ManifestVersion, Identity: id, ReceiptKey: claimFor(id).ReceiptKey, Expected: expected}
	data, _ := json.Marshal(intent)
	if err := s.expectedDocument(root, "expected.json", data); err != nil {
		return Receipt{}, err
	}
	name, err := bodyName(root)
	if err != nil {
		return Receipt{}, err
	}
	_, recoveryErr := root.Lstat("body.recovery")
	if recoveryErr != nil && !errors.Is(recoveryErr, os.ErrNotExist) {
		return Receipt{}, ErrIO
	}
	if m != nil && errors.Is(recoveryErr, os.ErrNotExist) {
		if name == "" || m.State == Published && name != "body.eml" {
			return Receipt{}, ErrIntegrity
		}
		if err := s.syncVerified(ctx, root, name, r); err != nil {
			return Receipt{}, err
		}
		if name == "body.partial" {
			if s.ops.rename(root, name, "body.staged") != nil {
				return Receipt{}, ErrIO
			}
			if err := s.syncDir(root); err != nil {
				return Receipt{}, err
			}
		}
		r.Reused = true
		return r, nil
	}
	if m != nil && m.State != Staged || name != "" && name != "body.partial" {
		return Receipt{}, ErrIntegrity
	}
	reused, err := s.expectedStream(ctx, root, r, reader)
	if err != nil {
		return Receipt{}, err
	}
	if m == nil {
		if err := s.expectedDocument(root, "manifest.next", stagedData); err != nil {
			return Receipt{}, err
		}
	}
	if err := s.writeManifest(root, staged); err != nil {
		return Receipt{}, err
	}
	if err := s.finishExpected(root); err != nil {
		return r, err
	}
	r.Reused = reused
	return r, nil
}
