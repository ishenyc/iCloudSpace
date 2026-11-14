package addresses

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"math/big"
	"strconv"
	"strings"

	"icloudspace/internal/operationlog"
)

type source struct {
	ID                               int64
	Kind, Namespace, Suffix, Forward string
	Revision, Generation             int64
	Enabled                          bool
	PrincipalRevision                int64
	Subject                          string
}

func readSource(ctx context.Context, tx *sql.Tx, id int64) (source, error) {
	var x source
	err := tx.QueryRowContext(ctx, `SELECT id,kind,address_namespace,address_suffix,imap_username,revision,source_generation,enabled FROM space.mail_sources WHERE id=$1 AND retired_at IS NULL FOR UPDATE`, id).Scan(&x.ID, &x.Kind, &x.Namespace, &x.Suffix, &x.Forward, &x.Revision, &x.Generation, &x.Enabled)
	if err != nil {
		return source{}, classify(err)
	}
	if x.Kind != "custom" {
		var subject sql.NullString
		err = tx.QueryRowContext(ctx, `SELECT dsid,revision FROM space.apple_principals WHERE source_id=$1 FOR SHARE`, id).Scan(&subject, &x.PrincipalRevision)
		if err != nil {
			return source{}, classify(err)
		}
		x.Subject = subject.String
	}
	return x, nil
}
func localInput(in CreateInput) (CreateInput, error) {
	var err error
	in.Address, err = NormalizeAddress(in.Address)
	if err != nil {
		return in, err
	}
	in.Label = strings.TrimSpace(in.Label)
	if in.SourceID < 1 || !text(in.Label, 512, false) || !validID(in.GroupID) || !text(in.OwnerKey, 256, true) || (in.CredentialProfile != "api_key_only" && in.CredentialProfile != "mailbox") {
		return in, &FieldError{"create"}
	}
	return in, nil
}
func (s *Service) capacity(ctx context.Context, tx *sql.Tx, src source, extra int64) error {
	return s.capacityExcept(ctx, tx, src, extra, "")
}
func uidValidity() (int64, error) {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint32(b[:])
		if n != 0 {
			return int64(n), nil
		}
	}
}
func (s *Service) insert(ctx context.Context, tx *sql.Tx, issue Issuer, src source, in CreateInput, kind string, remote *RemoteAddress) (Metadata, error) {
	return s.insertPolicy(ctx, tx, issue, src, in, kind, remote, true)
}

// Only explicit deployment-authorized external local registration can skip
// the source suffix rule. Provider identity and ordinary creation keep their
// existing constraints through insert's default wrapper.
func (s *Service) insertPolicy(ctx context.Context, tx *sql.Tx, issue Issuer, src source, in CreateInput, kind string, remote *RemoteAddress, requireSuffix bool) (Metadata, error) {
	if issue == nil {
		return Metadata{}, ErrIneligible
	}
	if src.Namespace == in.Address || requireSuffix && remote == nil && !strings.HasSuffix(in.Address, "@"+strings.ToLower(src.Suffix)) {
		return Metadata{}, &FieldError{"namespace"}
	}
	var namespace bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.mail_sources WHERE lower(address_namespace)=$1 AND retired_at IS NULL)`, in.Address).Scan(&namespace); err != nil {
		return Metadata{}, err
	}
	if namespace {
		return Metadata{}, ErrConflict
	}
	uid, err := uidValidity()
	if err != nil {
		return Metadata{}, err
	}
	now := s.clock()
	var id int64
	var providerID, owner, forward any
	var active any
	if remote != nil {
		providerID = remote.ID
		owner = src.Subject
		forward = remote.Forward
		active = remote.Active
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO space.private_addresses(source_id,email,normalized_email,kind,label,group_id,lifecycle,enabled,provider_address_id,provider_owner,provider_active,forwarding_email,revision,auth_generation,uid_validity,uid_next,created_at,updated_at) VALUES($1,$2,$2,$3,$4,$5,'confirmed',$6,$7,$8,$9,$10,1,1,$11,1,$12,$12) RETURNING id`, src.ID, in.Address, kind, in.Label, in.GroupID, in.Enabled, providerID, owner, active, forward, uid, now).Scan(&id)
	if err != nil {
		return Metadata{}, classify(err)
	}
	if err = issue(ctx, tx, IssueRequest{SourceID: src.ID, AddressID: id, Generation: 1, Profile: in.CredentialProfile, OwnerKey: in.OwnerKey}); err != nil {
		return Metadata{}, err
	}
	return scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM space.private_addresses a WHERE a.id=$1`, id))
}
func (s *Service) CreateLocal(ctx context.Context, in CreateInput) (Metadata, error) {
	in, err := localInput(in)
	if err != nil {
		return Metadata{}, err
	}
	ctx, release, err := s.enter(ctx, in.SourceID)
	if err != nil {
		return Metadata{}, err
	}
	defer release()
	issuance, err := s.beginIssue(ctx)
	if err != nil {
		return Metadata{}, err
	}
	defer issuance.Close()
	tx, err := s.begin(ctx)
	if err != nil {
		return Metadata{}, err
	}
	defer tx.Rollback()
	src, err := readSource(ctx, tx, in.SourceID)
	if err != nil {
		return Metadata{}, err
	}
	if err = lockGroup(ctx, tx, in.GroupID); err != nil {
		return Metadata{}, err
	}
	if in.Enabled {
		if err = s.capacity(ctx, tx, src, 1); err != nil {
			return Metadata{}, err
		}
	}
	a, err := s.insert(ctx, tx, issuance.Stage, src, in, "manual", nil)
	if err != nil {
		return Metadata{}, err
	}
	if err = auditAddressTx(ctx, tx, a.SourceID, a.ID, s.clock(), "address.created"); err != nil {
		return Metadata{}, err
	}
	return a, commit(tx)
}

// RandomAddress uses rejection sampling through crypto/rand.Int. Length is
// uniformly selected from 8..12 and every character from lowercase ASCII and
// digits; the configured suffix is fixed by the source owner.
func RandomAddress(suffix string) (string, error) {
	if !text(suffix, 253, true) || strings.ContainsAny(suffix, "@ /\\\t") || strings.Contains(suffix, "..") || !strings.Contains(suffix, ".") {
		return "", &FieldError{"suffix"}
	}
	for _, label := range strings.Split(suffix, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", &FieldError{"suffix"}
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return "", &FieldError{"suffix"}
			}
		}
	}
	length, err := rand.Int(rand.Reader, big.NewInt(5))
	if err != nil {
		return "", err
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8+int(length.Int64()))
	for i := range b {
		n, e := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if e != nil {
			return "", e
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b) + "@" + strings.ToLower(suffix), nil
}
func (s *Service) CreateRandom(ctx context.Context, in RandomInput) ([]Metadata, error) {
	if in.SourceID < 1 || in.Count < 1 || in.Count > MaximumLimit || !validID(in.GroupID) || !text(in.Label, 512, false) || !text(in.OwnerKey, 256, true) || (in.CredentialProfile != "api_key_only" && in.CredentialProfile != "mailbox") {
		return nil, &FieldError{"random"}
	}
	ctx, release, err := s.enter(ctx, in.SourceID)
	if err != nil {
		return nil, err
	}
	defer release()
	issuance, err := s.beginIssue(ctx)
	if err != nil {
		return nil, err
	}
	defer issuance.Close()
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	src, err := readSource(ctx, tx, in.SourceID)
	if err != nil {
		return nil, err
	}
	if src.Kind != "custom" {
		return nil, ErrIneligible
	}
	if err = lockGroup(ctx, tx, in.GroupID); err != nil {
		return nil, err
	}
	out := make([]Metadata, 0, in.Count)
	for range in.Count {
		var addr string
		for attempt := 0; attempt < 16; attempt++ {
			addr, err = RandomAddress(src.Suffix)
			if err != nil {
				return nil, err
			}
			var exists bool
			err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM space.private_addresses WHERE normalized_email=$1) OR EXISTS(SELECT 1 FROM space.mail_sources WHERE lower(address_namespace)=$1)`, addr).Scan(&exists)
			if err != nil {
				return nil, err
			}
			if !exists {
				break
			}
			addr = ""
		}
		if addr == "" {
			return nil, ErrConflict
		}
		a, e := s.insert(ctx, tx, issuance.Stage, src, CreateInput{Address: addr, Label: strings.TrimSpace(in.Label), GroupID: in.GroupID, Enabled: true, CredentialProfile: in.CredentialProfile, OwnerKey: in.OwnerKey}, "random", nil)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
		if err = auditAddressTx(ctx, tx, a.SourceID, a.ID, s.clock(), "address.random_created"); err != nil {
			return nil, err
		}
	}
	return out, commit(tx)
}

func (s *Service) Patch(ctx context.Context, id int64, in PatchInput) (Metadata, error) {
	if id < 1 || in.ExpectedRevision < 1 || !validID(in.Group.ID) || !in.Group.Set && in.Group.ID != nil || in.Label != nil && !text(*in.Label, 512, false) {
		return Metadata{}, &FieldError{"patch"}
	}
	current, err := s.Get(ctx, id)
	if err != nil {
		return Metadata{}, err
	}
	ctx, release, err := s.enter(ctx, current.SourceID)
	if err != nil {
		return Metadata{}, err
	}
	defer release()
	tx, err := s.begin(ctx)
	if err != nil {
		return Metadata{}, err
	}
	defer tx.Rollback()
	src, err := readSource(ctx, tx, current.SourceID)
	if err != nil {
		return Metadata{}, err
	}
	if in.Group.Set {
		if err = lockGroup(ctx, tx, in.Group.ID); err != nil {
			return Metadata{}, err
		}
	}
	a, err := scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM space.private_addresses a WHERE a.id=$1 AND a.deleted_at IS NULL FOR UPDATE`, id))
	if err != nil {
		return Metadata{}, err
	}
	if a.Revision != in.ExpectedRevision {
		return Metadata{}, ErrConflict
	}
	reenabled := in.Enabled != nil && *in.Enabled && !a.Enabled
	if in.Enabled != nil {
		if *in.Enabled && a.Lifecycle != "confirmed" {
			return Metadata{}, ErrIneligible
		}
		a.Enabled = *in.Enabled
	}
	if reenabled {
		if err = s.capacity(ctx, tx, src, 1); err != nil {
			return Metadata{}, err
		}
	}
	if in.Label != nil {
		a.Label = strings.TrimSpace(*in.Label)
	}
	if in.Group.Set {
		a.GroupID = in.Group.ID
	}
	err = tx.QueryRowContext(ctx, `UPDATE space.private_addresses SET label=$2,enabled=$3,group_id=$4,revision=revision+1,updated_at=greatest(updated_at+1,$5) WHERE id=$1 RETURNING revision,updated_at`, id, a.Label, a.Enabled, a.GroupID, s.clock()).Scan(&a.Revision, &a.UpdatedAt)
	if err != nil {
		return Metadata{}, err
	}
	if reenabled {
		_, err = tx.ExecContext(ctx, `INSERT INTO space.address_backfills(source_id,address_id,mailbox_name,source_generation,scan_epoch,uid_validity,lower_uid,captured_upper_uid,committed_uid,state,initialized,created_at,updated_at)
 SELECT $1,$2,c.mailbox_name,c.source_generation,
 greatest($3,coalesce((SELECT max(b.scan_epoch)+1 FROM space.address_backfills b WHERE b.source_id=c.source_id AND b.address_id=$2 AND b.source_generation=c.source_generation AND b.mailbox_name=c.mailbox_name),1)),
 c.uid_validity,0,c.observed_uid,0,'pending',true,$4,$4 FROM space.mailbox_cursors c WHERE c.source_id=$1 AND c.source_generation=$5`, src.ID, id, a.Revision, s.clock(), src.Generation)
		if err != nil {
			return Metadata{}, err
		}
	}
	// Eligibility-dependent metadata must describe the updated row. Reusing the
	// pre-update projection would advertise active grants after disabling it.
	a, err = scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM space.private_addresses a WHERE a.id=$1`, id))
	if err != nil {
		return Metadata{}, err
	}
	if err = auditAddressTx(ctx, tx, a.SourceID, a.ID, s.clock(), "address.updated"); err != nil {
		return Metadata{}, err
	}
	return a, commit(tx)
}

// DeleteLocal retires a local address into the visible archive. Payload removal
// remains a separate explicit localcleanup operation; no identity is hidden here.
func (s *Service) DeleteLocal(ctx context.Context, id, revision int64, confirm string) error {
	if id < 1 || revision < 1 {
		return &FieldError{"revision"}
	}
	a, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	ctx, release, err := s.enter(ctx, a.SourceID)
	if err != nil {
		return err
	}
	defer release()
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = readSource(ctx, tx, a.SourceID); err != nil {
		return err
	}
	a, err = scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM space.private_addresses a WHERE a.id=$1 AND a.deleted_at IS NULL FOR UPDATE`, id))
	if err != nil {
		return err
	}
	if a.Revision != revision || a.Address != confirm {
		return ErrConflict
	}
	if a.Lifecycle != "confirmed" || a.Kind == "apple" {
		return ErrIneligible
	}
	if _, err = tx.ExecContext(ctx, `UPDATE space.private_addresses SET lifecycle='archived',enabled=false,archived_at=$2::bigint,archive_reason='historical',revision=revision+1,updated_at=greatest(updated_at+1,$2::bigint) WHERE id=$1`, id, s.clock()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE space.address_grants SET revoked_at=coalesce(revoked_at,$2) WHERE address_id=$1`, id, s.clock()); err != nil {
		return err
	}
	if err = auditAddressTx(ctx, tx, a.SourceID, a.ID, s.clock(), "address.archived"); err != nil {
		return err
	}
	return commit(tx)
}

func auditAddressTx(ctx context.Context, tx *sql.Tx, source, address, now int64, action string) error {
	return operationlog.RecordAuditTx(ctx, tx, operationlog.ActorRecord(ctx, operationlog.Record{OccurredAt: now, Action: action, ResourceKind: "address", ResourceRef: strconv.FormatInt(address, 10), Outcome: "success", SourceID: &source, Fields: map[string]string{"component": "addresses"}}))
}
func (s *Service) tombstone(ctx context.Context, tx *sql.Tx, id int64) error {
	now := s.clock()
	if _, err := tx.ExecContext(ctx, `UPDATE space.private_addresses SET deleted_at=$2::bigint,enabled=false,revision=revision+1,updated_at=greatest(updated_at+1,$2::bigint) WHERE id=$1 AND deleted_at IS NULL`, id, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE space.address_grants SET revoked_at=coalesce(revoked_at,$2) WHERE address_id=$1`, id, now); err != nil {
		return err
	}
	return nil
}
