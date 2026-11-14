package providersession

import (
	"context"
	"errors"
	"strings"

	"icloudspace/internal/provider/apple"
)

// Restore accepts only the canonical capsule. It does not trust an imported
// validated/authenticated claim and performs no network action.
func (s *Service) Restore(ctx context.Context, id int64, actor Actor, key string, document apple.SessionDocument) (AuthResult, error) {
	return s.local(ctx, id, actor, key, RestoreSession, func(src source) (apple.SessionDocument, error) {
		if _, err := apple.EncodeSession(document); err != nil || !strings.EqualFold(document.Principal.AppleID, src.AppleID) || document.Principal.Region != src.Region || src.DSID != "" && document.Principal.DSID != src.DSID {
			return apple.SessionDocument{}, ErrBinding
		}
		document.ValidatedAtUnixNano = nil
		// An imported DSID cannot establish the first trusted identity anchor.
		// The next validation must prove the configured Apple ID before binding.
		if src.DSID == "" {
			document.Principal.DSID = ""
		}
		return document, nil
	}, false)
}
func (s *Service) ClearAuth(ctx context.Context, id int64, actor Actor, key string) (AuthResult, error) {
	return s.local(ctx, id, actor, key, ClearAuthentication, func(src source) (apple.SessionDocument, error) {
		return apple.NewSession(apple.Principal{AppleID: src.AppleID, Region: src.Region, DSID: src.DSID})
	}, true)
}

// Validate is an explicit read of the existing capsule. It does not log in or
// restore previous secrets when validation fails.
func (s *Service) Validate(ctx context.Context, id int64, actor Actor, key string) (AuthResult, error) {
	if id < 1 || !actorValid(actor) || !requestKey(key) {
		return AuthResult{}, ErrInvalid
	}
	if err := s.checkActor(ctx, actor); err != nil {
		return AuthResult{}, err
	}
	ctx, gate, close, err := s.enter(ctx, id)
	if err != nil {
		return AuthResult{}, err
	}
	defer close()
	if old, e := s.repo.findChallenge(ctx, id, actor, "", key); e == nil {
		src, e := s.repo.load(ctx, id)
		if e != nil {
			return AuthResult{}, e
		}
		previous, exists := receipt(old, key)
		if src.Scope != old.Document.Scope || !exists || previous.Action != ValidateSession {
			return AuthResult{}, ErrStale
		}
		out := s.result(src, old, key)
		if out.Receipt.Prepared || out.Receipt.Outcome == Unknown {
			return out, ErrRequestUnknown
		}
		return out, nil
	} else if !errors.Is(e, ErrNotFound) {
		return AuthResult{}, e
	}
	src, err := s.repo.load(ctx, id)
	if err != nil {
		return AuthResult{}, err
	}
	document, err := s.document(src, false)
	if err != nil {
		return AuthResult{}, err
	}
	c, err := s.newChallenge(src, actor, key, ValidateSession)
	if err != nil {
		return AuthResult{}, err
	}
	w, err := s.repo.encodeSession(src, document, false)
	if err != nil {
		return AuthResult{}, err
	}
	c, err = s.saveAuth(ctx, gate, w, actor, nil, c, true, false)
	if err != nil {
		return s.result(src, c, key), err
	}
	prepared, err := s.repo.load(ctx, id)
	if err != nil {
		return s.result(src, c, key), err
	}
	return s.runAuth(ctx, gate, prepared, c, actor, key, ValidateSession, func(client *apple.Client) error { return client.Validate(ctx) })
}
func (s *Service) local(ctx context.Context, id int64, actor Actor, key string, action Action, create func(source) (apple.SessionDocument, error), terminal bool) (AuthResult, error) {
	if id < 1 || !actorValid(actor) || !requestKey(key) {
		return AuthResult{}, ErrInvalid
	}
	if err := s.checkActor(ctx, actor); err != nil {
		return AuthResult{}, err
	}
	ctx, gate, close, err := s.enter(ctx, id)
	if err != nil {
		return AuthResult{}, err
	}
	defer close()
	if old, e := s.repo.findChallenge(ctx, id, actor, "", key); e == nil {
		src, e := s.repo.load(ctx, id)
		if e != nil {
			return AuthResult{}, e
		}
		previous, exists := receipt(old, key)
		if src.Scope != old.Document.Scope || !exists || previous.Action != action {
			return AuthResult{}, ErrStale
		}
		return s.result(src, old, key), nil
	} else if !errors.Is(e, ErrNotFound) {
		return AuthResult{}, e
	}
	src, err := s.repo.load(ctx, id)
	if err != nil {
		return AuthResult{}, err
	}
	document, err := create(src)
	if err != nil {
		return AuthResult{}, err
	}
	w, err := s.repo.encodeSession(src, document, false)
	if err != nil {
		return AuthResult{}, err
	}
	c, err := s.newChallenge(src, actor, key, action)
	if err != nil {
		return AuthResult{}, err
	}
	c.Document.Receipts[0].Outcome = Accepted
	c.Document.Receipts[0].Prepared = false
	c.Document.Receipts[0].FinishedAt = &w.info.SavedAt
	if terminal {
		c.State = "complete"
	}
	c, err = s.saveAuth(ctx, gate, w, actor, nil, c, true, false)
	persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.PersistenceTimeout)
	defer cancel()
	current, e := s.repo.load(persist, id)
	if e != nil {
		current = src
	}
	return s.result(current, c, key), err
}
