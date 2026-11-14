package syncengine

import (
	"context"
	"errors"
	"strings"
	"unicode"

	"icloudspace/internal/accounts"
	"icloudspace/internal/addresses"
	"icloudspace/internal/intake"
	"icloudspace/internal/provider/apple"
	upstream "icloudspace/internal/provider/imap"
	"icloudspace/internal/providersession"
	"icloudspace/internal/rounds"
	"icloudspace/internal/sourceguard"
)

func (e *Executor) current(ctx context.Context, in rounds.StepInput) (accounts.Metadata, Settings, error) {
	actual, err := e.config.Rounds.CurrentSource(ctx, in.Source.Scope.SourceID)
	if err != nil {
		return accounts.Metadata{}, Settings{}, err
	}
	if actual.Scope != in.Source.Scope || !actual.Enabled || actual.HasDirectory != in.Source.HasDirectory || actual.RestInterval != in.Source.RestInterval {
		return accounts.Metadata{}, Settings{}, rounds.ErrStale
	}
	var writes bool
	var revision int64
	if err = e.config.Intake.DB.QueryRowContext(ctx, `SELECT writes_enabled,configuration_revision FROM space.installation WHERE singleton`).Scan(&writes, &revision); err != nil {
		return accounts.Metadata{}, Settings{}, err
	}
	if !writes {
		return accounts.Metadata{}, Settings{}, providersession.ErrReadOnly
	}
	if revision != in.Source.Scope.ConfigurationRevision {
		return accounts.Metadata{}, Settings{}, rounds.ErrStale
	}
	metadata, err := e.config.Accounts.Get(ctx, in.Source.Scope.SourceID)
	if err != nil {
		return metadata, Settings{}, err
	}
	if !metadata.Enabled || metadata.ID != in.Source.Scope.SourceID || metadata.Revision != in.Source.Scope.Revision || metadata.SourceGeneration != in.Source.Scope.Generation || metadata.CredentialGeneration != in.Source.Scope.CredentialGeneration || actual.HasDirectory != (metadata.Kind != accounts.Custom) {
		return metadata, Settings{}, rounds.ErrStale
	}
	settings, err := e.config.Options(ctx, actual)
	if err != nil {
		return metadata, settings, err
	}
	if settings.Revision != in.Source.Scope.ConfigurationRevision || settings.Mailbox == "" || len(settings.Mailbox) > 1024 || strings.IndexFunc(settings.Mailbox, unicode.IsControl) >= 0 || settings.DirectoryProfile != "mailbox" && settings.DirectoryProfile != "api_key_only" {
		return metadata, settings, rounds.ErrStale
	}
	return metadata, settings, nil
}
func (e *Executor) Step(ctx context.Context, in rounds.StepInput) (rounds.StepResult, error) {
	if e == nil || !in.Gate.ValidFor(e.config.Registry, in.Source.Scope.SourceID) || in.RoundID == "" || len(in.RoundID) > 128 || strings.ContainsAny(in.RoundID, "\r\n\x00") || in.Phase != rounds.Directory && in.Phase != rounds.Mail {
		return failed(ErrInvalid, "invalid_step", false, false)
	}
	if in.Phase == rounds.Directory && (in.IMAPSlot != nil || in.Trigger == rounds.Public) || in.Phase == rounds.Mail && !e.config.Slots.Owns(in.IMAPSlot, in.Gate) {
		return failed(ErrInvalid, "invalid_admission", false, false)
	}
	ctx = sourceguard.WithLease(ctx, in.Gate)
	metadata, settings, err := e.current(ctx, in)
	if err != nil {
		return sourceFailure(err)
	}
	if in.Phase == rounds.Directory {
		return e.directory(ctx, in, metadata, settings)
	}
	return e.mail(ctx, in, metadata, settings)
}
func (e *Executor) directory(ctx context.Context, in rounds.StepInput, metadata accounts.Metadata, settings Settings) (rounds.StepResult, error) {
	if metadata.Apple == nil || !in.Source.HasDirectory {
		return failed(ErrInvalid, "directory_not_applicable", false, false)
	}
	directory, err := e.config.Sessions.Provider(metadata.ID).Directory(ctx)
	if err != nil {
		return providerFailure(err, "directory")
	}
	if _, _, err = e.current(ctx, in); err != nil {
		return sourceFailure(err)
	}
	_, err = e.config.Addresses.ReconcileDirectory(ctx, metadata.ID, metadata.Revision, directory, "sync:"+in.RoundID, settings.DirectoryProfile)
	if err != nil {
		return failed(err, "directory_checkpoint_failed", false, errors.Is(err, addresses.ErrCommitUnknown))
	}
	return rounds.StepResult{State: rounds.StepComplete}, nil
}
func providerFailure(err error, phase string) (rounds.StepResult, error) {
	var persistence *providersession.PersistenceError
	uncertain := errors.As(err, &persistence)
	if errors.Is(err, providersession.ErrLoginRequired) {
		return failed(err, "login_required", false, uncertain)
	}
	if errors.Is(err, providersession.ErrBinding) {
		return failed(err, "session_binding", false, uncertain)
	}
	if errors.Is(err, providersession.ErrReadOnly) || errors.Is(err, addresses.ErrReadOnly) {
		return failed(err, "read_only", false, uncertain)
	}
	if errors.Is(err, providersession.ErrStale) || errors.Is(err, rounds.ErrStale) {
		return failed(err, "source_changed", false, uncertain)
	}
	if errors.Is(err, ErrBackfillUnknown) {
		return failed(err, "backfill_prepare_unknown", false, true)
	}
	if errors.Is(err, intake.ErrTimestampRange) {
		return failed(err, phase+"_timestamp_range", false, false)
	}
	if errors.Is(err, intake.ErrUIDExhausted) {
		return failed(err, phase+"_uid_exhausted", false, false)
	}
	if errors.Is(err, intake.ErrSourceChanged) {
		return failed(err, phase+"_source_bytes_changed", false, false)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return failed(err, phase+"_cancelled", false, false)
	}
	if errors.As(err, &persistence) {
		return failed(err, phase+"_session_unknown", false, true)
	}
	var appleError *apple.Error
	if errors.As(err, &appleError) {
		retry := appleError.Kind == apple.DNS || appleError.Kind == apple.Connect || appleError.Kind == apple.Timeout || appleError.Kind == apple.RateLimited
		return failed(err, phase+"_"+string(appleError.Kind), retry, appleError.Unknown)
	}
	var imapError *upstream.Error
	if errors.As(err, &imapError) {
		retry := imapError.Kind == upstream.KindDNS || imapError.Kind == upstream.KindConnect || imapError.Kind == upstream.KindTimeout
		return failed(err, phase+"_"+string(imapError.Kind), retry, false)
	}
	return failed(err, phase+"_failed", false, errors.Is(err, intake.ErrUnknown) || errors.Is(err, intake.ErrUnresolved))
}

func sourceFailure(err error) (rounds.StepResult, error) {
	if errors.Is(err, rounds.ErrStale) || errors.Is(err, accounts.ErrNotFound) {
		return failed(err, "source_changed", false, false)
	}
	return providerFailure(err, "source_metadata")
}
