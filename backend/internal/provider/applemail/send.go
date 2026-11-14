package applemail

import (
	"context"

	"icloudspace/internal/mailout"
	"icloudspace/internal/provider/apple"
)

func (o *operation) Upload(ctx context.Context, route mailout.Route, reference mailout.Reference, input mailout.Upload) (mailout.Uploaded, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	client, err := o.client()
	if err != nil {
		return mailout.Uploaded{}, err
	}
	proof, ok := o.references[referenceID(reference)]
	if !ok || proof.reference != reference || !same(proof.from, route.ProviderFrom) || !o.validRoute(route) || !o.fresh(reference.CheckedAt) || len(o.parts) >= 10 {
		return mailout.Uploaded{}, mailout.ErrReference
	}
	if o.usesSMTP() {
		return o.stageSMTPPart(ctx, input)
	}
	part, remote := client.MailUploadPart(ctx, apple.MailUpload{Filename: input.Filename, MediaType: input.MediaType, Size: input.ByteSize, SHA256: input.SHA256, Body: input.Body})
	if err = o.checkpoint(ctx, remote); err != nil {
		return mailout.Uploaded{}, err
	}
	if _, exists := o.parts[part.GUID]; exists {
		return mailout.Uploaded{}, mailout.ErrProvider
	}
	if input.Inline && part.ContentID == nil {
		return mailout.Uploaded{}, mailout.ErrProvider
	}
	if input.Inline {
		part.Disposition = "inline"
	} else {
		part.Disposition = "attachment"
	}
	o.parts[part.GUID] = part
	cid := ""
	if part.ContentID != nil {
		cid = *part.ContentID
	}
	return mailout.Uploaded{ID: part.GUID, Filename: part.Name, MediaType: part.MediaType, ContentID: cid, URL: part.URL, ByteSize: part.Size, SHA256: input.SHA256, Inline: input.Inline, LogicalCID: input.LogicalCID}, nil
}
func (o *operation) Submit(ctx context.Context, input mailout.Submission) (mailout.RPCReceipt, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.submitted {
		return o.submission, joined(o.submissionError, mailout.ErrConflict)
	}
	notSent := mailout.RPCReceipt{RPCID: input.RPCID, Outcome: mailout.NotSent, Matched: true}
	client, err := o.client()
	if err != nil {
		return notSent, err
	}
	proof, ok := o.references[referenceID(input.Reference)]
	if !ok || proof.reference != input.Reference || !same(proof.from, input.Route.ProviderFrom) || !o.validRoute(input.Route) || !o.fresh(input.Reference.CheckedAt) || !same(input.Recipient, input.Route.Recipient) || !safe(input.RPCID, 256) || o.resolved == nil || !same(o.resolved.Relay, proof.relay) || !same(o.resolved.Forward, proof.from) {
		return notSent, mailout.ErrReference
	}
	if o.usesSMTP() {
		mailbox, err := o.mailbox(client, input.Route)
		if err != nil {
			return notSent, err
		}
		raw, id, err := o.smtpMIME(input, proof, o.provider.config.Clock())
		if err != nil {
			return notSent, err
		}
		defer clear(raw)
		o.submitted = true
		o.submission, o.submissionError = o.provider.config.SMTP.send(ctx, o.scope.Gate, mailbox, proof.relay, raw, input.RPCID, id)
		if o.submission.Outcome == mailout.Accepted {
			copy, copyErr := o.provider.config.Drafts.appendSent(ctx, o.scope.Gate, mailbox, raw)
			if copyErr != nil || copy.Outcome != mailout.Accepted {
				o.submissionError = smtpFailure("sent_copy", copyErr)
			} else {
				o.submission.UpstreamID = copy.Candidate.ID
			}
		}
		o.submissionError = o.checkpoint(ctx, o.submissionError)
		return o.submission, o.submissionError
	}
	parts := make([]apple.MailPart, 0, len(input.Attachments))
	seen := map[string]bool{}
	for _, file := range input.Attachments {
		part, ok := o.parts[file.ID]
		if !ok || seen[file.ID] || part.Name != file.Filename || part.Size != file.ByteSize || !same(part.MediaType, file.MediaType) || part.ContentID != nil && *part.ContentID != file.ContentID {
			return notSent, mailout.ErrProvider
		}
		seen[file.ID] = true
		parts = append(parts, part)
	}
	params := apple.MailSend{Date: o.provider.config.Clock().UTC().Format("Mon, 02 Jan 2006 15:04:05 -0000"), From: proof.from, To: proof.relay, Recents: input.Recipient, Subject: input.Subject, Text: input.Text, HTML: input.HTML, Attachments: parts, ClientBuild: apple.MailWebBuild, IsHME: true}
	if input.Reference.MessageID != "" {
		params.InReplyTo = []string{input.Reference.MessageID}
		params.References = []string{input.Reference.MessageID}
	}
	if proof.wireGUID != "" {
		params.Mode = "reply"
		params.MessageGUID = proof.wireGUID
	}
	o.submitted = true
	r, remote := client.MailSubmit(ctx, input.RPCID, params)
	receipt := rpcReceipt(r)
	o.submission = receipt
	o.submissionError = o.checkpoint(ctx, remote)
	return receipt, o.submissionError
}
func (o *operation) AppendDraft(ctx context.Context, route mailout.Route, plan mailout.BootstrapPlan) (mailout.AppendReceipt, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.appended {
		return o.draft, joined(o.draftError, mailout.ErrConflict)
	}
	notSent := mailout.AppendReceipt{Outcome: mailout.NotSent, Matched: true}
	client, err := o.client()
	if err != nil {
		return notSent, err
	}
	if !o.validRoute(route) || o.scope.Source.Kind != "apple_direct" || !safe(plan.RPCID, 256) || !safe(plan.Nonce, 256) || o.provider.config.Drafts == nil {
		return notSent, mailout.ErrReference
	}
	mailbox, err := o.mailbox(client, route)
	if err != nil {
		return notSent, err
	}
	raw, err := draftMIME(mailbox, route, plan, o.provider.config.Clock())
	if err != nil {
		return notSent, err
	}
	o.appended = true
	receipt, err := o.provider.config.Drafts.append(ctx, o.scope.Gate, mailbox, raw)
	if receipt.Candidate.ID != "" {
		receipt.Candidate.Nonce = plan.Nonce
		receipt.Candidate.MessageID = "<" + plan.Nonce + "@icloud.com>"
	}
	o.draft = receipt
	o.draftError = err
	return receipt, err
}

// SubmitSeed sends the verified stored MIME. It cannot alter the envelope or
// send a seed directly to the eventual recipient.
func (o *operation) SubmitSeed(ctx context.Context, route mailout.Route, candidate mailout.Candidate, plan mailout.BootstrapPlan) (mailout.RPCReceipt, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.seeded {
		return o.seed, joined(o.seedError, mailout.ErrConflict)
	}
	client, err := o.client()
	if err != nil {
		return mailout.RPCReceipt{RPCID: plan.RPCID, Outcome: mailout.NotSent, Matched: true}, err
	}
	notSent := mailout.RPCReceipt{RPCID: plan.RPCID, Outcome: mailout.NotSent, Matched: true}
	if !o.validRoute(route) || o.scope.Source.Kind != "apple_direct" || candidate.Nonce != plan.Nonce {
		return notSent, mailout.ErrReference
	}
	if _, err = o.mailbox(client, route); err != nil {
		return notSent, err
	}
	guid, ok := canonicalGUID(candidate.ID)
	if !ok {
		return notSent, mailout.ErrReference
	}
	e := mailout.Evidence{ContextKey: plan.ContextKey, OwnerKey: plan.OwnerKey, Nonce: plan.Nonce, Recipient: route.Recipient, CandidateID: candidate.ID, CandidateMessageID: candidate.MessageID, CandidateUIDValidity: candidate.UIDValidity, Draft: &plan.Draft}
	var found bool
	var readErr error
	if o.nativeMailbox() {
		_, found, readErr = o.nativeCandidate(ctx, route, e)
	} else {
		_, found, readErr = o.readCandidate(ctx, client, route, e, guid)
	}
	if readErr != nil || !found {
		return notSent, o.checkpoint(ctx, joined(readErr, mailout.ErrReference))
	}
	if o.usesSMTP() {
		mailbox, err := o.mailbox(client, route)
		if err != nil {
			return notSent, err
		}
		raw, err := o.nativeSeedRaw(ctx, route, candidate)
		if err != nil {
			return notSent, err
		}
		defer clear(raw)
		o.seeded = true
		o.seed, o.seedError = o.provider.config.SMTP.send(ctx, o.scope.Gate, mailbox, route.Alias, raw, plan.RPCID, candidate.MessageID)
		if o.seed.Outcome == mailout.Accepted {
			copy, copyErr := o.provider.config.Drafts.appendSent(ctx, o.scope.Gate, mailbox, raw)
			if copyErr != nil || copy.Outcome != mailout.Accepted {
				o.seedError = smtpFailure("sent_copy", copyErr)
			}
		}
		o.seedError = o.checkpoint(ctx, o.seedError)
		return o.seed, o.seedError
	}
	o.seeded = true
	r, remote := client.MailSendDraft(ctx, plan.RPCID, guid)
	o.seed = rpcReceipt(r)
	o.seedError = o.checkpoint(ctx, remote)
	return o.seed, o.seedError
}
