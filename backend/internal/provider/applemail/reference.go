package applemail

import (
	"bufio"
	"context"
	"mime"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"

	"icloudspace/internal/mailout"
	"icloudspace/internal/provider/apple"
)

func canonicalGUID(raw string) (string, bool) {
	if !strings.HasPrefix(raw, "message:") {
		raw = "message:" + raw
	}
	_, _, ok := apple.MailGUID(raw)
	return raw, ok
}
func headers(message apple.MailMessage) (textproto.MIMEHeader, error) {
	if len(message.LongHeader) == 0 || len(message.LongHeader) > 64<<10 || strings.ContainsRune(message.LongHeader, 0) {
		return nil, mailout.ErrReference
	}
	raw := strings.TrimRight(message.LongHeader, "\r\n") + "\r\n\r\n"
	header, err := textproto.NewReader(bufio.NewReader(strings.NewReader(raw))).ReadMIMEHeader()
	if err != nil {
		return nil, mailout.ErrReference
	}
	return header, nil
}
func one(header textproto.MIMEHeader, name string) string {
	values := header.Values(name)
	if len(values) != 1 {
		return ""
	}
	return strings.TrimSpace(values[0])
}
func exactAddress(header textproto.MIMEHeader, name, want string) bool {
	values := header.Values(name)
	if len(values) != 1 {
		return false
	}
	parsed, err := mail.ParseAddressList(values[0])
	return err == nil && len(parsed) == 1 && same(parsed[0].Address, want)
}
func messageID(header textproto.MIMEHeader) string {
	id := one(header, "Message-ID")
	if !safe(id, 2048) || !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, ">") || strings.ContainsAny(id, " \t") {
		return ""
	}
	return id
}
func subject(header textproto.MIMEHeader) string {
	value := one(header, "Subject")
	decoded, err := new(mime.WordDecoder).DecodeHeader(value)
	if err == nil {
		return decoded
	}
	return value
}
func nonceMatch(header textproto.MIMEHeader, nonce string) bool {
	return safe(nonce, 256) && len(nonce) >= 8 && subject(header) == nonce
}
func hmeAlias(header textproto.MIMEHeader, route mailout.Route, owner string) bool {
	if len(header.Values("X-ICLOUD-HME")) != 1 {
		return false
	}
	values := map[string]string{}
	for _, line := range header.Values("X-ICLOUD-HME") {
		for _, part := range strings.Split(line, ";") {
			key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok {
				value = strings.Trim(strings.TrimSpace(value), `"`)
				key = strings.ToLower(key)
				if _, duplicate := values[key]; duplicate {
					return false
				}
				values[key] = value
			}
		}
	}
	return same(values["p"], route.Alias) && same(values["f"], route.ProviderFrom) && same(values["s"], owner) && values["r"] == "to"
}

func relayForRecipient(raw, recipient string) bool {
	value, err := address(raw)
	if err != nil {
		return false
	}
	local, domain, ok := strings.Cut(value, "@")
	if !ok || domain != "icloud.com" && domain != "icloud.com.cn" && domain != "private.icloud.com" {
		return false
	}
	prefix := strings.NewReplacer("@", "_at_", ".", "_").Replace(strings.ToLower(recipient)) + "_"
	return strings.HasPrefix(local, prefix) && len(local) > len(prefix)
}
func incomingRelay(header textproto.MIMEHeader, recipient string) (string, bool) {
	from, err := address(one(header, "From"))
	if err != nil || !same(from, recipient) && !relayForRecipient(from, recipient) {
		return "", false
	}
	matches := map[string]bool{}
	if relayForRecipient(from, recipient) {
		matches[from] = true
	}
	if len(header.Values("Reply-To")) > 1 {
		return "", false
	}
	if value := one(header, "Reply-To"); value != "" {
		reply, err := address(value)
		if err != nil {
			return "", false
		}
		if relayForRecipient(reply, recipient) {
			matches[reply] = true
		} else if !same(reply, recipient) {
			return "", false
		}
	}
	if len(matches) != 1 {
		return "", false
	}
	for relay := range matches {
		return relay, true
	}
	return "", false
}
func referenceKey(e mailout.Evidence) string {
	return e.ContextKey + "\x00" + e.OwnerKey + "\x00" + e.Nonce
}
func referenceID(r mailout.Reference) string {
	return r.ContextKey + "\x00" + r.OwnerKey + "\x00" + r.Nonce
}
func evidenceValid(e mailout.Evidence, route mailout.Route) bool {
	return safe(e.ContextKey, 1024) && safe(e.OwnerKey, 256) && safe(e.Nonce, 256) && same(e.Recipient, route.Recipient)
}

// Recognize a draft by its explicit nonce header or by the nonce@icloud.com
// Message-ID paired with 7bit MIME. Both forms must match the owned nonce.
func draftMarker(header textproto.MIMEHeader, nonce string) bool {
	if len(header.Values("X-ICloudSpace-Compose-Nonce")) > 0 {
		return len(header.Values("X-ICloudSpace-Compose-Nonce")) == 1 && one(header, "X-ICloudSpace-Compose-Nonce") == nonce
	}
	return messageID(header) == "<"+nonce+"@icloud.com>" && len(header.Values("Content-Transfer-Encoding")) == 1 && strings.EqualFold(one(header, "Content-Transfer-Encoding"), "7bit")
}
func (o *operation) readCandidate(ctx context.Context, client *apple.Client, route mailout.Route, e mailout.Evidence, guid string) (mailout.Candidate, bool, error) {
	var selected []string
	if e.Draft != nil {
		folder, _, ok := apple.MailGUID(guid)
		if !ok {
			return mailout.Candidate{}, false, nil
		}
		rows, err := client.MailSearch(ctx, folder, e.Nonce, 20)
		if err != nil {
			return mailout.Candidate{}, false, err
		}
		if len(rows) >= 20 {
			return mailout.Candidate{}, false, mailout.ErrReference
		}
		for _, row := range rows {
			if row.GUID != guid {
				continue
			}
			if len(row.Parts) != 1 {
				return mailout.Candidate{}, false, nil
			}
			for _, part := range row.Parts {
				if !part.Attachment && same(part.MediaType, "text/plain") && part.GUID != "" && part.Size >= 0 && part.Size <= 64<<10 {
					selected = append(selected, part.GUID)
				}
			}
		}
		if len(selected) != 1 {
			return mailout.Candidate{}, false, nil
		}
	}
	message, err := client.MailGetParts(ctx, guid, selected)
	if err != nil {
		return mailout.Candidate{}, false, err
	}
	header, err := headers(message)
	if err != nil || !nonceMatch(header, e.Nonce) || !exactAddress(header, "From", route.ProviderFrom) || !exactAddress(header, "To", route.Alias) || !exactAddress(header, "Reply-To", route.Recipient) || len(header.Values("Cc")) != 0 || len(header.Values("Bcc")) != 0 {
		return mailout.Candidate{}, false, nil
	}
	if e.Draft != nil {
		intent := e.Draft
		if !same(intent.From, route.ProviderFrom) || !same(intent.To, route.Alias) || !same(intent.ReplyTo, route.Recipient) || intent.Subject != e.Nonce || !draftMarker(header, e.Nonce) {
			return mailout.Candidate{}, false, nil
		}
		media := "text/plain"
		if values := header.Values("Content-Type"); len(values) > 1 {
			return mailout.Candidate{}, false, nil
		} else if len(values) == 1 {
			var parseErr error
			media, _, parseErr = mime.ParseMediaType(values[0])
			if parseErr != nil {
				return mailout.Candidate{}, false, nil
			}
		}
		if !same(media, "text/plain") || len(message.Parts) != 1 {
			return mailout.Candidate{}, false, nil
		}
		matched := false
		for _, part := range message.Parts {
			if part.GUID == selected[0] {
				if matched || strings.TrimSuffix(strings.ReplaceAll(part.Content, "\r\n", "\n"), "\n") != strings.TrimSuffix(strings.ReplaceAll(intent.Text, "\r\n", "\n"), "\n") {
					return mailout.Candidate{}, false, nil
				}
				matched = true
			}
		}
		if !matched {
			return mailout.Candidate{}, false, nil
		}
	}
	id := messageID(header)
	if id == "" || e.CandidateMessageID != "" && e.CandidateMessageID != id {
		return mailout.Candidate{}, false, nil
	}
	folder, uid, _ := apple.MailGUID(guid)
	epoch, err := client.MailUIDValidity(ctx, folder)
	if err != nil {
		return mailout.Candidate{}, false, err
	}
	if e.CandidateUIDValidity != 0 && e.CandidateUIDValidity != epoch {
		return mailout.Candidate{}, false, nil
	}
	observedID := guid
	if e.CandidateID != "" {
		expected, ok := canonicalGUID(e.CandidateID)
		if !ok || expected != guid {
			return mailout.Candidate{}, false, nil
		}
		observedID = e.CandidateID
	}
	return mailout.Candidate{ID: observedID, MessageID: id, Nonce: e.Nonce, UIDValidity: epoch, UID: uid}, true, nil
}
func (o *operation) findCandidate(ctx context.Context, client *apple.Client, route mailout.Route, e mailout.Evidence) (mailout.Candidate, bool, error) {
	if o.nativeMailbox() {
		return o.nativeCandidate(ctx, route, e)
	}
	if e.CandidateID != "" {
		guid, ok := canonicalGUID(e.CandidateID)
		if !ok {
			return mailout.Candidate{}, false, mailout.ErrReference
		}
		return o.readCandidate(ctx, client, route, e, guid)
	}
	rows, err := client.MailSearch(ctx, "Drafts", e.Nonce, 20)
	if err != nil {
		return mailout.Candidate{}, false, err
	}
	if len(rows) >= 20 {
		return mailout.Candidate{}, false, mailout.ErrReference
	}
	var match mailout.Candidate
	found := false
	for _, row := range rows {
		candidate, ok, err := o.readCandidate(ctx, client, route, e, row.GUID)
		if err != nil {
			return mailout.Candidate{}, false, err
		}
		if ok {
			if found {
				return mailout.Candidate{}, false, mailout.ErrReference
			}
			found = true
			match = candidate
		}
	}
	return match, found, nil
}
func (o *operation) FindCandidate(ctx context.Context, route mailout.Route, e mailout.Evidence) (candidate mailout.Candidate, found bool, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	client, err := o.client()
	if err != nil {
		return candidate, false, err
	}
	if !o.validRoute(route) || !evidenceValid(e, route) {
		return candidate, false, mailout.ErrReference
	}
	candidate, found, err = o.findCandidate(ctx, client, route, e)
	return candidate, found, o.checkpoint(ctx, err)
}
func (o *operation) proof(ctx context.Context, client *apple.Client, route mailout.Route, e mailout.Evidence, guid string) (referenceProof, bool, error) {
	folder, uid, valid := apple.MailGUID(guid)
	if !valid || !strings.EqualFold(folder, "INBOX") && !strings.EqualFold(folder, "Junk") {
		return referenceProof{}, false, nil
	}
	message, err := client.MailGet(ctx, guid)
	if err != nil {
		return referenceProof{}, false, err
	}
	header, err := headers(message)
	owner, ownerErr := ownerAddress(client.Snapshot().Principal)
	if err != nil || len(header.Values("Subject")) > 1 || !exactAddress(header, "To", route.Alias) {
		return referenceProof{}, false, nil
	}
	// HME may rewrite the visible sender to an owner-specific Apple relay. The
	// nonce and HME p/f/s/r tuple bind the seed, and From must match either the
	// account owner or the relay corresponding to that owner.
	bootstrapSender := exactAddress(header, "From", owner) || relayForRecipient(one(header, "From"), owner)
	bootstrap := ownerErr == nil && nonceMatch(header, e.Nonce) && hmeAlias(header, route, owner) && bootstrapSender
	// Junk is eligible only for this exact, durably owned bootstrap nonce and
	// HME ownership tuple. Keep the real mailbox coordinate and verify its epoch.
	if !bootstrap && !strings.EqualFold(folder, "INBOX") {
		return referenceProof{}, false, nil
	}
	relay := ""
	if bootstrap {
		relay, err = address(one(header, "Reply-To"))
		if err != nil || !relayForRecipient(relay, route.Recipient) {
			return referenceProof{}, false, nil
		}
	} else {
		if !hmeAlias(header, route, route.Recipient) {
			return referenceProof{}, false, nil
		}
		var valid bool
		relay, valid = incomingRelay(header, route.Recipient)
		if !valid {
			return referenceProof{}, false, nil
		}
	}
	id := messageID(header)
	if id == "" || bootstrap && e.SeedMessageID != "" && id != e.SeedMessageID || message.MessageID != "" && message.MessageID != id {
		return referenceProof{}, false, nil
	}
	if message.Subject != "" {
		display := message.Subject
		if decoded, e := new(mime.WordDecoder).DecodeHeader(display); e == nil {
			display = decoded
		}
		if display != subject(header) {
			return referenceProof{}, false, nil
		}
	}
	epoch, err := client.MailUIDValidity(ctx, folder)
	if err != nil {
		return referenceProof{}, false, err
	}
	at, err := instant(o.provider.config.Clock())
	if err != nil {
		return referenceProof{}, false, err
	}
	seedID := e.SeedID
	if bootstrap && e.SeedID != "" {
		expected, ok := canonicalGUID(e.SeedID)
		if !ok || expected != guid {
			return referenceProof{}, false, nil
		}
		seedID = e.SeedID
	}
	if bootstrap && seedID == "" {
		seedID = guid
	}
	idFact := guid
	if e.ReferenceID != "" {
		canonical, ok := canonicalGUID(e.ReferenceID)
		if !ok || canonical != guid {
			return referenceProof{}, false, nil
		}
		idFact = e.ReferenceID
	}
	ref := mailout.Reference{ContextKey: e.ContextKey, OwnerKey: e.OwnerKey, Nonce: e.Nonce, CandidateID: e.CandidateID, CandidateUIDValidity: e.CandidateUIDValidity, SeedID: seedID, ID: idFact, MessageID: id, Subject: subject(header), Alias: route.Alias, Recipient: route.Recipient, UIDValidity: epoch, UID: uid, CheckedAt: at, Relay: relay}
	ref.Kind = mailout.IncomingReference
	if bootstrap {
		ref.Kind = mailout.SeedReference
	}
	return referenceProof{reference: ref, relay: relay, from: route.ProviderFrom, wireGUID: guid, bootstrap: bootstrap}, true, nil
}
func (o *operation) ReadReference(ctx context.Context, route mailout.Route, e mailout.Evidence) (reference mailout.Reference, found bool, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	client, err := o.client()
	if err != nil {
		return reference, false, err
	}
	if !o.validRoute(route) || !evidenceValid(e, route) {
		return reference, false, mailout.ErrReference
	}
	proof, ok, routeErr := o.preferredRoute(ctx, client, route, e)
	if routeErr != nil {
		return reference, false, o.checkpoint(ctx, routeErr)
	}
	if ok {
		o.references[referenceKey(e)] = proof
		return proof.reference, true, nil
	}
	if o.scope.Source.Kind == "apple_forwarded" {
		return reference, false, nil
	}
	var guids []string
	hintEpochs := map[string]uint32{}
	known := e.ReferenceID
	if known == "" {
		known = e.SeedID
	}
	if known == "" && e.CandidateID != "" {
		if guid, ok := canonicalGUID(e.CandidateID); ok {
			folder, _, _ := apple.MailGUID(guid)
			if same(folder, "INBOX") {
				known = e.CandidateID
			}
		}
	}
	if known != "" {
		guid, ok := canonicalGUID(known)
		if !ok {
			return reference, false, mailout.ErrReference
		}
		guids = []string{guid}
	} else if !o.nativeMailbox() {
		rows, e2 := client.MailSearch(ctx, "INBOX", e.Nonce, 20)
		if e2 != nil {
			return reference, false, o.checkpoint(ctx, e2)
		}
		if len(rows) >= 20 {
			return reference, false, o.checkpoint(ctx, mailout.ErrReference)
		}
		for _, row := range rows {
			guids = append(guids, row.GUID)
		}
	}
	if e.ReferenceID == "" && !o.nativeMailbox() {
		rows, e2 := client.MailSearch(ctx, "INBOX", route.Recipient, 20)
		if e2 != nil {
			return reference, false, o.checkpoint(ctx, e2)
		}
		if len(rows) >= 20 {
			return reference, false, o.checkpoint(ctx, mailout.ErrReference)
		}
		for _, row := range rows {
			duplicate := false
			for _, guid := range guids {
				duplicate = duplicate || guid == row.GUID
			}
			if !duplicate {
				guids = append(guids, row.GUID)
			}
		}
	}
	// An indexed WebMail search can be empty while the same message is already
	// readable by UID. The canonical mail owner supplies bounded observations
	// from this exact direct Apple mailbox, including already-consumed entries.
	// They locate candidates only; the WebMail header/route proof below remains
	// mandatory, and the observed mailbox epoch must still match.
	if o.nativeMailbox() && e.ReferenceID == "" && e.SeedOutcome != nil {
		hints, err := o.nativeSeeds(ctx, route, e)
		if err != nil {
			return reference, false, err
		}
		for _, hint := range hints {
			guid := "message:" + hint.folder + "/" + strconv.FormatUint(uint64(hint.UID), 10)
			guids = append(guids, guid)
			hintEpochs[guid] = hint.UIDValidity
		}
	}
	if e.ReferenceID == "" && o.scope.Source.Kind == "apple_direct" {
		if len(o.scope.RemoteHints) > 20 {
			return reference, false, o.checkpoint(ctx, mailout.ErrReference)
		}
		for _, hint := range o.scope.RemoteHints {
			if hint.UID == 0 || hint.UIDValidity == 0 {
				continue
			}
			guid := "message:INBOX/" + strconv.FormatUint(uint64(hint.UID), 10)
			if epoch, duplicate := hintEpochs[guid]; duplicate && epoch != hint.UIDValidity {
				return reference, false, o.checkpoint(ctx, mailout.ErrReference)
			}
			hintEpochs[guid] = hint.UIDValidity
			duplicate := false
			for _, known := range guids {
				duplicate = duplicate || known == guid
			}
			if !duplicate {
				guids = append(guids, guid)
			}
		}
		for _, hint := range o.scope.ArchiveHints {
			h, err := textproto.NewReader(bufio.NewReader(strings.NewReader(string(hint.Header)))).ReadMIMEHeader()
			if err != nil || !archiveRecipient(h, route) {
				continue
			}
			if _, ok := incomingRelay(h, route.Recipient); !ok {
				continue
			}
			guid := "message:INBOX/" + strconv.FormatUint(uint64(hint.UID), 10)
			if _, exists := hintEpochs[guid]; !exists {
				guids = append(guids, guid)
				hintEpochs[guid] = hint.UIDValidity
			}
			break
		}
	}
	var match referenceProof
	for _, guid := range guids {
		proof, ok, e2 := o.proof(ctx, client, route, e, guid)
		if e2 != nil {
			return reference, false, o.checkpoint(ctx, e2)
		}
		if ok {
			if epoch, hinted := hintEpochs[guid]; hinted && proof.reference.UIDValidity != epoch {
				continue
			}
			if found && proof.bootstrap && match.bootstrap {
				return reference, false, o.checkpoint(ctx, mailout.ErrReference)
			}
			if found && match.bootstrap {
				continue
			}
			if found && !proof.bootstrap && !match.bootstrap {
				if proof.reference.UIDValidity != match.reference.UIDValidity {
					return reference, false, o.checkpoint(ctx, mailout.ErrReference)
				}
				if proof.reference.UID <= match.reference.UID {
					continue
				}
			}
			found = true
			match = proof
		}
	}
	if found {
		folder, _, valid := apple.MailGUID(match.wireGUID)
		if !valid {
			return reference, false, o.checkpoint(ctx, mailout.ErrReference)
		}
		epoch, e2 := client.MailUIDValidity(ctx, folder)
		if e2 != nil {
			return reference, false, o.checkpoint(ctx, e2)
		}
		if epoch != match.reference.UIDValidity {
			return reference, false, o.checkpoint(ctx, mailout.ErrReference)
		}
	}
	if err = o.checkpoint(ctx, nil); err != nil {
		return reference, false, err
	}
	if !found {
		if proof, ok := o.archiveRoute(route, e); ok {
			o.references[referenceKey(e)] = proof
			return proof.reference, true, nil
		}
		return reference, false, nil
	}
	key := referenceKey(e)
	if _, exists := o.references[key]; !exists && len(o.references) >= 64 {
		return reference, false, mailout.ErrReference
	}
	o.references[key] = match
	return match.reference, true, nil
}
