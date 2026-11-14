package applemail

import (
	"bufio"
	"context"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"

	"icloudspace/internal/mailout"
	"icloudspace/internal/provider/apple"
)

// Prefer a matching archived reply, then an existing directory route for the
// recipient, then discovery/bootstrap. Unrelated mailbox entries must not veto
// a route already selected for this recipient.
func (o *operation) preferredRoute(ctx context.Context, client *apple.Client, route mailout.Route, e mailout.Evidence) (referenceProof, bool, error) {
	if o.scope.Source.Kind == "apple_direct" {
		for _, hint := range o.scope.ArchiveHints {
			if len(hint.Header) == 0 || len(hint.Header) > 64<<10 {
				continue
			}
			h, err := textproto.NewReader(bufio.NewReader(strings.NewReader(string(hint.Header)))).ReadMIMEHeader()
			if err != nil || !archiveRecipient(h, route) {
				continue
			}
			if _, ok := archiveRelay(h, route.Recipient); !ok {
				continue
			}
			if messageID(h) == "" || hint.UID == 0 || hint.UIDValidity == 0 {
				continue
			}
			proof, found, err := o.proof(ctx, client, route, e, "message:INBOX/"+strconv.FormatUint(uint64(hint.UID), 10))
			if err != nil {
				return referenceProof{}, false, err
			}
			if !found || proof.reference.MessageID != messageID(h) || proof.reference.UIDValidity != hint.UIDValidity {
				return referenceProof{}, false, mailout.ErrReference
			}
			return proof, true, nil
		}
	}
	proof, found := o.archiveRoute(route, e)
	return proof, found, nil
}

// Archive headers only locate an original relay. ResolveRoute must separately
// confirm that exact relay, owner, recipient and selected HME with Apple.
func (o *operation) archiveRoute(route mailout.Route, e mailout.Evidence) (referenceProof, bool) {
	relay, id, identity := "", "", ""
	for _, hint := range o.scope.ArchiveHints {
		if o.scope.Source.Kind != "apple_forwarded" {
			break
		}
		if len(hint.Header) == 0 || len(hint.Header) > 64<<10 {
			continue
		}
		h, err := textproto.NewReader(bufio.NewReader(strings.NewReader(string(hint.Header)))).ReadMIMEHeader()
		if err != nil {
			continue
		}
		if !archiveRecipient(h, route) {
			continue
		}
		value, ok := archiveRelay(h, route.Recipient)
		if !ok {
			continue
		}
		relay, id, identity = value, messageID(h), "archive:"+strconv.FormatInt(hint.ID, 10)
		break
	}
	if relay == "" {
		for _, entry := range o.mailRoutes {
			if same(entry.Alias, route.Alias) && entry.Active != nil && *entry.Active && same(entry.Forward, route.ProviderFrom) && same(entry.Recipient, route.Recipient) && relayForRecipient(entry.Relay, route.Recipient) {
				relay, identity = entry.Relay, "directory:"+route.ProviderAddressID
				break
			}
		}
	}
	if relay == "" {
		return referenceProof{}, false
	}
	at, err := instant(o.provider.config.Clock())
	if err != nil {
		return referenceProof{}, false
	}
	ref := mailout.Reference{Kind: mailout.RouteReference, ContextKey: e.ContextKey, OwnerKey: e.OwnerKey, Nonce: e.Nonce, ID: identity, MessageID: id, Alias: route.Alias, Recipient: route.Recipient, Relay: relay, CheckedAt: at}
	return referenceProof{reference: ref, relay: relay, from: route.ProviderFrom}, true
}

func archiveRecipient(h textproto.MIMEHeader, route mailout.Route) bool {
	if len(h.Values("X-ICLOUD-HME")) != 1 {
		return false
	}
	raw := one(h, "X-ICLOUD-HME")
	if raw == "" || len(raw) > 8<<10 || strings.ContainsAny(raw, "\r\n") {
		return false
	}
	parts := strings.Split(raw, ";")
	if len(parts) > 32 {
		return false
	}
	values := map[string]string{}
	for _, part := range parts {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return false
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			return false
		}
		for _, ch := range key {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
		if _, duplicate := values[key]; duplicate {
			return false
		}
		values[key] = strings.TrimSpace(value)
	}
	for _, key := range []string{"p", "f", "s"} {
		value := values[key]
		parsed, err := mail.ParseAddress(value)
		if err != nil || parsed.Name != "" || !strings.EqualFold(parsed.Address, value) || strings.ContainsAny(value, " \t;,<>\"") {
			return false
		}
	}
	role := strings.ToLower(values["r"])
	return (role == "to" || role == "cc") && !same(values["p"], values["f"]) && same(values["p"], route.Alias) && same(values["s"], route.Recipient)
}

func archiveRelay(h textproto.MIMEHeader, recipient string) (string, bool) {
	for _, name := range []string{"Reply-To", "From"} {
		addresses, err := mail.ParseAddressList(h.Get(name))
		if err != nil {
			continue
		}
		for _, value := range addresses {
			if relayForRecipient(value.Address, recipient) {
				return strings.ToLower(value.Address), true
			}
		}
	}
	return "", false
}
