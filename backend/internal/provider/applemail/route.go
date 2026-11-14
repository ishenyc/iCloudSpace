package applemail

import (
	"context"
	"icloudspace/internal/mailout"
)

func (o *operation) ResolveRoute(ctx context.Context, route mailout.Route, reference mailout.Reference) (mailout.RouteReceipt, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	notSent := mailout.RouteReceipt{Outcome: mailout.NotSent, Matched: true}
	proof, ok := o.references[referenceID(reference)]
	if o.routeAttempted || !ok || proof.reference != reference || !o.validRoute(route) || !same(proof.from, route.ProviderFrom) {
		return notSent, mailout.ErrReference
	}
	client, err := o.client()
	if err != nil {
		return notSent, err
	}
	o.routeAttempted = true
	value, receipt, err := client.MailResolveRoute(ctx, proof.relay)
	observed := mailout.RouteReceipt{Outcome: mailout.Outcome(receipt.Outcome), Matched: receipt.Matched}
	if receipt.Matched && receipt.Outcome == "accepted" {
		recipient := value.Recipient
		if recipient == "" && same(value.Relay, proof.relay) {
			recipient = route.Recipient
		}
		if !same(value.Alias, route.Alias) || value.Active == nil || !*value.Active || !same(value.Forward, route.ProviderFrom) || !same(value.Relay, proof.relay) || !same(recipient, route.Recipient) || !relayForRecipient(value.Relay, route.Recipient) {
			observed.Outcome = mailout.Rejected
			err = mailout.ErrProvider
		} else {
			o.resolved = &value
		}
	}
	return observed, o.checkpoint(ctx, err)
}
