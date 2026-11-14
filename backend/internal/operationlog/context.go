package operationlog

import (
	"context"
	"net/netip"
	"strconv"
)

// Actor contains verified metadata, never an authentication bearer. The HTTP
// boundary installs it only after authenticating the current browser session.
type Actor struct{ Kind, Ref, Origin, RequestID string }
type actorContextKey struct{}

func WithActor(ctx context.Context, actor Actor) (context.Context, error) {
	if ctx == nil || actor.Kind != "operator" && actor.Kind != "system" || token(actor.Ref, 128) != actor.Ref || actor.Ref == "" || len(actor.Origin) > 128 || actor.RequestID != "" && token(actor.RequestID, 128) != actor.RequestID {
		return ctx, ErrInvalid
	}
	if actor.Kind == "operator" {
		id, err := strconv.ParseInt(actor.Ref, 10, 64)
		if err != nil || id < 1 || strconv.FormatInt(id, 10) != actor.Ref {
			return ctx, ErrInvalid
		}
	}
	if ip, err := netip.ParseAddr(actor.Origin); err == nil {
		actor.Origin = ip.WithZone("").String()
	} else if actor.Origin != "" {
		if token(actor.Origin, 128) != actor.Origin {
			return ctx, ErrInvalid
		}
		actor.Origin = token(actor.Origin, 128)
	}
	actor.Ref = token(actor.Ref, 128)
	actor.RequestID = token(actor.RequestID, 128)
	return context.WithValue(ctx, actorContextKey{}, actor), nil
}
func ContextActor(ctx context.Context) Actor {
	if ctx != nil {
		if actor, ok := ctx.Value(actorContextKey{}).(Actor); ok {
			return actor
		}
	}
	return Actor{Kind: "system", Ref: "system"}
}

// ActorRecord attaches authenticated metadata without changing the caller's
// operation correlation. A request id remains separately available when an
// original operation key already occupies correlation_key.
func ActorRecord(ctx context.Context, record Record) Record {
	actor := ContextActor(ctx)
	record.ActorKind, record.ActorRef, record.Origin = actor.Kind, actor.Ref, actor.Origin
	fields := make(map[string]string, len(record.Fields)+1)
	for key, value := range record.Fields {
		fields[key] = value
	}
	if actor.RequestID != "" {
		fields["request_id"] = actor.RequestID
		if record.CorrelationKey == "" {
			record.CorrelationKey = actor.RequestID
		}
	}
	record.Fields = fields
	return record
}
