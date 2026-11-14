package sourceguard

import "context"

type leaseContextKey struct{}

// WithLease carries the existing business owner into provider adapters. It
// transfers no release ownership; adapters must validate registry and source.
func WithLease(ctx context.Context, lease *Lease) context.Context {
	return context.WithValue(ctx, leaseContextKey{}, lease)
}

func LeaseFromContext(ctx context.Context) *Lease {
	lease, _ := ctx.Value(leaseContextKey{}).(*Lease)
	return lease
}
