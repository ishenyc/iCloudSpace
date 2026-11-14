package sourceguard

import (
	"context"
	"sync"
)

type localMutationKey struct{}
type localMutationCheck struct {
	once  sync.Once
	check func(context.Context) error
	err   error
}

// WithLocalMutationCheck marks a single, purely local management command. Its
// owner calls CheckLocalMutation after the last source/credential gate wait.
// Provider workflows must not carry this check into recording an already
// accepted external result. Internal/system callers need no HTTP callback.
func WithLocalMutationCheck(ctx context.Context, check func(context.Context) error) context.Context {
	if check == nil {
		return ctx
	}
	return context.WithValue(ctx, localMutationKey{}, &localMutationCheck{check: check})
}

// CheckLocalMutation retains the first authorization result for this command.
// Repeated stages, including bulk issuance, cannot reauthenticate per address
// or turn an earlier denied command into an allowed partial write.
func CheckLocalMutation(ctx context.Context) error {
	check, _ := ctx.Value(localMutationKey{}).(*localMutationCheck)
	if check == nil {
		return nil
	}
	check.once.Do(func() { check.err = check.check(ctx) })
	return check.err
}
