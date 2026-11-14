package installation

import (
	"math"
	"time"
)

// Budgets describe concrete IO phases. Source admission and slot waits do not
// consume an IMAP segment's budget. Zero aggregate active time leaves a round
// uncapped while each segment and each retry remain independently bounded.
type Budgets struct {
	IMAPDial, IMAPTLSHandshake, SyncSegment, SyncRoundActive, Shutdown, HTTPRead time.Duration
	IncomingMessageBytes, BodyBytes                                              int64
}

func milliseconds(value int64, fallback time.Duration) (time.Duration, error) {
	if value < 0 || value > math.MaxInt64/int64(time.Millisecond) {
		return 0, ErrConfiguration
	}
	if value == 0 {
		return fallback, nil
	}
	return time.Duration(value) * time.Millisecond, nil
}

func (p Process) Budgets() (Budgets, error) {
	var out Budgets
	for _, item := range []struct {
		raw      int64
		fallback time.Duration
		target   *time.Duration
	}{
		{p.IMAPDialTimeoutMilliseconds, 8 * time.Second, &out.IMAPDial},
		{p.IMAPTLSHandshakeTimeoutMilliseconds, 8 * time.Second, &out.IMAPTLSHandshake},
		{p.SyncSegmentTimeoutMilliseconds, 70 * time.Second, &out.SyncSegment},
		{p.SyncRoundActiveTimeoutMilliseconds, 0, &out.SyncRoundActive},
		{p.ShutdownTimeoutMilliseconds, 10 * time.Second, &out.Shutdown},
		{p.HTTPReadTimeoutMilliseconds, 20 * time.Second, &out.HTTPRead},
	} {
		value, err := milliseconds(item.raw, item.fallback)
		if err != nil {
			return Budgets{}, err
		}
		*item.target = value
	}
	if p.IncomingMessageBytes < 0 || p.BodyBytes < 0 {
		return Budgets{}, ErrConfiguration
	}
	out.IncomingMessageBytes, out.BodyBytes = p.IncomingMessageBytes, p.BodyBytes
	if out.IncomingMessageBytes == 0 {
		out.IncomingMessageBytes = 100 << 20
	}
	if out.BodyBytes == 0 {
		out.BodyBytes = 512 << 10
	}
	return out, nil
}
