package apple

import (
	"context"
	"errors"
	"time"
)

const mailReadAttempts = 3

// This is an explicit semantic allowlist, not a retry policy for arbitrary
// GETs/POSTs. In particular, trust GETs, authentication, routing, drafts, seed
// sends and final sends remain single-attempt mutations.
func retryableMailRead(operation string, auth, mutation bool) bool {
	if auth || mutation {
		return false
	}
	switch operation {
	case "mail_get", "mail_list", "mail_mailbox", "mail_directory", "mail_validate":
		return true
	}
	return false
}

func transientMailRead(err error) bool {
	var e *Error
	if !errors.As(err, &e) || e.Unknown || e.Status >= 400 {
		return false
	}
	switch e.Kind {
	case Transport, Connect, Timeout:
		return true
	case DNS:
		return e.TransportReason == "dns_temporary"
	}
	return false
}

func (c *Client) readExchangeLocked(ctx context.Context, operation, method, endpoint string, body []byte) (exchangeResult, error) {
	// Retries share the original request timeout and any shorter caller budget.
	// Do not shorten a healthy individual read merely to reserve retry slots.
	budget := c.http.Timeout
	if budget <= 0 || budget > 30*time.Second {
		budget = 30 * time.Second
	}
	bounded, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var result exchangeResult
	var err error
	for attempt := 1; attempt <= mailReadAttempts; attempt++ {
		result, err = c.exchangeModeLocked(bounded, operation, method, endpoint, body, false, false, false)
		if err == nil {
			return result, nil
		}
		var diagnosed *Error
		if errors.As(err, &diagnosed) {
			diagnosed.Attempts = attempt
		}
		if attempt == mailReadAttempts || bounded.Err() != nil || !transientMailRead(err) {
			return result, err
		}
		// Discard idle keep-alive connections before reconstructing the exact
		// read body. Cookies already observed remain in this serialized client.
		c.http.CloseIdleConnections()
		delay := time.Duration(attempt) * 500 * time.Millisecond
		if deadline, ok := bounded.Deadline(); ok && time.Until(deadline) <= delay {
			return result, err
		}
		timer := time.NewTimer(delay)
		select {
		case <-bounded.Done():
			timer.Stop()
			return result, stoppedReadRetry(operation, attempt, bounded.Err())
		case <-timer.C:
		}
		if bounded.Err() != nil {
			return result, stoppedReadRetry(operation, attempt, bounded.Err())
		}
	}
	return result, err
}

func stoppedReadRetry(operation string, attempts int, cause error) *Error {
	err := networkError(operation, cause, false, false)
	err.Attempts, err.TransportPhase = attempts, "retry_wait"
	return err
}
