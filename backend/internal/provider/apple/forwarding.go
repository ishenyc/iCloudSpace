package apple

import (
	"context"
	"net/http"

	"icloudspace/internal/addresses"
)

// Apple's public Hide My Email bundle (2640Build18, en-us/main.js) declares
// POST /v1/hme/updateForwardTo with the forwardToEmail field:
// https://www.icloud.com/applications/hidemyemail/2640Build18/en-us/main.js
// The caller must durably record its single attempt and prove an empty remote
// directory first. Success still requires an authoritative directory readback.
func (c *Client) InitializeForwarding(ctx context.Context, target string) error {
	normalized, err := addresses.NormalizeAddress(target)
	if err != nil {
		return invalid("hme_initialize_forwarding")
	}
	if err = c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	response, err := c.hmeLocked(ctx, "hme_initialize_forwarding", http.MethodPost, "/v1/hme/updateForwardTo", map[string]string{"forwardToEmail": normalized}, true)
	if err != nil {
		return err
	}
	_, err = decodeHME("hme_initialize_forwarding", response, true)
	return err
}
