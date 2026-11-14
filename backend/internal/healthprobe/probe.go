package healthprobe

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Probe checks the actual local listener readiness, without opening the
// database, running maintenance or selecting an ambient network proxy.
func Probe(ctx context.Context, address string) bool {
	host, port, err := net.SplitHostPort(address)
	n, parseErr := strconv.ParseUint(port, 10, 16)
	ip := net.ParseIP(host)
	if err != nil || parseErr != nil || n == 0 || !(strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback()) {
		return false
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/healthz", nil)
	if err != nil {
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	var status struct {
		Status string `json:"status"`
	}
	return err == nil && len(raw) <= 1024 && json.Unmarshal(raw, &status) == nil && status.Status == "ok"
}
