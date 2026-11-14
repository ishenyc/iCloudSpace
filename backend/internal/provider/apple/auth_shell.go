package apple

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

const maxShellBytes = 512 << 10

// These are challenge metadata, not cookies or authentication tokens. An
// assertion still has to be produced by a genuine Apple-origin authenticator.
type TrustedPhone struct {
	ID      string `json:"id"`
	Numeric bool   `json:"numeric,omitempty"`
	Display string `json:"display"`
	Mode    string `json:"mode"`
}
type SecurityKeyChallenge struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Challenge  string   `json:"challenge"`
	RPID       string   `json:"rp_id"`
	RequestID  string   `json:"request_id,omitempty"`
	KeyHandles []string `json:"key_handles,omitempty"`
}
type AuthOptions struct {
	AuthType      string                 `json:"auth_type"`
	TrustedDevice bool                   `json:"trusted_device"`
	SMS           bool                   `json:"sms"`
	Phones        []TrustedPhone         `json:"phones"`
	SecurityKeys  []SecurityKeyChallenge `json:"security_keys"`
}
type AuthFlow struct {
	Options       AuthOptions `json:"options"`
	ReferrerQuery string      `json:"referrer_query,omitempty"`
}
type wirePhone struct {
	ID         json.RawMessage `json:"id"`
	Obfuscated string          `json:"obfuscatedNumber"`
	Number     string          `json:"numberWithDialCode"`
	LastTwo    string          `json:"lastTwoDigits"`
	Mode       string          `json:"pushMode"`
}
type wireKey struct {
	Challenge  string   `json:"challenge"`
	RPID       string   `json:"rpId"`
	RequestID  string   `json:"requestId"`
	KeyHandles []string `json:"keyHandles"`
}
type shellData struct {
	AuthType       string `json:"authType"`
	AuthAttributes string `json:"authAttributes"`
	Country        string `json:"countryCode"`
	ReferrerQuery  string `json:"referrerQuery"`
	TwoSV          struct {
		AuthType string          `json:"authType"`
		Factors  []string        `json:"authFactors"`
		Device   json.RawMessage `json:"deviceVerification"`
		Phone    struct {
			Phones []wirePhone `json:"trustedPhoneNumbers"`
			Phone  *wirePhone  `json:"phoneNumber"`
		} `json:"phoneNumberVerification"`
		FSA struct {
			Challenge wireKey `json:"fsaChallenge"`
		} `json:"fsaVerification"`
	} `json:"twoSV"`
}

func cloneFlow(flow *AuthFlow) *AuthFlow {
	if flow == nil {
		return nil
	}
	out := *flow
	out.Options.Phones = append([]TrustedPhone(nil), flow.Options.Phones...)
	out.Options.SecurityKeys = append([]SecurityKeyChallenge(nil), flow.Options.SecurityKeys...)
	for i := range out.Options.SecurityKeys {
		out.Options.SecurityKeys[i].KeyHandles = append([]string(nil), flow.Options.SecurityKeys[i].KeyHandles...)
	}
	return &out
}
func validFlow(flow *AuthFlow) bool {
	if flow == nil {
		return true
	}
	if len(flow.Options.Phones) > 20 || len(flow.Options.SecurityKeys) > 4 || !field(flow.Options.AuthType, 32, false) || !validReferrer(flow.ReferrerQuery) {
		return false
	}
	for _, p := range flow.Options.Phones {
		if !field(p.ID, 64, true) || !field(p.Display, 128, false) || (p.Mode != "sms" && p.Mode != "voice") {
			return false
		}
		if p.Numeric {
			for _, c := range p.ID {
				if c < '0' || c > '9' {
					return false
				}
			}
		}
	}
	for _, k := range flow.Options.SecurityKeys {
		if !validKeyChallenge(k) {
			return false
		}
	}
	b, _ := json.Marshal(flow)
	return len(b) <= 32<<10
}
func validReferrer(query string) bool {
	if query == "" {
		return true
	}
	if !strings.HasPrefix(query, "?") || len(query) > 4096 || strings.ContainsAny(query, "#\r\n\x00") {
		return false
	}
	values, err := url.ParseQuery(query[1:])
	if err != nil {
		return false
	}
	for key, list := range values {
		if !field(key, 128, true) || len(list) != 1 || !field(list[0], 2048, false) {
			return false
		}
	}
	return true
}
func validKeyChallenge(k SecurityKeyChallenge) bool {
	if k.Kind != "fsa1" && k.Kind != "fsa2" || !field(k.ID, 64, true) || !field(k.RequestID, 512, false) || len(k.KeyHandles) > 20 {
		return false
	}
	if k.RPID != "apple.com" && k.RPID != "idmsa.apple.com" {
		return false
	}
	challenge, err := decodeBase64(k.Challenge, 1024)
	if err != nil || len(challenge) < 16 {
		return false
	}
	for _, handle := range k.KeyHandles {
		if b, e := decodeBase64(handle, 1024); e != nil || len(b) == 0 {
			return false
		}
	}
	return true
}
func decodeBase64(value string, max int) ([]byte, error) {
	if len(value) > max*2 {
		return nil, ErrSession
	}
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		if b, err := encoding.Strict().DecodeString(value); err == nil && len(b) <= max {
			return b, nil
		}
	}
	return nil, ErrSession
}
func phoneID(raw json.RawMessage) (string, bool, error) {
	if len(raw) == 0 || len(raw) > 130 {
		return "", false, ErrSession
	}
	if raw[0] == '"' {
		var id string
		if json.Unmarshal(raw, &id) != nil || !field(id, 64, true) {
			return "", false, ErrSession
		}
		return id, false, nil
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return "", false, ErrSession
		}
	}
	return string(raw), true, nil
}
func maskPhone(number, lastTwo string) string {
	if len(lastTwo) == 2 && lastTwo[0] >= '0' && lastTwo[0] <= '9' && lastTwo[1] >= '0' && lastTwo[1] <= '9' {
		return "•••• " + lastTwo
	}
	var digits []rune
	for _, c := range number {
		if c >= '0' && c <= '9' {
			digits = append(digits, c)
		}
	}
	if len(digits) >= 2 {
		return "•••• " + string(digits[len(digits)-2:])
	}
	return "••••"
}

// ParseAuthShell reads data-only boot_args scripts. It never evaluates scripts,
// follows their asset URLs, or accepts HTML text as recipient/provider data.
func ParseAuthShell(body []byte) (*AuthFlow, string, string, error) {
	if len(body) == 0 || len(body) > maxShellBytes {
		return nil, "", "", ErrSession
	}
	tokens := html.NewTokenizer(bytes.NewReader(body))
	count := 0
	var direct []json.RawMessage
	for {
		kind := tokens.Next()
		if kind == html.ErrorToken {
			if tokens.Err() != io.EOF {
				return nil, "", "", ErrSession
			}
			break
		}
		if kind != html.StartTagToken {
			continue
		}
		name, more := tokens.TagName()
		if string(name) != "script" {
			continue
		}
		isJSON, isBoot := false, false
		for more {
			key, value, next := tokens.TagAttr()
			more = next
			if string(key) == "type" && strings.EqualFold(string(value), "application/json") {
				isJSON = true
			}
			if string(key) == "class" {
				for _, class := range strings.Fields(string(value)) {
					isBoot = isBoot || class == "boot_args"
				}
			}
		}
		if !isJSON || !isBoot {
			continue
		}
		count++
		if count > 16 {
			return nil, "", "", ErrSession
		}
		if tokens.Next() != html.TextToken {
			return nil, "", "", ErrSession
		}
		raw := append([]byte(nil), tokens.Text()...)
		if len(raw) > 128<<10 || uniqueJSON(raw) != nil {
			return nil, "", "", ErrSession
		}
		var document struct {
			Direct json.RawMessage `json:"direct"`
		}
		if json.Unmarshal(raw, &document) != nil || len(document.Direct) == 0 {
			return nil, "", "", ErrSession
		}
		direct = append(direct, document.Direct)
	}
	if count == 0 {
		return nil, "", "", ErrSession
	}
	merged := map[string]json.RawMessage{}
	for _, raw := range direct {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return nil, "", "", ErrSession
		}
		for _, key := range []string{"authType", "authAttributes", "countryCode", "referrerQuery", "twoSV"} {
			if value, ok := fields[key]; ok {
				if previous, exists := merged[key]; exists && !bytes.Equal(previous, value) {
					return nil, "", "", ErrSession
				}
				merged[key] = value
			}
		}
	}
	raw, _ := json.Marshal(merged)
	var data shellData
	if json.Unmarshal(raw, &data) != nil || !field(data.AuthAttributes, 32768, false) || !field(data.Country, 16, false) || !validReferrer(data.ReferrerQuery) {
		return nil, "", "", ErrSession
	}
	if data.AuthType == "" {
		data.AuthType = data.TwoSV.AuthType
	}
	flow := &AuthFlow{Options: AuthOptions{AuthType: data.AuthType, Phones: []TrustedPhone{}, SecurityKeys: []SecurityKeyChallenge{}}, ReferrerQuery: data.ReferrerQuery}
	factors := make(map[string]bool)
	for _, factor := range data.TwoSV.Factors {
		factors[factor] = true
	}
	flow.Options.TrustedDevice = len(data.TwoSV.Device) > 0 && string(data.TwoSV.Device) != "null"
	phones := data.TwoSV.Phone.Phones
	if data.TwoSV.Phone.Phone != nil {
		phones = append(phones, *data.TwoSV.Phone.Phone)
	}
	if len(phones) > 20 {
		return nil, "", "", ErrSession
	}
	seen := map[string]bool{}
	for _, phone := range phones {
		id, numeric, err := phoneID(phone.ID)
		if err != nil || seen[id] {
			return nil, "", "", ErrSession
		}
		seen[id] = true
		mode := phone.Mode
		if mode == "" {
			mode = "sms"
		}
		number := phone.Number
		if number == "" {
			number = phone.Obfuscated
		}
		flow.Options.Phones = append(flow.Options.Phones, TrustedPhone{ID: id, Numeric: numeric, Display: maskPhone(number, phone.LastTwo), Mode: mode})
	}
	hasKeys := factors["fsa1"] || factors["fsa2"]
	flow.Options.SMS = len(phones) > 0 && (!hasKeys || factors["sms"])
	for _, kind := range []string{"fsa2", "fsa1"} {
		if !factors[kind] {
			continue
		}
		wire := data.TwoSV.FSA.Challenge
		rp := strings.ToLower(wire.RPID)
		if rp == "" && kind == "fsa1" {
			rp = "idmsa.apple.com"
		}
		flow.Options.SecurityKeys = append(flow.Options.SecurityKeys, SecurityKeyChallenge{ID: kind, Kind: kind, Challenge: wire.Challenge, RPID: rp, RequestID: wire.RequestID, KeyHandles: wire.KeyHandles})
	}
	if !validFlow(flow) {
		return nil, "", "", ErrSession
	}
	return flow, data.AuthAttributes, data.Country, nil
}

// AuthorizeShell is a bounded read of the official auth shell. It neither sends
// an OTP nor executes browser script. Rotated headers/cookies remain in Snapshot
// even when the shell is malformed or the response is rejected.
func (c *Client) AuthorizeShell(ctx context.Context) (AuthOptions, error) {
	if err := c.lock(ctx); err != nil {
		return AuthOptions{}, err
	}
	defer c.unlock()
	q := url.Values{"frame_id": {c.document.Browser.FrameID}, "iframeId": {c.document.Browser.FrameID}, "client_id": {widgetKey}, "redirect_uri": {homeOrigin(c.document.Principal.Region)}, "response_type": {"code"}, "response_mode": {"web_message"}, "state": {c.document.Browser.FrameID}, "skVersion": {"7"}, "authVersion": {"latest"}, "isSRPEnabled": {"true"}}
	response, err := c.exchangeShellLocked(ctx, "authorize_shell", authOrigin+"/authorize/signin?"+q.Encode())
	if err != nil {
		return AuthOptions{}, err
	}
	if response.status < http.StatusOK || response.status >= http.StatusMultipleChoices {
		return AuthOptions{}, &Error{Kind: AuthenticationRequired, Operation: "authorize_shell", Status: response.status}
	}
	flow, attributes, country, err := ParseAuthShell(response.body)
	if err != nil {
		return AuthOptions{}, &Error{Kind: MalformedResponse, Operation: "authorize_shell", Status: response.status}
	}
	c.document.AuthFlow = flow
	if attributes != "" {
		c.document.Authentication.AuthAttributes = attributes
	}
	if country != "" {
		c.document.Browser.CountryCode = country
	}
	return cloneFlow(flow).Options, nil
}
