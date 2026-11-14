package apple

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

type SecurityKeyAssertion struct {
	ChallengeID       string `json:"challenge_id"`
	CredentialID      string `json:"credential_id"`
	ClientDataJSON    string `json:"client_data_json"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"user_handle,omitempty"`
}

func digits(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}
func (c *Client) challengeEndpoint(path string) string {
	endpoint := authOrigin + path
	if c.document.AuthFlow != nil {
		endpoint += c.document.AuthFlow.ReferrerQuery
	}
	return endpoint
}
func (c *Client) challengeReady() bool {
	return c.document.Authentication.SessionID != "" && c.document.Authentication.SCNT != "" && c.document.AuthFlow != nil
}

func (c *Client) RequestDeviceCode(ctx context.Context) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if !c.challengeReady() || !c.document.AuthFlow.Options.TrustedDevice {
		return &Error{Kind: AuthenticationRequired, Operation: "send_device_code"}
	}
	response, err := c.exchangeLocked(ctx, "send_device_code", http.MethodPut, c.challengeEndpoint("/verify/trusteddevice/securitycode"), nil, true, true)
	if err != nil {
		return err
	}
	return diagnose("send_device_code", response, true)
}
func (c *Client) VerifyTrustedDeviceCode(ctx context.Context, code string) error {
	if !digits(code) {
		return invalid("verify_device_code")
	}
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if !c.challengeReady() || !c.document.AuthFlow.Options.TrustedDevice {
		return &Error{Kind: AuthenticationRequired, Operation: "verify_device_code"}
	}
	body, _ := json.Marshal(map[string]any{"securityCode": map[string]string{"code": code}})
	response, err := c.exchangeLocked(ctx, "verify_device_code", http.MethodPost, c.challengeEndpoint("/verify/trusteddevice/securitycode"), body, true, true)
	if err != nil {
		return err
	}
	if response.status == http.StatusConflict {
		var verdict struct {
			SecurityCode struct {
				Valid *bool `json:"valid"`
			} `json:"securityCode"`
		}
		if json.Unmarshal(response.body, &verdict) == nil && verdict.SecurityCode.Valid != nil && *verdict.SecurityCode.Valid {
			return nil
		}
	}
	return diagnose("verify_device_code", response, true)
}

// _W push receipts use the ordinary trusted-device verifier in Apple's public
// widget. Non-web bridge receipts require a different handshake and are rejected.
func (c *Client) VerifyWebBridgeCode(ctx context.Context, code, transactionID, pushToken string) error {
	if !digits(code) || !field(transactionID, 2048, true) || !field(pushToken, 1024, true) || !strings.HasSuffix(transactionID, "_W") {
		return invalid("verify_web_bridge")
	}
	parts := strings.Split(transactionID, "_")
	if len(parts) < 4 {
		return invalid("verify_web_bridge")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		decoded, err = base64.RawStdEncoding.Strict().DecodeString(parts[2])
	}
	if err != nil || subtle.ConstantTimeCompare(decoded, []byte(pushToken)) != 1 {
		return invalid("verify_web_bridge")
	}
	return c.VerifyTrustedDeviceCode(ctx, code)
}
func (c *Client) phone(id, mode string) (map[string]any, bool) {
	if c.document.AuthFlow == nil || !c.document.AuthFlow.Options.SMS || (mode != "sms" && mode != "voice") {
		return nil, false
	}
	for _, phone := range c.document.AuthFlow.Options.Phones {
		if phone.ID != id || phone.Mode != mode {
			continue
		}
		var value any = phone.ID
		if phone.Numeric {
			value = json.Number(phone.ID)
		}
		return map[string]any{"id": value}, true
	}
	return nil, false
}
func (c *Client) RequestPhoneCode(ctx context.Context, id, mode string) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	phone, ok := c.phone(id, mode)
	if !ok || !c.challengeReady() {
		return invalid("send_phone_code")
	}
	body, _ := json.Marshal(map[string]any{"phoneNumber": phone, "mode": mode})
	response, err := c.exchangeLocked(ctx, "send_phone_code", http.MethodPut, c.challengeEndpoint("/verify/phone"), body, true, true)
	if err != nil {
		return err
	}
	return diagnose("send_phone_code", response, true)
}
func (c *Client) VerifyPhoneCode(ctx context.Context, id, mode, code string) error {
	if !digits(code) {
		return invalid("verify_phone_code")
	}
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	phone, ok := c.phone(id, mode)
	if !ok || !c.challengeReady() {
		return invalid("verify_phone_code")
	}
	body, _ := json.Marshal(map[string]any{"phoneNumber": phone, "securityCode": map[string]string{"code": code}, "mode": mode})
	response, err := c.exchangeLocked(ctx, "verify_phone_code", http.MethodPost, c.challengeEndpoint("/verify/phone/securitycode"), body, true, true)
	if err != nil {
		return err
	}
	return diagnose("verify_phone_code", response, true)
}

// securityPayload validates only locally observable challenge/origin/RP facts.
// Apple remains responsible for the assertion signature and account ownership.
func securityPayload(assertion SecurityKeyAssertion, challenge SecurityKeyChallenge, region Region) ([]byte, error) {
	if !validKeyChallenge(challenge) || assertion.ChallengeID != challenge.ID {
		return nil, ErrSession
	}
	credential, err := decodeBase64(assertion.CredentialID, 2048)
	if err != nil || len(credential) == 0 {
		return nil, ErrSession
	}
	client, err := decodeBase64(assertion.ClientDataJSON, 16<<10)
	if err != nil || uniqueJSON(client) != nil {
		return nil, ErrSession
	}
	var data struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
		TopOrigin   string `json:"topOrigin"`
	}
	if json.Unmarshal(client, &data) != nil || data.Type != "webauthn.get" || data.Origin != "https://idmsa.apple.com" {
		return nil, ErrSession
	}
	if data.CrossOrigin && data.TopOrigin != homeOrigin(region) && data.TopOrigin != "https://account.apple.com" {
		return nil, ErrSession
	}
	issued, err := decodeBase64(challenge.Challenge, 1024)
	if err != nil {
		return nil, ErrSession
	}
	returned, err := decodeBase64(data.Challenge, 1024)
	if err != nil || subtle.ConstantTimeCompare(issued, returned) != 1 {
		return nil, ErrSession
	}
	authenticator, err := decodeBase64(assertion.AuthenticatorData, 8<<10)
	if err != nil || len(authenticator) < 37 {
		return nil, ErrSession
	}
	rpHash := sha256.Sum256([]byte(challenge.RPID))
	rpMatches := subtle.ConstantTimeCompare(authenticator[:32], rpHash[:]) == 1
	if challenge.Kind == "fsa1" {
		legacy := sha256.Sum256([]byte("https://idmsa.apple.com"))
		rpMatches = rpMatches || subtle.ConstantTimeCompare(authenticator[:32], legacy[:]) == 1
	}
	if !rpMatches || authenticator[32]&1 == 0 || challenge.Kind == "fsa2" && authenticator[32]&4 == 0 {
		return nil, ErrSession
	}
	signature, err := decodeBase64(assertion.Signature, 8<<10)
	if err != nil || len(signature) == 0 {
		return nil, ErrSession
	}
	var user []byte
	if assertion.UserHandle != "" {
		user, err = decodeBase64(assertion.UserHandle, 64)
		if err != nil {
			return nil, ErrSession
		}
	}
	if len(challenge.KeyHandles) > 0 {
		found := false
		for _, handle := range challenge.KeyHandles {
			allowed, _ := decodeBase64(handle, 1024)
			found = found || bytes.Equal(allowed, credential)
		}
		if !found {
			return nil, ErrSession
		}
	}
	if challenge.Kind == "fsa1" {
		return json.Marshal(map[string]string{"challenge": base64.RawStdEncoding.EncodeToString(issued), "clientData": base64.StdEncoding.EncodeToString(client), "signatureData": base64.StdEncoding.EncodeToString(signature), "authenticatorData": base64.StdEncoding.EncodeToString(authenticator), "keyHandle": base64.RawURLEncoding.EncodeToString(credential)})
	}
	return json.Marshal(map[string]string{"challenge": base64.RawStdEncoding.EncodeToString(issued), "clientData": base64.RawURLEncoding.EncodeToString(client), "signatureData": base64.RawURLEncoding.EncodeToString(signature), "authenticatorData": base64.RawURLEncoding.EncodeToString(authenticator), "userHandle": base64.RawStdEncoding.EncodeToString(user), "credentialID": base64.RawURLEncoding.EncodeToString(credential), "rpId": challenge.RPID, "requestId": challenge.RequestID})
}
func (c *Client) VerifySecurityKey(ctx context.Context, assertion SecurityKeyAssertion) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if !c.challengeReady() {
		return &Error{Kind: AuthenticationRequired, Operation: "verify_security_key"}
	}
	var selected *SecurityKeyChallenge
	for _, challenge := range c.document.AuthFlow.Options.SecurityKeys {
		if challenge.ID == assertion.ChallengeID {
			copy := challenge
			selected = &copy
			break
		}
	}
	if selected == nil {
		return invalid("verify_security_key")
	}
	body, err := securityPayload(assertion, *selected, c.document.Principal.Region)
	if err != nil {
		return invalid("verify_security_key")
	}
	response, err := c.exchangeLocked(ctx, "verify_security_key", http.MethodPost, c.challengeEndpoint("/verify/security/key"), body, true, true)
	if err != nil {
		return err
	}
	return diagnose("verify_security_key", response, true)
}
