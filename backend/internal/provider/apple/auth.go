package apple

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// The public iCloud OAuth widget identifier is a protocol constant. It selects
// Apple's web authentication client and does not grant account access.
const widgetKey = "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d"

const authOrigin = "https://idmsa.apple.com/appleauth/auth"

// Login performs the two SRP messages once. It does not request a verification
// code, trust a browser, accept terms, or automatically fall back/restart login.
// A SecondFactorRequired error preserves the challenge capsule for the caller.
func (c *Client) Login(ctx context.Context, password string) error {
	if len(password) == 0 || len(password) > 4096 {
		return invalid("login")
	}
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if c.document.Browser.ClientID == "" || c.document.Browser.FrameID == "" {
		return invalid("login_browser")
	}
	attempt, err := beginSRP()
	if err != nil {
		return err
	}
	start, _ := json.Marshal(struct {
		Public    string   `json:"a"`
		Identity  string   `json:"accountName"`
		Protocols []string `json:"protocols"`
	}{base64.StdEncoding.EncodeToString(attempt.public.Bytes()), c.document.Principal.AppleID, []string{"s2k", "s2k_fo"}})
	response, err := c.exchangeLocked(ctx, "srp_start", http.MethodPost, authOrigin+"/signin/init", start, true, true)
	if err != nil {
		return err
	}
	if err := diagnose("srp_start", response, true); err != nil {
		return err
	}
	var challenge srpChallenge
	if json.Unmarshal(response.body, &challenge) != nil {
		return &Error{Kind: MalformedResponse, Operation: "srp_start", Status: response.status, Unknown: true}
	}
	m1, m2, err := attempt.proof(ctx, c.document.Principal.AppleID, password, challenge)
	if err != nil {
		return err
	}
	trust := []string{}
	if c.document.Authentication.TrustToken != "" {
		trust = append(trust, c.document.Authentication.TrustToken)
	}
	complete, _ := json.Marshal(struct {
		Identity     string   `json:"accountName"`
		Continuation string   `json:"c"`
		M1           string   `json:"m1"`
		M2           string   `json:"m2"`
		Remember     bool     `json:"rememberMe"`
		Trust        []string `json:"trustTokens"`
	}{c.document.Principal.AppleID, challenge.Continuation, m1, m2, true, trust})
	response, err = c.exchangeLocked(ctx, "srp_complete", http.MethodPost, authOrigin+"/signin/complete?isRememberMeEnabled=true", complete, true, true)
	if err != nil {
		return err
	}
	if response.status == http.StatusConflict {
		c.document.Assurance.HSAChallengeRequired = true
		return &Error{Kind: SecondFactorRequired, Operation: "srp_complete", Status: response.status, Code: responseCode(response.body)}
	}
	return diagnose("srp_complete", response, true)
}

// VerifyDeviceCode submits only the code supplied by the user. Delivery and
// browser trust are separate explicit operations. A failed/unknown attempt is
// never resubmitted, even if a response rotated the authentication headers.
func (c *Client) VerifyDeviceCode(ctx context.Context, code string) error {
	if len(code) != 6 {
		return invalid("verify_device_code")
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return invalid("verify_device_code")
		}
	}
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if c.document.Authentication.SessionID == "" || c.document.Authentication.SCNT == "" {
		return &Error{Kind: AuthenticationRequired, Operation: "verify_device_code"}
	}
	body, _ := json.Marshal(struct {
		Code struct {
			Value string `json:"code"`
		} `json:"securityCode"`
	}{Code: struct {
		Value string `json:"code"`
	}{code}})
	response, err := c.exchangeLocked(ctx, "verify_device_code", http.MethodPost, authOrigin+"/verify/trusteddevice/securitycode", body, true, true)
	if err != nil {
		return err
	}
	return deviceCodeVerdict(response)
}

// TrustSession is explicit and uses a fresh one-attempt transport because
// Apple's protocol spells this state-changing operation as GET. It does not
// perform the subsequent regional token exchange on the caller's behalf.
func (c *Client) TrustSession(ctx context.Context) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if c.document.Authentication.SessionID == "" || c.document.Authentication.SCNT == "" {
		return &Error{Kind: AuthenticationRequired, Operation: "trust_session"}
	}
	response, err := c.exchangeLocked(ctx, "trust_session", http.MethodGet, authOrigin+"/2sv/trust", nil, true, true)
	if err != nil {
		return err
	}
	return diagnose("trust_session", response, true)
}

// ExchangeToken exchanges the current Apple authentication token for regional
// web cookies and provider discovery. It never sends an account password.
func (c *Client) ExchangeToken(ctx context.Context) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if c.document.Authentication.SessionToken == "" {
		return &Error{Kind: AuthenticationRequired, Operation: "exchange_token"}
	}
	body, _ := json.Marshal(struct {
		Country  string `json:"accountCountryCode"`
		Token    string `json:"dsWebAuthToken"`
		Extended bool   `json:"extended_login"`
		Trust    string `json:"trustToken"`
	}{c.document.Browser.CountryCode, c.document.Authentication.SessionToken, true, c.document.Authentication.TrustToken})
	return c.accountCallLocked(ctx, "exchange_token", "accountLogin", body, true)
}

// Validate checks the existing web cookies. Authentication failure is returned
// as a fact; it never triggers login, OTP delivery or a business mutation.
func (c *Client) Validate(ctx context.Context) error {
	return c.validate(ctx,"validate")
}

// ValidateForMail validates the web session with the mail request headers.
// Ordinary account validation uses its account request profile.
func (c *Client) ValidateForMail(ctx context.Context) error {
	return c.validate(ctx,"mail_validate")
}
func (c *Client) validate(ctx context.Context,operation string) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	return c.accountCallLocked(ctx, operation, "validate", []byte("null"), false)
}

func (c *Client) accountCallLocked(ctx context.Context, operation, path string, body []byte, mutation bool) error {
	previous := c.cookieSnapshot(time.Now())
	response, err := c.exchangeLocked(ctx, operation, http.MethodPost, setupOrigin(c.document.Principal.Region)+"/setup/ws/1/"+path, body, false, mutation)
	if err == nil {
		err = c.acceptAccount(operation, response)
	}
	if err != nil {
		diagnosed, ok := err.(*Error)
		if !ok || diagnosed.Kind != SecondFactorRequired {
			// Setup cookies become part of this principal only after the
			// discovery document proves its identity. A foreign or malformed
			// response cannot replace an existing principal's cookies.
			c.replaceCookies(previous)
		}
	}
	return err
}

type appleAccount struct {
	Success *bool `json:"success"`
	Info    struct {
		DSID         decimalID `json:"dsid"`
		AppleID      string    `json:"appleId"`
		PrimaryEmail string    `json:"primaryEmail"`
		CountryCode  string    `json:"countryCode"`
		HSAVersion   int       `json:"hsaVersion"`
		HMEActive    bool      `json:"isHideMyEmailSubscriptionActive"`
		HMEAvailable bool      `json:"isHideMyEmailFeatureAvailable"`
	} `json:"dsInfo"`
	Services map[string]struct {
		URL string `json:"url"`
	} `json:"webservices"`
	ChallengeRequired bool `json:"hsaChallengeRequired"`
	TrustedBrowser    bool `json:"hsaTrustedBrowser"`
}

func (c *Client) acceptAccount(operation string, response exchangeResult) error {
	mutation := operation == "exchange_token"
	if err := diagnose(operation, response, mutation); err != nil {
		return err
	}
	var account appleAccount
	if json.Unmarshal(response.body, &account) != nil || (account.Success != nil && !*account.Success) || account.Info.DSID == "" {
		return &Error{Kind: MalformedResponse, Operation: operation, Status: response.status, Unknown: mutation}
	}
	current := c.document.Principal
	dsid := string(account.Info.DSID)
	for _, digit := range dsid {
		if digit < '0' || digit > '9' {
			return &Error{Kind: MalformedResponse, Operation: operation, Status: response.status, Unknown: mutation}
		}
	}
	// A known DSID remains authoritative across Apple's username aliases. On
	// first binding, the response must identify the requested login principal.
	if (current.DSID != "" && current.DSID != dsid) || (current.DSID == "" && !strings.EqualFold(current.AppleID, account.Info.AppleID)) {
		return &Error{Kind: AuthenticationRequired, Operation: operation, Status: response.status, Code: "PRINCIPAL_MISMATCH", Unknown: mutation}
	}
	next := cloneSession(c.document)
	next.Principal.DSID = dsid
	next.Principal.PrimaryEmail = account.Info.PrimaryEmail
	next.Browser.CountryCode = account.Info.CountryCode
	next.Assurance = Assurance{HSAVersion: account.Info.HSAVersion, HSAChallengeRequired: account.ChallengeRequired, TrustedBrowser: account.TrustedBrowser, HideMyEmailActive: account.Info.HMEActive, HideMyEmailAvailable: account.Info.HMEAvailable}
	for _, entry := range []struct {
		key         string
		role        Service
		destination *string
	}{{"premiummailsettings", PremiumMail, &next.Services.PremiumMail}, {"mccgateway", MailGateway, &next.Services.MailGateway}, {"mail", Mail, &next.Services.Mail}} {
		origin, err := CanonicalOrigin(account.Services[entry.key].URL, next.Principal.Region, entry.role)
		if err != nil {
			return &Error{Kind: MalformedResponse, Operation: operation, Status: response.status, Code: "SERVICE_ORIGIN", Unknown: mutation}
		}
		*entry.destination = origin
	}
	now := time.Now().UnixNano()
	next.ValidatedAtUnixNano = &now
	if validateSession(next) != nil {
		return &Error{Kind: MalformedResponse, Operation: operation, Status: response.status, Unknown: mutation}
	}
	c.document = next
	if account.ChallengeRequired || (account.Info.HSAVersion >= 1 && !account.TrustedBrowser) {
		return &Error{Kind: SecondFactorRequired, Operation: operation, Status: response.status}
	}
	return nil
}

// decimalID retains the exact provider identifier even when its JSON-number
// representation exceeds an int64 or a JavaScript integer's precision.
type decimalID string

func (id *decimalID) UnmarshalJSON(data []byte) error {
	value := string(data)
	if len(data) > 0 && data[0] == '"' {
		if json.Unmarshal(data, &value) != nil {
			return ErrSession
		}
	}
	if len(value) == 0 || len(value) > 32 {
		return ErrSession
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return ErrSession
		}
	}
	*id = decimalID(value)
	return nil
}

func responseCode(body []byte) string {
	var data struct {
		Code       jsonCode `json:"code"`
		ErrorCode  jsonCode `json:"errorCode"`
		ServerCode jsonCode `json:"serverErrorCode"`
		Errors     []struct {
			Code jsonCode `json:"code"`
		} `json:"serviceErrors"`
	}
	if json.Unmarshal(body, &data) != nil {
		return ""
	}
	for _, code := range []jsonCode{data.Code, data.ErrorCode, data.ServerCode} {
		if code != "" {
			return errorCode(code)
		}
	}
	if len(data.Errors) > 0 {
		return errorCode(data.Errors[0].Code)
	}
	return ""
}

func diagnose(operation string, response exchangeResult, mutation bool) error {
	code := responseCode(response.body)
	var verdict struct {
		Success       *bool             `json:"success"`
		ServiceErrors []json.RawMessage `json:"serviceErrors"`
		Error         json.RawMessage   `json:"error"`
		ErrorMessage  string            `json:"errorMessage"`
		ErrorReason   string            `json:"errorReason"`
	}
	_ = json.Unmarshal(response.body, &verdict)
	rejected := (verdict.Success != nil && !*verdict.Success) || len(verdict.ServiceErrors) > 0 || verdict.ErrorMessage != "" || verdict.ErrorReason != "" || (len(verdict.Error) > 0 && string(verdict.Error) != "null" && string(verdict.Error) != "false" && string(verdict.Error) != "0" && string(verdict.Error) != `""`)
	if response.status >= 200 && response.status < 300 && (code == "" || code == "0") && !rejected {
		return nil
	}
	kind := AppleRejected
	switch response.status {
	case http.StatusUnauthorized, http.StatusForbidden, 421, 450:
		kind = AuthenticationRequired
	case http.StatusTooManyRequests:
		kind = RateLimited
	}
	return &Error{Kind: kind, Operation: operation, Status: response.status, Code: code, Unknown: mutation && response.status >= 500, RetryAfter: retryAfter(response.header.Get("Retry-After"), time.Now())}
}
