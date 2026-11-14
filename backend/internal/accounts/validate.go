package accounts

import (
	"math"
	"net"
	"net/mail"
	"strings"
	"unicode/utf8"
)

func validKind(kind Kind) bool {
	return kind == Custom || kind == AppleDirect || kind == AppleForwarded
}

func boundedText(value string, maximum int, nonempty bool) bool {
	return (!nonempty || strings.TrimSpace(value) != "") && len(value) <= maximum &&
		utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func normalizeAddress(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if !boundedText(value, 320, true) {
		return "", false
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value || !strings.Contains(value, "@") {
		return "", false
	}
	return strings.ToLower(value), true
}

func validHost(host string) bool {
	if !boundedText(host, 253, true) || strings.ContainsAny(host, " \t/@?#\\") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if strings.Contains(host, ":") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

func normalizeInput(input CreateInput) (CreateInput, error) {
	if !validKind(input.Kind) {
		return input, &FieldError{"kind"}
	}
	if !boundedText(input.DisplayName, 512, false) {
		return input, &FieldError{"display_name"}
	}
	var ok bool
	if input.AddressNamespace, ok = normalizeAddress(input.AddressNamespace); !ok {
		return input, &FieldError{"address_namespace"}
	}
	if !validHost(input.Endpoint.Host) || input.Endpoint.Port < 1 || input.Endpoint.Port > 65535 ||
		!boundedText(input.Endpoint.Username, 512, true) {
		return input, &FieldError{"endpoint"}
	}
	input.Endpoint.Host = strings.ToLower(strings.TrimSuffix(input.Endpoint.Host, "."))
	if input.AddressSuffix == "" || !validHost(input.AddressSuffix) || net.ParseIP(input.AddressSuffix) != nil {
		return input, &FieldError{"address_suffix"}
	}
	input.AddressSuffix = strings.ToLower(strings.TrimSuffix(input.AddressSuffix, "."))
	if err := validateCredentials(input.Credentials); err != nil {
		return input, err
	}
	if input.Kind == Custom {
		if input.Apple != nil {
			return input, &FieldError{"apple"}
		}
	} else {
		if input.Apple == nil {
			return input, &FieldError{"apple"}
		}
		principal := *input.Apple
		if principal.AppleID, ok = normalizeAddress(principal.AppleID); !ok ||
			(principal.Region != "global" && principal.Region != "china") {
			return input, &FieldError{"apple"}
		}
		input.Apple = &principal
	}
	return input, nil
}

func validateCredentials(credentials Credentials) error {
	// A password is an exact value, not display text. Even whitespace-only
	// values remain intact; omission, rather than trimming, means "retain".
	if credentials.Version != 1 || len(credentials.IMAPPassword) == 0 ||
		len(credentials.IMAPPassword) > 16<<10 || !utf8.ValidString(credentials.IMAPPassword) {
		return &FieldError{"credentials"}
	}
	return nil
}

func normalizeQuery(filter Filter, page Page) (Filter, Page, error) {
	if !boundedText(filter.Query, 512, false) || filter.Kind != "" && !validKind(filter.Kind) {
		return filter, page, &FieldError{"filter"}
	}
	filter.Query = strings.TrimSpace(filter.Query)
	if page.Limit == 0 {
		page.Limit = DefaultLimit
	}
	if page.Limit < 1 || page.Limit > MaximumLimit || page.Offset < 0 {
		return filter, page, &FieldError{"page"}
	}
	return filter, page, nil
}

func nextRevision(value int64) (int64, error) {
	if value < 1 || value == math.MaxInt64 {
		return 0, ErrConflict
	}
	return value + 1, nil
}

func nextInstant(now, previous int64) (int64, error) {
	if now > previous {
		return now, nil
	}
	if previous == math.MaxInt64 {
		return 0, ErrConflict
	}
	return previous + 1, nil
}
