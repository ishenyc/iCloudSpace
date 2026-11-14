// Package accessimap exposes the canonical local mailbox as a read-only IMAP
// service. Authentication belongs to the shared address authority.
package accessimap

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-sasl"
)

// XOAUTH2 uses its own wire shape, distinct from OAUTHBEARER's GS2 framing.
// Raw bearer bytes are passed once to the shared authority and never retained
// on the connection. Only the authority's verified handle survives LOGIN.
func parseXOAUTH2(response []byte) (string, string, error) {
	if len(response) == 0 || len(response) > 8192 || !utf8.Valid(response) || !bytes.HasSuffix(response, []byte{1, 1}) {
		return "", "", imapserver.ErrAuthFailed
	}
	var user, token string
	seen := make(map[string]bool, 4)
	for _, field := range bytes.Split(response[:len(response)-2], []byte{1}) {
		key, value, ok := strings.Cut(string(field), "=")
		if !ok || seen[key] || strings.ContainsAny(value, "\x00\r\n\x7f") {
			return "", "", imapserver.ErrAuthFailed
		}
		seen[key] = true
		switch key {
		case "user":
			user = value
		case "auth":
			if !strings.HasPrefix(value, "Bearer ") {
				return "", "", imapserver.ErrAuthFailed
			}
			token = strings.TrimPrefix(value, "Bearer ")
		case "host", "port": // Routing hints never change the mailbox identity.
		default:
			return "", "", imapserver.ErrAuthFailed
		}
	}
	if user == "" || len(user) > 320 || token == "" || strings.ContainsAny(token, " \t") {
		return "", "", imapserver.ErrAuthFailed
	}
	return user, token, nil
}

type xoauth2Exchange struct {
	challenged, finished bool
	accept               func(string, string) error
}

func newXOAUTH2Server(accept func(string, string) error) sasl.Server {
	return &xoauth2Exchange{accept: accept}
}

func (x *xoauth2Exchange) Next(response []byte) ([]byte, bool, error) {
	if x.finished {
		return nil, false, imapserver.ErrAuthFailed
	}
	if response == nil && !x.challenged {
		x.challenged = true
		return []byte{}, false, nil
	}
	x.finished = true
	user, token, err := parseXOAUTH2(response)
	if err != nil {
		return nil, false, err
	}
	if err := x.accept(user, token); err != nil {
		return nil, false, err
	}
	return nil, true, nil
}
