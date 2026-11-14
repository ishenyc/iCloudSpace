package content

import (
	"strings"
	"unicode"

	messageMail "github.com/emersion/go-message/mail"
)

// Header tiers are protocol evidence, not an assertion that a sender-supplied
// header is trustworthy. The ingest owner binds this result to a source route.
var recipientTiers = [][]string{
	{"X-Original-To", "X-Apple-Original-To", "X-Original-Rcpt-To"},
	{"Original-Recipient", "X-Original-Recipient", "X-Apple-Original-Recipient", "Final-Recipient"},
	{"Envelope-To", "X-Envelope-To", "X-Forwarded-To"},
	{"Delivered-To", "X-Delivered-To", "X-Rcpt-To"},
}

var visibleRecipients = []string{"To", "Cc", "Apparently-To", "Resent-To", "Resent-Cc"}

type RecipientField struct {
	Header    string
	Tier      int
	Addresses []string // normalized addr-specs; display names never count
	Valid     bool
}

type RecipientEvidence struct {
	Strong  []RecipientField
	Weak    []RecipientField
	Privacy []string // the actual X-ICLOUD-HME values, including duplicates
	Limited bool
}

// CollectRecipients examines top-level fields only. Malformed/present fields
// remain visible so later classification cannot silently fall through a tier.
func CollectRecipients(headers []HeaderField, maxAddresses int) RecipientEvidence {
	var out RecipientEvidence
	left := maxAddresses
	for _, field := range headers {
		if strings.EqualFold(field.Name, "X-ICLOUD-HME") {
			out.Privacy = append(out.Privacy, field.Value)
			continue
		}
		tier, strong := evidenceTier(field.Name)
		weak := containsFold(visibleRecipients, field.Name)
		if !strong && !weak {
			continue
		}
		value := field.Value
		if strong && tier == 1 {
			if prefix, tail, found := strings.Cut(value, ";"); found {
				if !strings.EqualFold(strings.TrimSpace(prefix), "rfc822") {
					value = "" // invalid address type still blocks fallback
				} else {
					value = strings.TrimSpace(tail)
				}
			} else if !strings.EqualFold(field.Name, "X-Apple-Original-Recipient") && !strings.EqualFold(field.Name, "Final-Recipient") {
				value = "" // only these two observed Apple/MTA variants omit rfc822;
			}
		}
		parsed, err := messageMail.ParseAddressList(value)
		evidence := RecipientField{Header: field.Name, Tier: tier, Valid: err == nil && len(parsed) > 0}
		if err == nil {
			for _, address := range parsed {
				if left <= 0 {
					out.Limited = true
					evidence.Valid = false
					break
				}
				left--
				normalized := normalizeMailbox(address.Address)
				if normalized == "" {
					evidence.Valid = false
					continue
				}
				evidence.Addresses = append(evidence.Addresses, normalized)
			}
		}
		if strong {
			out.Strong = append(out.Strong, evidence)
		} else {
			out.Weak = append(out.Weak, evidence)
		}
	}
	return out
}

func evidenceTier(name string) (int, bool) {
	for tier, names := range recipientTiers {
		if containsFold(names, name) {
			return tier, true
		}
	}
	return 0, false
}

func containsFold(values []string, value string) bool {
	for _, candidate := range values {
		if strings.EqualFold(candidate, value) {
			return true
		}
	}
	return false
}

type SourceKind string

const (
	SourceDirect    SourceKind = "direct"
	SourceForwarded SourceKind = "forwarded"
	SourceCustom    SourceKind = "custom"
)

type SourceRoute struct {
	Kind SourceKind
	// PrimaryAddress is the source's receiving namespace, not its Apple login.
	PrimaryAddress string
	IMAPUsername   string
}

type Alias struct {
	ID      string
	Address string
	Enabled bool
}

type AliasMatch struct {
	ID      string
	Address string
}

type Attribution struct {
	Determinate bool
	Reason      string // stable classification, safe to log
	Matches     []AliasMatch
}

// Directory is an immutable normalized alias snapshot. A sync round can build
// it once and classify many parsed messages without repeatedly parsing every
// configured alias address. It is safe to share between parse workers.
type Directory struct {
	aliases []Alias
	known   map[string][]Alias
}

func NewDirectory(aliases []Alias) *Directory {
	directory := &Directory{aliases: make([]Alias, len(aliases)), known: make(map[string][]Alias, len(aliases))}
	for i, alias := range aliases {
		alias.Address = normalizeMailbox(alias.Address)
		directory.aliases[i] = alias
		if alias.Address != "" {
			directory.known[alias.Address] = append(directory.known[alias.Address], alias)
		}
	}
	return directory
}

// Attribute evaluates one parse against the whole alias snapshot. Returned
// order follows that snapshot; a message may match several aliases without
// reparsing MIME. Weak fallback requires an explicit per-source choice.
func Attribute(e RecipientEvidence, route SourceRoute, aliases []Alias, allowWeak bool) Attribution {
	return NewDirectory(aliases).Attribute(e, route, allowWeak)
}

func (directory *Directory) Attribute(e RecipientEvidence, route SourceRoute, allowWeak bool) Attribution {
	if directory == nil {
		return indeterminate("alias_directory")
	}
	if e.Limited {
		return indeterminate("recipient_budget")
	}
	aliases, known := directory.aliases, directory.known
	if route.Kind == SourceCustom {
		selected := e.Strong
		if len(selected) > 0 {
			firstTier := len(recipientTiers)
			for _, field := range selected {
				if field.Tier < firstTier {
					firstTier = field.Tier
				}
			}
			selected = nil
			for _, field := range e.Strong {
				if field.Tier == firstTier {
					selected = append(selected, field)
				}
			}
		} else if allowWeak {
			selected = e.Weak
		}
		addresses, valid := fieldSet(selected)
		if !valid {
			return indeterminate("malformed_recipient")
		}
		matched := matchAliases(addresses, aliases, known)
		if !matched.Determinate || len(matched.Matches) != len(addresses) {
			return indeterminate("custom_recipient_not_unique")
		}
		identities := make(map[string]bool, len(matched.Matches))
		for _, match := range matched.Matches {
			if match.ID == "" || identities[match.ID] {
				return indeterminate("custom_recipient_not_unique")
			}
			identities[match.ID] = true
		}
		return matched
	}
	if route.Kind != SourceDirect && route.Kind != SourceForwarded {
		return indeterminate("source_kind")
	}
	apple := normalizeMailbox(route.PrimaryAddress)
	physical := normalizeMailbox(route.IMAPUsername)
	if apple == "" || (route.Kind == SourceForwarded && physical == "") {
		return indeterminate("source_route")
	}
	strong, valid := fieldSet(e.Strong)
	if !valid {
		return indeterminate("malformed_strong_recipient")
	}
	weak, weakValid := fieldSet(e.Weak)
	if len(e.Privacy) > 0 {
		return attributePrivacy(e, route, aliases, known, apple, physical, strong, weak)
	}
	for address := range strong {
		if _, local := known[address]; !local && address != apple && address != physical {
			return indeterminate("foreign_strong_recipient")
		}
	}
	if route.Kind == SourceForwarded && !strong[physical] && !(allowWeak && len(e.Strong) == 0) {
		return indeterminate("forward_route_unproven")
	}
	strongAliases := localSet(strong, known)
	weakAliases := localSet(weak, known)
	if len(strongAliases) > 0 {
		if len(weakAliases) > 0 && !sameSet(strongAliases, weakAliases) {
			return indeterminate("recipient_conflict")
		}
		return matchAliases(strongAliases, aliases, known)
	}
	if allowWeak {
		if !weakValid {
			return indeterminate("malformed_weak_recipient")
		}
		return matchAliases(weakAliases, aliases, known)
	}
	return Attribution{Determinate: true, Reason: "no_strong_alias"}
}

func attributePrivacy(e RecipientEvidence, route SourceRoute, aliases []Alias, known map[string][]Alias, apple, physical string, strong, weak map[string]bool) Attribution {
	if len(e.Privacy) != 1 {
		return indeterminate("privacy_duplicate")
	}
	privacy, ok := privacyParameters(e.Privacy[0])
	if !ok {
		return indeterminate("privacy_malformed")
	}
	p, f := privacy["p"], privacy["f"]
	active := 0
	for _, alias := range known[p] {
		if alias.Enabled {
			active++
		}
	}
	if active != 1 {
		return indeterminate("privacy_alias_not_unique")
	}
	visible := false
	for _, field := range e.Weak {
		if strings.EqualFold(field.Header, privacy["r"]) && field.Valid {
			for _, address := range field.Addresses {
				visible = visible || address == p
			}
		}
	}
	if !visible {
		return indeterminate("privacy_visible_recipient_missing")
	}
	for _, field := range e.Strong {
		for _, address := range field.Addresses {
			if address != p && address != f && address != apple && address != physical {
				return indeterminate("privacy_strong_conflict")
			}
			if field.Tier == 1 && address != f && address != apple && address != physical {
				return indeterminate("privacy_original_recipient_conflict")
			}
		}
	}
	for address := range unionSet(strong, weak) {
		if _, local := known[address]; local && address != p {
			return indeterminate("privacy_local_alias_conflict")
		}
	}
	if route.Kind == SourceDirect {
		if f != apple {
			return indeterminate("privacy_forward_route")
		}
	} else if !strong[physical] || (f != apple && f != physical && !strong[f]) {
		return indeterminate("privacy_forward_route")
	}
	return matchAliases(map[string]bool{p: true}, aliases, known)
}

func privacyParameters(value string) (map[string]string, bool) {
	if len(value) > 8<<10 || strings.ContainsAny(value, "\r\n") {
		return nil, false
	}
	items := strings.Split(value, ";")
	if len(items) > 32 {
		return nil, false
	}
	params := make(map[string]string, len(items))
	for _, item := range items {
		key, value, found := strings.Cut(item, "=")
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		// Apple may leave d blank; the identity and routing fields remain required.
		if !found || key == "" || value == "" && key != "d" {
			return nil, false
		}
		for _, c := range key {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return nil, false
			}
		}
		if _, duplicate := params[key]; duplicate {
			return nil, false
		}
		params[key] = value
	}
	for _, key := range []string{"p", "f", "s"} {
		if key == "s" && params[key] == "" {
			continue
		}
		address := normalizeMailbox(params[key])
		if address == "" {
			return nil, false
		}
		params[key] = address
	}
	params["r"] = strings.ToLower(params["r"])
	if params["p"] == params["f"] || (params["r"] != "to" && params["r"] != "cc") {
		return nil, false
	}
	return params, true
}

func normalizeMailbox(value string) string {
	if value == "" || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return ""
	}
	address, err := messageMail.ParseAddress(strings.TrimSpace(value))
	if err != nil || address.Name != "" || !strings.Contains(address.Address, "@") {
		return ""
	}
	return strings.ToLower(address.Address)
}

func fieldSet(fields []RecipientField) (map[string]bool, bool) {
	set := make(map[string]bool)
	valid := true
	for _, field := range fields {
		valid = valid && field.Valid
		for _, address := range field.Addresses {
			set[address] = true
		}
	}
	return set, valid
}

func localSet(addresses map[string]bool, known map[string][]Alias) map[string]bool {
	set := make(map[string]bool)
	for address := range addresses {
		if _, ok := known[address]; ok {
			set[address] = true
		}
	}
	return set
}

func matchAliases(addresses map[string]bool, aliases []Alias, known map[string][]Alias) Attribution {
	out := Attribution{Determinate: true, Reason: "matched"}
	for _, alias := range aliases {
		address := alias.Address // Directory already normalized this immutable snapshot.
		if !alias.Enabled || !addresses[address] {
			continue
		}
		count := 0
		for _, candidate := range known[address] {
			if candidate.Enabled {
				count++
			}
		}
		if count != 1 {
			return indeterminate("alias_not_unique")
		}
		out.Matches = append(out.Matches, AliasMatch{ID: alias.ID, Address: address})
	}
	if len(out.Matches) == 0 {
		out.Reason = "no_alias"
	}
	return out
}

func indeterminate(reason string) Attribution { return Attribution{Reason: reason} }

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for value := range a {
		if !b[value] {
			return false
		}
	}
	return true
}

func unionSet(a, b map[string]bool) map[string]bool {
	union := make(map[string]bool, len(a)+len(b))
	for value := range a {
		union[value] = true
	}
	for value := range b {
		union[value] = true
	}
	return union
}
