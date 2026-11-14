package content

import (
	"container/heap"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type CodeSource string

const (
	CodeSubject CodeSource = "subject"
	CodeText    CodeSource = "text"
	CodeHTML    CodeSource = "html_text"
)

type CodeCandidate struct {
	Code    string
	Source  CodeSource
	Start   int // rune offset, inclusive, in the identified decoded text
	End     int // rune offset, exclusive
	Context string
	Score   int
}

// FindCodes finds whole ASCII digit runs of length 4..8, preserving leading
// zeroes. Context is scored within 80 runes; at most maxCandidates results are
// retained even for a hostile body containing many numbers. HTML offsets refer
// to TextFromHTML(html), whose byte limit is explicitly supplied by the caller.
// This pure result does not persist codes or imply that a message is consumed.
func FindCodes(subject, text, html string, maxCandidates int, htmlBytes int64) ([]CodeCandidate, error) {
	if maxCandidates <= 0 || htmlBytes <= 0 {
		return nil, ErrLimits
	}
	visible, err := TextFromHTML(html, htmlBytes)
	if err != nil {
		return nil, err
	}
	best := &codeHeap{}
	heap.Init(best)
	for _, source := range []struct {
		kind  CodeSource
		value string
	}{{CodeSubject, subject}, {CodeText, text}, {CodeHTML, visible}} {
		runes := []rune(source.value)
		for start := 0; start < len(runes); {
			if runes[start] < '0' || runes[start] > '9' {
				start++
				continue
			}
			end := start + 1
			for end < len(runes) && runes[end] >= '0' && runes[end] <= '9' {
				end++
			}
			length := end - start
			if length >= 4 && length <= 8 && (start == 0 || !wordNumberNeighbor(runes[start-1])) && (end == len(runes) || !wordNumberNeighbor(runes[end])) {
				left, right := max(0, start-80), min(len(runes), end+80)
				candidate := CodeCandidate{Code: string(runes[start:end]), Source: source.kind, Start: start, End: end,
					Context: string(runes[left:right])}
				candidate.Score = codeScore(candidate, start-left)
				if best.Len() < maxCandidates {
					heap.Push(best, candidate)
				} else if betterCode(candidate, (*best)[0]) {
					(*best)[0] = candidate
					heap.Fix(best, 0)
				}
			}
			start = end
		}
	}
	out := []CodeCandidate(*best)
	sort.Slice(out, func(i, j int) bool { return betterCode(out[i], out[j]) })
	return out, nil
}

// SelectCode restricts to the requested length (normally 6 for public OTP
// history). Pass 0 to select across 4..8 digits. Scoring never changes digits.
func SelectCode(candidates []CodeCandidate, digits int) (CodeCandidate, bool) {
	var best CodeCandidate
	found := false
	for _, candidate := range candidates {
		if (digits == 0 || len(candidate.Code) == digits) && (!found || betterCode(candidate, best)) {
			best, found = candidate, true
		}
	}
	return best, found
}

func wordNumberNeighbor(r rune) bool {
	return unicode.IsNumber(r) || unicode.IsLetter(r) || r == '_'
}

func codeScore(candidate CodeCandidate, start int) int {
	score := 0
	if len(candidate.Code) == 6 {
		score += 20
	}
	if candidate.Source == CodeSubject {
		score += 12
	}
	if candidate.Source == CodeHTML {
		score--
	}
	context := strings.ToLower(candidate.Context)
	positive := 0
	for _, keyword := range []string{"verify", "verification", "security code", "one-time", "one time", "login code", "sign-in code", "passcode", "otp", "confirmation code", "验证码", "驗證碼", "校验码", "校驗碼", "动态码", "動態碼", "一次性密码", "認証コード", "認証番号", "인증 코드"} {
		positive = max(positive, keywordScore(context, keyword, start, 100))
	}
	positive = max(positive, keywordScore(context, "code", start, 40))
	score += positive
	for _, keyword := range []string{"tracking", "invoice", "order number", "telephone", "phone", "unsubscribe", "订单", "訂單", "运单", "運單", "电话", "電話"} {
		if keywordScore(context, keyword, start, 80) > 30 {
			score -= 45
			break
		}
	}
	if positive == 0 && len(candidate.Code) == 4 && (strings.HasPrefix(candidate.Code, "19") || strings.HasPrefix(candidate.Code, "20")) {
		score -= 15
	}
	return score
}

func keywordScore(context, keyword string, codeOffset, weight int) int {
	best := 0
	base := 0
	for {
		index := strings.Index(context[base:], keyword)
		if index < 0 {
			return best
		}
		index += base
		keywordStart := utf8.RuneCountInString(context[:index])
		keywordEnd := keywordStart + utf8.RuneCountInString(keyword)
		distance := 0
		if keywordEnd < codeOffset {
			distance = codeOffset - keywordEnd
		}
		if keywordStart > codeOffset {
			distance = keywordStart - codeOffset
		}
		best = max(best, weight-distance)
		base = index + len(keyword)
	}
}

func betterCode(a, b CodeCandidate) bool {
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	if a.Source != b.Source {
		return sourceOrder(a.Source) < sourceOrder(b.Source)
	}
	return a.Start < b.Start
}

func sourceOrder(source CodeSource) int {
	switch source {
	case CodeSubject:
		return 0
	case CodeText:
		return 1
	default:
		return 2
	}
}

type codeHeap []CodeCandidate

func (h codeHeap) Len() int           { return len(h) }
func (h codeHeap) Less(i, j int) bool { return betterCode(h[j], h[i]) }
func (h codeHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *codeHeap) Push(value any)    { *h = append(*h, value.(CodeCandidate)) }
func (h *codeHeap) Pop() any          { end := len(*h) - 1; value := (*h)[end]; *h = (*h)[:end]; return value }
