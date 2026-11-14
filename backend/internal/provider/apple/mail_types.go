package apple

import "encoding/json"

// WebMail build and user-agent values used for Apple mail requests.
const MailWebBuild = "2638Hotfix77"
const serviceUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15"

// Mail primitives describe observed WebMail wire facts. The mailout domain
// owns durable intents, authorization and whether a mutation may be attempted.
type MailReceipt struct {
	RPCID      string
	Matched    bool
	Outcome    string
	UpstreamID string
}
type MailMessage struct {
	GUID       string          `json:"guid"`
	UID        string          `json:"uid"`
	Folder     string          `json:"folder"`
	MessageID  string          `json:"messageId"`
	Subject    string          `json:"subject"`
	LongHeader string          `json:"longHeader"`
	From       json.RawMessage `json:"from"`
	To         []string        `json:"to"`
	ReplyTo    []string        `json:"replyTo"`
	Parts      []MailBodyPart  `json:"parts"`
}
type MailBodyPart struct {
	Type       string `json:"type"`
	GUID       string `json:"guid"`
	Attachment bool   `json:"isattach"`
	Size       int64  `json:"size"`
	MediaType  string `json:"datatype"`
	Content    string `json:"content"`
}
type MailPart struct {
	GUID           string  `json:"guid"`
	Name           string  `json:"name"`
	URL            string  `json:"url"`
	ContentID      *string `json:"contentID"`
	Size           int64   `json:"size"`
	MediaType      string  `json:"datatype"`
	Disposition    string  `json:"contentDisposition"`
	Related        any     `json:"related"`
	StreamingURL   any     `json:"mailDropStreamingUrl"`
	ExpirationDate any     `json:"mailDropExpirationDate"`
	Thumbnail      bool    `json:"isMailDropThumbnail"`
}
type MailSend struct {
	Date        string     `json:"date"`
	From        string     `json:"from"`
	To          string     `json:"to"`
	Recents     string     `json:"recents,omitempty"`
	Subject     string     `json:"subject"`
	Text        string     `json:"textBody"`
	HTML        string     `json:"body"`
	InReplyTo   []string   `json:"headerInReplyTo,omitempty"`
	References  []string   `json:"headerReferences,omitempty"`
	Attachments []MailPart `json:"attachments"`
	DraftGUID   string     `json:"draftGuid,omitempty"`
	Mode        string     `json:"mode,omitempty"`
	MessageGUID string     `json:"msgGuid,omitempty"`
	ClientBuild string     `json:"webmailClientBuild"`
	IsHME       bool       `json:"isHME"`
}
