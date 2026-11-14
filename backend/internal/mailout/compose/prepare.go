package compose

import (
	"bytes"
	"errors"
	"mime"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"icloudspace/internal/content"
)

// The submission owner supplies the sender identity and owns route validation,
// durable fingerprints, provider calls and submission outcomes.
const MaxMailAttachments = 10
const MaxMailAttachmentBytes = 10 << 20
const MaxMailSendJSONBytes = 16 << 20

type MailAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Data        []byte `json:"data"`
	ContentID   string `json:"content_id,omitempty"`
}

var contentIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}@[a-zA-Z0-9][a-zA-Z0-9.-]{0,63}$`)
var attachmentTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$`)

func normalizeMailAttachments(input []MailAttachment) ([]MailAttachment, error) {
	if len(input) > MaxMailAttachments {
		return nil, errors.New("附件最多 10 个")
	}
	if len(input) == 0 {
		return nil, nil
	}
	result := make([]MailAttachment, len(input))
	ids := make(map[string]bool)
	total := 0
	for i, a := range input {
		a.Filename = strings.TrimSpace(a.Filename)
		if !validAttachmentFilename(a.Filename) {
			return nil, errors.New("附件文件名无效，不能包含路径或控制字符")
		}
		total += len(a.Data)
		if total > MaxMailAttachmentBytes {
			return nil, errors.New("附件总大小不能超过 10 MiB")
		}
		if a.ContentType == "" {
			a.ContentType = strings.Split(http.DetectContentType(a.Data), ";")[0]
		}
		a.ContentType = strings.ToLower(strings.TrimSpace(a.ContentType))
		typeName, params, err := mime.ParseMediaType(a.ContentType)
		if err != nil || len(params) != 0 || !attachmentTypePattern.MatchString(typeName) {
			return nil, errors.New("附件 MIME 类型无效")
		}
		a.ContentType = typeName
		if a.ContentID != "" {
			if !contentIDPattern.MatchString(a.ContentID) || ids[a.ContentID] {
				return nil, errors.New("正文图片 Content-ID 无效或重复")
			}
			ids[a.ContentID] = true
			if !isInlineImage(a.ContentType) || http.DetectContentType(a.Data) != a.ContentType {
				return nil, errors.New("正文图片仅支持内容匹配的 PNG、JPEG、GIF 或 WebP")
			}
		}
		result[i] = a
	}
	return result, nil
}

func validAttachmentFilename(name string) bool {
	return name != "" && name != "." && name != ".." && utf8.ValidString(name) && len(name) <= 255 && !strings.ContainsAny(name, "/\\") && strings.IndexFunc(name, unicode.IsControl) < 0
}
func isInlineImage(kind string) bool {
	return kind == "image/png" || kind == "image/jpeg" || kind == "image/gif" || kind == "image/webp"
}

func normalizeHMEAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	parsed, err := mail.ParseAddress(value)
	if value == "" || err != nil || parsed.Name != "" || !strings.EqualFold(strings.TrimSpace(parsed.Address), value) {
		return "", errors.New("must be a valid email address")
	}
	return strings.ToLower(value), nil
}

// Prepare validates the recipient, subject, body and attachments for sending.
// ContentID selects inline attachment disposition. Received-message rendering
// uses the separate content preparation and sanitization pipeline.
func Prepare(draft content.Draft) (*content.Prepared, error) {
	to, err := normalizeHMEAddress(draft.Recipient)
	if err != nil {
		return nil, errors.New("invalid recipient")
	}
	subject := strings.TrimSpace(draft.Subject)
	if !utf8.ValidString(subject) || subject == "" || len(subject) > 998 || strings.IndexFunc(subject, unicode.IsControl) >= 0 {
		return nil, errors.New("invalid subject")
	}
	var input []MailAttachment
	if len(draft.Attachments) != 0 {
		input = make([]MailAttachment, len(draft.Attachments))
		for i, file := range draft.Attachments {
			input[i] = MailAttachment{Filename: file.Filename, ContentType: file.MediaType, Data: file.Bytes, ContentID: file.ContentID}
		}
	}
	files, err := normalizeMailAttachments(input)
	if err != nil {
		return nil, err
	}
	body, err := Render(string(draft.Body.Format), draft.Body.Source)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(body.Text) == "" && len(files) == 0 {
		return nil, errors.New("请填写正文或添加附件")
	}
	cids := make(map[string]string)
	for _, file := range files {
		if file.ContentID != "" {
			cids[file.ContentID] = file.ContentID
		}
	}
	if _, err := RewriteCIDs(body.HTML, cids); err != nil {
		return nil, err
	}
	out := &content.Prepared{To: content.Mailbox{Address: to}, Subject: subject, Body: content.RenderedBody{Text: body.Text, HTML: body.HTML}}
	for _, file := range files {
		// bytes.Clone preserves the nil-versus-empty distinction.
		out.Attachments = append(out.Attachments, content.DraftAttachment{Filename: file.Filename, MediaType: file.ContentType, ContentID: file.ContentID, Inline: file.ContentID != "", Bytes: bytes.Clone(file.Data)})
	}
	return out, nil
}
