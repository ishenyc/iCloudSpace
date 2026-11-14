package applemail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/mail"
	"strings"
	"time"

	"github.com/emersion/go-message"
	messageMail "github.com/emersion/go-message/mail"
	"icloudspace/internal/content"
	"icloudspace/internal/mailout"
)

type smtpPart struct {
	descriptor mailout.Uploaded
	body       []byte
}

func (o *operation) stageSMTPPart(ctx context.Context, input mailout.Upload) (mailout.Uploaded, error) {
	if ctx.Err() != nil || input.ByteSize < 0 || input.ByteSize > content.DraftAttachmentBytes || len(o.smtpParts) >= content.DraftAttachments {
		return mailout.Uploaded{}, mailout.ErrInvalid
	}
	var size int64
	for _, part := range o.smtpParts {
		size += int64(len(part.body))
	}
	if size+input.ByteSize > content.DraftAttachmentBytes {
		return mailout.Uploaded{}, mailout.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(input.Body, input.ByteSize+1))
	if err != nil || int64(len(raw)) != input.ByteSize || sha256.Sum256(raw) != input.SHA256 {
		clear(raw)
		return mailout.Uploaded{}, mailout.ErrInvalid
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		clear(raw)
		return mailout.Uploaded{}, mailout.ErrProvider
	}
	id := "smtp-part-" + hex.EncodeToString(nonce[:])
	uploaded := mailout.Uploaded{ID: id, Filename: input.Filename, MediaType: input.MediaType, ByteSize: input.ByteSize, SHA256: input.SHA256, Inline: input.Inline, LogicalCID: input.LogicalCID}
	if input.Inline {
		uploaded.ContentID = id + "@icloudspace.invalid"
		uploaded.URL = "cid:" + uploaded.ContentID
	}
	if o.smtpParts == nil {
		o.smtpParts = make(map[string]smtpPart)
	}
	o.smtpParts[id] = smtpPart{descriptor: uploaded, body: raw}
	return uploaded, nil
}

func smtpMessageID(id string) (string, error) {
	if len(id) < 8 || len(id) > 256 {
		return "", mailout.ErrInvalid
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return "", mailout.ErrInvalid
		}
	}
	return id + "@icloud.com", nil
}

// smtpMIME keeps plaintext/HTML alternatives, CID-related inline images, and
// ordinary attachments in standard MIME. No temporary Apple upload is needed.
func (o *operation) smtpMIME(input mailout.Submission, proof referenceProof, at time.Time) ([]byte, string, error) {
	id, err := smtpMessageID(input.RPCID)
	if err != nil || strings.ContainsAny(input.Subject, "\r\n\x00") {
		return nil, "", mailout.ErrInvalid
	}
	var header messageMail.Header
	header.SetAddressList("From", []*mail.Address{{Address: proof.from}})
	header.SetAddressList("To", []*mail.Address{{Address: proof.relay}})
	header.SetSubject(input.Subject)
	header.SetDate(at)
	header.SetMessageID(id)
	if input.Reference.MessageID != "" {
		if !safe(input.Reference.MessageID, 2048) || !strings.HasPrefix(input.Reference.MessageID, "<") || !strings.HasSuffix(input.Reference.MessageID, ">") {
			return nil, "", mailout.ErrReference
		}
		header.Set("In-Reply-To", input.Reference.MessageID)
		header.Set("References", input.Reference.MessageID)
	}
	header.SetContentType("multipart/mixed", nil)
	var buffer bytes.Buffer
	writer, err := message.CreateWriter(&buffer, header.Header)
	if err != nil {
		return nil, "", err
	}
	var relatedHeader message.Header
	relatedHeader.SetContentType("multipart/related", nil)
	related, err := writer.CreatePart(relatedHeader)
	if err != nil {
		return nil, "", err
	}
	var alternativeHeader message.Header
	alternativeHeader.SetContentType("multipart/alternative", nil)
	alternative, err := related.CreatePart(alternativeHeader)
	if err != nil {
		return nil, "", err
	}
	for _, body := range []struct{ media, text string }{{"text/plain", input.Text}, {"text/html", input.HTML}} {
		var h message.Header
		h.SetContentType(body.media, map[string]string{"charset": "utf-8"})
		h.Set("Content-Transfer-Encoding", "quoted-printable")
		part, e := alternative.CreatePart(h)
		if e != nil {
			return nil, "", e
		}
		if _, e = io.WriteString(part, body.text); e != nil {
			return nil, "", e
		}
		if e = part.Close(); e != nil {
			return nil, "", e
		}
	}
	if err = alternative.Close(); err != nil {
		return nil, "", err
	}
	seen := make(map[string]bool)
	for _, file := range input.Attachments {
		part, ok := o.smtpParts[file.ID]
		if !ok || part.descriptor != file || seen[file.ID] {
			return nil, "", mailout.ErrProvider
		}
		seen[file.ID] = true
		if file.Inline {
			if err = writeSMTPPart(related, part); err != nil {
				return nil, "", err
			}
		}
	}
	if err = related.Close(); err != nil {
		return nil, "", err
	}
	for _, file := range input.Attachments {
		if !file.Inline {
			if err = writeSMTPPart(writer, o.smtpParts[file.ID]); err != nil {
				return nil, "", err
			}
		}
	}
	if err = writer.Close(); err != nil {
		return nil, "", err
	}
	if buffer.Len() > 16<<20 {
		return nil, "", mailout.ErrInvalid
	}
	return buffer.Bytes(), "<" + id + ">", nil
}

func writeSMTPPart(writer *message.Writer, part smtpPart) error {
	d := part.descriptor
	var header message.Header
	header.SetContentType(d.MediaType, map[string]string{"name": d.Filename})
	disposition := "attachment"
	if d.Inline {
		disposition = "inline"
		header.Set("Content-ID", "<"+d.ContentID+">")
	}
	header.SetContentDisposition(disposition, map[string]string{"filename": d.Filename})
	header.Set("Content-Transfer-Encoding", "base64")
	writerPart, err := writer.CreatePart(header)
	if err != nil {
		return err
	}
	if _, err = writerPart.Write(part.body); err != nil {
		return err
	}
	return writerPart.Close()
}
