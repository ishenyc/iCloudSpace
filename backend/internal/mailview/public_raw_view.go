package mailview

import (
	"context"

	"icloudspace/internal/addressauth"
	"icloudspace/internal/content"
)

// RawMessage describes one verified original under only raw_read authority.
// It does not borrow mail_read, a retained snapshot, or a reconstructed MIME.
// The caller retains its lease through serialization of this private result.
func (s *Service) RawMessage(ctx context.Context, lease *addressauth.Lease, uid uint32) (Message, error) {
	id, err := s.allow(lease, addressauth.RawRead)
	if err != nil {
		return Message{}, err
	}
	metadata, err := s.entry(ctx, id, uid)
	if err != nil {
		return Message{}, err
	}
	if err = s.observe(ctx, id); err != nil {
		return Message{}, err
	}
	raw, err := s.openObject(ctx, id, metadata.MessageID, uid, nil)
	if err != nil {
		return Message{}, err
	}
	raw = s.protect(lease, raw)
	defer raw.Close()
	parsed, _ := content.Parse(raw.Reader, s.options.Limits)
	if parsed == nil {
		return Message{}, ErrUnavailable
	}
	html, err := content.RenderReceived(parsed, 2*s.options.Limits.BodyBytes+4096)
	if err != nil {
		return Message{}, ErrBudget
	}
	result := Message{Metadata: metadata, Text: parsed.Text, HTML: html, BodyComplete: parsed.BodyComplete, Attachments: []Attachment{}}
	for _, part := range parsed.Attachments {
		result.Attachments = append(result.Attachments, Attachment{Part: part.Part, Filename: part.Filename, MediaType: part.MediaType,
			Disposition: part.Disposition, ContentID: part.ContentID, Inline: part.Inline, ByteSize: part.Size, Complete: part.Complete})
	}
	return result, nil
}
