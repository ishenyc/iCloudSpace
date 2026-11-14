package imap

import (
	"io"

	protocol "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// A failed SDK literal releases the decoder, which shares its buffered reader.
// Remember the first wire error: neither cleanup nor Next may read it again.
// Context checks belong outside this reader because they do not release the SDK.
type wireLiteral struct {
	r         protocol.LiteralReader
	remaining int64
	err       error
}

func (r *wireLiteral) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.r.Read(p)
	r.remaining -= int64(n)
	r.err = err
	return n, err
}

func (r *wireLiteral) finish() error {
	_, err := io.Copy(io.Discard, r)
	if err != nil {
		return err
	}
	if r.remaining != 0 {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// walkFetchMessage is the only owner of the message's wire literals. Callers
// close the transport on rejection, then this owner releases the decoder even
// when a callback never read, returned early, or panicked. A partial wire failure
// stops before Next, whose implicit discard would otherwise reread the literal.
// A complete buffered literal may be followed by another one, so closing the
// socket alone is not a reason to stop walking or wait for the decoder yet.
func walkFetchMessage(msg *imapclient.FetchMessageData, visit func(imapclient.FetchItemData, *wireLiteral), failed func(error), panicked func(any)) bool {
	for item := msg.Next(); item != nil; item = msg.Next() {
		var raw protocol.LiteralReader
		switch item := item.(type) {
		case imapclient.FetchItemDataBodySection:
			raw = item.Literal
		case imapclient.FetchItemDataBinarySection:
			raw = item.Literal
		}
		var literal *wireLiteral
		if raw != nil {
			literal = &wireLiteral{r: raw, remaining: raw.Size()}
		}
		func() {
			defer func() {
				if value := recover(); value != nil {
					panicked(value)
				}
			}()
			visit(item, literal)
		}()
		if literal != nil {
			if err := literal.finish(); err != nil {
				failed(err)
				return false
			}
		}
	}
	return true
}
