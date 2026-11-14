package accessimap

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
)

// The pinned SDK implements CLOSE by calling Expunge before Unselect. On this
// read-only service CLOSE must only unselect. Rewrite that exact no-argument
// command at the TLS plaintext boundary; literal bytes and continuation lines
// are never interpreted as a fresh command. No credentials are logged/retained.
type commandReader struct {
	raw          *bufio.Reader
	pending      []byte
	literal      int64
	continuation bool
}

func newCommandReader(raw io.Reader) *commandReader { return &commandReader{raw: bufio.NewReader(raw)} }
func incomingLiteral(line []byte) (int64, bool) {
	if !bytes.HasSuffix(line, []byte("}\r\n")) {
		return 0, false
	}
	start := bytes.LastIndexByte(line, '{')
	if start < 0 {
		return 0, false
	}
	digits := line[start+1 : len(line)-3]
	digits = bytes.TrimSuffix(digits, []byte("+"))
	if len(digits) == 0 {
		return 0, false
	}
	for _, b := range digits {
		if b < '0' || b > '9' {
			return 0, false
		}
	}
	n, e := strconv.ParseInt(string(digits), 10, 64)
	return n, e == nil && n >= 0
}
func (r *commandReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		clear(r.pending[:n])
		r.pending = r.pending[n:]
		return n, nil
	}
	if r.literal > 0 {
		n, e := r.raw.Read(p[:min(int64(len(p)), r.literal)])
		r.literal -= int64(n)
		return n, e
	}
	var line []byte
	for {
		part, e := r.raw.ReadSlice('\n')
		if len(line)+len(part) > 64<<10 {
			clear(line)
			return 0, errors.New("accessimap: command line budget exceeded")
		}
		line = append(line, part...)
		if e == bufio.ErrBufferFull {
			continue
		}
		if e != nil {
			clear(line)
			return 0, e
		}
		break
	}
	if !r.continuation && bytes.HasSuffix(line, []byte("\r\n")) {
		space := bytes.IndexByte(line, ' ')
		if space > 0 && bytes.EqualFold(line[space+1:len(line)-2], []byte("CLOSE")) {
			replacement := append([]byte(nil), line[:space+1]...)
			replacement = append(replacement, []byte("UNSELECT\r\n")...)
			clear(line)
			line = replacement
		}
	}
	if size, ok := incomingLiteral(line); ok {
		r.literal = size
		r.continuation = true
	} else {
		r.continuation = false
	}
	r.pending = line
	return r.Read(p)
}
