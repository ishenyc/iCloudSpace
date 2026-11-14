package accessimap

import (
	"bytes"
	"context"
	"errors"
	"icloudspace/internal/addressauth"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
)

// secureWire is constructed only around a service-owned tls.Server connection.
// It observes plaintext writes, not DebugWriter, and retains no body/auth log.
// A bounded read pump notices peer EOF and cancels SQL even during a command.
type secureWire struct {
	net.Conn
	ctx              context.Context
	cancel           context.CancelFunc
	once             sync.Once
	mu               sync.Mutex
	lease            *addressauth.Lease
	selecting        bool
	writeMu          sync.Mutex
	lineType         byte
	tail, statusLine []byte
	literal          int64
	readMu           sync.Mutex
	input            chan []byte
	readErr          chan error
	current          []byte
	commands         *commandReader
}

func newSecureWire(conn net.Conn) *secureWire {
	ctx, cancel := context.WithCancel(context.Background())
	w := &secureWire{Conn: conn, ctx: ctx, cancel: cancel, input: make(chan []byte, 32), readErr: make(chan error, 1)}
	w.commands = newCommandReader(rawWireReader{w})
	go w.pump()
	return w
}
func (w *secureWire) pump() {
	for {
		buf := make([]byte, 32<<10)
		n, e := w.Conn.Read(buf)
		if n > 0 {
			buf = buf[:n]
			select {
			case w.input <- buf:
			case <-w.ctx.Done():
				clear(buf)
				return
			default:
				clear(buf)
				w.readErr <- errors.New("accessimap: command pipeline budget exceeded")
				w.cancel()
				w.Conn.Close()
				return
			}
		}
		if e != nil {
			w.readErr <- e
			w.cancel()
			return
		}
	}
}
func (w *secureWire) Read(p []byte) (int, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()
	return w.commands.Read(p)
}

type rawWireReader struct{ wire *secureWire }

func (r rawWireReader) Read(p []byte) (int, error) { return r.wire.readRaw(p) }
func (w *secureWire) readRaw(p []byte) (int, error) {
	for len(w.current) == 0 {
		select {
		case w.current = <-w.input:
		case e := <-w.readErr:
			return 0, e
		case <-w.ctx.Done():
			return 0, io.EOF
		}
	}
	n := copy(p, w.current)
	clear(w.current[:n])
	w.current = w.current[n:]
	return n, nil
}
func (w *secureWire) attach(lease *addressauth.Lease, selecting bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lease = lease
	w.selecting = selecting
}
func (w *secureWire) active() *addressauth.Lease { w.mu.Lock(); defer w.mu.Unlock(); return w.lease }
func (w *secureWire) release(lease *addressauth.Lease) {
	w.mu.Lock()
	if lease == nil || w.lease == lease {
		old := w.lease
		w.lease = nil
		w.selecting = false
		w.mu.Unlock()
		if old != nil {
			old.Close()
		}
		return
	}
	w.mu.Unlock()
}
func (w *secureWire) Close() error {
	var e error
	w.once.Do(func() { w.cancel(); e = w.Conn.Close(); w.release(nil) })
	return e
}
func literalLength(tail []byte) (int64, bool) {
	if !bytes.HasSuffix(tail, []byte("}\r\n")) {
		return 0, false
	}
	start := bytes.LastIndexByte(tail, '{')
	if start < 0 {
		return 0, false
	}
	number := string(tail[start+1 : len(tail)-3])
	n, e := strconv.ParseInt(number, 10, 64)
	return n, e == nil && n >= 0
}
func taggedCompletion(line []byte) bool {
	fields := strings.SplitN(string(line), " ", 3)
	if len(fields) < 3 || fields[0] == "" || fields[0] == "*" || fields[0] == "+" {
		return false
	}
	return fields[1] == "OK" || fields[1] == "NO" || fields[1] == "BAD"
}
func (w *secureWire) Write(p []byte) (int, error) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	var out bytes.Buffer
	complete := false
	for offset := 0; offset < len(p); {
		if w.literal > 0 {
			n := min(int64(len(p)-offset), w.literal)
			out.Write(p[offset : offset+int(n)])
			offset += int(n)
			w.literal -= n
			continue
		}
		b := p[offset]
		offset++
		if w.lineType == 0 {
			if b == '*' || b == '+' {
				w.lineType = b
			} else {
				w.lineType = 't'
			}
		}
		if w.lineType == 't' {
			w.statusLine = append(w.statusLine, b)
			if len(w.statusLine) > 64<<10 {
				return 0, errors.New("accessimap: invalid status framing")
			}
		} else {
			out.WriteByte(b)
		}
		w.tail = append(w.tail, b)
		if len(w.tail) > 40 {
			w.tail = w.tail[len(w.tail)-40:]
		}
		if !bytes.HasSuffix(w.tail, []byte("\r\n")) {
			continue
		}
		if n, ok := literalLength(w.tail); ok {
			w.literal = n
			w.tail = nil
			continue
		}
		if w.lineType == 't' {
			line := w.statusLine
			w.mu.Lock()
			selecting := w.selecting
			w.mu.Unlock()
			if selecting && bytes.HasSuffix(line, []byte(" OK [READ-WRITE] SELECT completed\r\n")) {
				line = bytes.Replace(line, []byte("[READ-WRITE]"), []byte("[READ-ONLY]"), 1)
			}
			out.Write(line)
			complete = taggedCompletion(line) || complete
			w.statusLine = nil
		}
		w.lineType = 0
		w.tail = nil
	}
	data := out.Bytes()
	for len(data) > 0 {
		n, e := w.Conn.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if e != nil {
			w.Close()
			return 0, e
		}
		if n == 0 {
			w.Close()
			return 0, io.ErrShortWrite
		}
	}
	if complete {
		w.release(nil)
	}
	return len(p), nil
}
