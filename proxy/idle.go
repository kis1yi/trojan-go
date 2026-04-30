package proxy

import (
	"io"
	"time"
)

// deadlineSetter is implemented by net.Conn (and tunnel.Conn). The proxy
// relay applies a per-direction read deadline to detect a stalled peer; an
// io.Reader that does not satisfy this interface is returned unwrapped.
type deadlineSetter interface {
	SetReadDeadline(time.Time) error
}

// idleReader refreshes the read deadline on its underlying connection after
// every successful Read. Combined with io.Copy this implements a half-duplex
// idle eviction: a peer that stops sending for `idle` triggers a deadline
// error which propagates back through the relay so both copy goroutines can
// exit. Active flows refresh the deadline and are unaffected.
type idleReader struct {
	r    io.Reader
	d    deadlineSetter
	idle time.Duration
}

func newIdleReader(r io.Reader, idle time.Duration) io.Reader {
	if idle <= 0 {
		return r
	}
	d, ok := r.(deadlineSetter)
	if !ok {
		return r
	}
	_ = d.SetReadDeadline(time.Now().Add(idle))
	return &idleReader{r: r, d: d, idle: idle}
}

func (i *idleReader) Read(p []byte) (int, error) {
	n, err := i.r.Read(p)
	if n > 0 {
		_ = i.d.SetReadDeadline(time.Now().Add(i.idle))
	}
	return n, err
}
