package redirector

import (
	"net"
	"time"
)

// idleConn wraps a net.Conn and refreshes the read deadline after every
// successful Read. Combined with io.Copy, it implements a half-duplex idle
// timeout: a stalled peer (no incoming bytes for `idle`) terminates the copy
// without affecting an active stream.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func newIdleConn(c net.Conn, idle time.Duration) net.Conn {
	if idle <= 0 {
		return c
	}
	_ = c.SetReadDeadline(time.Now().Add(idle))
	return &idleConn{Conn: c, idle: idle}
}

func (c *idleConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return n, err
}
