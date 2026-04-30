package transport

import (
	"net"

	"github.com/kis1yi/trojan-go/tunnel"
)

type Conn struct {
	net.Conn
}

func (c *Conn) Metadata() *tunnel.Metadata {
	return nil
}

// NetConn exposes the embedded transport conn so callers walking a chain
// of wrappers (fallback.Unwrap, in particular) can descend past this
// layer. P1-1c: the trojan invalid-auth path uses this to recover the
// fallback rule attached by the TLS layer.
func (c *Conn) NetConn() net.Conn {
	return c.Conn
}
