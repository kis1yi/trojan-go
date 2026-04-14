package simplesocks

import (
	"bytes"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/tunnel"
	"github.com/kis1yi/trojan-go/tunnel/trojan"
)

// Conn is a simplesocks connection
type Conn struct {
	tunnel.Conn
	metadata      *tunnel.Metadata
	isOutbound    bool
	headerWritten bool
}

func (c *Conn) Metadata() *tunnel.Metadata {
	return c.metadata
}

func (c *Conn) Write(payload []byte) (int, error) {
	if c.isOutbound && !c.headerWritten {
		buf := bytes.NewBuffer(make([]byte, 0, 4096))
		c.metadata.Marshal(buf)
		buf.Write(payload)
		_, err := c.Conn.Write(buf.Bytes())
		if err != nil {
			return 0, common.NewError("failed to write simplesocks header").Base(err)
		}
		c.headerWritten = true
		return len(payload), nil
	}
	return c.Conn.Write(payload)
}

// PacketConn is a simplesocks packet connection
// The header syntax is the same as trojan's
type PacketConn struct {
	trojan.PacketConn
}
