package tls

import (
	"net"

	"github.com/kis1yi/trojan-go/fallback"
)

// ruleConn is the private wrapper the TLS server attaches to a connection
// that is about to be handed to the redirector. It satisfies
// `fallback.Aware` so the trojan layer (P1-1c) and the redirector
// (P1-1d) can recover the matched rule via fallback.Unwrap without the
// TLS package leaking a public interface beyond what `fallback.Aware`
// already provides.
//
// Embedding net.Conn forwards Read/Write/Close/etc; the only additional
// method is FallbackRule.
type ruleConn struct {
	net.Conn
	rule *fallback.Rule
}

// FallbackRule satisfies fallback.Aware.
func (c *ruleConn) FallbackRule() *fallback.Rule { return c.rule }

// NetConn lets fallback.Unwrap descend into the embedded connection. We
// expose the embedded conn (not crypto/tls.Conn.NetConn semantics) so
// callers walking the chain reach the underlying transport.
func (c *ruleConn) NetConn() net.Conn { return c.Conn }
