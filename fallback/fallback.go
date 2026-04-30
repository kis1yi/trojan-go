// Package fallback holds the type used to describe a single fallback
// destination plus the small `Aware` interface the TLS and trojan layers
// use to forward the matched rule down the connection chain.
//
// This package is intentionally tiny and dependency-free so both
// `tunnel/tls` and `tunnel/trojan` (and the redirector) can import it
// without creating an import cycle. The 2026 hardening plan sequences
// the work as P1-1a..P1-1d:
//
//	P1-1a (this commit)  type + config schema, no behaviour change
//	P1-1b                TLS-layer SNI/ALPN routing
//	P1-1c                trojan-layer rule propagation through wrappers
//	P1-1d                PROXY protocol v1/v2 emission on dial
//
// At P1-1a the redirector still consults the legacy
// `TLSConfig.FallbackHost`/`FallbackPort` pair; the rule type and the
// `fallback` YAML/JSON list are wired into config parsing only and are
// translated through `RulesFromLegacy` so existing single-fallback
// configs keep working untouched.
package fallback

import (
	"net"
	"strings"
)

// ProxyProtocolVersion encodes the on-the-wire PROXY protocol header
// version emitted on the redirected dial. Zero means "no PROXY header".
type ProxyProtocolVersion int

const (
	// ProxyProtocolNone disables PROXY header emission. Default.
	ProxyProtocolNone ProxyProtocolVersion = 0
	// ProxyProtocolV1 emits a human-readable v1 header.
	ProxyProtocolV1 ProxyProtocolVersion = 1
	// ProxyProtocolV2 emits the binary v2 header (recommended for
	// modern backends such as nginx and HAProxy).
	ProxyProtocolV2 ProxyProtocolVersion = 2
)

// Rule is the resolved, validated form of a single fallback entry. It is
// what `Aware` implementations expose.
type Rule struct {
	// SNI is the exact ServerName this rule matches. Empty SNI means the
	// rule does not constrain on SNI; combine with ALPN or IsDefault.
	SNI string
	// ALPN is the set of negotiated protocols this rule matches. Empty
	// means the rule does not constrain on ALPN.
	ALPN []string
	// Addr is the upstream host (hostname or IP literal) the fallback
	// dial targets.
	Addr string
	// Port is the upstream TCP port. Must be 1..65535 for the rule to be
	// usable; rules that fail validation are dropped at config-parse time.
	Port int
	// ProxyProtocol selects the PROXY header version emitted on the
	// fallback dial. Wired in P1-1d.
	ProxyProtocol ProxyProtocolVersion
	// IsDefault marks this rule as the catch-all. Match() returns it when
	// no explicit rule matches the SNI/ALPN of the incoming connection.
	IsDefault bool
}

// Match walks `rules` in declaration order and returns the first rule
// whose SNI / ALPN constraints satisfy the supplied values. If no
// explicit rule matches, the first `IsDefault` rule is returned. Returns
// nil only when neither an explicit match nor a default rule exists.
//
// Matching semantics:
//   - empty Rule.SNI   matches any serverName
//   - empty Rule.ALPN  matches any alpn
//   - non-empty Rule.SNI must equal serverName (case-insensitive)
//   - non-empty Rule.ALPN must contain alpn (exact, case-sensitive — ALPN
//     identifiers are wire constants, e.g. "h2", "http/1.1")
func Match(rules []Rule, serverName, alpn string) *Rule {
	var def *Rule
	for i := range rules {
		r := &rules[i]
		if r.IsDefault && def == nil {
			def = r
			continue
		}
		if r.SNI != "" && !strings.EqualFold(r.SNI, serverName) {
			continue
		}
		if len(r.ALPN) > 0 && !containsString(r.ALPN, alpn) {
			continue
		}
		return r
	}
	return def
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// Aware is the optional interface a `net.Conn` may implement to publish
// the fallback rule chosen for it during the TLS handshake. Connections
// that do not implement it fall back to the legacy redirector behaviour.
//
// The accessor returns nil when no rule was matched (e.g. the TLS layer
// was bypassed, or the rule list is empty).
type Aware interface {
	FallbackRule() *Rule
}

// Unwrap walks a chain of net.Conn wrappers looking for the first that
// implements `Aware` and returns its rule. Wrappers that expose a
// `NetConn() net.Conn` accessor (the convention used by `crypto/tls.Conn`
// and `common.RewindConn`) are descended into; everything else stops the
// walk. Returns nil if no Aware conn is found.
//
// This is the helper P1-1c will route every fallback dispatch through so
// the trojan-layer invalid-auth path uses the same matched rule as the
// TLS-layer probe path without coupling the trojan layer to TLS.
func Unwrap(c net.Conn) *Rule {
	for i := 0; c != nil && i < 8; i++ {
		if a, ok := c.(Aware); ok {
			if r := a.FallbackRule(); r != nil {
				return r
			}
		}
		type netConner interface{ NetConn() net.Conn }
		if nc, ok := c.(netConner); ok {
			c = nc.NetConn()
			continue
		}
		return nil
	}
	return nil
}
