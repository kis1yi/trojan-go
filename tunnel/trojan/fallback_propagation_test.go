package trojan

import (
	"net"
	"testing"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/fallback"
	"github.com/kis1yi/trojan-go/tunnel/transport"
)

// awareNetConn implements fallback.Aware so we can stand in for a TLS
// ruleConn in a unit test that exercises only the wrapper-walking
// contract — no real TLS handshake required.
type awareNetConn struct {
	net.Conn
	rule *fallback.Rule
}

func (a *awareNetConn) FallbackRule() *fallback.Rule { return a.rule }
func (a *awareNetConn) NetConn() net.Conn            { return a.Conn }

// pipeConn returns a closed half of a pipe — we only need a non-nil
// net.Conn the wrappers can embed; no IO happens in this test.
func pipeConn(t *testing.T) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a
}

// TestFallbackUnwrapDescendsTrojanWrappers proves that the chain the
// trojan invalid-auth path actually has on the wire — RewindConn over
// transport.Conn over a TLS-side ruleConn — is fully transparent to
// fallback.Unwrap. P1-1c regression: any future wrapper inserted between
// trojan and TLS must keep this test green.
func TestFallbackUnwrapDescendsTrojanWrappers(t *testing.T) {
	rule := &fallback.Rule{Addr: "127.0.0.1", Port: 8443}
	tls := &awareNetConn{Conn: pipeConn(t), rule: rule}
	tr := &transport.Conn{Conn: tls}
	rew := common.NewRewindConn(tr)

	got := fallback.Unwrap(rew)
	if got != rule {
		t.Fatalf("Unwrap did not recover the TLS-attached rule: got %#v want %#v", got, rule)
	}
}

// TestFallbackUnwrapReturnsNilWithoutAware proves the legacy path: when
// no wrapper in the chain implements fallback.Aware, Unwrap returns nil
// and the trojan layer falls through to s.redirAddr.
func TestFallbackUnwrapReturnsNilWithoutAware(t *testing.T) {
	tr := &transport.Conn{Conn: pipeConn(t)}
	rew := common.NewRewindConn(tr)
	if got := fallback.Unwrap(rew); got != nil {
		t.Fatalf("Unwrap should be nil when no rule is attached, got %#v", got)
	}
}
