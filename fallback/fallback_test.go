package fallback

import (
	"net"
	"testing"
)

func TestMatchPrefersExplicitOverDefault(t *testing.T) {
	rules := []Rule{
		{IsDefault: true, Addr: "127.0.0.1", Port: 80},
		{SNI: "site.example", Addr: "127.0.0.1", Port: 8443},
	}
	if got := Match(rules, "site.example", "h2"); got == nil || got.Port != 8443 {
		t.Fatalf("explicit SNI rule not preferred: got %#v", got)
	}
	if got := Match(rules, "other.example", "h2"); got == nil || !got.IsDefault {
		t.Fatalf("unmatched SNI did not fall through to default: got %#v", got)
	}
}

func TestMatchALPNFilter(t *testing.T) {
	rules := []Rule{
		{SNI: "site.example", ALPN: []string{"h2"}, Addr: "a", Port: 1},
		{SNI: "site.example", ALPN: []string{"http/1.1"}, Addr: "b", Port: 2},
	}
	if got := Match(rules, "site.example", "h2"); got == nil || got.Port != 1 {
		t.Fatalf("h2 routed wrong: %#v", got)
	}
	if got := Match(rules, "site.example", "http/1.1"); got == nil || got.Port != 2 {
		t.Fatalf("http/1.1 routed wrong: %#v", got)
	}
	if got := Match(rules, "site.example", "h3"); got != nil {
		t.Fatalf("h3 should not match either rule (no default present): %#v", got)
	}
}

func TestMatchSNIIsCaseInsensitive(t *testing.T) {
	rules := []Rule{{SNI: "Site.Example", Addr: "x", Port: 1}}
	if got := Match(rules, "site.example", ""); got == nil {
		t.Fatal("SNI match must be case-insensitive")
	}
}

func TestRulesFromLegacyTranslation(t *testing.T) {
	r := RulesFromLegacy("127.0.0.1", 80)
	if len(r) != 1 || !r[0].IsDefault || r[0].Addr != "127.0.0.1" || r[0].Port != 80 {
		t.Fatalf("legacy translation wrong: %#v", r)
	}
	if got := RulesFromLegacy("", 0); got != nil {
		t.Fatalf("zero legacy port must yield nil, got %#v", got)
	}
}

func TestRulesFromConfigDropsInvalid(t *testing.T) {
	in := []RuleConfig{
		{Addr: "ok", Port: 80},
		{Addr: "", Port: 80},                     // missing addr
		{Addr: "ok", Port: 0},                    // bad port
		{Addr: "ok", Port: 70000},                // out of range
		{Addr: "ok", Port: 80, ProxyProtocol: 3}, // bad pp version
		{Default: true, Addr: "fallback", Port: 8080},
	}
	out := RulesFromConfig(in)
	if len(out) != 2 {
		t.Fatalf("validation dropped wrong count: got %d kept of %d, %#v", len(out), len(in), out)
	}
}

func TestMergeRulesPrefersStructured(t *testing.T) {
	struc := []Rule{{Addr: "new", Port: 1, IsDefault: true}}
	got := MergeRules(struc, "legacy", 80)
	if len(got) != 1 || got[0].Addr != "new" {
		t.Fatalf("structured rules must win: %#v", got)
	}
	got = MergeRules(nil, "legacy", 80)
	if len(got) != 1 || got[0].Addr != "legacy" {
		t.Fatalf("nil structured must yield legacy translation: %#v", got)
	}
}

// awareConn implements Aware and embeds a net.Conn for the unwrap walk.
type awareConn struct {
	net.Conn
	rule *Rule
}

func (a *awareConn) FallbackRule() *Rule { return a.rule }

// netConner exposes a NetConn() to test the unwrap descent.
type wrapConn struct {
	net.Conn
	inner net.Conn
}

func (w *wrapConn) NetConn() net.Conn { return w.inner }

func TestUnwrapFindsDeepRule(t *testing.T) {
	r := &Rule{Addr: "x", Port: 1}
	a := &awareConn{rule: r}
	w := &wrapConn{inner: a}
	if got := Unwrap(w); got != r {
		t.Fatalf("Unwrap did not descend through NetConn: got %#v", got)
	}
	if got := Unwrap(nil); got != nil {
		t.Fatalf("Unwrap(nil) must be nil")
	}
}
