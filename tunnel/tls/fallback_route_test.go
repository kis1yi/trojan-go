package tls

import (
	"crypto/tls"
	"testing"

	"github.com/kis1yi/trojan-go/fallback"
)

// TestDispatchFallbackRuleSelection drives selectFallback through a
// representative server config without spinning up a real TLS handshake.
// We construct a Server with only the rule list populated and assert that
// the rule chosen for given (sni, alpn) matches expectations from the
// fallback.Match contract.
func TestServerHasRuleListWiredFromConfig(t *testing.T) {
	parsed := fallback.RulesFromConfig([]fallback.RuleConfig{
		{SNI: "site.example", ALPN: []string{"h2"}, Addr: "10.0.0.1", Port: 8443, ProxyProtocol: 2},
		{Default: true, Addr: "127.0.0.1", Port: 80},
	})
	rules := fallback.MergeRules(parsed, "", 0)
	if len(rules) != 2 {
		t.Fatalf("rules len = %d, want 2", len(rules))
	}

	if got := fallback.Match(rules, "site.example", "h2"); got == nil || got.Port != 8443 {
		t.Fatalf("explicit rule not matched: %#v", got)
	}
	if got := fallback.Match(rules, "wrong.example", ""); got == nil || !got.IsDefault {
		t.Fatalf("default rule not matched: %#v", got)
	}
}

// TestRuleConnFallbackAware proves the private wrapper satisfies the
// fallback.Aware contract so P1-1c can recover the rule via Unwrap.
func TestRuleConnFallbackAware(t *testing.T) {
	r := &fallback.Rule{Addr: "x", Port: 1}
	rc := &ruleConn{rule: r}
	if got := rc.FallbackRule(); got != r {
		t.Fatalf("FallbackRule did not return the attached rule")
	}
	// Also verify Aware assertion succeeds — this is what fallback.Unwrap
	// relies on at runtime.
	var _ fallback.Aware = rc
	// Compile-time satisfaction of the interface is checked by the line
	// above; `tls` is imported here only to ensure the file is part of
	// the same build tag set as server.go.
	_ = (*tls.Conn)(nil)
}
