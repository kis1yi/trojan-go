package fallback

// RuleConfig is the YAML/JSON form of a single fallback entry. It mirrors
// `Rule` field for field, with the addition of the `Default` boolean key
// (the in-memory `Rule.IsDefault` is named differently so the YAML key
// reads naturally — `default: true`).
//
// The schema lives next to the type so config/* and tunnel/tls can share
// it without import cycles.
type RuleConfig struct {
	SNI           string   `json:"sni" yaml:"sni"`
	ALPN          []string `json:"alpn" yaml:"alpn"`
	Addr          string   `json:"addr" yaml:"addr"`
	Port          int      `json:"port" yaml:"port"`
	ProxyProtocol int      `json:"proxy_protocol" yaml:"proxy-protocol"`
	Default       bool     `json:"default" yaml:"default"`
}

// RulesFromConfig validates the YAML-supplied list and converts it to the
// in-memory `Rule` slice used by Match. Invalid entries (missing addr,
// out-of-range port, unknown proxy-protocol version) are silently dropped
// — the caller is expected to log a Warn at parse time when len(in) !=
// len(out). Validation is intentionally permissive: an empty list is a
// valid configuration that disables structured fallback entirely.
func RulesFromConfig(in []RuleConfig) []Rule {
	if len(in) == 0 {
		return nil
	}
	out := make([]Rule, 0, len(in))
	for _, c := range in {
		if c.Addr == "" || c.Port <= 0 || c.Port > 65535 {
			continue
		}
		if c.ProxyProtocol < 0 || c.ProxyProtocol > 2 {
			continue
		}
		out = append(out, Rule{
			SNI:           c.SNI,
			ALPN:          append([]string(nil), c.ALPN...),
			Addr:          c.Addr,
			Port:          c.Port,
			ProxyProtocol: ProxyProtocolVersion(c.ProxyProtocol),
			IsDefault:     c.Default,
		})
	}
	return out
}

// RulesFromLegacy synthesises a single default rule from the legacy
// `fallback_addr`/`fallback_port` pair. Returns nil when port is unset.
// This preserves backwards compatibility for every config in the wild
// that has not migrated to the new `fallback:` list.
func RulesFromLegacy(addr string, port int) []Rule {
	if port <= 0 || port > 65535 {
		return nil
	}
	return []Rule{{
		Addr:      addr,
		Port:      port,
		IsDefault: true,
	}}
}

// MergeRules combines the structured `fallback:` list with the legacy
// pair. Structured rules win — if the new schema is populated the legacy
// fields are ignored entirely. This matches the migration contract in the
// 2026 hardening plan: operators opting into the new schema do not have
// to clear the old fields.
func MergeRules(structured []Rule, legacyAddr string, legacyPort int) []Rule {
	if len(structured) > 0 {
		return structured
	}
	return RulesFromLegacy(legacyAddr, legacyPort)
}
