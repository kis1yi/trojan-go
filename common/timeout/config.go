// Package timeout provides a unified deadline/idle-timeout configuration
// surface used across the proxy, tunnel and redirector packages. See the
// 2026 hardening plan (P0-1) for the rationale.
//
// All values in TimeoutConfig are expressed in seconds. A zero value selects
// the documented default; -1 disables the corresponding timeout.
package timeout

import (
	"context"
	"time"

	"github.com/kis1yi/trojan-go/config"
)

const Name = "TIMEOUT"

// Default values used when a field is left at its zero value.
const (
	DefaultTLSHandshake   = 10 * time.Second
	DefaultTrojanAuth     = 4 * time.Second
	DefaultTCPRelayIdle   = 5 * time.Minute
	DefaultUDPSessionIdle = 60 * time.Second
	DefaultFallbackDial   = 5 * time.Second
	DefaultFallbackIdle   = 30 * time.Second
)

// Config holds the deadline values for a single proxy instance. The struct is
// embedded under the TIMEOUT_CONFIG key in the per-instance context.
type Config struct {
	Timeout TimeoutConfig `json:"timeout" yaml:"timeout"`
}

// TimeoutConfig holds raw values in seconds. Use the Resolve* helpers to
// translate them into time.Duration with default/disabled handling.
type TimeoutConfig struct {
	TLSHandshake   int `json:"tls_handshake" yaml:"tls-handshake"`
	TrojanAuth     int `json:"trojan_auth" yaml:"trojan-auth"`
	TCPRelayIdle   int `json:"tcp_relay_idle" yaml:"tcp-relay-idle"`
	UDPSessionIdle int `json:"udp_session_idle" yaml:"udp-session-idle"`
	FallbackDial   int `json:"fallback_dial" yaml:"fallback-dial"`
	FallbackIdle   int `json:"fallback_idle" yaml:"fallback-idle"`
}

// resolve converts a raw int (seconds) into a duration applying the default
// rules: zero means the supplied default, -1 disables the timeout (returns 0
// which the callers must interpret as "no deadline").
func resolve(raw int, def time.Duration) time.Duration {
	switch {
	case raw == 0:
		return def
	case raw < 0:
		return 0
	default:
		return time.Duration(raw) * time.Second
	}
}

func (c TimeoutConfig) ResolveTLSHandshake() time.Duration {
	return resolve(c.TLSHandshake, DefaultTLSHandshake)
}

func (c TimeoutConfig) ResolveTrojanAuth() time.Duration {
	return resolve(c.TrojanAuth, DefaultTrojanAuth)
}

func (c TimeoutConfig) ResolveTCPRelayIdle() time.Duration {
	return resolve(c.TCPRelayIdle, DefaultTCPRelayIdle)
}

func (c TimeoutConfig) ResolveUDPSessionIdle() time.Duration {
	return resolve(c.UDPSessionIdle, DefaultUDPSessionIdle)
}

func (c TimeoutConfig) ResolveFallbackDial() time.Duration {
	return resolve(c.FallbackDial, DefaultFallbackDial)
}

func (c TimeoutConfig) ResolveFallbackIdle() time.Duration {
	return resolve(c.FallbackIdle, DefaultFallbackIdle)
}

// FromContext returns the TimeoutConfig stored in ctx, or a zero value (which
// resolves entirely to defaults) when no config has been registered. This
// allows packages that may run outside a configured proxy instance (tests,
// embedded uses) to call Resolve* helpers safely.
func FromContext(ctx context.Context) TimeoutConfig {
	if v := config.FromContext(ctx, Name); v != nil {
		if cfg, ok := v.(*Config); ok && cfg != nil {
			return cfg.Timeout
		}
	}
	return TimeoutConfig{}
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return new(Config)
	})
}
