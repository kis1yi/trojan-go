package timeout

import (
	"context"
	"testing"
	"time"

	"github.com/kis1yi/trojan-go/config"
)

func TestResolveDefaults(t *testing.T) {
	c := TimeoutConfig{}
	if got, want := c.ResolveTLSHandshake(), DefaultTLSHandshake; got != want {
		t.Errorf("TLSHandshake default: got %v, want %v", got, want)
	}
	if got, want := c.ResolveTrojanAuth(), DefaultTrojanAuth; got != want {
		t.Errorf("TrojanAuth default: got %v, want %v", got, want)
	}
	if got, want := c.ResolveTCPRelayIdle(), DefaultTCPRelayIdle; got != want {
		t.Errorf("TCPRelayIdle default: got %v, want %v", got, want)
	}
	if got, want := c.ResolveUDPSessionIdle(), DefaultUDPSessionIdle; got != want {
		t.Errorf("UDPSessionIdle default: got %v, want %v", got, want)
	}
	if got, want := c.ResolveFallbackDial(), DefaultFallbackDial; got != want {
		t.Errorf("FallbackDial default: got %v, want %v", got, want)
	}
	if got, want := c.ResolveFallbackIdle(), DefaultFallbackIdle; got != want {
		t.Errorf("FallbackIdle default: got %v, want %v", got, want)
	}
}

func TestResolveExplicitAndDisabled(t *testing.T) {
	c := TimeoutConfig{
		TLSHandshake: 7,
		TrojanAuth:   -1,
	}
	if got, want := c.ResolveTLSHandshake(), 7*time.Second; got != want {
		t.Errorf("explicit TLSHandshake: got %v, want %v", got, want)
	}
	if got := c.ResolveTrojanAuth(); got != 0 {
		t.Errorf("disabled TrojanAuth must resolve to 0, got %v", got)
	}
}

func TestFromContextEmpty(t *testing.T) {
	c := FromContext(context.Background())
	if got := c.ResolveTLSHandshake(); got != DefaultTLSHandshake {
		t.Errorf("FromContext default: got %v, want %v", got, DefaultTLSHandshake)
	}
}

func TestFromContextWithConfig(t *testing.T) {
	cfg := &Config{Timeout: TimeoutConfig{TLSHandshake: 3}}
	ctx := config.WithConfig(context.Background(), Name, cfg)
	c := FromContext(ctx)
	if got, want := c.ResolveTLSHandshake(), 3*time.Second; got != want {
		t.Errorf("FromContext explicit: got %v, want %v", got, want)
	}
}
