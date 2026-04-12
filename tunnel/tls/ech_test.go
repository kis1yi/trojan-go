package tls

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/p4gefau1t/trojan-go/config"
)

func makeECHCtx(ech bool, echConfig string, sni string) context.Context {
	return config.WithConfig(context.Background(), Name, &Config{
		RemoteHost: "example.com",
		RemotePort: 443,
		TLS: TLSConfig{
			SNI:    sni,
			Verify: true,
			ECH:    ech,
			ECHConfig: echConfig,
		},
	})
}

func TestECHDisabled(t *testing.T) {
	ctx := makeECHCtx(false, "", "example.com")
	client, err := NewClient(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if client.echEnabled {
		t.Error("expected echEnabled=false when ECH is disabled")
	}
	if client.echConfigRaw != nil {
		t.Error("expected echConfigRaw=nil when ECH is disabled")
	}
}

func TestGREASEECHMode(t *testing.T) {
	ctx := makeECHCtx(true, "", "example.com")
	client, err := NewClient(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !client.echEnabled {
		t.Error("expected echEnabled=true for GREASE ECH mode")
	}
	if client.echConfigRaw != nil {
		t.Error("expected echConfigRaw=nil for GREASE ECH mode (no config provided)")
	}
}

func TestFullECHMode(t *testing.T) {
	raw := []byte("test-ech-config-data")
	encoded := base64.StdEncoding.EncodeToString(raw)
	ctx := makeECHCtx(true, encoded, "example.com")
	client, err := NewClient(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !client.echEnabled {
		t.Error("expected echEnabled=true for full ECH mode")
	}
	if string(client.echConfigRaw) != string(raw) {
		t.Errorf("echConfigRaw mismatch: got %q, want %q", client.echConfigRaw, raw)
	}
}

func TestInvalidBase64ECHConfig(t *testing.T) {
	ctx := makeECHCtx(true, "!!!invalid-base64!!!", "example.com")
	_, err := NewClient(ctx, nil)
	if err == nil {
		t.Error("expected error for invalid base64 ech_config")
	}
}

func TestECHDisabledWithConfigPresent(t *testing.T) {
	ctx := makeECHCtx(false, "somevalue", "example.com")
	client, err := NewClient(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if client.echEnabled {
		t.Error("expected echEnabled=false when ECH is disabled even if ech_config is set")
	}
}
