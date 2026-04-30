package tls

import (
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/fallback"
)

type Config struct {
	RemoteHost string          `json:"remote_addr" yaml:"remote-addr"`
	RemotePort int             `json:"remote_port" yaml:"remote-port"`
	TLS        TLSConfig       `json:"ssl" yaml:"ssl"`
	Websocket  WebsocketConfig `json:"websocket" yaml:"websocket"`
}

type WebsocketConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

type TLSConfig struct {
	Verify               bool     `json:"verify" yaml:"verify"`
	VerifyHostName       bool     `json:"verify_hostname" yaml:"verify-hostname"`
	CertPath             string   `json:"cert" yaml:"cert"`
	KeyPath              string   `json:"key" yaml:"key"`
	KeyPassword          string   `json:"key_password" yaml:"key-password"`
	Cipher               string   `json:"cipher" yaml:"cipher"`
	PreferServerCipher   bool     `json:"prefer_server_cipher" yaml:"prefer-server-cipher"`
	SNI                  string   `json:"sni" yaml:"sni"`
	HTTPResponseFileName string   `json:"plain_http_response" yaml:"plain-http-response"`
	FallbackHost         string   `json:"fallback_addr" yaml:"fallback-addr"`
	FallbackPort         int      `json:"fallback_port" yaml:"fallback-port"`
	// Fallback is the P1-1 structured replacement for the legacy
	// FallbackHost/FallbackPort pair. When non-empty it takes precedence;
	// the legacy fields remain supported for backwards compatibility and
	// are auto-translated to a single default rule (see
	// fallback.MergeRules). At P1-1a this field is parsed and validated
	// but not yet consulted by the runtime fallback path — the routing
	// wire-up lands in P1-1b/c/d.
	Fallback []fallback.RuleConfig `json:"fallback" yaml:"fallback"`
	ReuseSession         bool     `json:"reuse_session" yaml:"reuse-session"`
	ALPN                 []string `json:"alpn" yaml:"alpn"`
	Curves               string   `json:"curves" yaml:"curves"`
	Fingerprint          string   `json:"fingerprint" yaml:"fingerprint"`
	KeyLogPath           string   `json:"key_log" yaml:"key-log"`
	CertCheckRate        int      `json:"cert_check_rate" yaml:"cert-check-rate"`
	ECH                  bool     `json:"ech" yaml:"ech"`
	ECHConfig            string   `json:"ech_config" yaml:"ech-config"`
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return &Config{
			TLS: TLSConfig{
				Verify:         true,
				VerifyHostName: true,
				Fingerprint:    "",
				ALPN:           []string{"http/1.1"},
			},
		}
	})
}
