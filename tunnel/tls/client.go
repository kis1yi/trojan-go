package tls

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"os"
	"strings"

	tls "github.com/refraction-networking/utls"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/tls/fingerprint"
	"github.com/p4gefau1t/trojan-go/tunnel/transport"
)

// Client is a tls client
type Client struct {
	verify        bool
	sni           string
	ca            *x509.CertPool
	cipher        []uint16
	sessionTicket bool
	reuseSession  bool
	fingerprint   string
	helloID       tls.ClientHelloID
	keyLogger     io.WriteCloser
	underlay      tunnel.Client
	echEnabled    bool
	echConfigRaw  []byte
}

func (c *Client) Close() error {
	if c.keyLogger != nil {
		c.keyLogger.Close()
	}
	return c.underlay.Close()
}

func (c *Client) DialPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

func (c *Client) DialConn(_ *tunnel.Address, overlay tunnel.Tunnel) (tunnel.Conn, error) {
	conn, err := c.underlay.DialConn(nil, &Tunnel{})
	if err != nil {
		return nil, common.NewError("tls failed to dial conn").Base(err)
	}

	tlsConfig := &tls.Config{
		RootCAs:            c.ca,
		ServerName:         c.sni,
		InsecureSkipVerify: !c.verify,
		KeyLogWriter:       c.keyLogger,
	}

	var tlsConn *tls.UConn
	if c.echEnabled && c.echConfigRaw != nil {
		// Full ECH mode: pass ECH config list to the TLS config
		tlsConfig.EncryptedClientHelloConfigList = c.echConfigRaw
		tlsConn = tls.UClient(conn, tlsConfig, c.helloID)
	} else if c.echEnabled {
		// GREASE ECH mode: inject GREASEEncryptedClientHelloExtension if not already present
		spec, err := tls.UTLSIdToSpec(c.helloID)
		if err != nil {
			return nil, common.NewError("failed to get TLS fingerprint spec for GREASE ECH").Base(err)
		}
		hasGREASE := false
		for _, ext := range spec.Extensions {
			if _, ok := ext.(*tls.GREASEEncryptedClientHelloExtension); ok {
				hasGREASE = true
				break
			}
		}
		if !hasGREASE {
			spec.Extensions = append(spec.Extensions, &tls.GREASEEncryptedClientHelloExtension{})
		}
		tlsConn = tls.UClient(conn, tlsConfig, tls.HelloCustom)
		if err := tlsConn.ApplyPreset(&spec); err != nil {
			return nil, common.NewError("tls failed to apply GREASE ECH preset").Base(err)
		}
	} else {
		tlsConn = tls.UClient(conn, tlsConfig, c.helloID)
	}

	if err := tlsConn.Handshake(); err != nil {
		return nil, common.NewError("tls failed to handshake with remote server").Base(err)
	}
	return &transport.Conn{
		Conn: tlsConn,
	}, nil
}

// NewClient creates a tls client
func NewClient(ctx context.Context, underlay tunnel.Client) (*Client, error) {
	cfg := config.FromContext(ctx, Name).(*Config)

	helloID := tls.ClientHelloID{}
	// keep the parameter name consistent with upstream
	// https://github.com/refraction-networking/utls/blob/35e5b05fc4b6f8c4351d755f2570bc293f30aaf6/u_common.go#L114-L132
	if cfg.TLS.Fingerprint != "" {
		switch strings.ToLower(cfg.TLS.Fingerprint) {
		case "chrome":
			helloID = tls.HelloChrome_Auto
		case "ios":
			helloID = tls.HelloIOS_Auto
		case "firefox":
			helloID = tls.HelloFirefox_Auto
		case "edge":
			helloID = tls.HelloEdge_Auto
		case "safari":
			helloID = tls.HelloSafari_Auto
		case "360browser":
			helloID = tls.Hello360_Auto
		case "qqbrowser":
			helloID = tls.HelloQQ_Auto
		default:
			return nil, common.NewError("Invalid 'fingerprint' value in configuration: '" + cfg.TLS.Fingerprint + "'. Possible values are 'chrome' (default), 'ios', 'firefox', 'edge', 'safari', '360browser', or 'qqbrowser'.")
		}
		log.Info("Your trojan's TLS fingerprint will look like", cfg.TLS.Fingerprint)
	} else {
		helloID = tls.HelloChrome_Auto
		log.Info("No 'fingerprint' value specified in your configuration. Your trojan's TLS fingerprint will look like Chrome by default.")
	}

	if cfg.TLS.SNI == "" {
		cfg.TLS.SNI = cfg.RemoteHost
		log.Warn("tls sni is unspecified")
	}

	var echEnabled bool
	var echConfigRaw []byte
	if cfg.TLS.ECH {
		if cfg.TLS.ECHConfig == "" {
			// GREASE ECH mode
			echEnabled = true
		} else {
			// Full ECH mode — decode base64-encoded ECH config
			decoded, err := base64.StdEncoding.DecodeString(cfg.TLS.ECHConfig)
			if err != nil || len(decoded) == 0 {
				return nil, common.NewError("invalid ech_config base64").Base(err)
			}
			echEnabled = true
			echConfigRaw = decoded
		}
	} else if cfg.TLS.ECHConfig != "" {
		log.Warn("ech_config is specified but ech is disabled, ignoring")
	}

	client := &Client{
		underlay:      underlay,
		verify:        cfg.TLS.Verify,
		sni:           cfg.TLS.SNI,
		cipher:        fingerprint.ParseCipher(strings.Split(cfg.TLS.Cipher, ":")),
		sessionTicket: cfg.TLS.ReuseSession,
		fingerprint:   cfg.TLS.Fingerprint,
		helloID:       helloID,
		echEnabled:    echEnabled,
		echConfigRaw:  echConfigRaw,
	}

	if cfg.TLS.CertPath != "" {
		caCertByte, err := os.ReadFile(cfg.TLS.CertPath)
		if err != nil {
			return nil, common.NewError("failed to load cert file").Base(err)
		}
		client.ca = x509.NewCertPool()
		ok := client.ca.AppendCertsFromPEM(caCertByte)
		if !ok {
			log.Warn("invalid cert list")
		}
		log.Info("using custom cert")

		// print cert info
		pemCerts := caCertByte
		for len(pemCerts) > 0 {
			var block *pem.Block
			block, pemCerts = pem.Decode(pemCerts)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			log.Trace("issuer:", cert.Issuer, "subject:", cert.Subject)
		}
	}

	if cfg.TLS.CertPath == "" {
		log.Info("cert is unspecified, using default ca list")
	}

	log.Debug("tls client created")
	return client, nil
}
