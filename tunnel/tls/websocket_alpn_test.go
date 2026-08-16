package tls

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/tunnel"
	"github.com/kis1yi/trojan-go/tunnel/transport"
)

type singleConnClient struct {
	conn tunnel.Conn
}

func (c *singleConnClient) DialConn(*tunnel.Address, tunnel.Tunnel) (tunnel.Conn, error) {
	return c.conn, nil
}

func (c *singleConnClient) DialPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

func (c *singleConnClient) Close() error {
	return c.conn.Close()
}

func TestForceWebsocketALPNPreservesFingerprint(t *testing.T) {
	fingerprints := []string{
		"chrome",
		"firefox",
		"ios",
		"edge",
		"safari",
		"360browser",
		"qqbrowser",
	}

	for _, fingerprint := range fingerprints {
		t.Run(fingerprint, func(t *testing.T) {
			id, err := resolveFingerprint(fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()

			conn := utls.UClient(clientSide, &utls.Config{ServerName: "example.com"}, id)
			if err := forceWebsocketALPN(conn); err != nil {
				t.Fatal(err)
			}
			if conn.ClientHelloID != id {
				t.Fatalf("fingerprint changed: got %v, want %v", conn.ClientHelloID, id)
			}
			if got := conn.HandshakeState.Hello.AlpnProtocols; len(got) != 1 || got[0] != websocketALPN {
				t.Fatalf("ALPN = %v, want [%q]", got, websocketALPN)
			}
		})
	}
}

func TestWebsocketNegotiatesHTTP1(t *testing.T) {
	cases := []struct {
		name      string
		websocket bool
		ech       bool
		wantALPN  string
	}{
		{name: "websocket", websocket: true, wantALPN: "http/1.1"},
		{name: "websocket with grease ech", websocket: true, ech: true, wantALPN: "http/1.1"},
		{name: "non-websocket", wantALPN: "h2"},
	}

	certificate, err := stdtls.X509KeyPair([]byte(rsa2048Cert), []byte(rsa2048Key))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			type handshakeResult struct {
				alpn string
				err  error
			}
			result := make(chan handshakeResult, 1)
			go func() {
				serverSide, err := listener.Accept()
				if err != nil {
					result <- handshakeResult{err: err}
					return
				}
				defer serverSide.Close()
				if err := serverSide.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					result <- handshakeResult{err: err}
					return
				}
				server := stdtls.Server(serverSide, &stdtls.Config{
					Certificates: []stdtls.Certificate{certificate},
					NextProtos:   []string{"h2", "http/1.1"},
				})
				err = server.Handshake()
				result <- handshakeResult{alpn: server.ConnectionState().NegotiatedProtocol, err: err}
			}()

			clientSide, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer clientSide.Close()
			if err := clientSide.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}

			ctx := config.WithConfig(context.Background(), Name, &Config{
				RemoteHost: "example.com",
				RemotePort: 443,
				TLS: TLSConfig{
					Verify:      false,
					SNI:         "example.com",
					Fingerprint: "chrome",
					ECH:         tc.ech,
				},
				Websocket: WebsocketConfig{Enabled: tc.websocket},
			})
			underlay := &singleConnClient{conn: &transport.Conn{Conn: clientSide}}
			client, err := NewClient(ctx, underlay)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := client.DialConn(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			serverResult := <-result
			if serverResult.err != nil {
				t.Fatal(serverResult.err)
			}
			if serverResult.alpn != tc.wantALPN {
				t.Fatalf("negotiated ALPN = %q, want %q", serverResult.alpn, tc.wantALPN)
			}
		})
	}
}
