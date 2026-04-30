package tls

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/common/timeout"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/tunnel/freedom"
	"github.com/kis1yi/trojan-go/tunnel/transport"
)

// TestTLSHandshakeTimeout exercises P0-1: a client that opens the TCP
// connection but never sends a TLS ClientHello must be closed within
// roughly tls_handshake seconds, not held forever.
func TestTLSHandshakeTimeout(t *testing.T) {
	_ = os.WriteFile("server-rsa2048.crt", []byte(rsa2048Cert), 0o777)
	_ = os.WriteFile("server-rsa2048.key", []byte(rsa2048Key), 0o777)

	serverCfg := &Config{
		TLS: TLSConfig{
			VerifyHostName: true,
			CertCheckRate:  1,
			KeyPath:        "server-rsa2048.key",
			CertPath:       "server-rsa2048.crt",
		},
	}
	port := common.PickPort("tcp", "127.0.0.1")
	transportConfig := &transport.Config{
		LocalHost:  "127.0.0.1",
		LocalPort:  port,
		RemoteHost: "127.0.0.1",
		RemotePort: port,
	}
	timeoutCfg := &timeout.Config{Timeout: timeout.TimeoutConfig{TLSHandshake: 1}}

	ctx := config.WithConfig(context.Background(), Name, serverCfg)
	ctx = config.WithConfig(ctx, transport.Name, transportConfig)
	ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})
	ctx = config.WithConfig(ctx, timeout.Name, timeoutCfg)

	tcpServer, err := transport.NewServer(ctx, nil)
	common.Must(err)
	s, err := NewServer(ctx, tcpServer)
	common.Must(err)
	defer s.Close()

	// Open a raw TCP connection and never send any bytes. The server-side
	// handshake must time out and close the connection well before we'd
	// otherwise block forever on Read.
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	start := time.Now()
	buf := [1]byte{}
	_, err = conn.Read(buf[:])
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("Read returned nil error after %s; expected EOF/connection close", elapsed)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("server took %s to close idle TLS handshake (limit ~tls_handshake+slack)", elapsed)
	}
}
