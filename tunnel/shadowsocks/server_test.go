package shadowsocks

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/tunnel"
)

type handshakeTestConn struct {
	net.Conn
}

func (c *handshakeTestConn) Metadata() *tunnel.Metadata { return nil }

type handshakeTestServer struct {
	conns  chan tunnel.Conn
	closed chan struct{}
	once   sync.Once
}

func (s *handshakeTestServer) AcceptConn(tunnel.Tunnel) (tunnel.Conn, error) {
	select {
	case conn := <-s.conns:
		return conn, nil
	case <-s.closed:
		return nil, common.NewError("test underlay closed")
	}
}

func (s *handshakeTestServer) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	return nil, common.NewError("not supported")
}

func (s *handshakeTestServer) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

func newHandshakeTestServer(t *testing.T) (*Server, *handshakeTestServer) {
	t.Helper()
	// The client and server share the dependency's global salt filter in tests.
	t.Setenv("SHADOWSOCKS_SF_CAPACITY", "-1")
	ctx := config.WithConfig(context.Background(), Name, &Config{
		RemoteHost: "127.0.0.1",
		RemotePort: 1,
		Shadowsocks: ShadowsocksConfig{
			Method:   "AES-128-GCM",
			Password: "test-handshake-password",
		},
	})
	underlay := &handshakeTestServer{
		conns:  make(chan tunnel.Conn, 4),
		closed: make(chan struct{}),
	}
	server, err := NewServer(ctx, underlay)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, underlay
}

func offerHandshakeTestConn(t *testing.T, underlay *handshakeTestServer) net.Conn {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	t.Cleanup(func() { _ = serverConn.Close() })
	underlay.conns <- &handshakeTestConn{Conn: serverConn}
	if err := clientConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return clientConn
}

func TestServerSaltOnlyConnectionDoesNotBlockAccept(t *testing.T) {
	server, underlay := newHandshakeTestServer(t)
	type result struct {
		conn tunnel.Conn
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, err := server.AcceptConn(nil)
		accepted <- result{conn: conn, err: err}
	}()

	idle := offerHandshakeTestConn(t, underlay)
	if _, err := idle.Write(bytes.Repeat([]byte{1}, 16)); err != nil {
		t.Fatal("failed to send the salt:", err)
	}
	// Keep the first peer open without supplying an encrypted length or payload.
	peer := offerHandshakeTestConn(t, underlay)
	cipher, err := core.PickCipher("AES-128-GCM", nil, "test-handshake-password")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("a later connection must finish its handshake independently")
	written := make(chan error, 1)
	go func() {
		_, err := cipher.StreamConn(peer).Write(payload)
		written <- err
	}()

	select {
	case got := <-accepted:
		if got.err != nil {
			t.Fatal(got.err)
		}
		defer got.conn.Close()
		if err := got.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(got.conn, buf); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf, payload) {
			t.Fatalf("decrypted payload = %q, want %q", buf, payload)
		}
	case <-time.After(time.Second):
		t.Fatal("a salt-only connection blocked a later valid connection")
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestServerCloseInterruptsPendingHandshake(t *testing.T) {
	server, underlay := newHandshakeTestServer(t)
	accepted := make(chan error, 1)
	go func() {
		conn, err := server.AcceptConn(nil)
		if conn != nil {
			_ = conn.Close()
		}
		accepted <- err
	}()
	peer := offerHandshakeTestConn(t, underlay)
	if _, err := peer.Write(bytes.Repeat([]byte{2}, 16)); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt the pending handshake")
	}
	select {
	case err := <-accepted:
		if err == nil {
			t.Fatal("AcceptConn succeeded after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("AcceptConn remained blocked after Close")
	}
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("peer read error = %v, want EOF", err)
	}
}

func TestServerCloseClosesUnacceptedConnection(t *testing.T) {
	server, underlay := newHandshakeTestServer(t)
	peer := offerHandshakeTestConn(t, underlay)
	cipher, err := core.PickCipher("AES-128-GCM", nil, "test-handshake-password")
	if err != nil {
		t.Fatal(err)
	}
	// Finish validation without an AcceptConn consumer taking ownership.
	if _, err := cipher.StreamConn(peer).Write([]byte("pending acceptance")); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("unaccepted peer read error = %v, want EOF", err)
	}
}
