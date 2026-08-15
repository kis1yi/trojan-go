package trojan

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/metrics"
	"github.com/kis1yi/trojan-go/statistic/memory"
	"github.com/kis1yi/trojan-go/test/util"
	"github.com/kis1yi/trojan-go/tunnel"
	"github.com/kis1yi/trojan-go/tunnel/freedom"
	"github.com/kis1yi/trojan-go/tunnel/transport"
)

// TestCutoffWatcherExitsOnNormalClose is the regression for the watcher leak:
// every authenticated tunnel used to leave a goroutine blocked on the user's
// cutoff channel after the connection had closed normally. The goroutine kept
// the InboundConn and its wrapped TLS connection reachable until the user was
// removed or the whole server stopped.
func TestCutoffWatcherExitsOnNormalClose(t *testing.T) {
	auth := newTestAuthenticator(t, "password")
	defer auth.Close()

	hash := common.SHA224String("password")
	if err := auth.SetUserIPLimit(hash, 1); err != nil {
		t.Fatalf("SetUserIPLimit: %v", err)
	}
	valid, user := auth.AuthUser(hash)
	if !valid {
		t.Fatal("configured user did not authenticate")
	}
	const ip = "127.0.0.1"
	if !user.AddIP(ip) {
		t.Fatal("failed to reserve first test connection's IP slot")
	}
	// A second connection from the same IP must remain accounted after
	// inbound.Close is called repeatedly for the first connection.
	if !user.AddIP(ip) {
		t.Fatal("failed to reserve second test connection's IP slot")
	}

	peer, conn := net.Pipe()
	defer peer.Close()

	inbound := &InboundConn{
		Conn:   addrConn{Conn: conn},
		user:   user,
		hash:   hash,
		ip:     ip,
		closed: make(chan struct{}),
		metadata: &tunnel.Metadata{
			Address: tunnel.NewAddressFromHostPort("tcp", "example.com", 80),
		},
	}
	activeBefore := metrics.Snapshot()[metrics.KeyActiveConnections]
	metrics.IncActiveConnections()
	defer inbound.Close()

	server := &Server{ctx: context.Background()}
	watcherExited := make(chan struct{})
	go func() {
		server.waitForUserCutoff(inbound, user.Done())
		close(watcherExited)
	}()

	if err := inbound.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// A second close must neither panic nor repeat IP/metrics accounting.
	if err := inbound.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	select {
	case <-watcherExited:
	case <-time.After(time.Second):
		t.Fatal("cutoff watcher did not exit after normal connection close")
	}
	if got := user.GetIP(); got != 1 {
		t.Fatalf("repeated Close disturbed the second connection's IP slot: got %d active IPs, want 1", got)
	}
	if !user.DelIP(ip) {
		t.Fatal("failed to release second test connection's IP slot")
	}
	if got := metrics.Snapshot()[metrics.KeyActiveConnections]; got != activeBefore {
		t.Fatalf("active connection gauge after repeated Close = %d, want %d", got, activeBefore)
	}
}

// TestQuotaCutoffClosesAcceptedTunnel is the P0-3d integration regression
// test. It builds a real trojan client/server pair over the in-memory
// transport, accepts a connection, then forces the user's quota to a
// value below the bytes already counted. The server-side `InboundConn`
// MUST be closed by the cutoff watcher within ~1 s — proving the active
// cutoff acts on already accepted connections rather than waiting for the
// next 10 s persistencer sweep.
func TestQuotaCutoffClosesAcceptedTunnel(t *testing.T) {
	transportPort := common.PickPort("tcp", "127.0.0.1")
	transportConfig := &transport.Config{
		LocalHost:  "127.0.0.1",
		LocalPort:  transportPort,
		RemoteHost: "127.0.0.1",
		RemotePort: transportPort,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = config.WithConfig(ctx, transport.Name, transportConfig)
	ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})
	tcpClient, err := transport.NewClient(ctx, nil)
	common.Must(err)
	tcpServer, err := transport.NewServer(ctx, nil)
	common.Must(err)

	serverPort := common.PickPort("tcp", "127.0.0.1")
	authConfig := &memory.Config{Passwords: []string{"password"}}
	clientConfig := &Config{RemoteHost: "127.0.0.1", RemotePort: serverPort}
	serverConfig := &Config{
		LocalHost:  "127.0.0.1",
		LocalPort:  serverPort,
		RemoteHost: "127.0.0.1",
		RemotePort: util.EchoPort,
	}

	ctx = config.WithConfig(ctx, memory.Name, authConfig)
	clientCtx := config.WithConfig(ctx, Name, clientConfig)
	serverCtx := config.WithConfig(ctx, Name, serverConfig)
	c, err := NewClient(clientCtx, tcpClient)
	common.Must(err)
	defer c.Close()
	s, err := NewServer(serverCtx, tcpServer)
	common.Must(err)
	defer s.Close()

	clientConn, err := c.DialConn(&tunnel.Address{
		DomainName:  "example.com",
		AddressType: tunnel.DomainName,
	}, nil)
	common.Must(err)
	defer clientConn.Close()
	common.Must2(clientConn.Write([]byte("hello")))

	serverConn, err := s.AcceptConn(nil)
	common.Must(err)
	defer serverConn.Close()

	buf := make([]byte, 5)
	common.Must2(serverConn.Read(buf))

	// Now force the user over quota. The auth instance lives inside the
	// trojan server; reach in via the package-private field for the test.
	hash := common.SHA224String("password")
	common.Must(s.auth.SetUserQuota(hash, 1)) // anything <= sent+recv triggers cutoff
	_, user := s.auth.AuthUser(hash)
	// Write at least one byte to push the AddRecvTraffic accounting hook.
	user.AddRecvTraffic(1)

	// The watcher goroutine must close the underlying transport. We confirm
	// by asserting the next Read on serverConn observes EOF/closed-conn
	// within 1 second.
	if err := serverConn.(net.Conn).SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	scratch := make([]byte, 8)
	n, readErr := serverConn.Read(scratch)
	if readErr == nil {
		t.Fatalf("expected read error after cutoff, got n=%d", n)
	}
	// Accept any of: closed, EOF, deadline-after-shutdown — but fail with a
	// clear message if it actually timed out (cutoff did not fire).
	if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
		t.Fatalf("read timed out instead of being closed by cutoff: %v", readErr)
	}
	t.Logf("cutoff closed tunnel as expected: %v", readErr)
}
