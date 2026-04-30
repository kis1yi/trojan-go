package trojan

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/statistic/memory"
	"github.com/kis1yi/trojan-go/tunnel"
)

// validHashOf returns the 56-byte ASCII hex SHA-224 hash of the given password
// as the trojan protocol expects on the wire.
func validHashOf(password string) []byte {
	h := common.SHA224String(password)
	if len(h) != 56 {
		panic("unexpected hash length")
	}
	return []byte(h)
}

// minimalMetadata returns a serialized trojan metadata block (Connect to
// example.com:80) followed by the CRLF terminator. This is the minimum byte
// sequence after the 56-byte hash + first CRLF that allows Auth() to succeed.
func minimalMetadata(t *testing.T) []byte {
	t.Helper()
	meta := &tunnel.Metadata{
		Command: Connect,
		Address: &tunnel.Address{
			DomainName:  "example.com",
			AddressType: tunnel.DomainName,
			Port:        80,
		},
	}
	var buf bytes.Buffer
	if err := meta.Marshal(&buf); err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return append(buf.Bytes(), '\r', '\n')
}

func newTestAuthenticator(t *testing.T, password string) *memory.Authenticator {
	t.Helper()
	cfg := &memory.Config{Passwords: []string{password}}
	ctx := config.WithConfig(context.Background(), memory.Name, cfg)
	auth, err := memory.NewAuthenticator(ctx)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return auth.(*memory.Authenticator)
}

// pipeAddr is a deterministic net.Addr for net.Pipe connections so that
// SplitHostPort succeeds inside Auth().
type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "127.0.0.1:0" }

// addrConn wraps a net.Conn to override RemoteAddr/LocalAddr with parseable
// host:port pairs (the default net.Pipe addresses are not host:port).
type addrConn struct {
	net.Conn
}

func (addrConn) RemoteAddr() net.Addr { return pipeAddr{} }
func (addrConn) LocalAddr() net.Addr  { return pipeAddr{} }

// TestAuthFragmentedHashHandshake exercises H2: ReadFull must reassemble a
// fragmented 56-byte hash that arrives in two TCP segments. With the previous
// single Conn.Read this would return short and reject a valid client.
func TestAuthFragmentedHashHandshake(t *testing.T) {
	prev := TrojanAuthTimeout
	TrojanAuthTimeout = 2 * time.Second
	defer func() { TrojanAuthTimeout = prev }()

	auth := newTestAuthenticator(t, "password")
	defer auth.Close()

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	hash := validHashOf("password")
	meta := minimalMetadata(t)

	go func() {
		// Fragment the hash in two writes with a small sleep between them.
		_, _ = clientSide.Write(hash[:30])
		time.Sleep(50 * time.Millisecond)
		_, _ = clientSide.Write(hash[30:])
		_, _ = clientSide.Write([]byte{'\r', '\n'})
		_, _ = clientSide.Write(meta)
	}()

	ic := &InboundConn{Conn: addrConn{Conn: serverSide}, auth: auth}
	if err := ic.Auth(); err != nil {
		t.Fatalf("Auth on fragmented hash: %v", err)
	}
}

// TestAuthSlowClientTimesOut exercises H2: a client that opens a connection
// and writes nothing must hit the auth timeout instead of tying up the accept
// goroutine forever.
func TestAuthSlowClientTimesOut(t *testing.T) {
	prev := TrojanAuthTimeout
	TrojanAuthTimeout = 100 * time.Millisecond
	defer func() { TrojanAuthTimeout = prev }()

	auth := newTestAuthenticator(t, "password")
	defer auth.Close()

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	ic := &InboundConn{Conn: addrConn{Conn: serverSide}, auth: auth}
	start := time.Now()
	err := ic.Auth()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Auth on silent client returned nil error")
	}
	if elapsed > time.Second {
		t.Fatalf("Auth took too long (%s) — read deadline did not fire", elapsed)
	}
}

// TestAuthInvalidHashRedaction exercises H2: when the client sends 56 bytes
// that are not a valid hash, the returned error must not contain the raw
// client-controlled bytes. The error string must be a single line of
// printable characters.
func TestAuthInvalidHashRedaction(t *testing.T) {
	prev := TrojanAuthTimeout
	TrojanAuthTimeout = 2 * time.Second
	defer func() { TrojanAuthTimeout = prev }()

	auth := newTestAuthenticator(t, "password")
	defer auth.Close()

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	// Send 56 binary bytes (e.g. embedded \n and 0xFF) that look nothing like
	// a SHA-224 hex hash.
	junk := make([]byte, 56)
	for i := range junk {
		junk[i] = 0xFF
	}
	junk[10] = '\n'
	junk[20] = 0
	go func() { _, _ = clientSide.Write(junk) }()

	ic := &InboundConn{Conn: addrConn{Conn: serverSide}, auth: auth}
	err := ic.Auth()
	if err == nil {
		t.Fatal("Auth on junk hash returned nil error")
	}
	msg := err.Error()
	if strings.ContainsRune(msg, '\n') {
		t.Fatalf("error message contains a raw newline: %q", msg)
	}
	if strings.Contains(msg, string(junk)) {
		t.Fatalf("error message leaks raw client bytes: %q", msg)
	}
	// The redacted form must be a short hex token, never the full hex.
	fullHex := hex.EncodeToString(junk)
	if strings.Contains(msg, fullHex) {
		t.Fatalf("error message leaks full hex of client bytes: %q", msg)
	}
}

// TestIPLimitRollbackOnMetadataFailure exercises H3: when a client sends a
// valid hash but malformed metadata, the user's IP slot must not be consumed
// because AddIP is now deferred until after the metadata parse succeeds.
func TestIPLimitRollbackOnMetadataFailure(t *testing.T) {
	prev := TrojanAuthTimeout
	TrojanAuthTimeout = 2 * time.Second
	defer func() { TrojanAuthTimeout = prev }()

	auth := newTestAuthenticator(t, "password")
	defer auth.Close()

	if err := auth.SetUserIPLimit(common.SHA224String("password"), 1); err != nil {
		t.Fatalf("SetUserIPLimit: %v", err)
	}
	_, user := auth.AuthUser(common.SHA224String("password"))

	for i := 0; i < 5; i++ {
		clientSide, serverSide := net.Pipe()
		hash := validHashOf("password")
		go func() {
			_, _ = clientSide.Write(hash)
			_, _ = clientSide.Write([]byte{'\r', '\n'})
			// Send malformed metadata: an unknown command byte and then close.
			_, _ = clientSide.Write([]byte{0xFE})
			clientSide.Close()
		}()
		ic := &InboundConn{Conn: addrConn{Conn: serverSide}, auth: auth}
		_ = ic.Auth() // expected to fail on metadata parse
		serverSide.Close()
	}

	if got := user.GetIP(); got != 0 {
		t.Fatalf("expected user.GetIP() == 0 after malformed-metadata failures, got %d", got)
	}
}
