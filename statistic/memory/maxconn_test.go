package memory

import (
	"context"
	"strings"
	"testing"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/common/queue"
	"github.com/kis1yi/trojan-go/config"
)

// TestMaxConnPerUserRejectsSurplusConnections asserts that the per-user
// connection cap configured via queue.MaxConnPerUser blocks the
// MaxConnPerUser+1-th AddIP call, while DelIP releases the slot.
//
// P1-2: this is the per-user backpressure half — the accept-queue half is
// covered structurally by the non-blocking sends and the ResolveAcceptQueueSize
// unit tests in common/queue.
func TestMaxConnPerUserRejectsSurplusConnections(t *testing.T) {
	const cap = 3
	cfgYAML := `
password:
  - "deadbeef"
queue:
  max-conn-per-user: ` + itoa(cap) + `
`
	ctx, err := config.WithYAMLConfig(context.Background(), []byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()

	hash := common.SHA224String("password")
	if err := auth.AddUser(hash); err != nil {
		t.Fatal(err)
	}
	_, u := auth.AuthUser(hash)
	if u == nil {
		t.Fatal("user not registered")
	}

	for i := 0; i < cap; i++ {
		if !u.AddIP("10.0.0.1") {
			t.Fatalf("connection %d should have been accepted under the cap", i+1)
		}
	}
	if u.AddIP("10.0.0.1") {
		t.Fatalf("connection %d should have been rejected by MaxConnPerUser=%d", cap+1, cap)
	}
	// Releasing one slot lets the next one in.
	u.DelIP("10.0.0.1")
	if !u.AddIP("10.0.0.1") {
		t.Fatal("after DelIP a new connection must be accepted again")
	}
}

// TestMaxConnPerUserDefaultIsUnlimited proves that without queue config,
// AddIP keeps accepting connections (regression guard against accidentally
// applying a non-zero default).
func TestMaxConnPerUserDefaultIsUnlimited(t *testing.T) {
	ctx, err := config.WithYAMLConfig(context.Background(), []byte("password: [\"deadbeef\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()

	hash := common.SHA224String("password")
	if err := auth.AddUser(hash); err != nil {
		t.Fatal(err)
	}
	_, u := auth.AuthUser(hash)
	for i := 0; i < 1000; i++ {
		if !u.AddIP("10.0.0.2") {
			t.Fatalf("default config should be unlimited, rejected at %d", i)
		}
	}
}

// TestQueueResolveDefaultsRoundTrip is a small belt-and-braces check that
// the queue config registers under the right key and threads through ctx.
func TestQueueResolveDefaultsRoundTrip(t *testing.T) {
	ctx, err := config.WithYAMLConfig(context.Background(), []byte("queue: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	q := queue.FromContext(ctx)
	if got := q.ResolveAcceptQueueSize(); got != queue.DefaultAcceptQueueSize {
		t.Fatalf("default accept queue size: got %d, want %d", got, queue.DefaultAcceptQueueSize)
	}
	if got := q.ResolveMaxConnPerUser(); got != 0 {
		t.Fatalf("default max conn per user: got %d, want 0", got)
	}
}

// itoa avoids a strconv import in a single call site that would otherwise
// be the only consumer in this test file.
func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b strings.Builder
	if n < 0 {
		b.WriteByte('-')
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	b.Write(buf[i:])
	return b.String()
}
