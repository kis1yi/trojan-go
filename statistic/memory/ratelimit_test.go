package memory

import (
	"context"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
)

// TestRateLimiterChunkingDelaysLargeWrite proves P0-2 fix: a single
// AddSentTraffic call larger than the burst is now chunked into burst-sized
// WaitN calls, so the throttling actually engages instead of being silently
// bypassed. With the old `2*limit` burst and a write of 32 KiB on a 4 KiB/s
// limit, WaitN returned ErrLimitExceededN and the limiter was a no-op.
func TestRateLimiterChunkingDelaysLargeWrite(t *testing.T) {
	cfg := &Config{Passwords: nil}
	ctx := config.WithConfig(context.Background(), Name, cfg)
	auth, err := NewAuthenticator(ctx)
	common.Must(err)
	defer auth.Close()

	common.Must(auth.AddUser("u"))
	_, user := auth.AuthUser("u")
	mu := user.(*User)

	// Use a very small custom limiter with burst smaller than the call size
	// so we can prove chunking happens without sleeping for seconds in a
	// fake-time-free unit test. limit = 1024 B/s, burst = 1024 B; calling
	// addLimited with 4096 B must take at least ~3s of token replenishment
	// (we already have one full burst available immediately, then need to
	// wait for ~3 more bursts).
	limit := 1024
	mu.limiterLock.Lock()
	mu.SendLimiter = rate.NewLimiter(rate.Limit(limit), limit)
	mu.limiterLock.Unlock()

	start := time.Now()
	mu.AddSentTraffic(4 * limit)
	elapsed := time.Since(start)

	// One burst is available immediately, the remaining 3 must be replenished
	// at `limit` tokens per second; expect ~3 s, accept >=2.5 s as "engaged".
	if elapsed < 2500*time.Millisecond {
		t.Fatalf("addLimited returned in %s; expected >= 2.5s, throttling did not engage", elapsed)
	}
	// Sanity: the byte counter must still be incremented.
	if sent, _ := mu.GetTraffic(); sent != uint64(4*limit) {
		t.Fatalf("Sent counter = %d, want %d", sent, 4*limit)
	}
}

// TestSetSpeedLimitDoesNotDeadlockUnderTraffic proves P0-2 fix: SetSpeedLimit
// (which acquires the limiter Lock) must not deadlock against a concurrent
// AddSentTraffic that is currently waiting on WaitN. The previous code held
// the RLock across WaitN, blocking SetSpeedLimit indefinitely.
func TestSetSpeedLimitDoesNotDeadlockUnderTraffic(t *testing.T) {
	cfg := &Config{Passwords: nil}
	ctx := config.WithConfig(context.Background(), Name, cfg)
	auth, err := NewAuthenticator(ctx)
	common.Must(err)
	defer auth.Close()

	common.Must(auth.AddUser("u"))
	common.Must(auth.SetUserSpeedLimit("u", 256, 256))
	_, user := auth.AuthUser("u")

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		// This will block in WaitN for several seconds at 256 B/s.
		user.AddSentTraffic(64 * 1024)
	}()

	// Give the writer a moment to enter WaitN, then reconfigure the limiter.
	time.Sleep(100 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		// Raising the limit should return immediately with the new code.
		_ = auth.SetUserSpeedLimit("u", 1<<20, 1<<20)
		close(done)
	}()

	select {
	case <-done:
		// SetUserSpeedLimit completed without waiting for the in-flight WaitN.
	case <-time.After(2 * time.Second):
		t.Fatal("SetUserSpeedLimit blocked behind in-flight AddSentTraffic")
	}

	// Don't leave the writer goroutine hanging: closing the user cancels
	// the context the limiter waits on.
	user.Close()
	wg.Wait()
}
