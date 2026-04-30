package memory

import (
	"context"
	"testing"
	"time"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
)

// TestActiveQuotaCutoffClosesUserDone is the P0-3d regression test. After
// `AddSentTraffic`/`AddRecvTraffic` push the running total at or above the
// configured quota, `User.Done()` MUST be closed within the same call so
// downstream consumers (the trojan tunnel watcher in `tunnel/trojan/
// server.go`) can react and tear down the in-flight transport instead of
// waiting up to 10 s for the next SQLite/MySQL sweep.
func TestActiveQuotaCutoffClosesUserDone(t *testing.T) {
	cfg := &Config{Passwords: nil}
	ctx := config.WithConfig(context.Background(), Name, cfg)
	auth, err := NewAuthenticator(ctx)
	common.Must(err)
	defer auth.Close()

	common.Must(auth.AddUser("over"))
	common.Must(auth.SetUserQuota("over", 1024))
	_, user := auth.AuthUser("over")

	select {
	case <-user.Done():
		t.Fatal("Done() fired before any traffic")
	default:
	}

	user.AddSentTraffic(600)
	select {
	case <-user.Done():
		t.Fatal("Done() fired below quota (sent=600 < 1024)")
	default:
	}

	// Crossing the threshold must close Done() synchronously.
	user.AddRecvTraffic(500) // total = 1100 >= 1024
	select {
	case <-user.Done():
		// expected
	case <-time.After(time.Second):
		t.Fatal("Done() did not fire after crossing quota")
	}
}

// TestActiveQuotaCutoffSkipsUnlimited verifies that the cutoff hook does
// not fire for unlimited (quota < 0) or disabled (quota == 0) users no
// matter how much traffic flows.
func TestActiveQuotaCutoffSkipsUnlimited(t *testing.T) {
	cfg := &Config{Passwords: nil}
	ctx := config.WithConfig(context.Background(), Name, cfg)
	auth, err := NewAuthenticator(ctx)
	common.Must(err)
	defer auth.Close()

	for _, hash := range []string{"unlimited", "disabled"} {
		common.Must(auth.AddUser(hash))
	}
	common.Must(auth.SetUserQuota("unlimited", -1))
	common.Must(auth.SetUserQuota("disabled", 0))

	for _, hash := range []string{"unlimited", "disabled"} {
		_, u := auth.AuthUser(hash)
		u.AddSentTraffic(1 << 20)
		u.AddRecvTraffic(1 << 20)
		select {
		case <-u.Done():
			t.Fatalf("user %q with non-positive quota was cut off", hash)
		case <-time.After(50 * time.Millisecond):
		}
	}
}
