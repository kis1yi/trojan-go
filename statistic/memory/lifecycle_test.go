package memory

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
)

// TestAuthenticatorLifecycle verifies that Authenticator.Close cancels every
// per-user goroutine (speedUpdater / trafficUpdater) and closes the optional
// SQLite persistencer. After Close returns, the goroutine count must drop back
// to the baseline measured before NewAuthenticator was called.
func TestAuthenticatorLifecycle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "lifecycle.db")
	cfg := &Config{
		Passwords: nil,
		Sqlite:    dbPath,
	}
	ctx := config.WithConfig(context.Background(), Name, cfg)

	baseline := runtime.NumGoroutine()

	auth, err := NewAuthenticator(ctx)
	common.Must(err)

	// Register a few users so multiple per-user goroutines are running.
	common.Must(auth.AddUser("user-a"))
	common.Must(auth.AddUser("user-b"))
	common.Must(auth.AddUser("user-c"))

	// Give the spawned goroutines a moment to land in the scheduler.
	time.Sleep(50 * time.Millisecond)
	if runtime.NumGoroutine() <= baseline {
		t.Fatalf("expected goroutine count to grow after AddUser, got %d (baseline %d)",
			runtime.NumGoroutine(), baseline)
	}

	if err := auth.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Wait up to 1 s for goroutines to wind down.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline+1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline+1 {
		t.Fatalf("goroutines did not return to baseline after Close: got %d, baseline %d",
			got, baseline)
	}
}
