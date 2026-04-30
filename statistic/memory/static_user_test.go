package memory

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
)

// TestStaticPasswordsSurviveQuotaSweep is the P0-3a regression test.
// Before the fix, `AddUser` left `User.quota` zero-valued. When SQLite
// persistence was enabled, the quota enforcement goroutine would treat
// quota==0 the same as a disabled user (the `quota > 0` branch was not
// taken so users with positive traffic were not removed, but operators
// reported the inverse pattern via MySQL where quota would later be
// initialized to 0 and traffic would tip the user over). The simpler
// fix is to default to -1 (unlimited) and require an explicit positive
// value to opt into enforcement. This test pins that behaviour: users
// loaded from cfg.Passwords keep authenticating across the first quota
// tick even with a small amount of traffic.
func TestStaticPasswordsSurviveQuotaSweep(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "static_quota.db")
	cfg := &Config{
		Passwords: []string{"static-user-secret"},
		Sqlite:    dbPath,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mctx := config.WithConfig(ctx, Name, cfg)
	auth, err := NewAuthenticator(mctx)
	common.Must(err)
	defer auth.Close()

	hash := common.SHA224String("static-user-secret")
	valid, user := auth.AuthUser(hash)
	if !valid {
		t.Fatal("static user not authenticated immediately after load")
	}
	if got := user.GetQuota(); got != -1 {
		t.Fatalf("static user quota = %d, want -1 (unlimited)", got)
	}

	user.AddSentTraffic(1024)
	user.AddRecvTraffic(2048)

	// Wait one full enforcement tick (10 s) plus a small buffer.
	time.Sleep(11 * time.Second)

	if valid, _ := auth.AuthUser(hash); !valid {
		t.Fatal("static user was removed by quota sweep despite unlimited quota")
	}
}
