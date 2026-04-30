package memory

import (
	"context"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
)

func TestMemoryAuth(t *testing.T) {
	cfg := &Config{
		Passwords: nil,
	}
	ctx := config.WithConfig(context.Background(), Name, cfg)
	auth, err := NewAuthenticator(ctx)
	common.Must(err)
	auth.AddUser("user1")
	valid, user := auth.AuthUser("user1")
	if !valid {
		t.Fatal("add, auth")
	}
	if user.GetHash() != "user1" {
		t.Fatal("Hash")
	}
	user.AddSentTraffic(100)
	user.AddRecvTraffic(200)
	sent, recv := user.GetTraffic()
	if sent != 100 || recv != 200 {
		t.Fatal("traffic")
	}
	sent, recv = user.ResetTraffic()
	if sent != 100 || recv != 200 {
		t.Fatal("ResetTraffic")
	}
	sent, recv = user.GetTraffic()
	if sent != 0 || recv != 0 {
		t.Fatal("ResetTraffic")
	}

	user.AddIP("1234")
	user.AddIP("5678")
	if user.GetIP() != 0 {
		t.Fatal("GetIP")
	}

	auth.SetUserIPLimit(user.GetHash(), 2)
	user.AddIP("1234")
	user.AddIP("5678")
	user.DelIP("1234")
	if user.GetIP() != 1 {
		t.Fatal("DelIP")
	}
	user.DelIP("5678")

	auth.SetUserIPLimit(user.GetHash(), 2)
	if !user.AddIP("1") || !user.AddIP("2") {
		t.Fatal("AddIP")
	}
	if user.AddIP("3") {
		t.Fatal("AddIP")
	}
	if !user.AddIP("2") {
		t.Fatal("AddIP")
	}

	auth.SetUserTraffic(user.GetHash(), 1234, 4321)
	if a, b := user.GetTraffic(); a != 1234 || b != 4321 {
		t.Fatal("SetTraffic")
	}

	user.ResetTraffic()
	// Producer rate: ~200 KiB/s sent, ~100 KiB/s recv. Chosen to exceed the
	// 64 KiB minimum burst (P0-2) within a few seconds so the limiter is
	// actually exercised in the SetUserSpeedLimit assertion below.
	go func() {
		k := 100
		chunk := 2 * 1024 // 2 KiB per tick
		for {
			time.Sleep(time.Second / time.Duration(k))
			user.AddSentTraffic(chunk)
			user.AddRecvTraffic(chunk / 2)
		}
	}()
	time.Sleep(time.Second * 4)
	if sent, recv := user.GetSpeed(); sent > 300*1024 || sent < 100*1024 || recv > 150*1024 || recv < 50*1024 {
		t.Error("GetSpeed", sent, recv)
	} else {
		t.Log("GetSpeed", sent, recv)
	}

	// 30 KiB/s send, 20 KiB/s recv: low enough to throttle the producer
	// (~200 KiB/s) once the 64 KiB burst is depleted.
	auth.SetUserSpeedLimit(user.GetHash(), 30*1024, 20*1024)
	time.Sleep(time.Second * 6)
	if sent, recv := user.GetSpeed(); sent > 60*1024 || recv > 40*1024 {
		t.Error("SetSpeedLimit", sent, recv)
	} else {
		t.Log("SetSpeedLimit", sent, recv)
	}

	auth.SetUserSpeedLimit(user.GetHash(), 0, 0)
	time.Sleep(time.Second * 4)
	if sent, recv := user.GetSpeed(); sent < 30*1024 || recv < 15*1024 {
		t.Error("SetSpeedLimit", sent, recv)
	} else {
		t.Log("SetSpeedLimit", sent, recv)
	}

	auth.AddUser("user2")
	valid, _ = auth.AuthUser("user2")
	if !valid {
		t.Fatal()
	}
	auth.DelUser("user2")
	valid, _ = auth.AuthUser("user2")
	if valid {
		t.Fatal()
	}
	auth.AddUser("user3")
	users := auth.ListUsers()
	if len(users) != 2 {
		t.Fatal()
	}
	user.Close()
	auth.Close()
}

func BenchmarkMemoryUsage(b *testing.B) {
	cfg := &Config{
		Passwords: nil,
	}
	ctx := config.WithConfig(context.Background(), Name, cfg)
	auth, err := NewAuthenticator(ctx)
	common.Must(err)

	m1 := runtime.MemStats{}
	m2 := runtime.MemStats{}
	runtime.ReadMemStats(&m1)
	for i := 0; i < b.N; i++ {
		common.Must(auth.AddUser(common.SHA224String("hash" + strconv.Itoa(i))))
	}
	runtime.ReadMemStats(&m2)

	b.ReportMetric(float64(m2.Alloc-m1.Alloc)/1024/1024, "MiB(Alloc)")
	b.ReportMetric(float64(m2.TotalAlloc-m1.TotalAlloc)/1024/1024, "MiB(TotalAlloc)")
}

// TestMemoryQuotaRoundtrip verifies that SetUserQuota and GetQuota work
// correctly for both positive and negative (unlimited) quota values.
func TestMemoryQuotaRoundtrip(t *testing.T) {
	cfg := &Config{Passwords: nil}
	ctx := config.WithConfig(context.Background(), Name, cfg)
	auth, err := NewAuthenticator(ctx)
	common.Must(err)
	defer auth.Close()

	common.Must(auth.AddUser("quotauser"))
	common.Must(auth.SetUserQuota("quotauser", 5000))
	_, user := auth.AuthUser("quotauser")
	if user.GetQuota() != 5000 {
		t.Fatalf("expected quota 5000, got %d", user.GetQuota())
	}

	// Negative quota means unlimited.
	common.Must(auth.SetUserQuota("quotauser", -1))
	if user.GetQuota() != -1 {
		t.Fatalf("expected quota -1 (unlimited), got %d", user.GetQuota())
	}
}

// TestMemoryQuotaEnforcementAndUnlimited exercises the quota enforcement
// goroutine that runs when a SQLite persistencer is configured. It verifies
// that a user whose traffic has exceeded a positive quota is removed, while a
// user with unlimited quota (quota < 0) is kept even with very high traffic.
//
// The enforcement goroutine fires every 10 seconds, so this test waits 11
// seconds for the first tick to complete.
func TestMemoryQuotaEnforcementAndUnlimited(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "quota_test.db")
	cfg := &Config{
		Passwords: nil,
		Sqlite:    dbPath,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mctx := config.WithConfig(ctx, Name, cfg)
	auth, err := NewAuthenticator(mctx)
	common.Must(err)
	defer auth.Close()

	// User that will exceed its quota.
	common.Must(auth.AddUser("over_quota"))
	common.Must(auth.SetUserQuota("over_quota", 1000))
	_, overUser := auth.AuthUser("over_quota")
	overUser.AddSentTraffic(600)
	overUser.AddRecvTraffic(500) // total = 1100 > 1000

	// User with unlimited quota (negative value).
	common.Must(auth.AddUser("unlimited"))
	common.Must(auth.SetUserQuota("unlimited", -1))
	_, unlimitedUser := auth.AuthUser("unlimited")
	unlimitedUser.AddSentTraffic(1000000)
	unlimitedUser.AddRecvTraffic(1000000)

	// Wait for the first enforcement tick (10 s interval + 1 s buffer).
	time.Sleep(11 * time.Second)

	if valid, _ := auth.AuthUser("over_quota"); valid {
		t.Fatal("over_quota user should have been removed by quota enforcement")
	}
	if valid, _ := auth.AuthUser("unlimited"); !valid {
		t.Fatal("unlimited user should still be present")
	}
}
