//go:build mysql_integration

package mysql

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConcurrentBatchUpdatesAreAdditive(t *testing.T) {
	rawDSNs := os.Getenv("TROJAN_GO_MYSQL_INTEGRATION_DSNS")
	if rawDSNs == "" {
		t.Skip("TROJAN_GO_MYSQL_INTEGRATION_DSNS is not set")
	}

	for _, dsn := range strings.Split(rawDSNs, ",") {
		dsn := strings.TrimSpace(dsn)
		if dsn == "" {
			continue
		}
		t.Run(dsn, func(t *testing.T) {
			testConcurrentBatchUpdatesAreAdditive(t, dsn)
		})
	}
}

func testConcurrentBatchUpdatesAreAdditive(t *testing.T, dsn string) {
	t.Helper()
	db1, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open node 1: %v", err)
	}
	defer db1.Close()
	db2, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open node 2: %v", err)
	}
	defer db2.Close()

	if _, err := db1.Exec("DROP TABLE IF EXISTS users"); err != nil {
		t.Fatalf("drop users before test: %v", err)
	}
	defer func() {
		_, _ = db1.Exec("DROP TABLE IF EXISTS users")
	}()
	if _, err := db1.Exec(`CREATE TABLE users (
		id INT UNSIGNED NOT NULL AUTO_INCREMENT,
		password CHAR(56) NOT NULL,
		download BIGINT UNSIGNED NOT NULL DEFAULT 0,
		upload BIGINT UNSIGNED NOT NULL DEFAULT 0,
		PRIMARY KEY (id),
		INDEX (password)
	) ENGINE=InnoDB`); err != nil {
		t.Fatalf("create users: %v", err)
	}
	if _, err := db1.Exec("INSERT INTO users (password) VALUES (?), (?)", "user-a", "user-b"); err != nil {
		t.Fatalf("insert users: %v", err)
	}

	newAuth := func(db *sql.DB, pending map[string]trafficDelta) *Authenticator {
		return &Authenticator{
			db:               db,
			ctx:              context.Background(),
			queryTimeout:     5 * time.Second,
			trafficBatchSize: DefaultTrafficBatchSize,
			pendingTraffic:   pending,
		}
	}
	a1 := newAuth(db1, map[string]trafficDelta{
		"user-a": {hash: "user-a", sent: 10, recv: 20},
		"user-b": {hash: "user-b", sent: 30, recv: 40},
	})
	a2 := newAuth(db2, map[string]trafficDelta{
		"user-a": {hash: "user-a", sent: 100, recv: 200},
		"user-b": {hash: "user-b", sent: 300, recv: 400},
	})

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, auth := range []*Authenticator{a1, a2} {
		wg.Add(1)
		go func(auth *Authenticator) {
			defer wg.Done()
			errs <- auth.flushPendingTraffic()
		}(auth)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("flushPendingTraffic: %v", err)
		}
	}

	want := map[string][2]uint64{
		"user-a": {110, 220},
		"user-b": {330, 440},
	}
	rows, err := db1.Query("SELECT password, download, upload FROM users")
	if err != nil {
		t.Fatalf("select totals: %v", err)
	}
	defer rows.Close()
	seen := make(map[string]bool)
	for rows.Next() {
		var hash string
		var download, upload uint64
		if err := rows.Scan(&hash, &download, &upload); err != nil {
			t.Fatalf("scan totals: %v", err)
		}
		if got, ok := want[hash]; !ok || download != got[0] || upload != got[1] {
			t.Fatalf("%s totals = (%d, %d), want %v", hash, download, upload, got)
		}
		seen[hash] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate totals: %v", err)
	}
	if len(seen) != len(want) {
		t.Fatalf("seen users = %d, want %d", len(seen), len(want))
	}
}
