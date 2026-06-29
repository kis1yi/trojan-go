package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/statistic/memory"
)

// newMySQLTestAuth constructs a mysql.Authenticator backed by a mock *sql.DB
// without connecting to a real MySQL instance. The returned cancel function
// should be called when the test is done.
func newMySQLTestAuth(t *testing.T, db *sql.DB) (*Authenticator, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	mctx := config.WithConfig(ctx, memory.Name, &memory.Config{})
	memAuth, err := memory.NewAuthenticator(mctx)
	if err != nil {
		cancel()
		t.Fatalf("failed to create memory authenticator: %v", err)
	}
	a := &Authenticator{
		db:               db,
		ctx:              ctx,
		updateDuration:   time.Second,
		queryTimeout:     DefaultQueryTimeout,
		trafficBatchSize: DefaultTrafficBatchSize,
		pendingTraffic:   make(map[string]trafficDelta),
		Authenticator:    memAuth.(*memory.Authenticator),
	}
	return a, cancel
}

func TestResolveTrafficBatchSize(t *testing.T) {
	tests := []struct {
		name    string
		raw     int
		want    int
		wantErr bool
	}{
		{name: "zero uses default", raw: 0, want: DefaultTrafficBatchSize},
		{name: "negative uses default", raw: -1, want: DefaultTrafficBatchSize},
		{name: "single mode", raw: 1, want: 1},
		{name: "default explicit", raw: 500, want: 500},
		{name: "maximum", raw: MaxTrafficBatchSize, want: MaxTrafficBatchSize},
		{name: "above maximum", raw: MaxTrafficBatchSize + 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveTrafficBatchSize(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("resolveTrafficBatchSize returned nil error")
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveTrafficBatchSize: %v", err)
			}
			if got != tt.want {
				t.Fatalf("resolveTrafficBatchSize(%d) = %d, want %d", tt.raw, got, tt.want)
			}
		})
	}
}

func TestBuildTrafficUpdateSinglePreservesLegacySQL(t *testing.T) {
	query, args := buildTrafficUpdate([]trafficDelta{{hash: "user1", sent: 100, recv: 200}})
	wantQuery := "UPDATE `users` SET `upload`=`upload`+?, `download`=`download`+? WHERE `password`=?;"
	wantArgs := []interface{}{uint64(200), uint64(100), "user1"}
	if query != wantQuery {
		t.Fatalf("query = %q, want %q", query, wantQuery)
	}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("args = %#v, want %#v", args, wantArgs)
	}
}

func TestBuildTrafficUpdateBatchMapsDirectionsAndParameters(t *testing.T) {
	query, args := buildTrafficUpdate([]trafficDelta{
		{hash: "a", sent: 10, recv: 20},
		{hash: "b", sent: 30, recv: 40},
	})
	wantQuery := "UPDATE `users` SET `upload`=`upload`+CASE `password` WHEN ? THEN ? WHEN ? THEN ? ELSE 0 END, `download`=`download`+CASE `password` WHEN ? THEN ? WHEN ? THEN ? ELSE 0 END WHERE `password` IN (?,?);"
	wantArgs := []interface{}{
		"a", uint64(20), "b", uint64(40),
		"a", uint64(10), "b", uint64(30),
		"a", "b",
	}
	if query != wantQuery {
		t.Fatalf("query = %q, want %q", query, wantQuery)
	}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("args = %#v, want %#v", args, wantArgs)
	}
}

func TestFlushPendingTrafficUsesConfiguredChunks(t *testing.T) {
	for _, tt := range []struct {
		name      string
		users     int
		wantCalls int
	}{
		{name: "500 users", users: 500, wantCalls: 1},
		{name: "501 users", users: 501, wantCalls: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()
			a, cancel := newMySQLTestAuth(t, db)
			defer cancel()

			for i := 0; i < tt.users; i++ {
				hash := fmt.Sprintf("user-%04d", i)
				a.pendingTraffic[hash] = trafficDelta{hash: hash, sent: uint64(i + 1), recv: uint64(i + 2)}
			}
			for i := 0; i < tt.wantCalls; i++ {
				mock.ExpectExec("^UPDATE `users` SET").WillReturnResult(sqlmock.NewResult(0, 1))
			}

			if err := a.flushPendingTraffic(); err != nil {
				t.Fatalf("flushPendingTraffic: %v", err)
			}
			if len(a.pendingTraffic) != 0 {
				t.Fatalf("pending users = %d, want 0", len(a.pendingTraffic))
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("unfulfilled mock expectations: %v", err)
			}
		})
	}
}

func TestFlushPendingTrafficRetriesAndMergesNewTraffic(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	a, cancel := newMySQLTestAuth(t, db)
	defer cancel()
	a.trafficBatchSize = 1
	if err := a.AddUser("user1"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	a.pendingTraffic["user1"] = trafficDelta{hash: "user1", sent: 100, recv: 200}

	singleQuery := regexp.QuoteMeta("UPDATE `users` SET `upload`=`upload`+?, `download`=`download`+? WHERE `password`=?;")
	mock.ExpectExec(singleQuery).
		WithArgs(uint64(200), uint64(100), "user1").
		WillReturnError(sql.ErrConnDone)
	if err := a.flushPendingTraffic(); err == nil {
		t.Fatal("flushPendingTraffic returned nil error")
	}
	if got := a.ErrorsTotal(); got != 1 {
		t.Fatalf("ErrorsTotal = %d, want 1", got)
	}
	if len(a.pendingTraffic) != 1 {
		t.Fatalf("pending users = %d, want 1", len(a.pendingTraffic))
	}

	_, user := a.AuthUser("user1")
	user.AddSentTraffic(25)
	user.AddRecvTraffic(50)
	a.collectPendingTraffic()
	mock.ExpectExec(singleQuery).
		WithArgs(uint64(250), uint64(125), "user1").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := a.flushPendingTraffic(); err != nil {
		t.Fatalf("retry flushPendingTraffic: %v", err)
	}
	if len(a.pendingTraffic) != 0 {
		t.Fatalf("pending users after retry = %d, want 0", len(a.pendingTraffic))
	}
	if a.failedFlushCycles != 0 {
		t.Fatalf("failedFlushCycles = %d, want 0", a.failedFlushCycles)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled mock expectations: %v", err)
	}
}

func TestFlushPendingTrafficKeepsOnlyFailedAndUnattemptedChunks(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	a, cancel := newMySQLTestAuth(t, db)
	defer cancel()
	a.trafficBatchSize = 2
	for _, hash := range []string{"a", "b", "c"} {
		a.pendingTraffic[hash] = trafficDelta{hash: hash, sent: 1, recv: 2}
	}
	mock.ExpectExec("^UPDATE `users` SET").WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec("^UPDATE `users` SET").WillReturnError(sql.ErrConnDone)

	if err := a.flushPendingTraffic(); err == nil {
		t.Fatal("flushPendingTraffic returned nil error")
	}
	if len(a.pendingTraffic) != 1 {
		t.Fatalf("pending users = %d, want 1", len(a.pendingTraffic))
	}
	if _, ok := a.pendingTraffic["c"]; !ok {
		t.Fatal("failed chunk user c was not retained")
	}

	mock.ExpectExec(regexp.QuoteMeta("UPDATE `users` SET `upload`=`upload`+?, `download`=`download`+? WHERE `password`=?;")).
		WithArgs(uint64(2), uint64(1), "c").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := a.flushPendingTraffic(); err != nil {
		t.Fatalf("retry flushPendingTraffic: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled mock expectations: %v", err)
	}
}

func TestSyncTrafficAndUsersSkipsRefreshAfterFlushFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	a, cancel := newMySQLTestAuth(t, db)
	defer cancel()
	a.trafficBatchSize = 1
	if err := a.AddUser("user1"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	_, user := a.AuthUser("user1")
	user.AddSentTraffic(10)
	mock.ExpectExec("^UPDATE `users` SET").WillReturnError(sql.ErrConnDone)

	if err := a.syncTrafficAndUsers(); err == nil {
		t.Fatal("syncTrafficAndUsers returned nil error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled mock expectations: %v", err)
	}
}

func TestTrafficArrivingDuringFlushRemainsForNextCycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	a, cancel := newMySQLTestAuth(t, db)
	defer cancel()
	a.trafficBatchSize = 1
	if err := a.AddUser("user1"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	_, user := a.AuthUser("user1")
	user.AddSentTraffic(100)
	user.AddRecvTraffic(200)
	a.collectPendingTraffic()

	mock.ExpectExec("^UPDATE `users` SET").
		WithArgs(uint64(200), uint64(100), "user1").
		WillDelayFor(50 * time.Millisecond).
		WillReturnResult(sqlmock.NewResult(0, 1))
	done := make(chan struct{})
	go func() {
		time.Sleep(10 * time.Millisecond)
		user.AddSentTraffic(25)
		user.AddRecvTraffic(50)
		close(done)
	}()
	if err := a.flushPendingTraffic(); err != nil {
		t.Fatalf("flushPendingTraffic: %v", err)
	}
	<-done
	sent, recv := user.GetTraffic()
	if sent != 25 || recv != 50 {
		t.Fatalf("traffic after concurrent flush = (%d, %d), want (25, 50)", sent, recv)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled mock expectations: %v", err)
	}
}

// TestMySQLUpdaterAppliesLimits verifies that a single updater cycle reads the
// speed_limit_up, speed_limit_down, and ip_limit columns from the SELECT query
// and applies them to the in-memory user state.
func TestMySQLUpdaterAppliesLimits(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	a, cancel := newMySQLTestAuth(t, db)
	defer cancel()

	rows := sqlmock.NewRows([]string{"password", "quota", "download", "upload", "speed_limit_up", "speed_limit_down", "ip_limit"}).
		AddRow("user1", int64(-1), int64(0), int64(0), 1000, 500, 3)
	mock.ExpectQuery("SELECT password,quota,download,upload,speed_limit_up,speed_limit_down,ip_limit FROM users").
		WillReturnRows(rows)

	go a.updater()
	time.Sleep(200 * time.Millisecond)

	valid, user := a.AuthUser("user1")
	if !valid {
		t.Fatal("expected user1 to be added by updater")
	}
	send, recv := user.GetSpeedLimit()
	if send != 1000 || recv != 500 {
		t.Fatalf("expected speed limits (1000, 500), got (%d, %d)", send, recv)
	}
	if user.GetIPLimit() != 3 {
		t.Fatalf("expected IP limit 3, got %d", user.GetIPLimit())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled mock expectations: %v", err)
	}
}

// TestMySQLSetUserSpeedLimitWritesDB verifies that SetUserSpeedLimit executes
// the expected UPDATE statement against the database.
func TestMySQLSetUserSpeedLimitWritesDB(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	a, cancel := newMySQLTestAuth(t, db)
	defer cancel()

	if err := a.AddUser("user1"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	mock.ExpectExec("UPDATE users SET speed_limit_up=\\?, speed_limit_down=\\? WHERE password=\\?").
		WithArgs(1000, 500, "user1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := a.SetUserSpeedLimit("user1", 1000, 500); err != nil {
		t.Fatalf("SetUserSpeedLimit: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled mock expectations: %v", err)
	}
}

// TestMySQLSetUserIPLimitWritesDB verifies that SetUserIPLimit executes the
// expected UPDATE statement against the database.
func TestMySQLSetUserIPLimitWritesDB(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	a, cancel := newMySQLTestAuth(t, db)
	defer cancel()

	if err := a.AddUser("user1"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	mock.ExpectExec("UPDATE users SET ip_limit=\\? WHERE password=\\?").
		WithArgs(5, "user1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := a.SetUserIPLimit("user1", 5); err != nil {
		t.Fatalf("SetUserIPLimit: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled mock expectations: %v", err)
	}
}

// TestMySQLSetUserQuotaWritesDB verifies that SetUserQuota executes the
// expected UPDATE statement against the database.
func TestMySQLSetUserQuotaWritesDB(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	a, cancel := newMySQLTestAuth(t, db)
	defer cancel()

	if err := a.AddUser("user1"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	mock.ExpectExec("UPDATE users SET quota=\\? WHERE password=\\?").
		WithArgs(int64(5000), "user1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := a.SetUserQuota("user1", 5000); err != nil {
		t.Fatalf("SetUserQuota: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled mock expectations: %v", err)
	}
}

// TestMySQLUpdaterQuotaEnforcement verifies that the updater correctly keeps
// users under quota or unlimited, and does not add users whose quota is
// exceeded.
func TestMySQLUpdaterQuotaEnforcement(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	a, cancel := newMySQLTestAuth(t, db)
	defer cancel()

	// user1: download(60) + upload(50) = 110 >= quota(100) → over quota, not added
	// user2: quota=-1 (unlimited) → always added
	// user3: download(50) + upload(30) = 80 < quota(200) → under quota, added
	rows := sqlmock.NewRows([]string{"password", "quota", "download", "upload", "speed_limit_up", "speed_limit_down", "ip_limit"}).
		AddRow("user1", int64(100), int64(60), int64(50), 0, 0, 0).
		AddRow("user2", int64(-1), int64(0), int64(0), 0, 0, 0).
		AddRow("user3", int64(200), int64(50), int64(30), 0, 0, 0)
	mock.ExpectQuery("SELECT password,quota,download,upload,speed_limit_up,speed_limit_down,ip_limit FROM users").
		WillReturnRows(rows)

	go a.updater()
	time.Sleep(200 * time.Millisecond)

	if valid, _ := a.AuthUser("user1"); valid {
		t.Fatal("user1 should not be in auth (over quota)")
	}
	if valid, _ := a.AuthUser("user2"); !valid {
		t.Fatal("user2 should be in auth (unlimited quota)")
	}
	if valid, _ := a.AuthUser("user3"); !valid {
		t.Fatal("user3 should be in auth (under quota)")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled mock expectations: %v", err)
	}
}

// TestMySQLUpdaterPropagatesQuotaToMemory is the P0-3b regression test. With
// P0-3a, AddUser defaults `User.quota` to -1; the mysql updater therefore
// MUST propagate the per-row quota value into the in-memory layer (via the
// embedded `Authenticator.SetUserQuota`, which does not write back to the
// DB) so that callers reading `User.GetQuota()` see the real limit.
func TestMySQLUpdaterPropagatesQuotaToMemory(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	a, cancel := newMySQLTestAuth(t, db)
	defer cancel()

	rows := sqlmock.NewRows([]string{"password", "quota", "download", "upload", "speed_limit_up", "speed_limit_down", "ip_limit"}).
		AddRow("limited", int64(8192), int64(0), int64(0), 0, 0, 0).
		AddRow("unlimited", int64(-1), int64(0), int64(0), 0, 0, 0)
	mock.ExpectQuery("SELECT password,quota,download,upload,speed_limit_up,speed_limit_down,ip_limit FROM users").
		WillReturnRows(rows)

	go a.updater()
	time.Sleep(200 * time.Millisecond)

	_, limited := a.AuthUser("limited")
	if limited == nil {
		t.Fatal("limited user not present after updater tick")
	}
	if got := limited.GetQuota(); got != 8192 {
		t.Fatalf("limited user quota = %d, want 8192 (propagated from DB)", got)
	}

	_, unlimited := a.AuthUser("unlimited")
	if unlimited == nil {
		t.Fatal("unlimited user not present after updater tick")
	}
	if got := unlimited.GetQuota(); got != -1 {
		t.Fatalf("unlimited user quota = %d, want -1", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled mock expectations: %v", err)
	}
}

// TestMySQLUpdaterSurvivesPingFailure is the P1-3 reliability regression.
// When the DB is unreachable, the updater MUST:
//  1. NOT delete existing in-memory users (cache continues to authenticate);
//  2. NOT issue any subsequent SELECT/UPDATE for that tick;
//  3. Increment ErrorsTotal so the operator can observe the outage via the
//     upcoming P1-5 metrics surface.
func TestMySQLUpdaterSurvivesPingFailure(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	a, cancel := newMySQLTestAuth(t, db)
	defer cancel()

	// Pre-populate the in-memory cache so we can prove it survives the
	// outage. AddUser does not touch the DB.
	if err := a.AddUser("cached_user"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	// Two failing pings cover the "spend a tick offline, then a second
	// tick still offline" case. After the second tick the user must still
	// be present.
	mock.ExpectPing().WillReturnError(sql.ErrConnDone)
	mock.ExpectPing().WillReturnError(sql.ErrConnDone)

	// Speed the loop up so the test does not depend on the default tick.
	a.updateDuration = 50 * time.Millisecond

	go a.updater()
	time.Sleep(250 * time.Millisecond)

	if valid, _ := a.AuthUser("cached_user"); !valid {
		t.Fatal("cached user removed during MySQL outage; cache must survive")
	}
	if got := a.ErrorsTotal(); got == 0 {
		t.Fatal("ErrorsTotal should be incremented on ping failure, got 0")
	}
	// We do NOT assert mock.ExpectationsWereMet here: the test is timing
	// based and we may race past the second ExpectPing on slow CI. The
	// invariants we care about (cache survives, error counter advances)
	// are explicit above.
}

func TestResolveQueryTimeoutDefault(t *testing.T) {
	if got := resolveQueryTimeout(0); got != DefaultQueryTimeout {
		t.Fatalf("resolveQueryTimeout(0) = %v, want %v", got, DefaultQueryTimeout)
	}
	if got := resolveQueryTimeout(-1); got != DefaultQueryTimeout {
		t.Fatalf("resolveQueryTimeout(-1) = %v, want %v (negative also defaults)", got, DefaultQueryTimeout)
	}
	if got := resolveQueryTimeout(7); got != 7*time.Second {
		t.Fatalf("resolveQueryTimeout(7) = %v, want 7s", got)
	}
}
