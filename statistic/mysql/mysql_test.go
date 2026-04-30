package mysql

import (
	"context"
	"database/sql"
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
		db:             db,
		ctx:            ctx,
		updateDuration: time.Second,
		queryTimeout:   DefaultQueryTimeout,
		Authenticator:  memAuth.(*memory.Authenticator),
	}
	return a, cancel
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
//   1. NOT delete existing in-memory users (cache continues to authenticate);
//   2. NOT issue any subsequent SELECT/UPDATE for that tick;
//   3. Increment ErrorsTotal so the operator can observe the outage via the
//      upcoming P1-5 metrics surface.
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
