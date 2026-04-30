package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	// MySQL Driver
	_ "github.com/go-sql-driver/mysql"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/log"
	"github.com/kis1yi/trojan-go/statistic"
	"github.com/kis1yi/trojan-go/statistic/memory"
)

const Name = "MYSQL"

// healthWarnInterval bounds how often the updater loop emits a Warn log line
// when the database is unreachable. P1-3: do not flood the log with
// per-iteration failures during an outage; log once per interval and keep
// serving from the in-memory cache.
const healthWarnInterval = 30 * time.Second

type Authenticator struct {
	*memory.Authenticator
	db             *sql.DB
	updateDuration time.Duration
	queryTimeout   time.Duration
	ctx            context.Context
	// errCount is the in-process MySQL error counter exported as
	// "mysql_errors_total" via P1-5 observability. It is incremented on
	// any failed db.PingContext / db.QueryContext / db.ExecContext call
	// from the updater, and on Set* helpers below. Read with atomic.LoadUint64.
	errCount uint64
}

// recordErr increments the in-process MySQL error counter. Always call it
// after wrapping the underlying error with common.NewError.
func (a *Authenticator) recordErr() {
	atomic.AddUint64(&a.errCount, 1)
}

// ErrorsTotal returns the lifetime count of MySQL errors observed by this
// authenticator. Exposed for the upcoming P1-5 metrics surface.
func (a *Authenticator) ErrorsTotal() uint64 {
	return atomic.LoadUint64(&a.errCount)
}

// queryCtx returns a context whose deadline is bounded by a.queryTimeout and
// the parent ctx. Callers MUST defer the returned cancel.
func (a *Authenticator) queryCtx() (context.Context, context.CancelFunc) {
	if a.queryTimeout <= 0 {
		// Defensive: zero timeout disables the deadline, which we never want.
		return context.WithTimeout(a.ctx, DefaultQueryTimeout)
	}
	return context.WithTimeout(a.ctx, a.queryTimeout)
}

// pingDB is a lightweight reachability probe used at the top of every
// updater iteration. Returns the wrapped error on failure; the caller is
// responsible for the rate-limited Warn log.
func (a *Authenticator) pingDB() error {
	ctx, cancel := a.queryCtx()
	defer cancel()
	if err := a.db.PingContext(ctx); err != nil {
		a.recordErr()
		return common.NewError("mysql ping failed").Base(err)
	}
	return nil
}

func (a *Authenticator) updater() {
	var lastWarnAt time.Time
	for {
		// P1-3: probe the DB once per iteration. On failure we log at most
		// once per healthWarnInterval and skip this tick — existing
		// in-memory users keep authenticating from the cache, so the proxy
		// continues to serve traffic during a transient MySQL outage.
		if err := a.pingDB(); err != nil {
			if time.Since(lastWarnAt) > healthWarnInterval {
				log.Warn(common.NewError("mysql unreachable, serving from cache").Base(err))
				lastWarnAt = time.Now()
			}
			select {
			case <-time.After(a.updateDuration):
				continue
			case <-a.ctx.Done():
				log.Debug("MySQL daemon exiting...")
				return
			}
		}
		lastWarnAt = time.Time{}

		for _, user := range a.ListUsers() {
			// swap upload and download for users
			hash := user.GetHash()
			sent, recv := user.ResetTraffic()

			ctx, cancel := a.queryCtx()
			s, err := a.db.ExecContext(ctx, "UPDATE `users` SET `upload`=`upload`+?, `download`=`download`+? WHERE `password`=?;", recv, sent, hash)
			cancel()
			if err != nil {
				a.recordErr()
				log.Error(common.NewError("failed to update data to user table").Base(err))
				continue
			}
			if r, err := s.RowsAffected(); err != nil {
				if r == 0 {
					a.DelUser(hash)
				}
			}
		}
		log.Info("buffered data has been written into the database")

		// update memory
		ctx, cancel := a.queryCtx()
		rows, err := a.db.QueryContext(ctx, "SELECT password,quota,download,upload,speed_limit_up,speed_limit_down,ip_limit FROM users")
		if err != nil || (rows != nil && rows.Err() != nil) {
			a.recordErr()
			log.Error(common.NewError("failed to pull data from the database").Base(err))
			if rows != nil {
				_ = rows.Close()
			}
			cancel()
			select {
			case <-time.After(a.updateDuration):
				continue
			case <-a.ctx.Done():
				log.Debug("MySQL daemon exiting...")
				return
			}
		}
		userMap := make(map[string]bool)
		for rows.Next() {
			var hash string
			var quota, download, upload int64
			var speedLimitUp, speedLimitDown, ipLimit int
			err := rows.Scan(&hash, &quota, &download, &upload, &speedLimitUp, &speedLimitDown, &ipLimit)
			if err != nil {
				a.recordErr()
				log.Error(common.NewError("failed to obtain data from the query result").Base(err))
				break
			}
			userMap[hash] = true
			if download+upload < quota || quota < 0 {
				a.AddUser(hash)
				a.Authenticator.SetUserSpeedLimit(hash, speedLimitUp, speedLimitDown)
				a.Authenticator.SetUserIPLimit(hash, ipLimit)
				// P0-3b: propagate quota into the memory layer so that
				// in-process callers (e.g. the active-cutoff hook in
				// P0-3d, and `User.GetQuota` consumers) see the real
				// per-user limit. Use the embedded `Authenticator`'s
				// `SetUserQuota`, NOT the wrapper above, to avoid issuing
				// a redundant `UPDATE users SET quota=?` against the DB
				// for a value we just read from it.
				a.Authenticator.SetUserQuota(hash, quota)
			} else {
				a.DelUser(hash)
			}
		}
		// P1-3: every *sql.Rows must be Close()d. The original code never
		// closed `rows`, leaking the underlying connection back to the pool
		// only when GC eventually finalised the Rows. Close explicitly so
		// the connection is returned immediately on every iteration.
		_ = rows.Close()
		cancel()
		for _, user := range a.ListUsers() {
			if _, ok := userMap[user.GetHash()]; !ok {
				a.DelUser(user.GetHash())
			}
		}

		select {
		case <-time.After(a.updateDuration):
		case <-a.ctx.Done():
			log.Debug("MySQL daemon exiting...")
			return
		}
	}
}

func (a *Authenticator) SetUserSpeedLimit(hash string, send, recv int) error {
	err := a.Authenticator.SetUserSpeedLimit(hash, send, recv)
	ctx, cancel := a.queryCtx()
	defer cancel()
	_, dbErr := a.db.ExecContext(ctx, "UPDATE users SET speed_limit_up=?, speed_limit_down=? WHERE password=?", send, recv, hash)
	if dbErr != nil {
		a.recordErr()
		log.Error(common.NewError("failed to update speed limit for user").Base(dbErr))
	}
	return err
}

func (a *Authenticator) SetUserIPLimit(hash string, limit int) error {
	err := a.Authenticator.SetUserIPLimit(hash, limit)
	ctx, cancel := a.queryCtx()
	defer cancel()
	_, dbErr := a.db.ExecContext(ctx, "UPDATE users SET ip_limit=? WHERE password=?", limit, hash)
	if dbErr != nil {
		a.recordErr()
		log.Error(common.NewError("failed to update ip limit for user").Base(dbErr))
	}
	return err
}

func (a *Authenticator) SetUserQuota(hash string, quota int64) error {
	err := a.Authenticator.SetUserQuota(hash, quota)
	ctx, cancel := a.queryCtx()
	defer cancel()
	_, dbErr := a.db.ExecContext(ctx, "UPDATE users SET quota=? WHERE password=?", quota, hash)
	if dbErr != nil {
		a.recordErr()
		log.Error(common.NewError("failed to update quota for user").Base(dbErr))
	}
	return err
}

func connectDatabase(driverName, username, password, ip string, port int, dbName string) (*sql.DB, error) {
	path := strings.Join([]string{username, ":", password, "@tcp(", ip, ":", fmt.Sprintf("%d", port), ")/", dbName, "?charset=utf8"}, "")
	return sql.Open(driverName, path)
}

func NewAuthenticator(ctx context.Context) (statistic.Authenticator, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	db, err := connectDatabase(
		"mysql",
		cfg.MySQL.Username,
		cfg.MySQL.Password,
		cfg.MySQL.ServerHost,
		cfg.MySQL.ServerPort,
		cfg.MySQL.Database,
	)
	if err != nil {
		return nil, common.NewError("Failed to connect to database server").Base(err)
	}
	memoryAuth, err := memory.NewAuthenticator(ctx)
	if err != nil {
		return nil, err
	}
	a := &Authenticator{
		db:             db,
		ctx:            ctx,
		updateDuration: time.Duration(cfg.MySQL.CheckRate) * time.Second,
		queryTimeout:   resolveQueryTimeout(cfg.MySQL.QueryTimeout),
		Authenticator:  memoryAuth.(*memory.Authenticator),
	}
	go a.updater()
	log.Debug("mysql authenticator created")
	return a, nil
}

// resolveQueryTimeout maps the configured value (seconds) to a duration
// using the same default-rules style as common/timeout: zero ⇒ default,
// negative ⇒ also default (a disabled DB timeout is never desirable; we
// would rather fail fast than hang the updater forever).
func resolveQueryTimeout(raw int) time.Duration {
	if raw <= 0 {
		return DefaultQueryTimeout
	}
	return time.Duration(raw) * time.Second
}

func init() {
	statistic.RegisterAuthenticatorCreator(Name, NewAuthenticator)
}
