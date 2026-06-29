package mysql

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/log"
	"github.com/kis1yi/trojan-go/metrics"
	"github.com/kis1yi/trojan-go/statistic"
	"github.com/kis1yi/trojan-go/statistic/memory"
)

const Name = "MYSQL"

type trafficDelta struct {
	hash string
	sent uint64
	recv uint64
}

// healthWarnInterval bounds how often the updater loop emits a Warn log line
// when the database is unreachable. P1-3: do not flood the log with
// per-iteration failures during an outage; log once per interval and keep
// serving from the in-memory cache.
const healthWarnInterval = 30 * time.Second

type Authenticator struct {
	*memory.Authenticator
	db                *sql.DB
	updateDuration    time.Duration
	queryTimeout      time.Duration
	trafficBatchSize  int
	pendingTraffic    map[string]trafficDelta
	failedFlushCycles uint64
	ctx               context.Context
	// errCount is the in-process MySQL error counter exported as
	// "mysql_errors_total" via P1-5 observability. It is incremented on
	// any failed db.PingContext / db.QueryContext / db.ExecContext call
	// from the updater, and on Set* helpers below. Read with atomic.LoadUint64.
	errCount uint64
}

func (a *Authenticator) collectPendingTraffic() {
	if a.pendingTraffic == nil {
		a.pendingTraffic = make(map[string]trafficDelta)
	}
	for _, user := range a.ListUsers() {
		sent, recv := user.ResetTraffic()
		if sent == 0 && recv == 0 {
			continue
		}
		hash := user.GetHash()
		pending := a.pendingTraffic[hash]
		pending.hash = hash
		pending.sent += sent
		pending.recv += recv
		a.pendingTraffic[hash] = pending
	}
}

func (a *Authenticator) sortedPendingTraffic() []trafficDelta {
	pending := make([]trafficDelta, 0, len(a.pendingTraffic))
	for _, delta := range a.pendingTraffic {
		if delta.sent != 0 || delta.recv != 0 {
			pending = append(pending, delta)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].hash < pending[j].hash
	})
	return pending
}

func buildTrafficUpdate(batch []trafficDelta) (string, []interface{}) {
	if len(batch) == 1 {
		delta := batch[0]
		return "UPDATE `users` SET `upload`=`upload`+?, `download`=`download`+? WHERE `password`=?;", []interface{}{delta.recv, delta.sent, delta.hash}
	}

	var query strings.Builder
	query.WriteString("UPDATE `users` SET `upload`=`upload`+CASE `password`")
	args := make([]interface{}, 0, len(batch)*5)
	for _, delta := range batch {
		query.WriteString(" WHEN ? THEN ?")
		args = append(args, delta.hash, delta.recv)
	}
	query.WriteString(" ELSE 0 END, `download`=`download`+CASE `password`")
	for _, delta := range batch {
		query.WriteString(" WHEN ? THEN ?")
		args = append(args, delta.hash, delta.sent)
	}
	query.WriteString(" ELSE 0 END WHERE `password` IN (")
	for i, delta := range batch {
		if i > 0 {
			query.WriteByte(',')
		}
		query.WriteByte('?')
		args = append(args, delta.hash)
	}
	query.WriteString(");")
	return query.String(), args
}

func (a *Authenticator) pendingTrafficStats() (int, uint64) {
	var bytes uint64
	for _, delta := range a.pendingTraffic {
		bytes += delta.sent + delta.recv
	}
	return len(a.pendingTraffic), bytes
}

func (a *Authenticator) flushPendingTraffic() error {
	pending := a.sortedPendingTraffic()
	if len(pending) == 0 {
		a.failedFlushCycles = 0
		return nil
	}

	started := time.Now()
	batchSize := a.trafficBatchSize
	if batchSize <= 0 {
		batchSize = DefaultTrafficBatchSize
	}
	for start := 0; start < len(pending); start += batchSize {
		end := start + batchSize
		if end > len(pending) {
			end = len(pending)
		}
		batch := pending[start:end]
		query, args := buildTrafficUpdate(batch)
		ctx, cancel := a.queryCtx()
		_, err := a.db.ExecContext(ctx, query, args...)
		cancel()
		if err != nil {
			a.recordErr()
			a.failedFlushCycles++
			users, bytes := a.pendingTrafficStats()
			wrapped := common.NewError("failed to flush buffered traffic batch").Base(err)
			log.Errorf("%s; pending_users=%d pending_bytes=%d failed_cycles=%d flush_duration=%s", wrapped, users, bytes, a.failedFlushCycles, time.Since(started))
			return wrapped
		}
		for _, delta := range batch {
			delete(a.pendingTraffic, delta.hash)
		}
	}

	a.failedFlushCycles = 0
	log.Infof("buffered traffic has been written into the database; users=%d flush_duration=%s", len(pending), time.Since(started))
	return nil
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

func (a *Authenticator) refreshUsers() error {
	ctx, cancel := a.queryCtx()
	defer cancel()
	rows, err := a.db.QueryContext(ctx, "SELECT password,quota,download,upload,speed_limit_up,speed_limit_down,ip_limit FROM users")
	if err != nil {
		a.recordErr()
		wrapped := common.NewError("failed to pull data from the database").Base(err)
		log.Error(wrapped)
		return wrapped
	}
	defer rows.Close()

	userMap := make(map[string]bool)
	for rows.Next() {
		var hash string
		var quota, download, upload int64
		var speedLimitUp, speedLimitDown, ipLimit int
		if err := rows.Scan(&hash, &quota, &download, &upload, &speedLimitUp, &speedLimitDown, &ipLimit); err != nil {
			a.recordErr()
			wrapped := common.NewError("failed to obtain data from the query result").Base(err)
			log.Error(wrapped)
			return wrapped
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
	if err := rows.Err(); err != nil {
		a.recordErr()
		wrapped := common.NewError("failed while reading user rows").Base(err)
		log.Error(wrapped)
		return wrapped
	}

	for _, user := range a.ListUsers() {
		if _, ok := userMap[user.GetHash()]; !ok {
			a.DelUser(user.GetHash())
		}
	}
	return nil
}

func (a *Authenticator) syncTrafficAndUsers() error {
	a.collectPendingTraffic()
	if err := a.flushPendingTraffic(); err != nil {
		return err
	}
	return a.refreshUsers()
}

func (a *Authenticator) waitForNextUpdate() bool {
	select {
	case <-time.After(a.updateDuration):
		return true
	case <-a.ctx.Done():
		log.Debug("MySQL daemon exiting...")
		return false
	}
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
			if !a.waitForNextUpdate() {
				return
			}
			continue
		}
		lastWarnAt = time.Time{}

		if err := a.syncTrafficAndUsers(); err != nil {
			if !a.waitForNextUpdate() {
				return
			}
			continue
		}
		if !a.waitForNextUpdate() {
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

func connectDatabase(driverName, username, password, ip string, port int, dbName string, tlsMode, tlsCA string) (*sql.DB, error) {
	tlsParam := ""
	switch strings.ToLower(tlsMode) {
	case "true", "skip-verify":
		tlsParam = "&tls=" + strings.ToLower(tlsMode)
	case "custom":
		if tlsCA == "" {
			return nil, common.NewError("mysql tls_mode is 'custom' but tls_ca is not set")
		}
		caPEM, err := os.ReadFile(tlsCA)
		if err != nil {
			return nil, common.NewError("failed to read mysql tls_ca file").Base(err)
		}
		rootCAs := x509.NewCertPool()
		if ok := rootCAs.AppendCertsFromPEM(caPEM); !ok {
			return nil, common.NewError("failed to append mysql tls_ca certificates")
		}
		tlsConfig := &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		}
		if err := mysql.RegisterTLSConfig("trojan-go-custom", tlsConfig); err != nil {
			return nil, common.NewError("failed to register mysql custom TLS config").Base(err)
		}
		tlsParam = "&tls=trojan-go-custom"
	}

	path := strings.Join([]string{username, ":", password, "@tcp(", ip, ":", fmt.Sprintf("%d", port), ")/", dbName, "?charset=utf8"}, "")
	if tlsParam != "" {
		path += tlsParam
	}
	return sql.Open(driverName, path)
}

func NewAuthenticator(ctx context.Context) (statistic.Authenticator, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	trafficBatchSize, err := resolveTrafficBatchSize(cfg.MySQL.TrafficBatchSize)
	if err != nil {
		return nil, err
	}
	db, err := connectDatabase(
		"mysql",
		cfg.MySQL.Username,
		cfg.MySQL.Password,
		cfg.MySQL.ServerHost,
		cfg.MySQL.ServerPort,
		cfg.MySQL.Database,
		cfg.MySQL.TLSMode,
		cfg.MySQL.TLSCA,
	)
	if err != nil {
		return nil, common.NewError("Failed to connect to database server").Base(err)
	}
	memoryAuth, err := memory.NewAuthenticator(ctx)
	if err != nil {
		return nil, err
	}
	a := &Authenticator{
		db:               db,
		ctx:              ctx,
		updateDuration:   time.Duration(cfg.MySQL.CheckRate) * time.Second,
		queryTimeout:     resolveQueryTimeout(cfg.MySQL.QueryTimeout),
		trafficBatchSize: trafficBatchSize,
		pendingTraffic:   make(map[string]trafficDelta),
		Authenticator:    memoryAuth.(*memory.Authenticator),
	}
	// P1-5: hand the metrics package a reference to this authenticator's
	// error counter so Snapshot() can publish mysql_errors_total without an
	// import cycle. Replacing a previously-installed provider is fine: only
	// one MySQL authenticator is ever active at a time per process.
	metrics.SetMySQLErrorsProvider(a.ErrorsTotal)
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

func resolveTrafficBatchSize(raw int) (int, error) {
	if raw <= 0 {
		return DefaultTrafficBatchSize, nil
	}
	if raw > MaxTrafficBatchSize {
		return 0, common.NewErrorf("mysql traffic_batch_size must be between 1 and %d", MaxTrafficBatchSize)
	}
	return raw, nil
}

func init() {
	statistic.RegisterAuthenticatorCreator(Name, NewAuthenticator)
}
