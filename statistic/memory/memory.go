package memory

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/log"
	"github.com/kis1yi/trojan-go/statistic"
	"github.com/kis1yi/trojan-go/statistic/sqlite"
)

const Name = "MEMORY"

type User struct {
	// WARNING: do not change the order of these fields.
	// 64-bit fields that use `sync/atomic` package functions
	// must be 64-bit aligned on 32-bit systems.
	// Reference: https://github.com/golang/go/issues/599
	// Solution: https://github.com/golang/go/issues/11891#issuecomment-433623786
	Sent        uint64
	Recv        uint64
	lastSent    uint64
	lastRecv    uint64
	sendSpeed   uint64
	recvSpeed   uint64
	quota       int64
	Hash        string
	ipLock      sync.Mutex
	ipTable     map[string]int
	ipNum       int
	MaxIPNum    int
	limiterLock sync.RWMutex
	SendLimiter *rate.Limiter
	RecvLimiter *rate.Limiter
	ctx         context.Context
	cancel      context.CancelFunc
	// P0-3d: dedicated cutoff signal, closed exactly once when the user is
	// removed (DelUser/Close) or when their quota is exceeded. This is
	// intentionally NOT closed when the parent authenticator context is
	// cancelled (e.g. server shutdown), because shutdown should let the
	// normal connection-close path tear down tunnels rather than racing
	// the relay loop with an out-of-band conn close.
	cutoff     chan struct{}
	cutoffOnce sync.Once
}

func (u *User) fireCutoff() {
	u.cutoffOnce.Do(func() { close(u.cutoff) })
}

func (u *User) Close() error {
	u.ResetTraffic()
	u.fireCutoff()
	u.cancel()
	return nil
}

func (u *User) AddIP(ip string) bool {
	u.ipLock.Lock()
	defer u.ipLock.Unlock()
	if u.MaxIPNum <= 0 {
		return true
	}
	if count, found := u.ipTable[ip]; found {
		u.ipTable[ip] = count + 1
		return true
	}
	if u.ipNum+1 > u.MaxIPNum {
		return false
	}
	u.ipTable[ip] = 1
	u.ipNum++
	return true
}

func (u *User) DelIP(ip string) bool {
	u.ipLock.Lock()
	defer u.ipLock.Unlock()
	if u.MaxIPNum <= 0 {
		return true
	}
	count, found := u.ipTable[ip]
	if !found {
		return false
	}
	if count <= 1 {
		delete(u.ipTable, ip)
		u.ipNum--
	} else {
		u.ipTable[ip] = count - 1
	}
	return true
}

func (u *User) GetIP() int {
	u.ipLock.Lock()
	defer u.ipLock.Unlock()
	return u.ipNum
}

func (u *User) setIPLimit(n int) {
	u.ipLock.Lock()
	defer u.ipLock.Unlock()
	u.MaxIPNum = n
}

func (u *User) GetIPLimit() int {
	u.ipLock.Lock()
	defer u.ipLock.Unlock()
	return u.MaxIPNum
}

func (u *User) GetQuota() int64 {
	return atomic.LoadInt64(&u.quota)
}

func (u *User) SetQuota(quota int64) {
	atomic.StoreInt64(&u.quota, quota)
}

// Done satisfies statistic.Metadata. Returns a channel that is closed when
// the user is cut off — either because their quota was exceeded or because
// they were removed by the operator (DelUser / Close). Authenticator
// shutdown does NOT fire this channel; tunnel teardown during shutdown is
// handled by the normal connection-close path. Callers (typically a
// tunnel.Conn wrapper) can react to cutoff by closing the underlying
// transport so in-flight reads observe a closed-conn error.
func (u *User) Done() <-chan struct{} {
	return u.cutoff
}

// minRateLimitBurst is the floor on the burst size when constructing a new
// rate.Limiter. Without this floor, configurations such as 4 KiB/s would
// produce burst = 8 KiB which is smaller than the relay buffer (32 KiB by
// default). Calls to WaitN(burst+1) return ErrLimitExceededN immediately and
// the limiter is silently bypassed. We default to max(2*limit, 64 KiB) to
// ensure burst is always >= the relay buffer; callers feed the limiter in
// chunks of at most `burst` bytes (see addLimited below).
const minRateLimitBurst = 64 * 1024

func burstFor(limit int) int {
	b := limit * 2
	if b < minRateLimitBurst {
		b = minRateLimitBurst
	}
	return b
}

// addLimited applies the configured rate limit to `n` bytes of traffic. The
// limiter pointer is snapshotted under the read lock and the lock is
// released before WaitN runs, so concurrent SetSpeedLimit reconfigurations
// are not blocked by long throttled writes. The work is chunked at
// `limiter.Burst()` boundaries so a single relay write larger than the burst
// is not silently passed through unthrottled.
func (u *User) addLimited(limiter *rate.Limiter, n int) {
	if limiter == nil || n <= 0 {
		return
	}
	burst := limiter.Burst()
	if burst <= 0 {
		return
	}
	remaining := n
	for remaining > 0 {
		chunk := remaining
		if chunk > burst {
			chunk = burst
		}
		if err := limiter.WaitN(u.ctx, chunk); err != nil {
			// Context cancellation is normal on connection close; log at
			// Debug and stop counting. Do not raise to Error — it would spam
			// the log on every closed connection that was being throttled.
			log.Debug("rate limiter wait:", err)
			return
		}
		remaining -= chunk
	}
}

func (u *User) AddSentTraffic(sent int) {
	u.limiterLock.RLock()
	limiter := u.SendLimiter
	u.limiterLock.RUnlock()
	u.addLimited(limiter, sent)
	total := atomic.AddUint64(&u.Sent, uint64(sent))
	u.checkQuota(total + atomic.LoadUint64(&u.Recv))
}

func (u *User) AddRecvTraffic(recv int) {
	u.limiterLock.RLock()
	limiter := u.RecvLimiter
	u.limiterLock.RUnlock()
	u.addLimited(limiter, recv)
	total := atomic.AddUint64(&u.Recv, uint64(recv))
	u.checkQuota(total + atomic.LoadUint64(&u.Sent))
}

// checkQuota implements the P0-3d active cutoff. The previous behaviour
// only enforced quota at the next 10 s SQLite/MySQL sweep, allowing a
// single tunnel to overshoot its byte budget by gigabytes between ticks.
// Now, every traffic accounting call compares the running total against
// the per-user quota and cancels `u.ctx` as soon as the threshold is
// crossed. The cancellation propagates immediately into:
//   - any in-flight `WaitN` call inside `addLimited` (see the rate limiter
//     wait error path),
//   - the `relayConnLoop`/`relayPacketLoop` reads in `proxy/proxy.go` that
//     are wrapped with `idleReader` / `SetReadDeadline` (P0-1),
//   - the `speedUpdater` and `trafficUpdater` goroutines started by
//     `Authenticator.AddUser`.
// `Close()` is idempotent w.r.t. cancel, so racing callers are safe.
func (u *User) checkQuota(total uint64) {
	q := atomic.LoadInt64(&u.quota)
	if q <= 0 {
		return // <0 unlimited, ==0 disabled (no enforcement, see P0-3a/c)
	}
	if total >= uint64(q) {
		u.fireCutoff()
		u.cancel()
	}
}

func (u *User) SetSpeedLimit(send, recv int) {
	u.limiterLock.Lock()
	defer u.limiterLock.Unlock()

	if send <= 0 {
		u.SendLimiter = nil
	} else {
		u.SendLimiter = rate.NewLimiter(rate.Limit(send), burstFor(send))
	}
	if recv <= 0 {
		u.RecvLimiter = nil
	} else {
		u.RecvLimiter = rate.NewLimiter(rate.Limit(recv), burstFor(recv))
	}
}

func (u *User) GetSpeedLimit() (send, recv int) {
	u.limiterLock.RLock()
	defer u.limiterLock.RUnlock()

	if u.SendLimiter != nil {
		send = int(u.SendLimiter.Limit())
	}
	if u.RecvLimiter != nil {
		recv = int(u.RecvLimiter.Limit())
	}
	return
}

func (u *User) GetHash() string {
	return u.Hash
}

func (u *User) setTraffic(send, recv uint64) {
	atomic.StoreUint64(&u.Sent, send)
	atomic.StoreUint64(&u.Recv, recv)
}

func (u *User) GetTraffic() (uint64, uint64) {
	return atomic.LoadUint64(&u.Sent), atomic.LoadUint64(&u.Recv)
}

func (u *User) ResetTraffic() (uint64, uint64) {
	sent := atomic.SwapUint64(&u.Sent, 0)
	recv := atomic.SwapUint64(&u.Recv, 0)
	atomic.StoreUint64(&u.lastSent, 0)
	atomic.StoreUint64(&u.lastRecv, 0)
	return sent, recv
}

func (u *User) speedUpdater() {
	ticker := time.NewTicker(time.Second)
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-ticker.C:
			sent, recv := u.GetTraffic()
			lastSent := atomic.LoadUint64(&u.lastSent)
			lastRecv := atomic.LoadUint64(&u.lastRecv)
			atomic.StoreUint64(&u.sendSpeed, sent-lastSent)
			atomic.StoreUint64(&u.recvSpeed, recv-lastRecv)
			atomic.StoreUint64(&u.lastSent, sent)
			atomic.StoreUint64(&u.lastRecv, recv)
		}
	}
}

func (u *User) trafficUpdater(pst statistic.Persistencer) {
	ticker := time.NewTicker(10 * time.Second)
	var lastSent, lastRecv uint64
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-ticker.C:
			if pst != nil {
				sent, recv := u.GetTraffic()
				if sent != lastSent || recv != lastRecv {
					log.Debugf("Update %s traffic", log.RedactHash(u.Hash))
					err := pst.UpdateUserTraffic(u.Hash, sent, recv)
					if err != nil {
						log.Debugf("Update user %s traffic failed: %s", log.RedactHash(u.Hash), err)
						continue
					}
					lastRecv = recv
					lastSent = sent
				}
			}
		}
	}
}

func (u *User) GetSpeed() (uint64, uint64) {
	return atomic.LoadUint64(&u.sendSpeed), atomic.LoadUint64(&u.recvSpeed)
}

type Authenticator struct {
	users  sync.Map
	pst    statistic.Persistencer
	ctx    context.Context
	cancel context.CancelFunc
}

func (a *Authenticator) AuthUser(hash string) (bool, statistic.User) {
	if user, found := a.users.Load(hash); found {
		return true, user.(*User)
	}
	return false, nil
}

func (a *Authenticator) AddUser(hash string) error {
	if _, found := a.users.Load(hash); found {
		return common.NewError("hash " + hash + " is already exist")
	}
	ctx, cancel := context.WithCancel(a.ctx)
	meter := &User{
		Hash:    hash,
		ipTable: make(map[string]int),
		ctx:     ctx,
		cancel:  cancel,
		cutoff:  make(chan struct{}),
		// P0-3a: default quota to -1 (unlimited). Without this, statically
		// configured users (loaded via cfg.Passwords) would be created with
		// quota == 0, which the SQLite quota enforcement loop interprets as
		// "disabled / over quota" and immediately removes the user, breaking
		// authentication for the YAML/JSON `passwords` config path.
		quota: -1,
	}
	go meter.speedUpdater()
	a.users.Store(hash, meter)
	if a.pst != nil {
		go meter.trafficUpdater(a.pst)
		err := a.pst.SaveUser(meter)
		if err != nil {
			log.Errorf("Save user %s failed: %s", log.RedactHash(hash), err)
		}
	}
	return nil
}

func (a *Authenticator) DelUser(hash string) error {
	meter, found := a.users.Load(hash)
	if !found {
		return common.NewError("hash " + hash + " not found")
	}
	meter.(*User).Close()
	a.users.Delete(hash)
	if a.pst != nil {
		a.pst.DeleteUser(hash)
	}
	return nil
}

func (a *Authenticator) ListUsers() []statistic.User {
	result := make([]statistic.User, 0)
	a.users.Range(func(k, v interface{}) bool {
		result = append(result, v.(*User))
		return true
	})
	return result
}

func (a *Authenticator) Close() error {
	if a.cancel != nil {
		a.cancel()
	}
	a.users.Range(func(k, v interface{}) bool {
		v.(*User).Close()
		return true
	})
	if closer, ok := a.pst.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			return common.NewError("failed to close persistencer").Base(err)
		}
	}
	return nil
}

func (a *Authenticator) SetUserTraffic(hash string, sent, recv uint64) error {
	u, exist := a.users.Load(hash)
	if !exist {
		return common.NewErrorf("user %v not found", hash)
	}
	user := u.(*User)
	user.setTraffic(sent, recv)
	if a.pst != nil {
		err := a.pst.SaveUser(user)
		if err != nil {
			log.Errorf("Save user %s failed: %s", log.RedactHash(hash), err)
		}
	}
	return nil
}

func (a *Authenticator) SetUserSpeedLimit(hash string, send, recv int) error {
	u, exist := a.users.Load(hash)
	if !exist {
		return common.NewErrorf("user %v not found", hash)
	}
	user := u.(*User)
	user.SetSpeedLimit(send, recv)
	if a.pst != nil {
		err := a.pst.SaveUser(user)
		if err != nil {
			log.Errorf("Save user %s failed: %s", log.RedactHash(hash), err)
		}
	}
	return nil
}

func (a *Authenticator) SetUserIPLimit(hash string, limit int) error {
	u, exist := a.users.Load(hash)
	if !exist {
		return common.NewErrorf("user %v not found", hash)
	}
	user := u.(*User)
	user.setIPLimit(limit)
	if a.pst != nil {
		err := a.pst.SaveUser(user)
		if err != nil {
			log.Errorf("Save user %s failed: %s", log.RedactHash(hash), err)
		}
	}
	return nil
}

func (a *Authenticator) SetUserQuota(hash string, quota int64) error {
	u, exist := a.users.Load(hash)
	if !exist {
		return common.NewErrorf("user %v not found", hash)
	}
	user := u.(*User)
	user.SetQuota(quota)
	if a.pst != nil {
		err := a.pst.SaveUser(user)
		if err != nil {
			log.Errorf("Save user %s failed: %s", log.RedactHash(hash), err)
		}
	}
	return nil
}

func NewAuthenticator(ctx context.Context) (statistic.Authenticator, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	a := &Authenticator{}
	a.ctx, a.cancel = context.WithCancel(ctx)
	var err error
	if cfg.Sqlite != "" {
		a.pst, err = sqlite.NewSqlitePersistencer(cfg.Sqlite)
		if err != nil {
			return nil, err
		}
	}
	if a.pst != nil {
		err := a.pst.ListUser(func(hash string, u statistic.Metadata) bool {
			if _, found := a.users.Load(hash); found {
				log.Error("hash " + log.RedactHash(hash) + " is already exist")
				return true
			}
			ctx, cancel := context.WithCancel(a.ctx)
			user := &User{
				Hash:    hash,
				ipTable: make(map[string]int),
				ctx:     ctx,
				cancel:  cancel,
			}
			user.setIPLimit(u.GetIPLimit())
			user.SetSpeedLimit(u.GetSpeedLimit())
			user.setTraffic(u.GetTraffic())
			user.SetQuota(u.GetQuota())
			go user.speedUpdater()
			go user.trafficUpdater(a.pst)
			a.users.Store(hash, user)
			return true
		})
		if err != nil {
			log.Errorf("List user from persistencer: %s", err)
		}
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-a.ctx.Done():
					return
				case <-ticker.C:
					a.users.Range(func(k, v interface{}) bool {
						user := v.(*User)
						quota := user.GetQuota()
						if quota > 0 {
							sent, recv := user.GetTraffic()
							if sent+recv >= uint64(quota) {
								a.DelUser(user.Hash)
							}
						}
						return true
					})
				}
			}
		}()
	}
	for _, password := range cfg.Passwords {
		hash := common.SHA224String(password)
		a.AddUser(hash)
	}
	log.Debug("memory authenticator created")
	return a, nil
}

func init() {
	statistic.RegisterAuthenticatorCreator(Name, NewAuthenticator)
}
