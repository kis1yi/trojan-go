// Package metrics provides a tiny in-process counter surface for the 2026
// hardening cycle (P1-5). It is intentionally minimal:
//   - no external dependencies (no Prometheus, no expvar);
//   - all counters are sync/atomic uint64 / int64;
//   - Snapshot() returns a flat map suitable for the GetMetrics gRPC RPC
//     once that wire surface is added in a follow-up.
//
// Counter naming follows the plan and is stable; consumers may rely on the
// keys returned by Snapshot:
//
//	active_connections          gauge, current accepted trojan tunnels
//	auth_failures_total         counter, rejected trojan handshakes
//	fallback_total              counter, redirector dispatches
//	quota_cutoff_total          counter, users hitting their quota cap
//	rate_limit_wait_total_ns    counter, cumulative time spent in rate.Limiter.WaitN
//	mysql_errors_total          counter, MySQL backend errors (sourced from statistic/mysql)
//	goroutines                  gauge, runtime.NumGoroutine() at sample time
//
// All counters monotonically increase except active_connections (up/down)
// and goroutines (sampled). Read with Snapshot; write through the helpers
// below. Every helper is safe for concurrent use.
package metrics

import (
	"runtime"
	"sync/atomic"
)

// Counter ids. Keep these as exported constants so internal callers can use
// IncCounter(metrics.AuthFailures) without typo risk.
const (
	KeyActiveConnections    = "active_connections"
	KeyAuthFailures         = "auth_failures_total"
	KeyFallback             = "fallback_total"
	KeyQuotaCutoff          = "quota_cutoff_total"
	KeyRateLimitWaitTotalNS = "rate_limit_wait_total_ns"
	KeyMySQLErrorsTotal     = "mysql_errors_total"
	KeyGoroutines           = "goroutines"
)

var (
	activeConnections   int64  // gauge
	authFailures        uint64 // counter
	fallbackTotal       uint64 // counter
	quotaCutoffTotal    uint64 // counter
	rateLimitWaitNanos  uint64 // counter
	mysqlErrorsProvider func() uint64
)

// IncActiveConnections / DecActiveConnections track the live trojan tunnel
// count. Use a deferred Dec immediately after a successful Inc to avoid
// drift on early-return paths.
func IncActiveConnections() { atomic.AddInt64(&activeConnections, 1) }
func DecActiveConnections() { atomic.AddInt64(&activeConnections, -1) }

// IncAuthFailures increments the rejected-handshake counter. Call from the
// trojan auth path after the handshake is conclusively rejected (NOT for
// fallback dispatches — those have their own counter).
func IncAuthFailures() { atomic.AddUint64(&authFailures, 1) }

// IncFallback increments the redirector dispatch counter. Per-reason
// breakdown is deferred until the gRPC GetMetrics RPC lands (the wire type
// for that is map<string,int64>; a single bucket is the only sensible thing
// to expose without sub-keys).
func IncFallback() { atomic.AddUint64(&fallbackTotal, 1) }

// IncQuotaCutoff increments the per-user-quota-exceeded counter. Called
// from the statistic/memory layer when a user's cutoff signal fires.
func IncQuotaCutoff() { atomic.AddUint64(&quotaCutoffTotal, 1) }

// AddRateLimitWaitNanos accumulates time spent inside rate.Limiter.WaitN.
// The caller is expected to measure with time.Since (in nanoseconds) around
// the WaitN invocation.
func AddRateLimitWaitNanos(ns int64) {
	if ns <= 0 {
		return
	}
	atomic.AddUint64(&rateLimitWaitNanos, uint64(ns))
}

// SetMySQLErrorsProvider lets the statistic/mysql package register a
// callback that exposes its own error counter through Snapshot without
// creating an import cycle. Calling with nil is a no-op.
func SetMySQLErrorsProvider(p func() uint64) {
	mysqlErrorsProvider = p
}

// Snapshot returns the current value of every counter as a flat map keyed
// by the exported KeyX constants. The returned map is a fresh allocation;
// callers may mutate it freely.
func Snapshot() map[string]int64 {
	out := map[string]int64{
		KeyActiveConnections:    atomic.LoadInt64(&activeConnections),
		KeyAuthFailures:         int64(atomic.LoadUint64(&authFailures)),
		KeyFallback:             int64(atomic.LoadUint64(&fallbackTotal)),
		KeyQuotaCutoff:          int64(atomic.LoadUint64(&quotaCutoffTotal)),
		KeyRateLimitWaitTotalNS: int64(atomic.LoadUint64(&rateLimitWaitNanos)),
		KeyGoroutines:           int64(runtime.NumGoroutine()),
	}
	if mysqlErrorsProvider != nil {
		out[KeyMySQLErrorsTotal] = int64(mysqlErrorsProvider())
	} else {
		out[KeyMySQLErrorsTotal] = 0
	}
	return out
}
