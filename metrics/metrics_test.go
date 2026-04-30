package metrics

import (
	"sync"
	"testing"
)

func TestSnapshotKeysPresent(t *testing.T) {
	snap := Snapshot()
	for _, k := range []string{
		KeyActiveConnections,
		KeyAuthFailures,
		KeyFallback,
		KeyQuotaCutoff,
		KeyRateLimitWaitTotalNS,
		KeyMySQLErrorsTotal,
		KeyGoroutines,
	} {
		if _, ok := snap[k]; !ok {
			t.Fatalf("snapshot missing key %q", k)
		}
	}
	if snap[KeyGoroutines] <= 0 {
		t.Fatalf("goroutines gauge non-positive: %d", snap[KeyGoroutines])
	}
}

func TestCountersAreConcurrencySafe(t *testing.T) {
	const goroutines = 16
	const perGoroutine = 1000

	startActive := Snapshot()[KeyActiveConnections]
	startAuth := Snapshot()[KeyAuthFailures]

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				IncActiveConnections()
				IncAuthFailures()
				IncFallback()
				IncQuotaCutoff()
				AddRateLimitWaitNanos(1)
				DecActiveConnections()
			}
		}()
	}
	wg.Wait()

	snap := Snapshot()
	if got, want := snap[KeyActiveConnections]-startActive, int64(0); got != want {
		t.Fatalf("active_connections drift: got %d, want %d (Inc/Dec must balance)", got, want)
	}
	if got := snap[KeyAuthFailures] - startAuth; got != int64(goroutines*perGoroutine) {
		t.Fatalf("auth_failures_total = %d, want %d", got, goroutines*perGoroutine)
	}
}

func TestMySQLErrorsProviderWiring(t *testing.T) {
	defer SetMySQLErrorsProvider(nil)

	// No provider: snapshot must report zero, not panic.
	SetMySQLErrorsProvider(nil)
	if got := Snapshot()[KeyMySQLErrorsTotal]; got != 0 {
		t.Fatalf("with no provider mysql_errors_total = %d, want 0", got)
	}

	SetMySQLErrorsProvider(func() uint64 { return 42 })
	if got := Snapshot()[KeyMySQLErrorsTotal]; got != 42 {
		t.Fatalf("provider value not propagated: got %d, want 42", got)
	}
}

func TestAddRateLimitWaitNanosIgnoresNonPositive(t *testing.T) {
	before := Snapshot()[KeyRateLimitWaitTotalNS]
	AddRateLimitWaitNanos(0)
	AddRateLimitWaitNanos(-100)
	if got := Snapshot()[KeyRateLimitWaitTotalNS]; got != before {
		t.Fatalf("non-positive samples must not advance counter: before=%d after=%d", before, got)
	}
}
