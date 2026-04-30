// Package queue provides a unified accept-queue / per-user connection cap
// configuration surface used across the tunnel and statistic packages. See
// the 2026 hardening plan (P1-2) for the rationale.
//
// Defaults match the plan:
//   - accept_queue_size: 256 (per accept channel)
//   - max_conn_per_user: 0  (unlimited)
//
// Zero selects the documented default; -1 disables the cap (i.e. -1 for
// max_conn_per_user is identical to 0; -1 for accept_queue_size means
// "buffer one element only", which is rarely useful but supported for
// symmetry with common/timeout).
package queue

import (
	"context"

	"github.com/kis1yi/trojan-go/config"
)

const Name = "QUEUE"

const (
	DefaultAcceptQueueSize = 256
	DefaultMaxConnPerUser  = 0
)

// Config holds queue/connection-cap values for a single proxy instance. The
// struct is embedded under the QUEUE key in the per-instance context.
type Config struct {
	Queue QueueConfig `json:"queue" yaml:"queue"`
}

// QueueConfig holds raw values. Use the Resolve* helpers to translate them
// into actual cap values with default/disabled handling.
type QueueConfig struct {
	AcceptQueueSize int `json:"accept_queue_size" yaml:"accept-queue-size"`
	MaxConnPerUser  int `json:"max_conn_per_user" yaml:"max-conn-per-user"`
}

// ResolveAcceptQueueSize returns the buffer size to use when constructing an
// accept channel. The minimum effective size is 1 — a value of -1 (disabled)
// collapses to a length-1 buffered channel because Go does not allow negative
// channel sizes.
func (c QueueConfig) ResolveAcceptQueueSize() int {
	switch {
	case c.AcceptQueueSize == 0:
		return DefaultAcceptQueueSize
	case c.AcceptQueueSize < 0:
		return 1
	default:
		return c.AcceptQueueSize
	}
}

// ResolveMaxConnPerUser returns the per-user concurrent connection cap.
// 0 means "unlimited"; any negative value is normalised to 0.
func (c QueueConfig) ResolveMaxConnPerUser() int {
	if c.MaxConnPerUser <= 0 {
		return 0
	}
	return c.MaxConnPerUser
}

// FromContext returns the QueueConfig stored in ctx, or a zero value (which
// resolves entirely to defaults) when no config has been registered. This
// allows packages that may run outside a configured proxy instance (tests,
// embedded uses) to call Resolve* helpers safely.
func FromContext(ctx context.Context) QueueConfig {
	if v := config.FromContext(ctx, Name); v != nil {
		if cfg, ok := v.(*Config); ok && cfg != nil {
			return cfg.Queue
		}
	}
	return QueueConfig{}
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return new(Config)
	})
}
