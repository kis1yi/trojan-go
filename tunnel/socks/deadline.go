package socks

import (
	"sync"
	"time"
)

// packetDeadline provides deadline notifications for a virtual packet
// connection without applying them to the shared UDP listener.
type packetDeadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func makePacketDeadline() packetDeadline {
	return packetDeadline{cancel: make(chan struct{})}
}

// set updates the deadline. A zero time disables it, while an expired
// deadline keeps future operations timed out until it is refreshed.
func (d *packetDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel
	}
	d.timer = nil

	closed := isClosed(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}

	if duration := time.Until(t); duration > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		d.timer = time.AfterFunc(duration, func() {
			close(d.cancel)
		})
		return
	}

	if !closed {
		close(d.cancel)
	}
}

func (d *packetDeadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
