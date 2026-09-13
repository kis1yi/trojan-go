package router

import (
	"sync"
	"time"
)

// packetDeadline stores a virtual connection deadline. Each update closes the
// current change channel so reads which are already blocked can recalculate
// their timer without forwarding the deadline to either underlying packet
// connection.
type packetDeadline struct {
	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{}
}

func makePacketDeadline() packetDeadline {
	return packetDeadline{changed: make(chan struct{})}
}

func (d *packetDeadline) set(t time.Time) {
	d.mu.Lock()
	d.deadline = t
	close(d.changed)
	d.changed = make(chan struct{})
	d.mu.Unlock()
}

func (d *packetDeadline) state() (time.Time, <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.deadline, d.changed
}

func stopTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
