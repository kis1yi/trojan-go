package redirector

import (
	"context"
	"io"
	"net"
	"reflect"
	"time"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/common/timeout"
	"github.com/kis1yi/trojan-go/log"
)

type Dial func(net.Addr) (net.Conn, error)

func defaultDial(addr net.Addr) (net.Conn, error) {
	return net.Dial("tcp", addr.String())
}

// dialerWithTimeout returns a Dial that bounds the dial step. The fallback
// path must not block indefinitely on an unreachable backend; see P0-1.
func dialerWithTimeout(d time.Duration) Dial {
	if d <= 0 {
		return defaultDial
	}
	return func(addr net.Addr) (net.Conn, error) {
		return net.DialTimeout("tcp", addr.String(), d)
	}
}

type Redirection struct {
	Dial
	RedirectTo  net.Addr
	InboundConn net.Conn
}

type Redirector struct {
	ctx             context.Context
	redirectionChan chan *Redirection
	dialTimeout     time.Duration
	idleTimeout     time.Duration
}

func (r *Redirector) Redirect(redirection *Redirection) {
	select {
	case r.redirectionChan <- redirection:
		log.Debug("redirect request")
	case <-r.ctx.Done():
		log.Debug("exiting")
	}
}

func (r *Redirector) worker() {
	for {
		select {
		case redirection := <-r.redirectionChan:
			handle := func(redirection *Redirection) {
				if redirection.InboundConn == nil || reflect.ValueOf(redirection.InboundConn).IsNil() {
					log.Error("nil inbound conn")
					return
				}
				defer redirection.InboundConn.Close()
				if redirection.RedirectTo == nil || reflect.ValueOf(redirection.RedirectTo).IsNil() {
					log.Error("nil redirection addr")
					return
				}
				if redirection.Dial == nil {
					redirection.Dial = dialerWithTimeout(r.dialTimeout)
				}
				log.Warn("redirecting connection from", redirection.InboundConn.RemoteAddr(), "to", redirection.RedirectTo.String())
				outboundConn, err := redirection.Dial(redirection.RedirectTo)
				if err != nil {
					log.Error(common.NewError("failed to redirect to target address").Base(err))
					return
				}
				defer outboundConn.Close()
				errChan := make(chan error, 2)
				copyConn := func(a, b net.Conn) {
					if r.idleTimeout > 0 {
						// Wrap the source so each successful read refreshes
						// the read deadline. Half-duplex idle eviction
						// prevents leaked fallback sessions when one side
						// stops sending. See P0-1.
						b = newIdleConn(b, r.idleTimeout)
					}
					_, err := io.Copy(a, b)
					errChan <- err
				}
				go copyConn(outboundConn, redirection.InboundConn)
				go copyConn(redirection.InboundConn, outboundConn)
				select {
				case err := <-errChan:
					if err != nil {
						log.Error(common.NewError("failed to redirect").Base(err))
					}
					log.Info("redirection done")
				case <-r.ctx.Done():
					log.Debug("exiting")
					return
				}
			}
			go handle(redirection)
		case <-r.ctx.Done():
			log.Debug("shutting down redirector")
			return
		}
	}
}

func NewRedirector(ctx context.Context) *Redirector {
	t := timeout.FromContext(ctx)
	r := &Redirector{
		ctx:             ctx,
		redirectionChan: make(chan *Redirection, 64),
		dialTimeout:     t.ResolveFallbackDial(),
		idleTimeout:     t.ResolveFallbackIdle(),
	}
	go r.worker()
	return r
}
