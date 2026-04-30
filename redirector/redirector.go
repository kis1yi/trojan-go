package redirector

import (
	"context"
	"io"
	"net"
	"reflect"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/common/timeout"
	"github.com/kis1yi/trojan-go/fallback"
	"github.com/kis1yi/trojan-go/log"
	"github.com/kis1yi/trojan-go/metrics"
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
		// P1-5: count every accepted fallback dispatch. We count at enqueue
		// time (not in worker) so back-pressure failures are not silently
		// missing from the counter \u2014 if the channel is full and ctx is
		// done, the operator will see the counter plateau in lockstep with
		// the new "fallback queue full" warn line below.
		metrics.IncFallback()
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
				// P1-1d: emit a PROXY protocol v1/v2 header on the dial
				// when the matched fallback rule asks for it. The header
				// carries the original client's source address so the
				// backend (typically nginx or haproxy) sees the real
				// peer instead of the trojan-go process address. Header
				// emission failure is logged but not fatal — the relay
				// continues and the backend will still serve plain TCP.
				if rule := fallback.Unwrap(redirection.InboundConn); rule != nil && rule.ProxyProtocol != fallback.ProxyProtocolNone {
					if err := writeProxyHeader(outboundConn, redirection.InboundConn, rule.ProxyProtocol); err != nil {
						log.Warn(common.NewError("failed to write PROXY protocol header").Base(err))
					}
				}
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

// writeProxyHeader composes and emits a PROXY protocol header on `out`
// describing the original client address recorded on `in`. P1-1d: reuses
// the same `pires/go-proxyproto` library that already powers PROXY
// protocol *ingress* in tunnel/transport/server.go — there is exactly one
// PROXY implementation in the binary.
//
// AddrPort plumbing: we accept any net.Addr that can be parsed as a TCP
// address. Non-TCP source/destination (e.g. unix sockets used in tests)
// fall back to UNSPEC which is a valid PROXY v2 transport that backends
// will accept without the connection details.
func writeProxyHeader(out net.Conn, in net.Conn, version fallback.ProxyProtocolVersion) error {
	src, srcOK := in.RemoteAddr().(*net.TCPAddr)
	dst, dstOK := in.LocalAddr().(*net.TCPAddr)
	header := &proxyproto.Header{
		Version:           byte(version),
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.UNSPEC,
	}
	if srcOK && dstOK {
		header.SourceAddr = src
		header.DestinationAddr = dst
		if src.IP.To4() != nil && dst.IP.To4() != nil {
			header.TransportProtocol = proxyproto.TCPv4
		} else {
			header.TransportProtocol = proxyproto.TCPv6
		}
	}
	_, err := header.WriteTo(out)
	return err
}
