package trojan

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/kis1yi/trojan-go/api"
	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/common/queue"
	"github.com/kis1yi/trojan-go/common/timeout"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/log"
	"github.com/kis1yi/trojan-go/recorder"
	"github.com/kis1yi/trojan-go/redirector"
	"github.com/kis1yi/trojan-go/statistic"
	"github.com/kis1yi/trojan-go/statistic/memory"
	"github.com/kis1yi/trojan-go/statistic/mysql"
	"github.com/kis1yi/trojan-go/tunnel"
	"github.com/kis1yi/trojan-go/tunnel/mux"
)

var Auth statistic.Authenticator

// InboundConn is a trojan inbound connection
type InboundConn struct {
	// WARNING: do not change the order of these fields.
	// 64-bit fields that use `sync/atomic` package functions
	// must be 64-bit aligned on 32-bit systems.
	// Reference: https://github.com/golang/go/issues/599
	// Solution: https://github.com/golang/go/issues/11891#issuecomment-433623786
	sent uint64
	recv uint64

	net.Conn
	auth        statistic.Authenticator
	user        statistic.User
	hash        string
	metadata    *tunnel.Metadata
	ip          string
	authTimeout time.Duration
}

func (c *InboundConn) Metadata() *tunnel.Metadata {
	return c.metadata
}

func (c *InboundConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	atomic.AddUint64(&c.sent, uint64(n))
	c.user.AddSentTraffic(n)
	return n, err
}

func (c *InboundConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	atomic.AddUint64(&c.recv, uint64(n))
	c.user.AddRecvTraffic(n)
	return n, err
}

func (c *InboundConn) Close() error {
	log.Debug("user", log.RedactHash(c.hash), "from", c.Conn.RemoteAddr(), "tunneling to", c.metadata.Address, "closed",
		"sent:", common.HumanFriendlyTraffic(atomic.LoadUint64(&c.sent)), "recv:", common.HumanFriendlyTraffic(atomic.LoadUint64(&c.recv)))
	c.user.DelIP(c.ip)
	return c.Conn.Close()
}

// TrojanAuthTimeout bounds how long the server is willing to wait for a
// client to send the 56-byte hash + CRLF + metadata block. Censorship probes
// commonly hold the connection open without writing any auth bytes; without a
// deadline this would tie up an accept goroutine indefinitely.
//
// The package-level value is kept as a backwards-compatible default and is
// overridden per-server via the unified TIMEOUT_CONFIG (see
// common/timeout). It is declared as a var (not const) so tests can shrink it
// without sleeping for the production default.
var TrojanAuthTimeout = timeout.DefaultTrojanAuth

func (c *InboundConn) Auth() error {
	// Bound the time spent reading the auth header. The deadline is cleared
	// before returning (success or failure) so that long-lived tunnels do not
	// inherit the short auth deadline and the fallback path does not hand a
	// nearly-expired deadline to the redirector backend.
	d := c.authTimeout
	if d == 0 {
		d = TrojanAuthTimeout
	}
	if d > 0 {
		if err := c.Conn.SetReadDeadline(time.Now().Add(d)); err != nil {
			// Some net.Conn implementations (e.g. exotic mocks in tests) may
			// not support deadlines. Log at Debug and continue — a missing
			// deadline only weakens the slow-loris protection, it does not
			// corrupt the handshake.
			log.Debug("trojan: SetReadDeadline failed:", err)
		}
	}
	authOK := false
	defer func() {
		if !authOK {
			// Always clear the deadline on failure so the fallback path that
			// rewinds and redirects this connection starts with a clean
			// slate. Errors are intentionally ignored here.
			_ = c.Conn.SetReadDeadline(time.Time{})
		}
	}()

	userHash := [56]byte{}
	if _, err := io.ReadFull(c.Conn, userHash[:]); err != nil {
		return common.NewError("failed to read hash").Base(err)
	}

	valid, user := c.auth.AuthUser(string(userHash[:]))
	if !valid {
		// userHash is arbitrary client-controlled bytes — sanitise to hex
		// before redacting so log lines stay single-line and printable.
		return common.NewError("invalid hash:" + log.RedactHash(hex.EncodeToString(userHash[:])))
	}
	c.hash = string(userHash[:])
	c.user = user

	ip, _, err := net.SplitHostPort(c.Conn.RemoteAddr().String())
	if err != nil {
		return common.NewError("failed to parse host:" + c.Conn.RemoteAddr().String()).Base(err)
	}
	c.ip = ip

	crlf := [2]byte{}
	if _, err = io.ReadFull(c.Conn, crlf[:]); err != nil {
		return common.NewError("failed to read crlf after hash").Base(err)
	}

	c.metadata = &tunnel.Metadata{}
	if err := c.metadata.Unmarshal(c.Conn); err != nil {
		return common.NewError("failed to read trojan metadata").Base(err)
	}

	if _, err = io.ReadFull(c.Conn, crlf[:]); err != nil {
		return common.NewError("failed to read crlf after metadata").Base(err)
	}

	// Defer IP-limit accounting until after metadata parsing succeeds; if the
	// limit is full, the connection is closed before any traffic can flow.
	if !user.AddIP(ip) {
		c.ip = ""
		return common.NewError("ip limit reached")
	}

	authOK = true
	// Clear the auth deadline now that the handshake is complete; long-lived
	// tunnels must not inherit the short deadline.
	if err := c.Conn.SetReadDeadline(time.Time{}); err != nil {
		log.Debug("trojan: clear read deadline failed:", err)
	}
	return nil
}

func (c *InboundConn) Record() {
	log.Debug("user", log.RedactHash(c.hash), "from", c.Conn.RemoteAddr(), "tunneling to", c.metadata.Address)
	recorder.Add(c.hash, c.Conn.RemoteAddr(), c.metadata.Address, "TCP", nil)
}

func (c *InboundConn) Hash() string {
	return c.hash
}

// Server is a trojan tunnel server
type Server struct {
	auth        statistic.Authenticator
	redir       *redirector.Redirector
	redirAddr   *tunnel.Address
	underlay    tunnel.Server
	connChan    chan tunnel.Conn
	muxChan     chan tunnel.Conn
	packetChan  chan tunnel.PacketConn
	ctx         context.Context
	cancel      context.CancelFunc
	authTimeout time.Duration
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil { // Closing
			log.Error(common.NewError("trojan failed to accept conn").Base(err))
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			continue
		}
		go func(conn tunnel.Conn) {
			rewindConn := common.NewRewindConn(conn)
			rewindConn.SetBufferSize(128)
			defer rewindConn.StopBuffering()

			inboundConn := &InboundConn{
				Conn:        rewindConn,
				auth:        s.auth,
				authTimeout: s.authTimeout,
			}

			if err := inboundConn.Auth(); err != nil {
				rewindConn.Rewind()
				rewindConn.StopBuffering()
				log.Warn(common.NewError("connection with invalid trojan header from " + rewindConn.RemoteAddr().String()).Base(err))
				s.redir.Redirect(&redirector.Redirection{
					RedirectTo:  s.redirAddr,
					InboundConn: rewindConn,
				})
				return
			}

			// P0-3d: as soon as the user is authenticated, watch their cutoff
			// channel. When `User.Done()` fires (quota exceeded, operator
			// removal, or authenticator shutdown) close the underlying
			// transport so the in-flight relay loop in `proxy/proxy.go`
			// observes EOF/closed-conn and tears down both directions. We
			// stop watching when the connection itself is closed for any
			// other reason (e.g. peer hangup) by also selecting on a local
			// done channel that the wrapping `InboundConn.Close` signals.
			if done := inboundConn.user.Done(); done != nil {
				// If Done() is already closed at install time the user has
				// been removed or the authenticator was shut down. Because
				// the trojan auth in this codebase is held in a process-
				// wide var (`Auth`) that survives Server.Close, this state
				// is reachable when a Server is rebuilt against a stale
				// Authenticator (e.g. tests with -count>1). Skip installing
				// the watcher in that case so we do not close a brand-new
				// transport based on a stale signal; the connection will
				// still be torn down by ordinary Read/Write errors.
				select {
				case <-done:
				default:
					go func(c *InboundConn, cutoff <-chan struct{}) {
						select {
						case <-cutoff:
							log.Info("user", log.RedactHash(c.hash), "cut off (quota or removal); closing tunnel from", c.Conn.RemoteAddr())
							_ = c.Conn.Close()
						case <-s.ctx.Done():
						}
					}(inboundConn, done)
				}
			}

			rewindConn.StopBuffering()
			switch inboundConn.metadata.Command {
			case Connect:
				if inboundConn.metadata.DomainName == "MUX_CONN" {
					s.offer(s.muxChan, inboundConn, "trojan.muxChan")
					log.Debug("mux(r) connection")
				} else {
					if s.deliver(s.connChan, inboundConn, "trojan.connChan") {
						log.Debug("normal trojan connection")
						inboundConn.Record()
					}
				}

			case Associate:
				s.offerPacket(s.packetChan, &PacketConn{Conn: inboundConn}, "trojan.packetChan")
				log.Debug("trojan udp connection")
			case Mux:
				s.offer(s.muxChan, inboundConn, "trojan.muxChan")
				log.Debug("mux connection")
			default:
				log.Error(common.NewError(fmt.Sprintf("unknown trojan command %d", inboundConn.metadata.Command)))
			}
		}(conn)
	}
}

func (s *Server) AcceptConn(nextTunnel tunnel.Tunnel) (tunnel.Conn, error) {
	switch nextTunnel.(type) {
	case *mux.Tunnel:
		select {
		case t := <-s.muxChan:
			return t, nil
		case <-s.ctx.Done():
			return nil, common.NewError("trojan client closed")
		}
	default:
		select {
		case t := <-s.connChan:
			return t, nil
		case <-s.ctx.Done():
			return nil, common.NewError("trojan client closed")
		}
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	select {
	case t := <-s.packetChan:
		return t, nil
	case <-s.ctx.Done():
		return nil, common.NewError("trojan client closed")
	}
}

// offer pushes c onto ch without ever blocking the accept goroutine.
// P1-2: drop on full queue and log at Warn rather than parking. The
// connection is closed on drop so the per-IP/per-user counters that
// `Auth()` already incremented are released by the deferred Close path.
func (s *Server) offer(ch chan<- tunnel.Conn, c tunnel.Conn, label string) {
	if !s.deliver(ch, c, label) {
		_ = c.Close()
	}
}

// deliver is the same non-blocking send as offer but reports whether the
// hand-off succeeded so the caller can skip side-effects (Record, log) on
// drop.
func (s *Server) deliver(ch chan<- tunnel.Conn, c tunnel.Conn, label string) bool {
	select {
	case ch <- c:
		return true
	case <-s.ctx.Done():
		_ = c.Close()
		return false
	default:
		log.Warn("accept queue full, dropping trojan connection from", c.RemoteAddr(), "queue="+label)
		_ = c.Close()
		return false
	}
}

func (s *Server) offerPacket(ch chan<- tunnel.PacketConn, c tunnel.PacketConn, label string) {
	select {
	case ch <- c:
	case <-s.ctx.Done():
		_ = c.Close()
	default:
		log.Warn("accept queue full, dropping trojan packet conn", "queue="+label)
		_ = c.Close()
	}
}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	ctx, cancel := context.WithCancel(ctx)

	if Auth == nil {
		var err error
		if cfg.MySQL.Enabled {
			log.Debug("mysql enabled")
			Auth, err = statistic.NewAuthenticator(ctx, mysql.Name)
		} else {
			log.Debug("auth by config file")
			Auth, err = statistic.NewAuthenticator(ctx, memory.Name)
		}
		if err != nil {
			cancel()
			return nil, common.NewError("trojan failed to create authenticator")
		}
	}

	if cfg.API.Enabled {
		go api.RunService(ctx, Name+"_SERVER", Auth)
	}

	recorder.Capacity = cfg.RecordCapacity

	redirAddr := tunnel.NewAddressFromHostPort("tcp", cfg.RemoteHost, cfg.RemotePort)
	qsize := queue.FromContext(ctx).ResolveAcceptQueueSize()
	s := &Server{
		underlay:    underlay,
		auth:        Auth,
		redirAddr:   redirAddr,
		connChan:    make(chan tunnel.Conn, qsize),
		muxChan:     make(chan tunnel.Conn, qsize),
		packetChan:  make(chan tunnel.PacketConn, qsize),
		ctx:         ctx,
		cancel:      cancel,
		redir:       redirector.NewRedirector(ctx),
		authTimeout: timeout.FromContext(ctx).ResolveTrojanAuth(),
	}

	if !cfg.DisableHTTPCheck {
		redirConn, err := net.Dial("tcp", redirAddr.String())
		if err != nil {
			cancel()
			return nil, common.NewError("invalid redirect address. check your http server: " + redirAddr.String()).Base(err)
		}
		redirConn.Close()
	}

	go s.acceptLoop()
	log.Debug("trojan server created")
	return s, nil
}
