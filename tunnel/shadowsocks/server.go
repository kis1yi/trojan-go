package shadowsocks

import (
	"context"
	"net"

	"github.com/shadowsocks/go-shadowsocks2/core"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/log"
	"github.com/kis1yi/trojan-go/redirector"
	"github.com/kis1yi/trojan-go/tunnel"
)

const maxPendingHandshakes = 64

type acceptResult struct {
	conn tunnel.Conn
	err  error
}

type Server struct {
	core.Cipher
	*redirector.Redirector
	underlay  tunnel.Server
	redirAddr net.Addr
	ctx       context.Context
	cancel    context.CancelFunc
	results   chan acceptResult
}

func (s *Server) AcceptConn(overlay tunnel.Tunnel) (tunnel.Conn, error) {
	select {
	case result := <-s.results:
		return result.conn, result.err
	case <-s.ctx.Done():
		return nil, common.NewError("shadowsocks server closed")
	}
}

func (s *Server) acceptLoop() {
	pending := make(chan struct{}, maxPendingHandshakes)
	for {
		// Bound unauthenticated connections without making every accept wait
		// for one peer to send its salt and first complete AEAD chunk.
		select {
		case pending <- struct{}{}:
		case <-s.ctx.Done():
			return
		}
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil {
			<-pending
			select {
			case s.results <- acceptResult{err: common.NewError("shadowsocks failed to accept connection from underlying tunnel").Base(err)}:
			case <-s.ctx.Done():
				return
			}
			continue
		}
		go func() {
			defer func() { <-pending }()
			// Closing the underlay listener does not close accepted connections.
			// Interrupt a pending read when this server shuts down.
			stop := context.AfterFunc(s.ctx, func() { _ = conn.Close() })
			defer stop()
			validated, err := s.validateConn(conn)
			if s.ctx.Err() != nil {
				_ = conn.Close()
				return
			}
			select {
			case s.results <- acceptResult{conn: validated, err: err}:
			case <-s.ctx.Done():
				_ = conn.Close()
			}
		}()
	}
}

func (s *Server) validateConn(conn tunnel.Conn) (tunnel.Conn, error) {
	rewindConn := common.NewRewindConn(conn)
	rewindConn.SetBufferSize(1024)
	defer rewindConn.StopBuffering()

	// try to read something from this connection
	buf := [1024]byte{}
	testConn := s.Cipher.StreamConn(rewindConn)
	if _, err := testConn.Read(buf[:]); err != nil {
		if s.ctx.Err() != nil {
			return nil, common.NewError("shadowsocks server closed")
		}
		log.Error(common.NewError("shadowsocks failed to decrypt").Base(err))
		rewindConn.Rewind()
		rewindConn.StopBuffering()
		s.Redirect(&redirector.Redirection{
			RedirectTo:  s.redirAddr,
			InboundConn: rewindConn,
		})
		return nil, common.NewError("invalid aead payload")
	}
	rewindConn.Rewind()
	rewindConn.StopBuffering()

	return &Conn{
		aeadConn: s.Cipher.StreamConn(rewindConn),
		Conn:     conn,
	}, nil
}

func (s *Server) AcceptPacket(t tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	cipher, err := core.PickCipher(cfg.Shadowsocks.Method, nil, cfg.Shadowsocks.Password)
	if err != nil {
		return nil, common.NewError("invalid shadowsocks cipher").Base(err)
	}
	if cfg.RemoteHost == "" {
		return nil, common.NewError("invalid shadowsocks redirection address")
	}
	if cfg.RemotePort == 0 {
		return nil, common.NewError("invalid shadowsocks redirection port")
	}
	ctx, cancel := context.WithCancel(ctx)
	log.Debug("shadowsocks server created")
	server := &Server{
		underlay:   underlay,
		Cipher:     cipher,
		Redirector: redirector.NewRedirector(ctx),
		redirAddr:  tunnel.NewAddressFromHostPort("tcp", cfg.RemoteHost, cfg.RemotePort),
		ctx:        ctx,
		cancel:     cancel,
		results:    make(chan acceptResult),
	}
	go server.acceptLoop()
	return server, nil
}
