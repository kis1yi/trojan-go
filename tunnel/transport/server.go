package transport

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/common/queue"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/log"
	"github.com/kis1yi/trojan-go/tunnel"
)

// Server is a server of transport layer
type Server struct {
	tcpListener net.Listener
	cmd         *exec.Cmd
	connChan    chan tunnel.Conn
	wsChan      chan tunnel.Conn
	httpLock    sync.RWMutex
	nextHTTP    bool
	ctx         context.Context
	cancel      context.CancelFunc
}

func (s *Server) Close() error {
	s.cancel()
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill()
	}
	return s.tcpListener.Close()
}

func (s *Server) acceptLoop() {
	for {
		tcpConn, err := s.tcpListener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
			default:
				log.Error(common.NewError("transport accept error").Base(err))
				time.Sleep(time.Millisecond * 100)
			}
			return
		}

		go func(tcpConn net.Conn) {
			log.Debug("tcp connection from", tcpConn.RemoteAddr())
			s.httpLock.RLock()
			if s.nextHTTP { // plaintext mode enabled
				s.httpLock.RUnlock()
				// we use real http header parser to mimic a real http server
				rewindConn := common.NewRewindConn(tcpConn)
				rewindConn.SetBufferSize(512)
				defer rewindConn.StopBuffering()

				r := bufio.NewReader(rewindConn)
				httpReq, err := http.ReadRequest(r)
				rewindConn.Rewind()
				rewindConn.StopBuffering()
				if err != nil {
					// this is not a http request, pass it to trojan protocol layer for further inspection
					s.offer(s.connChan, &Conn{Conn: rewindConn}, "transport.connChan")
				} else {
					// this is a http request, pass it to websocket protocol layer
					log.Debug("plaintext http request: ", httpReq)
					s.offer(s.wsChan, &Conn{Conn: rewindConn}, "transport.wsChan")
				}
			} else {
				s.httpLock.RUnlock()
				s.offer(s.connChan, &Conn{Conn: tcpConn}, "transport.connChan")
			}
		}(tcpConn)
	}
}

func (s *Server) AcceptConn(overlay tunnel.Tunnel) (tunnel.Conn, error) {
	// TODO fix import cycle
	if overlay != nil && (overlay.Name() == "WEBSOCKET" || overlay.Name() == "HTTP") {
		s.httpLock.Lock()
		s.nextHTTP = true
		s.httpLock.Unlock()
		select {
		case conn := <-s.wsChan:
			return conn, nil
		case <-s.ctx.Done():
			return nil, common.NewError("transport server closed")
		}
	}
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("transport server closed")
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

// NewServer creates a transport layer server
func NewServer(ctx context.Context, _ tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	listenAddress := tunnel.NewAddressFromHostPort("tcp", cfg.LocalHost, cfg.LocalPort)

	var cmd *exec.Cmd
	if cfg.TransportPlugin.Enabled {
		log.Warn("transport server will use plugin and work in plain text mode")
		switch cfg.TransportPlugin.Type {
		case "shadowsocks":
			trojanHost := "127.0.0.1"
			trojanPort := common.PickPort("tcp", trojanHost)
			cfg.TransportPlugin.Env = append(
				cfg.TransportPlugin.Env,
				"SS_REMOTE_HOST="+cfg.LocalHost,
				"SS_REMOTE_PORT="+strconv.FormatInt(int64(cfg.LocalPort), 10),
				"SS_LOCAL_HOST="+trojanHost,
				"SS_LOCAL_PORT="+strconv.FormatInt(int64(trojanPort), 10),
				"SS_PLUGIN_OPTIONS="+cfg.TransportPlugin.Option,
			)

			cfg.LocalHost = trojanHost
			cfg.LocalPort = trojanPort
			listenAddress = tunnel.NewAddressFromHostPort("tcp", cfg.LocalHost, cfg.LocalPort)
			log.Debug("new listen address", listenAddress)
			log.Debug("plugin env", cfg.TransportPlugin.Env)

			cmd = exec.Command(cfg.TransportPlugin.Command, cfg.TransportPlugin.Arg...)
			cmd.Env = append(cmd.Env, cfg.TransportPlugin.Env...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stdout
			cmd.Start()
		case "other":
			cmd = exec.Command(cfg.TransportPlugin.Command, cfg.TransportPlugin.Arg...)
			cmd.Env = append(cmd.Env, cfg.TransportPlugin.Env...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stdout
			cmd.Start()
		case "plaintext":
			// do nothing
		default:
			return nil, common.NewError("invalid plugin type: " + cfg.TransportPlugin.Type)
		}
	}
	tcpListener, err := net.Listen("tcp", listenAddress.String())
	if err != nil {
		return nil, err
	}

	if cfg.TCP.ProxyProtocol {
		tcpListener = &proxyproto.Listener{Listener: tcpListener}
		log.Info("proxy protocol enabled")
	}

	ctx, cancel := context.WithCancel(ctx)
	qsize := queue.FromContext(ctx).ResolveAcceptQueueSize()
	server := &Server{
		tcpListener: tcpListener,
		cmd:         cmd,
		ctx:         ctx,
		cancel:      cancel,
		connChan:    make(chan tunnel.Conn, qsize),
		wsChan:      make(chan tunnel.Conn, qsize),
	}
	go server.acceptLoop()
	return server, nil
}

// offer pushes c onto ch without ever blocking the accept goroutine.
// P1-2: if the consumer is not draining, drop the connection and log once at
// Warn rather than parking the accept loop. The fast path is the buffered
// `case ch <- c`; the `default` only fires when the queue is full.
func (s *Server) offer(ch chan<- tunnel.Conn, c tunnel.Conn, label string) {
	select {
	case ch <- c:
	case <-s.ctx.Done():
		_ = c.Close()
	default:
		log.Warn("accept queue full, dropping connection from", c.RemoteAddr(), "queue="+label)
		_ = c.Close()
	}
}
