package tls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/common/queue"
	"github.com/kis1yi/trojan-go/common/timeout"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/fallback"
	"github.com/kis1yi/trojan-go/log"
	"github.com/kis1yi/trojan-go/redirector"
	"github.com/kis1yi/trojan-go/tunnel"
	"github.com/kis1yi/trojan-go/tunnel/tls/fingerprint"
	"github.com/kis1yi/trojan-go/tunnel/transport"
	"github.com/kis1yi/trojan-go/tunnel/websocket"
)

// Server is a tls server
type Server struct {
	fallbackAddress    *tunnel.Address
	fallbackRules      []fallback.Rule
	verifySNI          bool
	sni                string
	alpn               []string
	PreferServerCipher bool
	keyPair            []tls.Certificate
	keyPairLock        sync.RWMutex
	httpResp           []byte
	cipherSuite        []uint16
	sessionTicket      bool
	curve              []tls.CurveID
	keyLogger          io.WriteCloser
	connChan           chan tunnel.Conn
	wsChan             chan tunnel.Conn
	redir              *redirector.Redirector
	ctx                context.Context
	cancel             context.CancelFunc
	underlay           tunnel.Server
	nextHTTP           int32
	portOverrider      map[string]int
	timeouts           timeout.TimeoutConfig
}

func (s *Server) Close() error {
	s.cancel()
	if s.keyLogger != nil {
		s.keyLogger.Close()
	}
	return s.underlay.Close()
}

func isDomainNameMatched(pattern string, domainName string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		domainPrefixLen := len(domainName) - len(suffix) - 1
		return strings.HasSuffix(domainName, suffix) && domainPrefixLen > 0 && !strings.Contains(domainName[:domainPrefixLen], ".")
	}
	return pattern == domainName
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil {
			select {
			case <-s.ctx.Done():
			default:
				log.Fatal(common.NewError("transport accept error" + err.Error()))
			}
			return
		}
		go func(conn net.Conn) {
			tlsConfig := &tls.Config{
				CipherSuites:             s.cipherSuite,
				PreferServerCipherSuites: s.PreferServerCipher,
				SessionTicketsDisabled:   !s.sessionTicket,
				NextProtos:               s.alpn,
				KeyLogWriter:             s.keyLogger,
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					s.keyPairLock.RLock()
					defer s.keyPairLock.RUnlock()
					sni := s.keyPair[0].Leaf.Subject.CommonName
					dnsNames := s.keyPair[0].Leaf.DNSNames
					if s.sni != "" {
						sni = s.sni
					}
					matched := isDomainNameMatched(sni, hello.ServerName)
					for _, name := range dnsNames {
						if isDomainNameMatched(name, hello.ServerName) {
							matched = true
							break
						}
					}
					if s.verifySNI && !matched {
						return nil, common.NewError("sni mismatched: " + hello.ServerName + ", expected: " + s.sni)
					}
					return &s.keyPair[0], nil
				},
			}

			// ------------------------ WAR ZONE ----------------------------

			handshakeRewindConn := common.NewRewindConn(conn)
			handshakeRewindConn.SetBufferSize(2048)

			// P0-1: bound the TLS handshake. Slow-loris probes that complete
			// the TCP handshake but never send a ClientHello must not tie up
			// an accept goroutine indefinitely.
			if d := s.timeouts.ResolveTLSHandshake(); d > 0 {
				_ = handshakeRewindConn.SetDeadline(time.Now().Add(d))
			}

			tlsConn := tls.Server(handshakeRewindConn, tlsConfig)
			err = tlsConn.Handshake()
			handshakeRewindConn.StopBuffering()

			if err != nil {
				if strings.Contains(err.Error(), "first record does not look like a TLS handshake") {
					// not a valid tls client hello
					handshakeRewindConn.Rewind()
					log.Error(common.NewError("failed to perform tls handshake with " + tlsConn.RemoteAddr().String() + ", redirecting").Base(err))
					switch {
					case s.fallbackAddress != nil || len(s.fallbackRules) > 0:
						// P1-1b: state is nil here — SNI/ALPN are
						// unknown because the handshake never reached
						// the ClientHello stage. dispatchFallback will
						// pick the default rule (or the legacy
						// fallbackAddress).
						s.dispatchFallback(handshakeRewindConn, nil)
					case s.httpResp != nil:
						handshakeRewindConn.Write(s.httpResp)
						handshakeRewindConn.Close()
					default:
						handshakeRewindConn.Close()
					}
				} else {
					// in other cases, simply close it
					tlsConn.Close()
					log.Error(common.NewError("tls handshake failed").Base(err))
				}
				return
			}

			// Handshake is complete; the trojan auth deadline (P0-1) takes
			// over once the trojan layer reads, so clear the deadline here.
			_ = handshakeRewindConn.SetDeadline(time.Time{})

			log.Debug("tls connection from", conn.RemoteAddr())
			state := tlsConn.ConnectionState()
			log.Trace("tls handshake", tls.CipherSuiteName(state.CipherSuite), state.DidResume, state.NegotiatedProtocol)

			// we use a real http header parser to mimic a real http server.
			// P0-1: a client that completes TLS but then sends no HTTP/trojan
			// bytes must not block forever in http.ReadRequest. Reuse the
			// trojan-auth budget here — once trojan accepts the conn it will
			// install its own (matching) deadline and clear it on success.
			rewindConn := common.NewRewindConn(tlsConn)
			rewindConn.SetBufferSize(1024)
			if d := s.timeouts.ResolveTrojanAuth(); d > 0 {
				_ = rewindConn.SetReadDeadline(time.Now().Add(d))
			}
			r := bufio.NewReader(rewindConn)
			httpReq, err := http.ReadRequest(r)
			rewindConn.Rewind()
			rewindConn.StopBuffering()
			_ = rewindConn.SetReadDeadline(time.Time{})
			if err != nil {
				// this is not a http request. pass it to trojan protocol layer for further inspection
				s.offer(s.connChan, &transport.Conn{Conn: rewindConn}, "tls.connChan")
			} else {
				if atomic.LoadInt32(&s.nextHTTP) != 1 {
					// there is no websocket layer waiting for connections, redirect it
					log.Error("incoming http request, but no websocket server is listening")
					// P1-1b: handshake succeeded — pass the real
					// ConnectionState so SNI/ALPN-aware rules can route
					// active probes that complete TLS but speak the
					// wrong upper-layer protocol.
					st := tlsConn.ConnectionState()
					s.dispatchFallback(rewindConn, &st)
					return
				}
				// this is a http request, pass it to websocket protocol layer
				log.Debug("http req: ", httpReq)
				s.offer(s.wsChan, &transport.Conn{Conn: rewindConn}, "tls.wsChan")
			}
		}(conn)
	}
}

// dispatchFallback resolves the SNI/ALPN-matched fallback rule, wraps the
// supplied connection in a ruleConn so downstream layers can recover the
// rule via fallback.Unwrap, and pushes the redirect request. P1-1b: when
// no rule matches and no default exists, fall back to the legacy
// fallbackAddress (still populated from FallbackHost/FallbackPort) so
// pre-migration configs keep working unchanged.
//
// `state` may be nil for the failed-handshake path, in which case
// SNI/ALPN are unknown and only the default rule (or legacy fallback)
// applies.
func (s *Server) dispatchFallback(conn net.Conn, state *tls.ConnectionState) {
	var sni, alpn string
	if state != nil {
		sni = state.ServerName
		alpn = state.NegotiatedProtocol
	}
	rule := fallback.Match(s.fallbackRules, sni, alpn)
	if rule != nil {
		s.redir.Redirect(&redirector.Redirection{
			InboundConn: &ruleConn{Conn: conn, rule: rule},
			RedirectTo:  tunnel.NewAddressFromHostPort("tcp", rule.Addr, rule.Port),
		})
		return
	}
	if s.fallbackAddress != nil {
		s.redir.Redirect(&redirector.Redirection{
			InboundConn: conn,
			RedirectTo:  s.fallbackAddress,
		})
		return
	}
	// No rule, no legacy fallback, no http_response: drop. The matching
	// log line is emitted by the caller (it has more context).
	_ = conn.Close()
}

// offer pushes c onto ch without ever blocking the accept goroutine.
// P1-2: if the consumer is not draining, drop the connection and log once at
// Warn rather than parking the accept loop.
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

func (s *Server) AcceptConn(overlay tunnel.Tunnel) (tunnel.Conn, error) {
	if _, ok := overlay.(*websocket.Tunnel); ok {
		atomic.StoreInt32(&s.nextHTTP, 1)
		log.Debug("next proto http")
		// websocket overlay
		select {
		case conn := <-s.wsChan:
			return conn, nil
		case <-s.ctx.Done():
			return nil, common.NewError("transport server closed")
		}
	}
	// trojan overlay
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

func (s *Server) checkKeyPairLoop(checkRate time.Duration, keyPath string, certPath string, password string) {
	var lastKeyBytes, lastCertBytes []byte
	ticker := time.NewTicker(checkRate)

	for {
		log.Debug("checking cert...")
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			log.Error(common.NewError("tls failed to check key").Base(err))
			continue
		}
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			log.Error(common.NewError("tls failed to check cert").Base(err))
			continue
		}
		if !bytes.Equal(keyBytes, lastKeyBytes) || !bytes.Equal(lastCertBytes, certBytes) {
			log.Info("new key pair detected")
			keyPair, err := loadKeyPair(keyPath, certPath, password)
			if err != nil {
				log.Error(common.NewError("tls failed to load new key pair").Base(err))
				continue
			}
			s.keyPairLock.Lock()
			s.keyPair = []tls.Certificate{*keyPair}
			s.keyPairLock.Unlock()
			lastKeyBytes = keyBytes
			lastCertBytes = certBytes
		}

		select {
		case <-ticker.C:
			continue
		case <-s.ctx.Done():
			log.Debug("exiting")
			ticker.Stop()
			return
		}
	}
}

func loadKeyPair(keyPath string, certPath string, password string) (*tls.Certificate, error) {
	if password != "" {
		keyFile, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, common.NewError("failed to load key file").Base(err)
		}
		keyBlock, _ := pem.Decode(keyFile)
		if keyBlock == nil {
			return nil, common.NewError("failed to decode key file")
		}
		// NOTE: x509.DecryptPEMBlock is deprecated since Go 1.16 because the
		// underlying RFC 1423 PEM encryption is insecure. Modern PKCS#8 keys
		// (e.g. produced by `openssl pkcs8 -topk8`) are not supported here;
		// migrating callers to a stronger KDF is tracked as a follow-up.
		decryptedKey, err := x509.DecryptPEMBlock(keyBlock, []byte(password))
		if err != nil {
			return nil, common.NewError("failed to decrypt key").Base(err)
		}
		// DecryptPEMBlock returns DER bytes; tls.X509KeyPair expects PEM, so
		// re-wrap the decrypted DER in a PEM block of the original type.
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  keyBlock.Type,
			Bytes: decryptedKey,
		})

		certFile, err := os.ReadFile(certPath)
		if err != nil {
			return nil, common.NewError("failed to load cert file").Base(err)
		}

		keyPair, err := tls.X509KeyPair(certFile, keyPEM)
		if err != nil {
			return nil, common.NewError("failed to load key pair").Base(err)
		}
		keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
		if err != nil {
			return nil, common.NewError("failed to parse leaf certificate").Base(err)
		}

		return &keyPair, nil
	}
	keyPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, common.NewError("failed to load key pair").Base(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, common.NewError("failed to parse leaf certificate").Base(err)
	}
	return &keyPair, nil
}

// NewServer creates a tls layer server
func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)

	// P1-1a/b: build the structured rule list and translate the legacy
	// FallbackHost/FallbackPort pair to a default rule when the new
	// `fallback:` list is unset. Validation drops malformed entries; warn
	// once if the operator's input was partially rejected.
	parsed := fallback.RulesFromConfig(cfg.TLS.Fallback)
	if len(parsed) != len(cfg.TLS.Fallback) {
		log.Warn("tls: dropped", len(cfg.TLS.Fallback)-len(parsed), "invalid fallback rules; check addr/port/proxy_protocol fields")
	}
	rules := fallback.MergeRules(parsed, cfg.TLS.FallbackHost, cfg.TLS.FallbackPort)

	var fallbackAddress *tunnel.Address
	var httpResp []byte
	if cfg.TLS.FallbackPort != 0 {
		if cfg.TLS.FallbackHost == "" {
			cfg.TLS.FallbackHost = cfg.RemoteHost
			log.Warn("empty tls fallback address")
		}
		fallbackAddress = tunnel.NewAddressFromHostPort("tcp", cfg.TLS.FallbackHost, cfg.TLS.FallbackPort)
		fallbackConn, err := net.Dial("tcp", fallbackAddress.String())
		if err != nil {
			return nil, common.NewError("invalid fallback address").Base(err)
		}
		fallbackConn.Close()
	} else if len(rules) == 0 {
		log.Warn("empty tls fallback port")
		if cfg.TLS.HTTPResponseFileName != "" {
			httpRespBody, err := os.ReadFile(cfg.TLS.HTTPResponseFileName)
			if err != nil {
				return nil, common.NewError("invalid response file").Base(err)
			}
			httpResp = httpRespBody
		} else {
			log.Warn("empty tls http response")
		}
	}

	keyPair, err := loadKeyPair(cfg.TLS.KeyPath, cfg.TLS.CertPath, cfg.TLS.KeyPassword)
	if err != nil {
		return nil, common.NewError("tls failed to load key pair")
	}

	var keyLogger io.WriteCloser
	if cfg.TLS.KeyLogPath != "" {
		log.Warn("tls key logging activated. USE OF KEY LOGGING COMPROMISES SECURITY. IT SHOULD ONLY BE USED FOR DEBUGGING.")
		file, err := os.OpenFile(cfg.TLS.KeyLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, common.NewError("failed to open key log file").Base(err)
		}
		keyLogger = file
	}

	var cipherSuite []uint16
	if len(cfg.TLS.Cipher) != 0 {
		cipherSuite = fingerprint.ParseCipher(strings.Split(cfg.TLS.Cipher, ":"))
	}

	ctx, cancel := context.WithCancel(ctx)
	qsize := queue.FromContext(ctx).ResolveAcceptQueueSize()
	server := &Server{
		underlay:           underlay,
		fallbackAddress:    fallbackAddress,
		fallbackRules:      rules,
		httpResp:           httpResp,
		verifySNI:          cfg.TLS.VerifyHostName,
		sni:                cfg.TLS.SNI,
		alpn:               cfg.TLS.ALPN,
		PreferServerCipher: cfg.TLS.PreferServerCipher,
		sessionTicket:      cfg.TLS.ReuseSession,
		connChan:           make(chan tunnel.Conn, qsize),
		wsChan:             make(chan tunnel.Conn, qsize),
		redir:              redirector.NewRedirector(ctx),
		keyPair:            []tls.Certificate{*keyPair},
		keyLogger:          keyLogger,
		cipherSuite:        cipherSuite,
		ctx:                ctx,
		cancel:             cancel,
		timeouts:           timeout.FromContext(ctx),
	}

	go server.acceptLoop()
	if cfg.TLS.CertCheckRate > 0 {
		go server.checkKeyPairLoop(
			time.Second*time.Duration(cfg.TLS.CertCheckRate),
			cfg.TLS.KeyPath,
			cfg.TLS.CertPath,
			cfg.TLS.KeyPassword,
		)
	}

	log.Debug("tls server created")
	return server, nil
}
