package redirector

import (
	"bufio"
	"net"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/kis1yi/trojan-go/fallback"
)

// stubAddrConn lets us pin RemoteAddr/LocalAddr to known TCP addresses
// without setting up a real socket pair.
type stubAddrConn struct {
	net.Conn
	remote net.Addr
	local  net.Addr
}

func (s *stubAddrConn) RemoteAddr() net.Addr { return s.remote }
func (s *stubAddrConn) LocalAddr() net.Addr  { return s.local }

// TestWriteProxyHeaderRoundtripV2 ensures the v2 header writeProxyHeader
// emits is parseable by the same `pires/go-proxyproto` library and
// carries the original client TCP source/destination. P1-1d regression.
func TestWriteProxyHeaderRoundtripV2(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		hdr *proxyproto.Header
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		hdr, err := proxyproto.Read(bufio.NewReader(c))
		resCh <- result{hdr: hdr, err: err}
	}()

	out, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer out.Close()

	in := &stubAddrConn{
		remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51000},
		local:  &net.TCPAddr{IP: net.ParseIP("198.51.100.5"), Port: 443},
	}
	if err := writeProxyHeader(out, in, fallback.ProxyProtocolV2); err != nil {
		t.Fatalf("writeProxyHeader: %v", err)
	}

	r := <-resCh
	if r.err != nil {
		t.Fatalf("proxyproto.Read: %v", r.err)
	}
	if r.hdr.Version != 2 {
		t.Fatalf("version = %d, want 2", r.hdr.Version)
	}
	if r.hdr.TransportProtocol != proxyproto.TCPv4 {
		t.Fatalf("transport = %v, want TCPv4", r.hdr.TransportProtocol)
	}
	if got := r.hdr.SourceAddr.(*net.TCPAddr); got.Port != 51000 || !got.IP.Equal(net.ParseIP("203.0.113.7")) {
		t.Fatalf("source = %v, want 203.0.113.7:51000", got)
	}
	if got := r.hdr.DestinationAddr.(*net.TCPAddr); got.Port != 443 || !got.IP.Equal(net.ParseIP("198.51.100.5")) {
		t.Fatalf("dest = %v, want 198.51.100.5:443", got)
	}
}

// TestWriteProxyHeaderV1Text proves the v1 (text) variant also roundtrips.
func TestWriteProxyHeaderV1Text(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		hdr *proxyproto.Header
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		hdr, err := proxyproto.Read(bufio.NewReader(c))
		resCh <- result{hdr: hdr, err: err}
	}()

	out, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer out.Close()

	in := &stubAddrConn{
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345},
		local:  &net.TCPAddr{IP: net.ParseIP("198.51.100.5"), Port: 443},
	}
	if err := writeProxyHeader(out, in, fallback.ProxyProtocolV1); err != nil {
		t.Fatalf("writeProxyHeader: %v", err)
	}

	r := <-resCh
	if r.err != nil {
		t.Fatalf("proxyproto.Read: %v", r.err)
	}
	if r.hdr.Version != 1 {
		t.Fatalf("version = %d, want 1", r.hdr.Version)
	}
}
