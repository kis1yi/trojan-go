package router

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kis1yi/trojan-go/tunnel"
)

type packetConnStub struct {
	closed   chan struct{}
	closeOne sync.Once

	mu                    sync.Mutex
	readFromCalls         int
	readWithMetadataCalls int
	setReadDeadlineCalls  int
	setWriteDeadlineCalls int
	readFromErr           error
	readWithMetadataErr   error
	writtenMetadata       *tunnel.Metadata
}

func newPacketConnStub() *packetConnStub {
	return &packetConnStub{closed: make(chan struct{})}
}

func (c *packetConnStub) ReadFrom([]byte) (int, net.Addr, error) {
	c.mu.Lock()
	c.readFromCalls++
	err := c.readFromErr
	c.mu.Unlock()
	if err != nil {
		return 0, nil, err
	}
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *packetConnStub) WriteTo(p []byte, _ net.Addr) (int, error) {
	return len(p), nil
}

func (c *packetConnStub) Close() error {
	c.closeOne.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *packetConnStub) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (c *packetConnStub) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *packetConnStub) SetReadDeadline(time.Time) error {
	c.mu.Lock()
	c.setReadDeadlineCalls++
	c.mu.Unlock()
	return nil
}

func (c *packetConnStub) SetWriteDeadline(time.Time) error {
	c.mu.Lock()
	c.setWriteDeadlineCalls++
	c.mu.Unlock()
	return nil
}

func (c *packetConnStub) WriteWithMetadata(p []byte, metadata *tunnel.Metadata) (int, error) {
	c.mu.Lock()
	c.writtenMetadata = metadata
	c.mu.Unlock()
	return len(p), nil
}

func (c *packetConnStub) ReadWithMetadata([]byte) (int, *tunnel.Metadata, error) {
	c.mu.Lock()
	c.readWithMetadataCalls++
	err := c.readWithMetadataErr
	c.mu.Unlock()
	if err != nil {
		return 0, nil, err
	}
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *packetConnStub) readCalls() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readFromCalls, c.readWithMetadataCalls
}

func (c *packetConnStub) deadlineCalls() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.setReadDeadlineCalls, c.setWriteDeadlineCalls
}

func newTestPacketConn(direct net.PacketConn, proxy tunnel.PacketConn) *PacketConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &PacketConn{
		Client:       &Client{defaultPolicy: Proxy},
		PacketConn:   direct,
		proxy:        proxy,
		packetChan:   make(chan *packetInfo, 16),
		ctx:          ctx,
		cancel:       cancel,
		readDeadline: makePacketDeadline(),
	}
}

func TestPacketConnReadDeadlineIsVirtualAndDoesNotSpin(t *testing.T) {
	direct := newPacketConnStub()
	proxy := newPacketConnStub()
	conn := newTestPacketConn(direct, proxy)
	loopDone := make(chan struct{})
	go func() {
		conn.packetLoop()
		close(loopDone)
	}()
	t.Cleanup(func() {
		conn.Close()
		select {
		case <-loopDone:
		case <-time.After(time.Second):
			t.Error("router packet loop did not stop")
		}
	})

	waitForPacketReads(t, direct, proxy)
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	err := readRouterPacketError(t, conn)
	assertRouterDeadlineError(t, err)

	directReadDeadlines, _ := direct.deadlineCalls()
	proxyReadDeadlines, _ := proxy.deadlineCalls()
	if directReadDeadlines != 0 || proxyReadDeadlines != 0 {
		t.Fatalf("read deadline reached underlying packet connections: direct=%d proxy=%d", directReadDeadlines, proxyReadDeadlines)
	}

	// An expired deadline used to make the direct reader retry immediately and
	// log thousands of errors per second. Both internal readers must remain on
	// their original blocking read until Close unblocks them.
	time.Sleep(20 * time.Millisecond)
	directReads, _ := direct.readCalls()
	_, proxyReads := proxy.readCalls()
	if directReads != 1 || proxyReads != 1 {
		t.Fatalf("underlying reads were retried after deadline: direct=%d proxy=%d", directReads, proxyReads)
	}
}

func TestPacketConnDirectReadSurvivesVirtualDeadline(t *testing.T) {
	direct, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := newPacketConnStub()
	conn := newTestPacketConn(direct, proxy)
	loopDone := make(chan struct{})
	go func() {
		conn.packetLoop()
		close(loopDone)
	}()
	t.Cleanup(func() {
		conn.Close()
		select {
		case <-loopDone:
		case <-time.After(time.Second):
			t.Error("router packet loop did not stop")
		}
	})

	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	assertRouterDeadlineError(t, readRouterPacketError(t, conn))
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	sender, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	payload := []byte("response after timeout")
	if _, err := sender.WriteTo(payload, direct.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, MaxPacketSize)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("unexpected payload: got %q, want %q", buf[:n], payload)
	}
	if addr.String() != sender.LocalAddr().String() {
		t.Fatalf("unexpected source: got %s, want %s", addr, sender.LocalAddr())
	}
}

func TestPacketConnReadDeadlineCanChangeWhileReadIsBlocked(t *testing.T) {
	direct := newPacketConnStub()
	proxy := newPacketConnStub()
	conn := newTestPacketConn(direct, proxy)
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadWithMetadata(make([]byte, MaxPacketSize))
		result <- err
	}()

	time.Sleep(10 * time.Millisecond)
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		t.Fatalf("cleared deadline still ended pending read: %v", err)
	case <-time.After(60 * time.Millisecond):
	}

	payload := []byte("after deadline clear")
	conn.packetChan <- &packetInfo{
		src:     &tunnel.Metadata{Address: tunnel.NewAddressFromHostPort("udp", "1.1.1.1", 53)},
		payload: payload,
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending read did not resume after clearing deadline")
	}

	if err := conn.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _, err := conn.ReadWithMetadata(make([]byte, MaxPacketSize))
		result <- err
	}()
	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		assertRouterDeadlineError(t, err)
	case <-time.After(time.Second):
		t.Fatal("shortened deadline did not end pending read")
	}
}

func TestPacketConnExpiredDeadlineDoesNotConsumeQueuedPacket(t *testing.T) {
	direct := newPacketConnStub()
	proxy := newPacketConnStub()
	conn := newTestPacketConn(direct, proxy)
	defer conn.Close()

	payload := []byte("queued response")
	address := tunnel.NewAddressFromHostPort("udp", "8.8.8.8", 53)
	conn.packetChan <- &packetInfo{
		src:     &tunnel.Metadata{Address: address},
		payload: payload,
	}
	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	assertRouterDeadlineError(t, readRouterPacketError(t, conn))

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, MaxPacketSize)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("unexpected payload: got %q, want %q", buf[:n], payload)
	}
	if addr.String() != address.String() {
		t.Fatalf("unexpected source: got %s, want %s", addr, address)
	}
}

func TestPacketConnStopsUnderlyingReadersAfterPermanentError(t *testing.T) {
	direct := newPacketConnStub()
	proxy := newPacketConnStub()
	direct.readFromErr = errors.New("direct read failed")
	proxy.readWithMetadataErr = errors.New("proxy read failed")
	conn := newTestPacketConn(direct, proxy)
	defer conn.Close()

	loopDone := make(chan struct{})
	go func() {
		conn.packetLoop()
		close(loopDone)
	}()
	select {
	case <-loopDone:
	case <-time.After(time.Second):
		t.Fatal("direct packet reader did not stop after permanent error")
	}
	waitForPacketReads(t, direct, proxy)
	time.Sleep(20 * time.Millisecond)
	directReads, _ := direct.readCalls()
	_, proxyReads := proxy.readCalls()
	if directReads != 1 || proxyReads != 1 {
		t.Fatalf("permanent errors were retried: direct=%d proxy=%d", directReads, proxyReads)
	}
}

func TestPacketConnWriteDeadlineReachesBothRoutes(t *testing.T) {
	direct := newPacketConnStub()
	proxy := newPacketConnStub()
	conn := newTestPacketConn(direct, proxy)
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	directReadDeadlines, directWriteDeadlines := direct.deadlineCalls()
	proxyReadDeadlines, proxyWriteDeadlines := proxy.deadlineCalls()
	if directReadDeadlines != 0 || proxyReadDeadlines != 0 {
		t.Fatalf("write deadline changed a read deadline: direct=%d proxy=%d", directReadDeadlines, proxyReadDeadlines)
	}
	if directWriteDeadlines != 1 || proxyWriteDeadlines != 1 {
		t.Fatalf("write deadline was not applied to both routes: direct=%d proxy=%d", directWriteDeadlines, proxyWriteDeadlines)
	}

	payload := []byte("request")
	if _, err := conn.WriteTo(payload, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}); err != nil {
		t.Fatal(err)
	}
	proxy.mu.Lock()
	written := proxy.writtenMetadata
	proxy.mu.Unlock()
	if written == nil || written.Address.String() != "8.8.8.8:53" {
		t.Fatalf("WriteTo did not preserve destination metadata: %v", written)
	}
}

func waitForPacketReads(t *testing.T, direct, proxy *packetConnStub) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		directReads, _ := direct.readCalls()
		_, proxyReads := proxy.readCalls()
		if directReads > 0 && proxyReads > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("packet readers did not start: direct=%d proxy=%d", directReads, proxyReads)
		}
		time.Sleep(time.Millisecond)
	}
}

func readRouterPacketError(t *testing.T, conn *PacketConn) error {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadWithMetadata(make([]byte, MaxPacketSize))
		result <- err
	}()
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for router packet read")
		return nil
	}
}

func assertRouterDeadlineError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("unexpected deadline error: %v", err)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("deadline error does not implement net.Error timeout semantics: %v", err)
	}
}
