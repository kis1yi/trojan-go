package socks

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

type queuedDatagram struct {
	payload []byte
	source  net.Addr
}

type packetListenerStub struct {
	packets chan queuedDatagram
	closed  chan struct{}
	once    sync.Once

	mu               sync.Mutex
	readErr          error
	readCalls        int
	setDeadlineCalls int
	setReadCalls     int
	setWriteCalls    int
	localAddr        net.Addr
}

func newPacketListenerStub() *packetListenerStub {
	return &packetListenerStub{
		packets:   make(chan queuedDatagram, 8),
		closed:    make(chan struct{}),
		localAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1081},
	}
}

func (c *packetListenerStub) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	c.readCalls++
	err := c.readErr
	c.mu.Unlock()
	if err != nil {
		return 0, nil, err
	}

	select {
	case packet := <-c.packets:
		return copy(p, packet.payload), packet.source, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *packetListenerStub) WriteTo(p []byte, _ net.Addr) (int, error) {
	return len(p), nil
}

func (c *packetListenerStub) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *packetListenerStub) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *packetListenerStub) SetDeadline(time.Time) error {
	c.mu.Lock()
	c.setDeadlineCalls++
	c.mu.Unlock()
	return nil
}

func (c *packetListenerStub) SetReadDeadline(time.Time) error {
	c.mu.Lock()
	c.setReadCalls++
	c.mu.Unlock()
	return nil
}

func (c *packetListenerStub) SetWriteDeadline(time.Time) error {
	c.mu.Lock()
	c.setWriteCalls++
	c.mu.Unlock()
	return nil
}

func (c *packetListenerStub) WriteWithMetadata(p []byte, _ *tunnel.Metadata) (int, error) {
	return len(p), nil
}

func (c *packetListenerStub) ReadWithMetadata([]byte) (int, *tunnel.Metadata, error) {
	return 0, nil, errors.New("not implemented by packet listener stub")
}

func (c *packetListenerStub) enqueue(payload []byte, source net.Addr) {
	packet := make([]byte, len(payload))
	copy(packet, payload)
	c.packets <- queuedDatagram{payload: packet, source: source}
}

func (c *packetListenerStub) deadlineCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.setDeadlineCalls + c.setReadCalls + c.setWriteCalls
}

func (c *packetListenerStub) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readCalls
}

func TestPacketConnDeadlines(t *testing.T) {
	conn := newPacketConn(
		context.Background(),
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1081},
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20001},
	)
	defer conn.Close()
	if _, err := conn.WriteTo([]byte("payload"), nil); err == nil {
		t.Fatal("WriteTo accepted a nil destination")
	}

	payload := []byte("response")
	conn.input <- &packetInfo{
		metadata: &tunnel.Metadata{Address: tunnel.NewAddressFromHostPort("udp", "1.1.1.1", 53)},
		payload:  payload,
	}

	if err := conn.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}

	readErr := readPacketError(t, conn)
	assertDeadlineError(t, readErr)

	_, writeErr := conn.WriteWithMetadata([]byte("payload"), &tunnel.Metadata{
		Address: tunnel.NewAddressFromHostPort("udp", "1.1.1.1", 53),
	})
	assertDeadlineError(t, writeErr)

	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, MaxPacketSize)
	n, _, err := conn.ReadWithMetadata(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("unexpected payload after clearing deadline: %q", buf[:n])
	}

	if _, err := conn.WriteWithMetadata([]byte("payload"), &tunnel.Metadata{
		Address: tunnel.NewAddressFromHostPort("udp", "1.1.1.1", 53),
	}); err != nil {
		t.Fatalf("write failed after clearing deadline: %v", err)
	}
}

func TestPacketConnFutureReadDeadline(t *testing.T) {
	conn := newPacketConn(
		context.Background(),
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1081},
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20001},
	)
	defer conn.Close()

	start := time.Now()
	if err := conn.SetReadDeadline(start.Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	assertDeadlineError(t, readPacketError(t, conn))
	if elapsed := time.Since(start); elapsed < 10*time.Millisecond {
		t.Fatalf("future deadline fired too early: %v", elapsed)
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	payload := []byte("after refresh")
	conn.input <- &packetInfo{
		metadata: &tunnel.Metadata{Address: tunnel.NewAddressFromHostPort("udp", "1.1.1.1", 53)},
		payload:  payload,
	}
	buf := make([]byte, MaxPacketSize)
	n, _, err := conn.ReadWithMetadata(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("unexpected payload after refreshing deadline: %q", buf[:n])
	}
}

func TestClosedPacketConnRejectsQueuedOperations(t *testing.T) {
	conn := newPacketConn(
		context.Background(),
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1081},
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20001},
	)
	conn.input <- &packetInfo{
		metadata: &tunnel.Metadata{Address: tunnel.NewAddressFromHostPort("udp", "1.1.1.1", 53)},
		payload:  []byte("queued"),
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if _, _, err := conn.ReadWithMetadata(make([]byte, MaxPacketSize)); err == nil {
		t.Fatal("read succeeded after close")
	}
	if _, err := conn.WriteWithMetadata([]byte("payload"), &tunnel.Metadata{
		Address: tunnel.NewAddressFromHostPort("udp", "1.1.1.1", 53),
	}); err == nil {
		t.Fatal("write succeeded after close")
	}
	if err := conn.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("unexpected SetDeadline error after close: %v", err)
	}
}

func TestPacketDispatchKeepsSessionDeadlinesLocal(t *testing.T) {
	listener := newPacketListenerStub()
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		packetChan:       make(chan tunnel.PacketConn, 4),
		listenPacketConn: listener,
		mapping:          make(map[string]*PacketConn),
		ctx:              ctx,
		cancel:           cancel,
	}
	dispatchDone := make(chan struct{})
	go func() {
		server.packetDispatchLoop()
		close(dispatchDone)
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		select {
		case <-dispatchDone:
		case <-time.After(time.Second):
			t.Error("packet dispatcher did not stop")
		}
	})

	target := tunnel.NewAddressFromHostPort("udp", "1.1.1.1", 53)
	sourceA := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20001}
	sourceB := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20002}
	listener.enqueue(makeUDPFrame(t, target, []byte("first")), sourceA)

	first := receivePacketConn(t, server.packetChan)
	assertPacketPayload(t, first, []byte("first"))

	past := time.Now().Add(-time.Second)
	if err := first.SetReadDeadline(past); err != nil {
		t.Fatal(err)
	}
	assertDeadlineError(t, readPacketError(t, first))
	if err := first.SetWriteDeadline(past); err != nil {
		t.Fatal(err)
	}
	if err := first.SetDeadline(past); err != nil {
		t.Fatal(err)
	}
	if err := first.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	waitForMappingRemoval(t, server, sourceA.String())

	listener.enqueue(makeUDPFrame(t, target, []byte("replacement session")), sourceA)
	replacement := receivePacketConn(t, server.packetChan)
	assertPacketPayload(t, replacement, []byte("replacement session"))

	listener.enqueue(makeUDPFrame(t, target, []byte("second session")), sourceB)
	second := receivePacketConn(t, server.packetChan)
	assertPacketPayload(t, second, []byte("second session"))

	if calls := listener.deadlineCalls(); calls != 0 {
		t.Fatalf("session deadline was delegated to shared listener %d times", calls)
	}
}

func TestPacketDispatchStopsOnPermanentReadError(t *testing.T) {
	listener := newPacketListenerStub()
	listener.readErr = errors.New("permanent UDP listener failure")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &Server{
		listenPacketConn: listener,
		ctx:              ctx,
		cancel:           cancel,
	}

	done := make(chan struct{})
	go func() {
		server.packetDispatchLoop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		listener.Close()
		t.Fatal("packet dispatcher retried a permanent read error indefinitely")
	}

	if calls := listener.calls(); calls != 1 {
		t.Fatalf("unexpected ReadFrom call count: got %d, want 1", calls)
	}
}

func makeUDPFrame(t *testing.T, address *tunnel.Address, payload []byte) []byte {
	t.Helper()
	buf := bytes.NewBuffer(make([]byte, 0, MaxPacketSize))
	buf.Write([]byte{0, 0, 0})
	if err := address.Marshal(buf); err != nil {
		t.Fatal(err)
	}
	buf.Write(payload)
	return buf.Bytes()
}

func receivePacketConn(t *testing.T, packetChan <-chan tunnel.PacketConn) tunnel.PacketConn {
	t.Helper()
	select {
	case conn := <-packetChan:
		return conn
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for packet connection")
		return nil
	}
}

func waitForMappingRemoval(t *testing.T, server *Server, key string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		server.mappingLock.RLock()
		_, found := server.mapping[key]
		server.mappingLock.RUnlock()
		if !found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for UDP session %s to be removed", key)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertPacketPayload(t *testing.T, conn tunnel.PacketConn, want []byte) {
	t.Helper()
	buf := make([]byte, MaxPacketSize)
	type result struct {
		n   int
		err error
	}
	resultChan := make(chan result, 1)
	go func() {
		n, _, err := conn.ReadWithMetadata(buf)
		resultChan <- result{n: n, err: err}
	}()

	select {
	case result := <-resultChan:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if !bytes.Equal(buf[:result.n], want) {
			t.Fatalf("unexpected packet payload: got %q, want %q", buf[:result.n], want)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for packet payload")
	}
}

func readPacketError(t *testing.T, conn tunnel.PacketConn) error {
	t.Helper()
	resultChan := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadWithMetadata(make([]byte, MaxPacketSize))
		resultChan <- err
	}()
	select {
	case err := <-resultChan:
		return err
	case <-time.After(time.Second):
		conn.Close()
		t.Fatal("timed out waiting for packet read to return")
		return nil
	}
}

func assertDeadlineError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("unexpected deadline error: %v", err)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("deadline error does not implement net.Error timeout semantics: %v", err)
	}
}
