package socks

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/tunnel"
)

type Conn struct {
	net.Conn
	metadata *tunnel.Metadata
}

func (c *Conn) Metadata() *tunnel.Metadata {
	return c.metadata
}

type packetInfo struct {
	metadata *tunnel.Metadata
	payload  []byte
}

type PacketConn struct {
	input         chan *packetInfo
	output        chan *packetInfo
	localAddr     net.Addr
	src           net.Addr
	ctx           context.Context
	cancel        context.CancelFunc
	readDeadline  packetDeadline
	writeDeadline packetDeadline
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, metadata, err := c.ReadWithMetadata(p)
	if err != nil {
		return 0, nil, err
	}
	return n, metadata.Address, nil
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if addr == nil {
		return 0, common.NewError("socks UDP destination is nil")
	}
	address, ok := addr.(*tunnel.Address)
	if !ok {
		address, err = tunnel.NewAddressFromAddr("udp", addr.String())
		if err != nil {
			return 0, common.NewError("socks failed to parse UDP destination").Base(err)
		}
	}
	return c.WriteWithMetadata(p, &tunnel.Metadata{Address: address})
}

func (c *PacketConn) Close() error {
	c.cancel()
	c.readDeadline.set(time.Time{})
	c.writeDeadline.set(time.Time{})
	return nil
}

func (c *PacketConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *PacketConn) SetDeadline(t time.Time) error {
	if isClosed(c.ctx.Done()) {
		return net.ErrClosed
	}
	c.readDeadline.set(t)
	c.writeDeadline.set(t)
	return nil
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	if isClosed(c.ctx.Done()) {
		return net.ErrClosed
	}
	c.readDeadline.set(t)
	return nil
}

func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	if isClosed(c.ctx.Done()) {
		return net.ErrClosed
	}
	c.writeDeadline.set(t)
	return nil
}

func (c *PacketConn) WriteWithMetadata(p []byte, m *tunnel.Metadata) (int, error) {
	if isClosed(c.ctx.Done()) {
		return 0, common.NewError("socks packet conn closed")
	}
	if isClosed(c.writeDeadline.wait()) {
		return 0, os.ErrDeadlineExceeded
	}

	newP := make([]byte, len(p))
	copy(newP, p)
	select {
	case c.output <- &packetInfo{
		metadata: m,
		payload:  newP,
	}:
		return len(p), nil
	case <-c.ctx.Done():
		return 0, common.NewError("socks packet conn closed")
	case <-c.writeDeadline.wait():
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *PacketConn) ReadWithMetadata(p []byte) (int, *tunnel.Metadata, error) {
	if isClosed(c.ctx.Done()) {
		return 0, nil, common.NewError("socks packet conn closed")
	}
	if isClosed(c.readDeadline.wait()) {
		return 0, nil, os.ErrDeadlineExceeded
	}

	select {
	case info := <-c.input:
		n := copy(p, info.payload)
		return n, info.metadata, nil
	case <-c.ctx.Done():
		return 0, nil, common.NewError("socks packet conn closed")
	case <-c.readDeadline.wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func newPacketConn(parent context.Context, localAddr, src net.Addr) *PacketConn {
	ctx, cancel := context.WithCancel(parent)
	return &PacketConn{
		input:         make(chan *packetInfo, 128),
		output:        make(chan *packetInfo, 128),
		localAddr:     localAddr,
		src:           src,
		ctx:           ctx,
		cancel:        cancel,
		readDeadline:  makePacketDeadline(),
		writeDeadline: makePacketDeadline(),
	}
}
