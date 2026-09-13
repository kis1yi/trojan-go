package router

import (
	"context"
	"io"
	"net"
	"os"
	"time"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/tunnel"
)

type packetInfo struct {
	src     *tunnel.Metadata
	payload []byte
	err     error
}

type PacketConn struct {
	proxy tunnel.PacketConn
	net.PacketConn
	packetChan chan *packetInfo
	*Client
	ctx    context.Context
	cancel context.CancelFunc

	readDeadline packetDeadline
}

func (c *PacketConn) packetLoop() {
	go func() {
		for {
			buf := make([]byte, MaxPacketSize)
			n, addr, err := c.proxy.ReadWithMetadata(buf)
			if err != nil {
				select {
				case <-c.ctx.Done():
					return
				case c.packetChan <- &packetInfo{err: err}:
					return
				}
			}
			select {
			case c.packetChan <- &packetInfo{
				src:     addr,
				payload: buf[:n],
			}:
			case <-c.ctx.Done():
				return
			}
		}
	}()
	for {
		buf := make([]byte, MaxPacketSize)
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			case c.packetChan <- &packetInfo{err: err}:
				return
			}
		}
		if addr == nil {
			select {
			case c.packetChan <- &packetInfo{err: common.NewError("router received udp packet without source address")}:
			case <-c.ctx.Done():
			}
			return
		}
		address, err := tunnel.NewAddressFromAddr("udp", addr.String())
		if err != nil {
			select {
			case c.packetChan <- &packetInfo{err: common.NewError("router failed to parse udp source address").Base(err)}:
			case <-c.ctx.Done():
			}
			return
		}
		select {
		case c.packetChan <- &packetInfo{
			src: &tunnel.Metadata{
				Address: address,
			},
			payload: buf[:n],
		}:
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *PacketConn) Close() error {
	c.cancel()
	c.proxy.Close()
	return c.PacketConn.Close()
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, metadata, err := c.ReadWithMetadata(p)
	if err != nil {
		return 0, nil, err
	}
	if metadata == nil || metadata.Address == nil {
		return 0, nil, common.NewError("router received udp packet without source address")
	}
	return n, metadata.Address, nil
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if addr == nil {
		return 0, common.NewError("router udp destination is nil")
	}
	address, ok := addr.(*tunnel.Address)
	if !ok {
		address, err = tunnel.NewAddressFromAddr("udp", addr.String())
		if err != nil {
			return 0, common.NewError("router failed to parse udp destination").Base(err)
		}
	}
	return c.WriteWithMetadata(p, &tunnel.Metadata{Address: address})
}

func (c *PacketConn) WriteWithMetadata(p []byte, m *tunnel.Metadata) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	default:
	}
	if m == nil || m.Address == nil {
		return 0, common.NewError("router udp destination is nil")
	}
	policy := c.Route(m.Address)
	switch policy {
	case Proxy:
		return c.proxy.WriteWithMetadata(p, m)
	case Block:
		return 0, common.NewError("router blocked address (udp): " + m.Address.String())
	case Bypass:
		ip, err := m.Address.ResolveIP()
		if err != nil {
			return 0, common.NewError("router failed to resolve udp address").Base(err)
		}
		return c.PacketConn.WriteTo(p, &net.UDPAddr{
			IP:   ip,
			Port: m.Address.Port,
		})
	default:
		panic("unknown policy")
	}
}

func (c *PacketConn) ReadWithMetadata(p []byte) (int, *tunnel.Metadata, error) {
	for {
		select {
		case <-c.ctx.Done():
			return 0, nil, io.EOF
		default:
		}

		deadline, changed := c.readDeadline.state()
		if !deadline.IsZero() && !deadline.After(time.Now()) {
			return 0, nil, os.ErrDeadlineExceeded
		}

		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}

		select {
		case info := <-c.packetChan:
			stopTimer(timer)
			if info.err != nil {
				return 0, nil, info.err
			}
			n := copy(p, info.payload)
			return n, info.src, nil
		case <-c.ctx.Done():
			stopTimer(timer)
			return 0, nil, io.EOF
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-changed:
			stopTimer(timer)
		}
	}
}

func (c *PacketConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	select {
	case <-c.ctx.Done():
		return net.ErrClosed
	default:
	}
	c.readDeadline.set(t)
	return nil
}

func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	select {
	case <-c.ctx.Done():
		return net.ErrClosed
	default:
	}
	if err := c.proxy.SetWriteDeadline(t); err != nil {
		return common.NewError("router failed to set proxy udp write deadline").Base(err)
	}
	if err := c.PacketConn.SetWriteDeadline(t); err != nil {
		return common.NewError("router failed to set direct udp write deadline").Base(err)
	}
	return nil
}
