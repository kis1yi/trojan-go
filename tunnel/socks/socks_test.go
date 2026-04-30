package socks_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/txthinking/socks5"
	"golang.org/x/net/proxy"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/test/util"
	"github.com/kis1yi/trojan-go/tunnel"
	"github.com/kis1yi/trojan-go/tunnel/adapter"
	"github.com/kis1yi/trojan-go/tunnel/socks"
)

func TestSocks(t *testing.T) {
	port := common.PickPort("tcp", "127.0.0.1")
	ctx := config.WithConfig(context.Background(), adapter.Name, &adapter.Config{
		LocalHost: "127.0.0.1",
		LocalPort: port,
	})
	ctx = config.WithConfig(ctx, socks.Name, &socks.Config{
		LocalHost: "127.0.0.1",
		LocalPort: port,
	})
	tcpServer, err := adapter.NewServer(ctx, nil)
	common.Must(err)
	addr := tunnel.NewAddressFromHostPort("tcp", "127.0.0.1", port)
	s, err := socks.NewServer(ctx, tcpServer)
	common.Must(err)
	socksClient, err := proxy.SOCKS5("tcp", addr.String(), nil, proxy.Direct)
	common.Must(err)
	var conn1, conn2 net.Conn
	wg := sync.WaitGroup{}
	wg.Add(2)

	time.Sleep(time.Second * 2)
	go func() {
		defer wg.Done()
		var acceptErr error
		conn2, acceptErr = s.AcceptConn(nil)
		if acceptErr != nil {
			t.Error(acceptErr)
		}
	}()

	time.Sleep(time.Second * 1)
	go func() {
		defer wg.Done()
		var dialErr error
		conn1, dialErr = socksClient.Dial("tcp", util.EchoAddr)
		if dialErr != nil {
			t.Error(dialErr)
		}
	}()

	wg.Wait()
	if !util.CheckConn(conn1, conn2) {
		t.Fail()
	}
	fmt.Println(conn2.(tunnel.Conn).Metadata())

	udpConn, err := net.ListenPacket("udp", ":0")
	common.Must(err)

	addr = &tunnel.Address{
		AddressType: tunnel.DomainName,
		DomainName:  "google.com",
		Port:        12345,
	}

	payload := util.GeneratePayload(1024)
	buf := bytes.NewBuffer(make([]byte, 0, 4096))
	buf.Write([]byte{0, 0, 0}) // RSV, FRAG
	common.Must(addr.Marshal(buf))
	buf.Write(payload)

	udpConn.WriteTo(buf.Bytes(), &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	})

	packet, err := s.AcceptPacket(nil)
	common.Must(err)
	recvBuf := make([]byte, 4096)
	n, m, err := packet.ReadWithMetadata(recvBuf)
	common.Must(err)
	if m.DomainName != "google.com" || m.Port != 12345 || n != 1024 || !(bytes.Equal(recvBuf[:n], payload)) {
		t.Fail()
	}

	payload = util.GeneratePayload(1024)
	_, err = packet.WriteWithMetadata(payload, &tunnel.Metadata{
		Address: &tunnel.Address{
			AddressType: tunnel.IPv4,
			IP:          net.ParseIP("123.123.234.234"),
			Port:        12345,
		},
	})
	common.Must(err)

	_, _, err = udpConn.ReadFrom(recvBuf)
	common.Must(err)

	r := bytes.NewReader(recvBuf)
	header := [3]byte{}
	r.Read(header[:])
	addr = new(tunnel.Address)
	common.Must(addr.Unmarshal(r))
	if addr.IP.String() != "123.123.234.234" || addr.Port != 12345 {
		t.Fail()
	}

	recvBuf, err = io.ReadAll(r)
	common.Must(err)

	if bytes.Equal(recvBuf, payload) {
		t.Fail()
	}
	packet.Close()
	udpConn.Close()

	c, _ := socks5.NewClient(fmt.Sprintf("127.0.0.1:%d", port), "", "", 0, 0)

	conn, err := c.Dial("udp", util.EchoAddr)
	common.Must(err)

	payload = util.GeneratePayload(4096)
	recvBuf = make([]byte, 4096)

	conn.Write(payload)

	newPacket, err := s.AcceptPacket(nil)
	common.Must(err)

	_, m, err = newPacket.ReadWithMetadata(recvBuf)
	common.Must(err)
	if m.String() != util.EchoAddr || !bytes.Equal(recvBuf, payload) {
		t.Fail()
	}

	s.Close()
}
