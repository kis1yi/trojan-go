package shadowsocks

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/test/util"
	"github.com/kis1yi/trojan-go/tunnel/freedom"
	"github.com/kis1yi/trojan-go/tunnel/transport"
)

func TestShadowsocks(t *testing.T) {
	// Disable the go-shadowsocks2 global salt replay filter.
	// In-process tests share the singleton BloomRing, so the client's
	// AddSalt is immediately visible to the server's CheckSalt, causing
	// a spurious ErrRepeatedSalt ("invalid aead payload").
	t.Setenv("SHADOWSOCKS_SF_CAPACITY", "-1")

	p, err := strconv.ParseInt(util.HTTPPort, 10, 32)
	common.Must(err)

	port := common.PickPort("tcp", "127.0.0.1")
	transportConfig := &transport.Config{
		LocalHost:  "127.0.0.1",
		LocalPort:  port,
		RemoteHost: "127.0.0.1",
		RemotePort: port,
	}
	ctx := config.WithConfig(context.Background(), transport.Name, transportConfig)
	ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})
	tcpClient, err := transport.NewClient(ctx, nil)
	common.Must(err)
	tcpServer, err := transport.NewServer(ctx, nil)
	common.Must(err)

	cfg := &Config{
		RemoteHost: "127.0.0.1",
		RemotePort: int(p),
		Shadowsocks: ShadowsocksConfig{
			Enabled:  true,
			Method:   "AES-128-GCM",
			Password: "password",
		},
	}
	ctx = config.WithConfig(ctx, Name, cfg)

	c, err := NewClient(ctx, tcpClient)
	common.Must(err)
	s, err := NewServer(ctx, tcpServer)
	common.Must(err)

	wg := sync.WaitGroup{}
	wg.Add(2)
	var conn1, conn2 net.Conn
	go func() {
		var err error
		conn1, err = c.DialConn(nil, nil)
		if err != nil {
			t.Error(err)
			wg.Done()
			return
		}
		conn1.Write(util.GeneratePayload(1024))
		wg.Done()
	}()
	go func() {
		var err error
		conn2, err = s.AcceptConn(nil)
		if err != nil {
			t.Error(err)
			wg.Done()
			return
		}
		buf := [1024]byte{}
		conn2.Read(buf[:])
		wg.Done()
	}()
	wg.Wait()
	if t.Failed() {
		return
	}
	if !util.CheckConn(conn1, conn2) {
		t.Fail()
	}

	go func() {
		var err error
		conn2, err = s.AcceptConn(nil)
		if err == nil {
			t.Fail()
		}
	}()

	// test redirection
	conn3, err := tcpClient.DialConn(nil, nil)
	common.Must(err)
	// Build a payload that looks like a garbled HTTP request so the target
	// HTTP server can parse the request line and reply with 400 instead of
	// blocking forever waiting for '\n'.  Random bytes alone may lack a
	// newline (~1.8 % chance for 1024 bytes), which causes the HTTP server
	// to stall on ReadLine and deadlocks the redirector ↔ test pipeline.
	payload := util.GeneratePayload(1024)
	payload[len(payload)-1] = '\n'
	n, err := conn3.Write(payload)
	common.Must(err)
	fmt.Println("write:", n)
	buf := [1024]byte{}
	conn3.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = conn3.Read(buf[:])
	if err != nil {
		t.Fatal("failed to read redirected response:", err)
	}
	fmt.Println("read:", n)
	if !strings.Contains(string(buf[:n]), "Bad Request") {
		t.Fail()
	}
	conn1.Close()
	conn3.Close()
	c.Close()
	s.Close()
}
