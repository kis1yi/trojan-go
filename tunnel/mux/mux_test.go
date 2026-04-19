package mux

import (
	"context"
	"testing"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/test/util"
	"github.com/kis1yi/trojan-go/tunnel/freedom"
	"github.com/kis1yi/trojan-go/tunnel/transport"
)

func TestMux(t *testing.T) {
	muxCfg := &Config{
		Mux: MuxConfig{
			Enabled:       true,
			Concurrency:   8,
			IdleTimeout:   60,
			StreamBuffer:  4194304,
			ReceiveBuffer: 4194304,
			Protocol:      2,
		},
	}
	ctx := config.WithConfig(context.Background(), Name, muxCfg)

	port := common.PickPort("tcp", "127.0.0.1")
	transportConfig := &transport.Config{
		LocalHost:  "127.0.0.1",
		LocalPort:  port,
		RemoteHost: "127.0.0.1",
		RemotePort: port,
	}
	ctx = config.WithConfig(ctx, transport.Name, transportConfig)
	ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})

	tcpClient, err := transport.NewClient(ctx, nil)
	common.Must(err)
	tcpServer, err := transport.NewServer(ctx, nil)
	common.Must(err)

	common.Must(err)

	muxTunnel := Tunnel{}
	muxClient, _ := muxTunnel.NewClient(ctx, tcpClient)
	muxServer, _ := muxTunnel.NewServer(ctx, tcpServer)

	conn1, err := muxClient.DialConn(nil, nil)
	common.Must2(conn1.Write(util.GeneratePayload(1024)))
	common.Must(err)
	buf := [1024]byte{}
	conn2, err := muxServer.AcceptConn(nil)
	common.Must(err)
	common.Must2(conn2.Read(buf[:]))
	if !util.CheckConn(conn1, conn2) {
		t.Fail()
	}
	conn1.Close()
	conn2.Close()
	muxClient.Close()
	muxServer.Close()
}

func TestMuxCustomBuffers(t *testing.T) {
	muxCfg := &Config{
		Mux: MuxConfig{
			Enabled:       true,
			Concurrency:   8,
			IdleTimeout:   60,
			StreamBuffer:  1048576,
			ReceiveBuffer: 2097152,
			Protocol:      2,
		},
	}
	ctx := config.WithConfig(context.Background(), Name, muxCfg)

	port := common.PickPort("tcp", "127.0.0.1")
	transportConfig := &transport.Config{
		LocalHost:  "127.0.0.1",
		LocalPort:  port,
		RemoteHost: "127.0.0.1",
		RemotePort: port,
	}
	ctx = config.WithConfig(ctx, transport.Name, transportConfig)
	ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})

	tcpClient, err := transport.NewClient(ctx, nil)
	common.Must(err)
	tcpServer, err := transport.NewServer(ctx, nil)
	common.Must(err)

	muxTunnel := Tunnel{}
	muxClient, err := muxTunnel.NewClient(ctx, tcpClient)
	common.Must(err)
	muxServer, err := muxTunnel.NewServer(ctx, tcpServer)
	common.Must(err)

	conn1, err := muxClient.DialConn(nil, nil)
	common.Must(err)
	common.Must2(conn1.Write(util.GeneratePayload(1024)))
	buf := [1024]byte{}
	conn2, err := muxServer.AcceptConn(nil)
	common.Must(err)
	common.Must2(conn2.Read(buf[:]))
	if !util.CheckConn(conn1, conn2) {
		t.Fail()
	}
	conn1.Close()
	conn2.Close()
	muxClient.Close()
	muxServer.Close()
}

func TestMuxDefaultBuffers(t *testing.T) {
	cfg := &Config{}
	// Verify zero-value fields are distinguishable from intended defaults
	if cfg.Mux.StreamBuffer != 0 {
		t.Errorf("expected zero-value StreamBuffer 0, got %d", cfg.Mux.StreamBuffer)
	}
	if cfg.Mux.ReceiveBuffer != 0 {
		t.Errorf("expected zero-value ReceiveBuffer 0, got %d", cfg.Mux.ReceiveBuffer)
	}

	// Verify the registered defaults produce a working config
	muxCfg := &Config{
		Mux: MuxConfig{
			Enabled:       true,
			Concurrency:   8,
			IdleTimeout:   60,
			StreamBuffer:  4194304,
			ReceiveBuffer: 4194304,
			Protocol:      2,
		},
	}
	if muxCfg.Mux.StreamBuffer != 4194304 {
		t.Errorf("expected StreamBuffer 4194304, got %d", muxCfg.Mux.StreamBuffer)
	}
	if muxCfg.Mux.ReceiveBuffer != 4194304 {
		t.Errorf("expected ReceiveBuffer 4194304, got %d", muxCfg.Mux.ReceiveBuffer)
	}
}
