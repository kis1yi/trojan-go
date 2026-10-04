package websocket

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/tunnel/freedom"
	"github.com/kis1yi/trojan-go/tunnel/transport"
)

func TestClientWritesBinaryFrames(t *testing.T) {
	type receivedFrame struct {
		payload     []byte
		payloadType byte
		err         error
	}
	received := make(chan receivedFrame, 1)
	server := httptest.NewServer(websocket.Handler(func(conn *websocket.Conn) {
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			received <- receivedFrame{err: err}
			return
		}
		var frame receivedFrame
		codec := websocket.Codec{
			Unmarshal: func(data []byte, payloadType byte, _ interface{}) error {
				frame.payload = append([]byte(nil), data...)
				frame.payloadType = payloadType
				if payloadType != websocket.BinaryFrame {
					return common.NewError("binary websocket frame required")
				}
				return nil
			},
		}
		frame.err = codec.Receive(conn, nil)
		received <- frame
		if frame.err == nil {
			if err := websocket.Message.Send(conn, frame.payload); err != nil {
				t.Errorf("echo binary frame: %v", err)
			}
		}
	}))
	t.Cleanup(server.Close)

	host, portString, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	ctx := config.WithConfig(context.Background(), Name, &Config{
		Websocket: WebsocketConfig{Enabled: true, Host: "localhost", Path: "/ws"},
	})
	ctx = config.WithConfig(ctx, transport.Name, &transport.Config{RemoteHost: host, RemotePort: port})
	ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})
	underlay, err := transport.NewClient(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { underlay.Close() })
	client, err := NewClient(ctx, underlay)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialConn(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// Encrypted stream data can contain bytes that are invalid in a text frame.
	payload := []byte{0xff, 0xfe, 0x00, 0x80, 0x01, 0xc0, 0xaf}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-received:
		if frame.payloadType != websocket.BinaryFrame {
			t.Fatalf("websocket frame type = %d, want binary (%d): %v", frame.payloadType, websocket.BinaryFrame, frame.err)
		}
		if frame.err != nil {
			t.Fatal(frame.err)
		}
		if !bytes.Equal(frame.payload, payload) {
			t.Fatalf("received payload = %x, want %x", frame.payload, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for websocket frame")
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("echoed payload = %x, want %x", echo, payload)
	}
}
