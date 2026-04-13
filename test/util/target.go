package util

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/websocket"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/log"
)

var (
	HTTPAddr string
	HTTPPort string
)

func runHelloHTTPServer() {
	httpHello := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("HelloWorld"))
	}

	wsConfig, err := websocket.NewConfig("wss://127.0.0.1/websocket", "https://127.0.0.1")
	common.Must(err)
	wsServer := websocket.Server{
		Config: *wsConfig,
		Handler: func(conn *websocket.Conn) {
			conn.Write([]byte("HelloWorld"))
		},
		Handshake: func(wsConfig *websocket.Config, httpRequest *http.Request) error {
			log.Debug("websocket url", httpRequest.URL, "origin", httpRequest.Header.Get("Origin"))
			return nil
		},
	}
	mux := &http.ServeMux{}
	mux.HandleFunc("/", httpHello)
	mux.HandleFunc("/websocket", wsServer.ServeHTTP)
	HTTPAddr = GetTestAddr()
	_, HTTPPort, _ = net.SplitHostPort(HTTPAddr)
	server := http.Server{
		Addr:    HTTPAddr,
		Handler: mux,
	}
	go server.ListenAndServe()
	time.Sleep(time.Second * 1) // wait for http server
	fmt.Println("http test server listening on", HTTPAddr)
	wg.Done()
}

var (
	EchoAddr string
	EchoPort int
)

func runTCPEchoServer() {
	listener, err := net.Listen("tcp", EchoAddr)
	common.Must(err)
	wg.Done()
	go func() {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				for {
					buf := make([]byte, 2048)
					conn.SetDeadline(time.Now().Add(time.Second * 5))
					n, err := conn.Read(buf)
					conn.SetDeadline(time.Time{})
					if err != nil {
						return
					}
					_, err = conn.Write(buf[0:n])
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
}

func runUDPEchoServer() {
	conn, err := net.ListenPacket("udp", EchoAddr)
	common.Must(err)
	wg.Done()
	go func() {
		for {
			buf := make([]byte, 1024*8)
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			log.Info("Echo from", addr)
			conn.WriteTo(buf[0:n], addr)
		}
	}()
}

func GeneratePayload(length int) []byte {
	buf := make([]byte, length)
	io.ReadFull(rand.Reader, buf)
	return buf
}

var (
	BlackHoleAddr string
	BlackHolePort int
)

func runTCPBlackHoleServer() {
	listener, err := net.Listen("tcp", BlackHoleAddr)
	common.Must(err)
	wg.Done()
	go func() {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				io.Copy(io.Discard, conn)
				conn.Close()
			}(conn)
		}
	}()
}

func runUDPBlackHoleServer() {
	conn, err := net.ListenPacket("udp", BlackHoleAddr)
	common.Must(err)
	wg.Done()
	go func() {
		defer conn.Close()
		buf := make([]byte, 1024*8)
		for {
			_, _, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()
}

var wg = sync.WaitGroup{}

// pickDualPort returns a port available for both TCP and UDP on the given host.
func pickDualPort(host string) int {
	for retry := 0; retry < 16; retry++ {
		l, err := net.Listen("tcp", host+":0")
		if err != nil {
			continue
		}
		_, port, _ := net.SplitHostPort(l.Addr().String())
		l.Close()
		uc, err := net.ListenPacket("udp", host+":"+port)
		if err != nil {
			continue
		}
		uc.Close()
		p, _ := strconv.Atoi(port)
		return p
	}
	panic("failed to pick a dual TCP/UDP port")
}

func init() {
	wg.Add(5)
	runHelloHTTPServer()

	// Pick ports available for both TCP and UDP to avoid Windows
	// ephemeral port exclusion issues (Hyper-V reserves port ranges
	// that may differ between protocols).
	EchoPort = pickDualPort("127.0.0.1")
	EchoAddr = fmt.Sprintf("127.0.0.1:%d", EchoPort)

	BlackHolePort = pickDualPort("127.0.0.1")
	BlackHoleAddr = fmt.Sprintf("127.0.0.1:%d", BlackHolePort)

	runTCPEchoServer()
	runUDPEchoServer()

	runTCPBlackHoleServer()
	runUDPBlackHoleServer()

	wg.Wait()
}
