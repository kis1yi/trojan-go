package mux

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"github.com/kis1yi/trojan-go/common"
	"github.com/kis1yi/trojan-go/config"
	"github.com/kis1yi/trojan-go/log"
	"github.com/kis1yi/trojan-go/tunnel"
)

type muxID uint32

func generateMuxID() muxID {
	return muxID(rand.Uint32())
}

type smuxClientInfo struct {
	id             muxID
	client         *smux.Session
	lastActiveTime time.Time
	underlayConn   tunnel.Conn
}

// Client is a smux client
type Client struct {
	clientPoolLock sync.Mutex
	clientPool     map[muxID]*smuxClientInfo
	underlay       tunnel.Client
	concurrency    int
	timeout        time.Duration
	streamBuffer   int
	receiveBuffer  int
	protocol       int
	ctx            context.Context
	cancel         context.CancelFunc
	closed         bool
}

func (c *Client) Close() error {
	c.clientPoolLock.Lock()
	if c.closed {
		c.clientPoolLock.Unlock()
		c.cancel()
		return nil
	}
	c.closed = true
	clients := c.drainClientPoolLocked()
	c.clientPoolLock.Unlock()

	c.cancel()
	closeMuxClients(clients)
	return nil
}

func (c *Client) drainClientPoolLocked() []*smuxClientInfo {
	clients := make([]*smuxClientInfo, 0, len(c.clientPool))
	for id, info := range c.clientPool {
		delete(c.clientPool, id)
		log.Debug("mux client", id, "closed")
		clients = append(clients, info)
	}
	return clients
}

func closeMuxClients(clients []*smuxClientInfo) {
	for _, info := range clients {
		if info.underlayConn != nil {
			_ = info.underlayConn.Close()
		}
		if info.client != nil {
			_ = info.client.Close()
		}
	}
}

func (c *Client) cleanLoop() {
	var checkDuration time.Duration
	if c.timeout <= 0 {
		checkDuration = time.Second * 10
		log.Warn("negative mux timeout")
	} else {
		checkDuration = c.timeout / 4
	}
	log.Debug("check duration:", checkDuration.Seconds(), "s")
	for {
		select {
		case <-time.After(checkDuration):
			c.clientPoolLock.Lock()
			var clientsToClose []*smuxClientInfo
			for id, info := range c.clientPool {
				if info.client.IsClosed() {
					delete(c.clientPool, id)
					log.Info("mux client", id, "is dead")
					clientsToClose = append(clientsToClose, info)
				} else if info.client.NumStreams() == 0 && time.Since(info.lastActiveTime) > c.timeout {
					delete(c.clientPool, id)
					log.Info("mux client", id, "is closed due to inactivity")
					clientsToClose = append(clientsToClose, info)
				}
			}
			log.Debug("current mux clients: ", len(c.clientPool))
			for id, info := range c.clientPool {
				log.Debug(fmt.Sprintf("  - %x: %d/%d", id, info.client.NumStreams(), c.concurrency))
			}
			c.clientPoolLock.Unlock()
			closeMuxClients(clientsToClose)
		case <-c.ctx.Done():
			log.Debug("shutting down mux cleaner..")
			c.clientPoolLock.Lock()
			c.closed = true
			clients := c.drainClientPoolLocked()
			c.clientPoolLock.Unlock()
			closeMuxClients(clients)
			return
		}
	}
}

func (c *Client) newMuxClient() (*smuxClientInfo, error) {
	// The mutex should be locked when this function is called
	id := generateMuxID()
	if _, found := c.clientPool[id]; found {
		return nil, common.NewError("duplicated id")
	}

	fakeAddr := &tunnel.Address{
		DomainName:  "MUX_CONN",
		AddressType: tunnel.DomainName,
	}
	conn, err := c.underlay.DialConn(fakeAddr, &Tunnel{})
	if err != nil {
		return nil, common.NewError("mux failed to dial").Base(err)
	}
	conn = newStickyConn(conn)

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = c.protocol
	smuxConfig.MaxStreamBuffer = c.streamBuffer
	smuxConfig.MaxReceiveBuffer = c.receiveBuffer
	client, err := smux.Client(conn, smuxConfig)
	if err != nil {
		conn.Close()
		return nil, common.NewError("mux failed to create smux client").Base(err)
	}
	info := &smuxClientInfo{
		client:         client,
		underlayConn:   conn,
		id:             id,
		lastActiveTime: time.Now(),
	}
	c.clientPool[id] = info
	return info, nil
}

func (c *Client) DialConn(*tunnel.Address, tunnel.Tunnel) (tunnel.Conn, error) {
	var clientsToClose []*smuxClientInfo

	createNewConn := func(info *smuxClientInfo) (tunnel.Conn, error) {
		rwc, err := info.client.Open()
		info.lastActiveTime = time.Now()
		if err != nil {
			delete(c.clientPool, info.id)
			clientsToClose = append(clientsToClose, info)
			return nil, common.NewError("mux failed to open stream from client").Base(err)
		}
		return &Conn{
			rwc:  rwc,
			Conn: info.underlayConn,
		}, nil
	}

	c.clientPoolLock.Lock()
	if c.closed {
		c.clientPoolLock.Unlock()
		return nil, common.NewError("mux client closed")
	}
	for _, info := range c.clientPool {
		if info.client.IsClosed() {
			delete(c.clientPool, info.id)
			log.Info(fmt.Sprintf("Mux client %x is closed", info.id))
			clientsToClose = append(clientsToClose, info)
			continue
		}
		if info.client.NumStreams() < c.concurrency || c.concurrency <= 0 {
			conn, err := createNewConn(info)
			c.clientPoolLock.Unlock()
			closeMuxClients(clientsToClose)
			return conn, err
		}
	}

	info, err := c.newMuxClient()
	if err != nil {
		c.clientPoolLock.Unlock()
		closeMuxClients(clientsToClose)
		return nil, common.NewError("no available mux client found").Base(err)
	}
	conn, err := createNewConn(info)
	c.clientPoolLock.Unlock()
	closeMuxClients(clientsToClose)
	return conn, err
}

func (c *Client) DialPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

func NewClient(ctx context.Context, underlay tunnel.Client) (*Client, error) {
	clientConfig := config.FromContext(ctx, Name).(*Config)
	ctx, cancel := context.WithCancel(ctx)
	client := &Client{
		underlay:      underlay,
		concurrency:   clientConfig.Mux.Concurrency,
		timeout:       time.Duration(clientConfig.Mux.IdleTimeout) * time.Second,
		streamBuffer:  clientConfig.Mux.StreamBuffer,
		receiveBuffer: clientConfig.Mux.ReceiveBuffer,
		protocol:      clientConfig.Mux.Protocol,
		ctx:           ctx,
		cancel:        cancel,
		clientPool:    make(map[muxID]*smuxClientInfo),
	}
	go client.cleanLoop()
	log.Debug("mux client created")
	return client, nil
}
