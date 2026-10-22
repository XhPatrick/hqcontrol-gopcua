package server

import (
	"context"
	"crypto/rsa"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"time"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
	"github.com/gopcua/opcua/uasc"
)

type channelBroker struct {
	endpoints map[string]*ua.EndpointDescription

	connections map[*uacp.Conn]struct{}
	stop        chan struct{}
	done        chan struct{}
	closing     bool
	drained     bool

	// mu protects concurrent modification of s, secureChannelID, and secureTokenID
	mu sync.RWMutex
	// s is a slice of all SecureChannels watched by the channelBroker
	s map[uint32]*uasc.SecureChannel

	// Next Secure Channel ID to issue to a client
	secureChannelID uint32

	// Next Token ID to issue to a client
	secureTokenID uint32

	// msgChan is the common channel that all messages from all channels
	// get funneled into for handling
	msgChan chan *uasc.MessageBody
	logger  Logger
}

func newChannelBroker(logger Logger) *channelBroker {
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	return &channelBroker{
		endpoints:       make(map[string]*ua.EndpointDescription),
		connections:     make(map[*uacp.Conn]struct{}),
		stop:            make(chan struct{}),
		done:            make(chan struct{}),
		s:               make(map[uint32]*uasc.SecureChannel),
		msgChan:         make(chan *uasc.MessageBody),
		secureChannelID: uint32(rng.Int31()),
		secureTokenID:   uint32(rng.Int31()),
		logger:          logger,
	}
}

// RegisterConn connects a new UACP connection to the channel broker's list
// of connections and starts waiting for data on it.  Data is pushed onto the broker's
// Response channel
// Blocks until the context is done, the connection closes, or a critical error
func (c *channelBroker) RegisterConn(ctx context.Context, conn *uacp.Conn, localCert []byte, localKey *rsa.PrivateKey) error {
	secureChannelID, secureTokenID, err := c.admitConnection(conn)
	if err != nil {
		_ = conn.Close()
		return err
	}
	return c.serveAdmittedConnection(ctx, conn, localCert, localKey, secureChannelID, secureTokenID)
}

func (c *channelBroker) startConnection(ctx context.Context, conn *uacp.Conn, localCert []byte, localKey *rsa.PrivateKey) error {
	secureChannelID, secureTokenID, err := c.admitConnection(conn)
	if err != nil {
		_ = conn.Close()
		return err
	}
	go func() { _ = c.serveAdmittedConnection(ctx, conn, localCert, localKey, secureChannelID, secureTokenID) }()
	return nil
}

func (c *channelBroker) serveAdmittedConnection(ctx context.Context, conn *uacp.Conn, localCert []byte, localKey *rsa.PrivateKey, secureChannelID, secureTokenID uint32) error {
	defer c.releaseConnection(conn, secureChannelID)
	defer conn.Close()
	canceled := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		defer close(canceled)
		_ = conn.Close()
	})
	defer func() {
		if !stopCancellation() {
			<-canceled
		}
	}()
	cfg := defaultChannelConfig()
	cfg.Certificate, cfg.LocalKey = localCert, localKey
	errch := make(chan error, 1)
	sc, err := uasc.NewServerSecureChannel("", conn, cfg, errch, secureChannelID,
		uint32(mrand.Int31n(1023)+1), secureTokenID)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(); _ = sc.Close() }()
	c.mu.Lock()
	c.s[secureChannelID] = sc
	count := len(c.s)
	c.mu.Unlock()
	if c.logger != nil {
		c.logger.Info("Registered new channel (id %d) now at %d channels", secureChannelID, count)
	}
	return c.receiveConnection(ctx, sc)
}

func (c *channelBroker) admitConnection(conn *uacp.Conn) (uint32, uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing {
		return 0, 0, net.ErrClosed
	}
	c.connections[conn] = struct{}{}
	c.secureChannelID++
	c.secureTokenID++
	return c.secureChannelID, c.secureTokenID, nil
}

func (c *channelBroker) releaseConnection(conn *uacp.Conn, id uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.s, id)
	delete(c.connections, conn)
	c.signalDrainedLocked()
}

func (c *channelBroker) signalDrainedLocked() {
	if c.closing && len(c.connections) == 0 && !c.drained {
		c.drained = true
		close(c.done)
	}
}

func (c *channelBroker) receiveConnection(ctx context.Context, sc *uasc.SecureChannel) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stop:
			return net.ErrClosed
		default:
		}
		msg := sc.Receive(ctx)
		if msg.Err == io.EOF {
			return nil
		}
		if msg.Err != nil {
			return msg.Err
		}
		select {
		case c.msgChan <- msg:
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stop:
			return net.ErrClosed
		}
	}
}

func (c *channelBroker) stopConnections() {
	c.mu.Lock()
	if !c.closing {
		c.closing = true
		close(c.stop)
	}
	connections := make([]*uacp.Conn, 0, len(c.connections))
	for conn := range c.connections {
		connections = append(connections, conn)
	}
	c.signalDrainedLocked()
	c.mu.Unlock()
	// Closing the original socket interrupts native reads and writes. It must
	// precede secure-channel Close, which otherwise may itself attempt a write.
	for _, conn := range connections {
		_ = conn.Close()
	}
}

// Close closes admission and joins all admitted secure-channel registrations.
func (c *channelBroker) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.closeContext(ctx)
}

func (c *channelBroker) closeContext(ctx context.Context) error {
	c.stopConnections()
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *channelBroker) ReadMessage(ctx context.Context) *uasc.MessageBody {
	select {
	case <-ctx.Done():
		return nil
	case <-c.stop:
		return nil
	case msg := <-c.msgChan:
		return msg
	}
}
