package uacp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

const lifecycleFailureLimit = 2 * time.Second

func TestAcceptHandshakeNoHELReturnsCancellationAndClosesAcceptedTCP(t *testing.T) {
	server, peer := newLifecycleTCPPair(t)
	l := &Listener{ack: DefaultServerACK, endpoint: "opc.tcp://127.0.0.1/lifecycle"}
	a := startLifecycleHandshake(t, l, server)

	// This proves the helper reached context.AfterFunc setup on the actual
	// accepted TCP connection. It does not claim an OS Read-entry hook.
	waitLifecycleSignal(t, a.contextDoneRequested, "handshake cancellation setup")
	a.cancel()
	waitLifecycleSignal(t, a.done, "canceled handshake return")
	if a.conn != nil || !errors.Is(a.err, context.Canceled) {
		t.Fatalf("canceled handshake: conn=%p err=%v", a.conn, a.err)
	}
	assertLifecycleTCPClosed(t, server)
	assertLifecyclePeerEOF(t, peer)
}

func TestAcceptHandshakeHELDetachesCancellationBeforeReturningConnection(t *testing.T) {
	server, peer := newLifecycleTCPPair(t)
	l := &Listener{ack: DefaultServerACK, endpoint: "opc.tcp://127.0.0.1/lifecycle"}
	a := startLifecycleHandshake(t, l, server)
	client := newLifecycleConn(t, peer)
	ctx, cancel := context.WithTimeout(context.Background(), lifecycleFailureLimit)
	defer cancel()
	if err := client.Handshake(ctx, l.endpoint); err != nil {
		t.Fatalf("actual HEL/ACK: %v", err)
	}
	waitLifecycleSignal(t, a.done, "HEL handoff")
	if a.err != nil || a.conn == nil || a.conn.TCPConn != server {
		t.Fatalf("HEL handoff: conn=%p err=%v", a.conn, a.err)
	}

	// Cancellation after handoff must not close the successfully returned Conn.
	a.cancel()
	assertLifecycleExchange(t, client, a.conn, "after-HEL")
}

func TestAcceptHandshakeRHEClosesOriginalAndReturnedCloseOwnsReplacement(t *testing.T) {
	server, peer := newLifecycleTCPPair(t)
	replacementListener := newLifecycleTCPListener(t)
	l := &Listener{ack: DefaultServerACK, endpoint: "opc.tcp://127.0.0.1/lifecycle"}
	a := startLifecycleHandshake(t, l, server)
	client := newLifecycleConn(t, peer)
	setLifecycleDeadline(t, peer)
	if err := client.Send("RHEF", &ReverseHello{
		ServerURI: replacementListener.Addr().String(), EndpointURL: l.endpoint,
	}); err != nil {
		t.Fatalf("actual RHE: %v", err)
	}
	waitLifecycleSignal(t, a.done, "RHE handoff")
	if a.err != nil || a.conn == nil || a.conn.TCPConn == server {
		t.Fatalf("RHE replacement: conn=%p err=%v", a.conn, a.err)
	}
	replacementPeer, err := replacementListener.AcceptTCP()
	if err != nil {
		t.Fatalf("accept actual RHE replacement: %v", err)
	}
	t.Cleanup(func() { closeLifecycleOwned(t, replacementPeer) })
	assertLifecycleTCPClosed(t, server)
	assertLifecyclePeerEOF(t, peer)

	a.cancel()
	assertLifecycleExchange(t, newLifecycleConn(t, replacementPeer), a.conn, "after-RHE")
	if err := a.conn.Close(); err != nil {
		t.Fatalf("first returned Conn.Close must close replacement: %v", err)
	}
	assertLifecycleTCPClosed(t, a.conn.TCPConn)
	assertLifecyclePeerEOF(t, replacementPeer)
}

type lifecycleHandshakeAttempt struct {
	cancel               context.CancelFunc
	contextDoneRequested chan struct{}
	done                 chan struct{}
	conn                 *Conn
	err                  error
}

// The observation is only a helper-entry gate. It does not pretend to observe
// syscall entry or to pause the private cancellation callback after TCP.Close.
type lifecycleObservedContext struct {
	context.Context
	requested chan struct{}
	once      sync.Once
}

func (ctx *lifecycleObservedContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.requested) })
	return ctx.Context.Done()
}

func startLifecycleHandshake(t *testing.T, l *Listener, c *net.TCPConn) *lifecycleHandshakeAttempt {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	a := &lifecycleHandshakeAttempt{
		cancel: cancel, contextDoneRequested: make(chan struct{}), done: make(chan struct{}),
	}
	observed := &lifecycleObservedContext{Context: ctx, requested: a.contextDoneRequested}
	go func() {
		defer close(a.done)
		a.conn, a.err = l.acceptHandshake(observed, c)
	}()
	t.Cleanup(func() {
		cancel()
		// Force native IO to return even against the old no-cancellation code.
		closeLifecycleOwned(t, c)
		select {
		case <-a.done:
			if a.conn != nil {
				closeLifecycleOwned(t, a.conn)
			}
		case <-time.After(lifecycleFailureLimit):
			t.Errorf("handshake goroutine did not join after owned TCP close")
		}
	})
	return a
}

func newLifecycleTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l := newLifecycleTCPListener(t)
	dialer := net.Dialer{Timeout: lifecycleFailureLimit}
	client, err := dialer.DialContext(context.Background(), "tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial owned TCP listener: %v", err)
	}
	peer, ok := client.(*net.TCPConn)
	if !ok {
		closeLifecycleOwned(t, client)
		t.Fatal("owned TCP dial returned a non-TCP connection")
	}
	t.Cleanup(func() { closeLifecycleOwned(t, peer) })
	server, err := l.AcceptTCP()
	if err != nil {
		t.Fatalf("accept owned TCP connection: %v", err)
	}
	t.Cleanup(func() { closeLifecycleOwned(t, server) })
	return server, peer
}

func newLifecycleTCPListener(t *testing.T) *net.TCPListener {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen on owned loopback endpoint: %v", err)
	}
	t.Cleanup(func() { closeLifecycleOwned(t, l) })
	if err := l.SetDeadline(time.Now().Add(lifecycleFailureLimit)); err != nil {
		t.Fatalf("bound owned AcceptTCP: %v", err)
	}
	return l
}

func newLifecycleConn(t *testing.T, c *net.TCPConn) *Conn {
	t.Helper()
	conn, err := NewConn(c, DefaultClientACK)
	if err != nil {
		t.Fatalf("wrap owned TCP connection: %v", err)
	}
	return conn
}

func waitLifecycleSignal(t *testing.T, done <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(lifecycleFailureLimit):
		t.Fatalf("%s did not complete", label)
	}
}

func setLifecycleDeadline(t *testing.T, c *net.TCPConn) {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(lifecycleFailureLimit)); err != nil {
		t.Fatalf("bound owned TCP operation: %v", err)
	}
}

func assertLifecycleTCPClosed(t *testing.T, c *net.TCPConn) {
	t.Helper()
	if err := c.SetReadDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("exact owned TCP descriptor remained open: %v", err)
	}
}

func assertLifecyclePeerEOF(t *testing.T, c *net.TCPConn) {
	t.Helper()
	setLifecycleDeadline(t, c)
	var b [1]byte
	n, err := c.Read(b[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("owned peer did not observe actual close: n=%d err=%v", n, err)
	}
}

func assertLifecycleExchange(t *testing.T, client, server *Conn, label string) {
	t.Helper()
	setLifecycleDeadline(t, client.TCPConn)
	setLifecycleDeadline(t, server.TCPConn)
	assertLifecyclePacket(t, client, server, []byte(label+"-request"))
	assertLifecyclePacket(t, server, client, []byte(label+"-response"))
}

func assertLifecyclePacket(t *testing.T, sender, receiver *Conn, want []byte) {
	t.Helper()
	if err := sender.Send("MSGF", &Message{Data: want}); err != nil {
		t.Fatalf("send actual post-handoff packet: %v", err)
	}
	b, err := receiver.Receive()
	if err != nil {
		t.Fatalf("receive actual post-handoff packet: %v", err)
	}
	if len(b) < hdrlen || string(b[:4]) != "MSGF" || !bytes.Equal(b[hdrlen:], want) {
		t.Fatalf("post-handoff packet differs: got=%x want=%x", b, want)
	}
}

func closeLifecycleOwned(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Errorf("close owned lifecycle resource: %v", err)
	}
}
