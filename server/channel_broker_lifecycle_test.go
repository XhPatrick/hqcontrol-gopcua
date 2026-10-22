package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
)

// These tests deliberately omit Server.New/Start, the XML address space, sessions
// and an application message receiver. Client.Dial completes real HEL/ACK/OPN.
// In the pinned SDK, Receive handles OPN and then returns an empty MessageBody,
// which RegisterConn tries to forward to the unbuffered broker channel.
const brokerLifecycleTestLimit = 2 * time.Second

type brokerLifecycleTestOperation struct {
	done chan struct{}
	err  error // Read only after done closes.
}

type brokerLifecycleTestPeer struct {
	broker       *channelBroker
	listener     *uacp.Listener
	client       *opcua.Client
	registration *brokerLifecycleTestOperation
	dial         *brokerLifecycleTestOperation
	closing      *brokerLifecycleTestOperation
	raw          atomic.Pointer[uacp.Conn]
	ctx          context.Context
	cancel       context.CancelFunc
}

func TestChannelBrokerCallerCancellationAfterActualOPNExitsRegistration(t *testing.T) {
	peer := newBrokerLifecycleTestPeer(t)
	if !waitBrokerLifecycleTestOperation(t, "actual Client.Dial", peer.dial) {
		return
	}
	if peer.dial.err != nil {
		t.Fatalf("fixture did not complete actual HEL/ACK/OPN: %v", peer.dial.err)
	}
	if peer.raw.Load() == nil {
		t.Fatal("OPN completed without an accepted, owned UACP connection")
	}

	peer.cancel()
	if !waitBrokerLifecycleTestOperation(t, "canceled RegisterConn", peer.registration) {
		return
	}
	if !errors.Is(peer.ctx.Err(), context.Canceled) {
		t.Fatalf("registration context error = %v, want cancellation", peer.ctx.Err())
	}
	assertBrokerLifecycleTestRegistrationClosed(t, peer)
	peer.startClose()
	if waitBrokerLifecycleTestOperation(t, "Close after registration exit", peer.closing) && peer.closing.err != nil {
		t.Errorf("Close after completed cancellation: %v", peer.closing.err)
	}
}

func TestChannelBrokerCloseAfterActualOPNJoinsWithoutCallerCancellation(t *testing.T) {
	peer := newBrokerLifecycleTestPeer(t)
	if !waitBrokerLifecycleTestOperation(t, "actual Client.Dial", peer.dial) {
		return
	}
	if peer.dial.err != nil {
		t.Fatalf("fixture did not complete actual HEL/ACK/OPN: %v", peer.dial.err)
	}
	if peer.raw.Load() == nil {
		t.Fatal("OPN completed without an accepted, owned UACP connection")
	}

	// Do not cancel the caller here. Closing the broker must itself interrupt
	// both a blocked forward and an actual Receive on its original connection.
	peer.startClose()
	if !waitBrokerLifecycleTestOperation(t, "Close with live caller", peer.closing) {
		return
	}
	if peer.closing.err != nil {
		t.Errorf("Close: %v", peer.closing.err)
	}
	if err := peer.ctx.Err(); err != nil {
		t.Errorf("test canceled the registration caller while testing broker Close: %v", err)
	}
	if !waitBrokerLifecycleTestOperation(t, "RegisterConn after Close", peer.registration) {
		return
	}
	assertBrokerLifecycleTestRegistrationClosed(t, peer)
}

func newBrokerLifecycleTestPeer(t *testing.T) *brokerLifecycleTestPeer {
	t.Helper()
	peer := &brokerLifecycleTestPeer{broker: newChannelBroker(nil)}
	peer.ctx, peer.cancel = context.WithCancel(context.Background())
	t.Cleanup(func() { peer.cleanup(t) })
	listener, err := uacp.Listen(peer.ctx, "opc.tcp://127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("listen for owned UACP peer: %v", err)
	}
	peer.listener = listener
	endpoint := fmt.Sprintf("opc.tcp://%s", listener.Addr())
	peer.client, err = opcua.NewClient(endpoint,
		opcua.SecurityPolicy(ua.SecurityPolicyURINone),
		opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.AutoReconnect(false),
		opcua.RequestTimeout(brokerLifecycleTestLimit),
	)
	if err != nil {
		t.Fatalf("create owned OPC UA client: %v", err)
	}
	peer.registration = startBrokerLifecycleTestOperation(peer.registerConnection)
	peer.dial = startBrokerLifecycleTestOperation(func() error {
		ctx, cancel := context.WithTimeout(peer.ctx, brokerLifecycleTestLimit)
		defer cancel()
		return peer.client.Dial(ctx)
	})
	return peer
}

func (peer *brokerLifecycleTestPeer) registerConnection() error {
	conn, err := peer.listener.Accept(peer.ctx)
	if err != nil {
		return fmt.Errorf("fixture UACP Accept: %w", err)
	}
	peer.raw.Store(conn)
	return peer.broker.RegisterConn(peer.ctx, conn, nil, nil)
}

func TestChannelBrokerCallerCancellationInsideNativeReceiveExitsRegistration(t *testing.T) {
	peer := newBrokerLifecycleTestPeer(t)
	if !waitBrokerLifecycleTestOperation(t, "actual Client.Dial", peer.dial) {
		return
	}
	if peer.dial.err != nil {
		t.Fatal(peer.dial.err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), brokerLifecycleTestLimit)
	defer cancel()
	msg := peer.broker.ReadMessage(ctx)
	if msg == nil || msg.Err != nil || msg.Request() != nil || msg.Response() != nil {
		t.Fatal("fixture did not consume the actual empty OPN completion")
	}
	waitBrokerLifecycleTestNativeReceive(t, ctx)
	peer.cancel()
	if !waitBrokerLifecycleTestOperation(t, "native Receive after caller cancellation", peer.registration) {
		return
	}
	assertBrokerLifecycleTestRegistrationClosed(t, peer)
}

// A structured stack snapshot proves the owned registration passed the Receive
// context check and entered a native read. The idle peer sends no more packets.
// No goroutine ID, stack text, sleep or elapsed delay substitutes for that gate.
func waitBrokerLifecycleTestNativeReceive(t *testing.T, ctx context.Context) {
	t.Helper()
	for ctx.Err() == nil {
		records := make([]runtime.StackRecord, runtime.NumGoroutine()+16)
		n, ok := runtime.GoroutineProfile(records)
		if ok {
			for _, record := range records[:n] {
				if brokerLifecycleTestNativeReceiveStack(record.Stack()) {
					return
				}
			}
		}
		runtime.Gosched()
	}
	t.Fatalf("owned registration did not enter actual native Receive: %v", ctx.Err())
}

func brokerLifecycleTestNativeReceiveStack(pcs []uintptr) bool {
	frames := runtime.CallersFrames(pcs)
	var owned, receive, native, descriptor bool
	for {
		frame, more := frames.Next()
		switch frame.Function {
		case "github.com/gopcua/opcua/server.(*brokerLifecycleTestPeer).registerConnection":
			owned = true
		case "github.com/gopcua/opcua/uasc.(*SecureChannel).readChunk":
			receive = true
		case "github.com/gopcua/opcua/uacp.(*Conn).Receive":
			native = true
		case "net.(*netFD).Read":
			descriptor = true
		}
		if !more {
			return owned && receive && native && descriptor
		}
	}
}

func startBrokerLifecycleTestOperation(run func() error) *brokerLifecycleTestOperation {
	op := &brokerLifecycleTestOperation{done: make(chan struct{})}
	go func() {
		defer close(op.done)
		op.err = run()
	}()
	return op
}

func (peer *brokerLifecycleTestPeer) startClose() {
	if peer.closing == nil {
		peer.closing = startBrokerLifecycleTestOperation(peer.broker.Close)
	}
}

func waitBrokerLifecycleTestOperation(t *testing.T, label string, op *brokerLifecycleTestOperation) bool {
	t.Helper()
	if op == nil {
		t.Errorf("%s was not started", label)
		return false
	}
	timer := time.NewTimer(brokerLifecycleTestLimit)
	defer timer.Stop()
	select {
	case <-op.done:
		return true
	case <-timer.C:
		t.Errorf("%s did not actually return; map removal or a silent Close timeout is not completion", label)
		return false
	}
}

func assertBrokerLifecycleTestRegistrationClosed(t *testing.T, peer *brokerLifecycleTestPeer) {
	t.Helper()
	if err := peer.registration.err; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Errorf("registration exited with an unexpected failure: %v", err)
	}
	// The caller has already joined registration; this check does not compete
	// with Receive or force the test's desired production shutdown to happen.
	peer.broker.mu.RLock()
	remaining := len(peer.broker.s)
	rawRemaining := len(peer.broker.connections)
	peer.broker.mu.RUnlock()
	if remaining != 0 || rawRemaining != 0 {
		t.Errorf("completed registration retained %d secure-channel and %d raw entries", remaining, rawRemaining)
	}
	conn := peer.raw.Load()
	if conn == nil {
		t.Error("registration never owned an actual UACP connection")
		return
	}
	// An operation on the captured descriptor must report its actual closed
	// state. Resetting a live deadline would return nil, so map-only cleanup
	// cannot satisfy this assertion. No competing raw Read is introduced.
	if err := conn.SetReadDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Errorf("captured original UACP descriptor is not closed: %v", err)
	}
}

func (peer *brokerLifecycleTestPeer) cleanup(t *testing.T) {
	t.Helper()
	peer.cancel()
	if peer.listener != nil {
		reportBrokerLifecycleTestClose(t, "listener", peer.listener.Close())
	}
	if conn := peer.raw.Load(); conn != nil {
		reportBrokerLifecycleTestClose(t, "captured raw connection", conn.Close())
	}
	peer.joinFailedRegistration(t)
	peer.closeClient(t)
	peer.startClose()
	if waitBrokerLifecycleTestOperation(t, "cleanup broker Close", peer.closing) && peer.closing.err != nil {
		t.Errorf("cleanup broker Close: %v", peer.closing.err)
	}
}

func (peer *brokerLifecycleTestPeer) joinFailedRegistration(t *testing.T) {
	t.Helper()
	// Failure cleanup only: release the one old OPN forward. No broad drain or
	// receiver is present during either test's production assertions.
	ctx, cancel := context.WithTimeout(context.Background(), brokerLifecycleTestLimit)
	drain := startBrokerLifecycleTestOperation(func() error {
		msg := peer.broker.ReadMessage(ctx)
		if msg != nil && (msg.Err != nil || msg.Request() != nil || msg.Response() != nil) {
			return errors.New("cleanup received a message other than the single owned OPN completion")
		}
		return nil
	})
	if peer.registration != nil {
		waitBrokerLifecycleTestOperation(t, "cleanup RegisterConn", peer.registration)
	}
	// Also cover an accepted connection published during failure cleanup.
	if conn := peer.raw.Load(); conn != nil {
		reportBrokerLifecycleTestClose(t, "captured raw connection after join", conn.Close())
	}
	cancel()
	if waitBrokerLifecycleTestOperation(t, "cleanup one-message receiver", drain) && drain.err != nil {
		t.Error(drain.err)
	}
}

func (peer *brokerLifecycleTestPeer) closeClient(t *testing.T) {
	t.Helper()
	if peer.dial != nil && waitBrokerLifecycleTestOperation(t, "cleanup Client.Dial", peer.dial) && peer.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), brokerLifecycleTestLimit)
		reportBrokerLifecycleTestClose(t, "client", peer.client.Close(ctx))
		cancel()
	}
}

func reportBrokerLifecycleTestClose(t *testing.T, name string, err error) {
	t.Helper()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close owned %s: %v", name, err)
	}
}
