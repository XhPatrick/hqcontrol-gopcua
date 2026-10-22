package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uacp"
)

// The lifecycle tests need no XML address space or application session.
func newLifecycleTestServer(t *testing.T) (*Server, context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	srv := &Server{
		cfg: &serverConfig{endpoints: []string{"opc.tcp://127.0.0.1:0"}},
		url: "opc.tcp://127.0.0.1:0", status: &ua.ServerStatusDataType{},
		cb: newChannelBroker(nil), sb: newSessionBroker(nil), handlers: make(map[uint16]Handler),
	}
	t.Cleanup(func() {
		cancel()
		if err := srv.Close(); err != nil {
			t.Errorf("owned server cleanup: %v", err)
		}
	})
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return srv, ctx, cancel
}

func TestServerCloseJoinsIdleAcceptAndMonitor(t *testing.T) {
	srv, ctx, _ := newLifecycleTestServer(t)
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal("Close depended on cancellation of the caller context")
	}
	assertLifecycleTestServerJoined(t, srv)
}

func TestServerCloseJoinsActualOPNConnection(t *testing.T) {
	srv, ctx, _ := newLifecycleTestServer(t)
	raw := dialLifecycleTestServer(t, srv, ctx)
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal("Close depended on cancellation of the caller context")
	}
	assertLifecycleTestServerJoined(t, srv)
	if err := raw.SetReadDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("original admitted descriptor remained open: %v", err)
	}
}

func TestServerParentCancellationJoinsConnectionAndLoops(t *testing.T) {
	srv, ctx, cancel := newLifecycleTestServer(t)
	raw := dialLifecycleTestServer(t, srv, ctx)
	cancel()
	assertLifecycleTestServerJoined(t, srv)
	if err := raw.SetReadDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("parent cancellation left original descriptor open: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
}

func dialLifecycleTestServer(t *testing.T, srv *Server, ctx context.Context) *uacp.Conn {
	t.Helper()
	client, err := opcua.NewClient(fmt.Sprintf("opc.tcp://%s", srv.l.Addr()),
		opcua.SecurityPolicy(ua.SecurityPolicyURINone), opcua.SecurityMode(ua.MessageSecurityModeNone),
		opcua.AutoReconnect(false), opcua.RequestTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := client.Close(cleanup); err != nil {
			t.Errorf("owned client cleanup: %v", err)
		}
	})
	dial, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := client.Dial(dial); err != nil {
		t.Fatalf("actual HEL/ACK/OPN did not complete: %v", err)
	}
	srv.cb.mu.RLock()
	defer srv.cb.mu.RUnlock()
	if len(srv.cb.connections) != 1 {
		t.Fatalf("completed OPN has %d owned registrations", len(srv.cb.connections))
	}
	for raw := range srv.cb.connections {
		return raw
	}
	t.Fatal("missing original descriptor")
	return nil
}

func assertLifecycleTestServerJoined(t *testing.T, srv *Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, done := range []<-chan struct{}{srv.stopDone, srv.acceptDone, srv.monitorDone, srv.cb.done} {
		if err := waitServerLoop(ctx, done); err != nil {
			t.Fatalf("server loop or admitted registration did not actually exit: %v", err)
		}
	}
	srv.cb.mu.RLock()
	defer srv.cb.mu.RUnlock()
	if len(srv.cb.s) != 0 || len(srv.cb.connections) != 0 {
		t.Fatal("joined server retained channel or descriptor registrations")
	}
}
