package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gopcua/opcua/ua"
)

func TestDeleteSubscriptionDoesNotHoldRegistryWhilePurgingItems(t *testing.T) {
	srv := &Server{}
	service := &SubscriptionService{srv: srv, Subs: make(map[uint32]*Subscription)}
	srv.SubscriptionService = service
	srv.MonitoredItemService = &MonitoredItemService{
		SubService: service,
		Subs:       make(map[uint32][]*MonitoredItem),
	}
	sub := NewSubscription()
	sub.ID, sub.running, sub.srv = 1, true, service
	service.Subs[sub.ID] = sub
	srv.MonitoredItemService.Mu.Lock()
	deleted := make(chan struct{})
	go func() {
		service.DeleteSubscription(sub.ID)
		close(deleted)
	}()
	t.Cleanup(func() {
		srv.MonitoredItemService.Mu.Unlock()
		select {
		case <-deleted:
		case <-time.After(time.Second):
			t.Error("subscription deletion did not complete after item lock release")
		}
	})
	select {
	case <-sub.shutdown:
	case <-time.After(time.Second):
		t.Fatal("subscription deletion did not reach its stop boundary")
	}
	registryReleased := make(chan struct{})
	go func() {
		service.Mu.Lock()
		service.Mu.Unlock()
		close(registryReleased)
	}()
	select {
	case <-registryReleased:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("subscription registry is blocked by unrelated monitored-item cleanup")
	}
}

type subscriptionExitGate struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (*subscriptionExitGate) Debug(string, ...any) {}
func (*subscriptionExitGate) Error(string, ...any) {}
func (*subscriptionExitGate) Warn(string, ...any)  {}
func (g *subscriptionExitGate) Info(format string, _ ...any) {
	if format == "Subscription %d shutting down." {
		g.once.Do(func() { close(g.entered) })
		<-g.release
	}
}

func TestSubscriptionRetirementRemainsVisibleUntilActualExit(t *testing.T) {
	gate := &subscriptionExitGate{entered: make(chan struct{}), release: make(chan struct{})}
	srv := &Server{cfg: &serverConfig{logger: gate}}
	service := &SubscriptionService{srv: srv, Subs: make(map[uint32]*Subscription)}
	srv.SubscriptionService = service
	srv.MonitoredItemService = &MonitoredItemService{Subs: make(map[uint32][]*MonitoredItem)}
	sub := NewSubscription()
	sub.ID, sub.running, sub.srv = 1, true, service
	sub.RevisedPublishingInterval = 60_000
	service.Subs[sub.ID] = sub
	sub.Start()
	t.Cleanup(func() {
		close(gate.release)
		select {
		case <-sub.Done():
		case <-time.After(time.Second):
			t.Error("subscription run did not exit after its gate was released")
		}
	})
	service.DeleteSubscription(sub.ID)
	select {
	case <-gate.entered:
	case <-time.After(time.Second):
		t.Fatal("native subscription run did not reach exit")
	}
	service.Mu.Lock()
	retained := service.Subs[sub.ID] == sub && !sub.running
	service.Mu.Unlock()
	if !retained {
		t.Fatal("unconfirmed retirement returned its registration before native exit")
	}
	select {
	case <-sub.Done():
		t.Fatal("subscription reported exit before cleanup completed")
	default:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := service.closeSubscriptions(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("incomplete shutdown must report its actual deadline: %v", err)
	}
}

func TestSubscriptionFinalizerCannotRemoveAnotherInstance(t *testing.T) {
	srv := &Server{MonitoredItemService: &MonitoredItemService{Subs: make(map[uint32][]*MonitoredItem)}}
	service := &SubscriptionService{srv: srv, Subs: make(map[uint32]*Subscription)}
	old, current := NewSubscription(), NewSubscription()
	t.Cleanup(current.cancel)
	old.ID, current.ID = 1, 1
	old.srv, old.running = service, true
	service.Subs[1] = current
	service.finishSubscription(old)
	if service.Subs[1] != current {
		t.Fatal("old finalizer removed another subscription instance")
	}
}

func TestSubscriptionIDAllocationDoesNotReuseHolesOrWrap(t *testing.T) {
	service := &SubscriptionService{Subs: make(map[uint32]*Subscription)}
	first, err := service.nextSubscriptionIDLocked()
	if err != nil {
		t.Fatal(err)
	}
	service.Subs[first] = NewSubscription()
	t.Cleanup(service.Subs[first].cancel)
	second, err := service.nextSubscriptionIDLocked()
	if err != nil {
		t.Fatal(err)
	}
	delete(service.Subs, first)
	service.Subs[second] = NewSubscription()
	t.Cleanup(service.Subs[second].cancel)
	third, err := service.nextSubscriptionIDLocked()
	if err != nil || first == 0 || second <= first || third <= second {
		t.Fatalf("subscription hole reused a live identity: %d %d %d %v", first, second, third, err)
	}
	service.lastSubscriptionID = ^uint32(0)
	if id, err := service.nextSubscriptionIDLocked(); id != 0 || err != ua.StatusBadTooManySubscriptions {
		t.Fatalf("exhausted wire IDs must reject rather than wrap: %d %v", id, err)
	}
}
