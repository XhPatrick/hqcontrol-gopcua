package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gopcua/opcua/ua"
)

func TestMonitoredNotificationFullQueueStopsAfterSubscriptionRetirement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	srv, subscriptions, items := newMonitoredRetirementServices()
	namespace := &monitoredRetirementNamespace{
		MapNamespace: &MapNamespace{srv: srv, name: "retirement", Data: make(map[string]any)},
		entered:      make(chan struct{}), release: make(chan struct{}),
	}
	srv.AddNamespace(namespace)
	node := ua.NewStringNodeID(namespace.ID(), "value")
	sub := NewSubscription()
	sub.ID, sub.running, sub.srv = 7, true, subscriptions
	sub.NotifyChannel = make(chan *ua.MonitoredItemNotification, 1)
	sub.NotifyChannel <- &ua.MonitoredItemNotification{ClientHandle: 99}
	subscriptions.Subs[sub.ID] = sub
	item := monitoredRetirementItem(11, sub, node)
	items.Items[item.ID], items.Nodes[node.String()], items.Subs[sub.ID] = item, []*MonitoredItem{item}, []*MonitoredItem{item}
	notified := make(chan struct{})
	var probed, retired chan struct{}
	t.Cleanup(func() {
		// A historical unconditional send can finish after exactly the one
		// test-owned queued value is drained. Every started operation is joined.
		namespace.allowValue()
		select {
		case <-sub.NotifyChannel:
		default:
		}
		<-notified
		if probed != nil {
			<-probed
		}
		if retired != nil {
			<-retired
		} else {
			subscriptions.deleteSubscriptionInstance(sub)
		}
		sub.cancel()
	})
	go func() { defer close(notified); items.ChangeNotification(node) }()
	waitMonitoredRetirement(t, ctx, namespace.entered, "notification never entered the real Attribute call")
	if len(sub.NotifyChannel) != cap(sub.NotifyChannel) {
		t.Fatal("the exact subscription queue must remain full at the Attribute gate")
	}
	probed = make(chan struct{})
	go func() { items.Mu.Lock(); items.Mu.Unlock(); close(probed) }()
	waitMonitoredRetirement(t, ctx, probed, "old notification holds ItemMu during Attribute delivery")
	retired = make(chan struct{})
	go func() { defer close(retired); subscriptions.deleteSubscriptionInstance(sub) }()
	waitMonitoredRetirement(t, ctx, sub.shutdown, "exact subscription did not reach its stop boundary")
	waitMonitoredRetirement(t, ctx, retired, "notification prevented exact item purge")
	namespace.allowValue()
	waitMonitoredRetirement(t, ctx, notified, "full notification queue ignored the subscription shutdown")
}

func TestMonitoredRetirementPurgesOnlyTheExactSubscriptionInstance(t *testing.T) {
	_, subscriptions, items := newMonitoredRetirementServices()
	old, current := NewSubscription(), NewSubscription()
	t.Cleanup(old.cancel)
	t.Cleanup(current.cancel)
	old.ID, current.ID = 7, 7
	old.srv, current.srv = subscriptions, subscriptions
	old.running, current.running = true, true
	subscriptions.Subs[7] = current
	node := ua.NewStringNodeID(1, "shared")
	oldItem := monitoredRetirementItem(11, old, node)
	currentItem := monitoredRetirementItem(12, current, node)
	items.Items[11], items.Items[12] = oldItem, currentItem
	items.Nodes[node.String()] = []*MonitoredItem{oldItem, currentItem}
	items.Subs[7] = []*MonitoredItem{oldItem, currentItem}
	subscriptions.finishSubscription(old)
	if subscriptions.Subs[7] != current || !current.running {
		t.Fatal("the old finalizer replaced or stopped the new same-ID subscription")
	}
	if items.Items[11] != nil || items.Items[12] != currentItem {
		t.Fatal("exact retirement removed a new monitored item or retained an old item")
	}
	if got := items.Nodes[node.String()]; len(got) != 1 || got[0] != currentItem {
		t.Fatalf("node index does not retain exactly the new instance: %#v", got)
	}
	if got := items.Subs[7]; len(got) != 1 || got[0] != currentItem {
		t.Fatalf("subscription item index does not retain exactly the new instance: %#v", got)
	}
}

func TestStoppedSubscriptionRejectsNewMonitoredItems(t *testing.T) {
	srv, subscriptions, items := newMonitoredRetirementServices()
	srv.sb = newSessionBroker(nil)
	session := srv.sb.NewSession()
	sub := NewSubscription()
	t.Cleanup(sub.cancel)
	sub.ID, sub.srv, sub.Session, sub.running = 7, subscriptions, session, true
	subscriptions.Subs[sub.ID] = sub
	subscriptions.deleteSubscriptionInstance(sub)
	request := &ua.CreateMonitoredItemsRequest{
		RequestHeader:  &ua.RequestHeader{AuthenticationToken: session.AuthTokenID},
		SubscriptionID: sub.ID,
		ItemsToCreate: []*ua.MonitoredItemCreateRequest{
			monitoredRetirementItem(11, sub, ua.NewStringNodeID(0, "value")).Req,
		},
	}
	response, err := items.CreateMonitoredItems(nil, request, 0)
	if err == nil || response != nil {
		t.Fatalf("stopping subscription admitted a monitored item: response=%#v error=%v", response, err)
	}
	if len(items.Items) != 0 || len(items.Nodes) != 0 || len(items.Subs) != 0 || items.id != 0 {
		t.Fatal("rejected creation changed monitored-item indexes or consumed an item ID")
	}
	if subscriptions.Subs[sub.ID] != sub || sub.running {
		t.Fatal("rejected creation changed the pending retirement registration")
	}
}

func newMonitoredRetirementServices() (*Server, *SubscriptionService, *MonitoredItemService) {
	srv := &Server{cfg: &serverConfig{}}
	subscriptions := &SubscriptionService{srv: srv, Subs: make(map[uint32]*Subscription)}
	items := &MonitoredItemService{
		SubService: subscriptions, Items: make(map[uint32]*MonitoredItem),
		Nodes: make(map[string][]*MonitoredItem), Subs: make(map[uint32][]*MonitoredItem),
	}
	srv.SubscriptionService, srv.MonitoredItemService = subscriptions, items
	return srv, subscriptions, items
}

func monitoredRetirementItem(id uint32, sub *Subscription, node *ua.NodeID) *MonitoredItem {
	return &MonitoredItem{ID: id, Sub: sub, Req: &ua.MonitoredItemCreateRequest{
		ItemToMonitor:       &ua.ReadValueID{NodeID: node, AttributeID: ua.AttributeIDValue},
		RequestedParameters: &ua.MonitoringParameters{ClientHandle: id},
	}}
}

type monitoredRetirementNamespace struct {
	*MapNamespace
	entered, release       chan struct{}
	enterOnce, releaseOnce sync.Once
}

func (ns *monitoredRetirementNamespace) Attribute(_ *ua.NodeID, _ ua.AttributeID) *ua.DataValue {
	ns.enterOnce.Do(func() { close(ns.entered) })
	<-ns.release
	return &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(int32(7))}
}

func (ns *monitoredRetirementNamespace) allowValue() {
	ns.releaseOnce.Do(func() { close(ns.release) })
}

func waitMonitoredRetirement(t *testing.T, ctx context.Context, ready <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatalf("%s: %v", message, ctx.Err())
	}
}
