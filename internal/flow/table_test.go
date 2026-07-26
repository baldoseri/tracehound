package flow

import (
	"net/netip"
	"testing"
	"time"

	"github.com/baldoseri/tracehound/internal/model"
)

var (
	hostA = netip.MustParseAddr("10.0.0.5")
	hostB = netip.MustParseAddr("93.184.216.34")
	base  = time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
)

func pkt(src netip.Addr, sport uint16, dst netip.Addr, dport uint16, flags uint8, at time.Duration, size int) model.Packet {
	return model.Packet{
		Timestamp:  base.Add(at),
		Src:        src,
		Dst:        dst,
		SrcPort:    sport,
		DstPort:    dport,
		Proto:      model.ProtoTCP,
		TCPFlags:   flags,
		WireLength: size,
	}
}

// TestEvictionIsReported is the missing link that let reassembler state leak.
//
// Eviction dropped a flow and told nobody, so everything holding per-flow state
// keyed off Reap and never heard about flows that did not go idle but were
// pushed out under pressure. Eviction takes from the cold end of the LRU, which
// is exactly where a half-open TLS flow waiting for its second segment sits.
func TestEvictionIsReported(t *testing.T) {
	var evicted []model.FlowKey
	tbl := New(Options{
		MaxFlows: 4,
		OnEvict:  func(k model.FlowKey) { evicted = append(evicted, k) },
	})

	for i := 0; i < 20; i++ {
		p := pkt(hostA, uint16(10000+i), hostB, 443, model.TCPSyn, time.Duration(i)*time.Second, 74)
		tbl.Observe(&p)
	}

	if len(evicted) == 0 {
		t.Fatal("no evictions reported; per-flow state held elsewhere would leak")
	}
	if got := tbl.Len(); got > 4 {
		t.Errorf("table holds %d flows, want at most 4", got)
	}

	// A key reported as evicted must actually be gone, or a caller acting on
	// the callback would drop state for a flow that is still live.
	live := map[model.FlowKey]bool{}
	for _, f := range tbl.Drain() {
		live[f.Key] = true
	}
	for _, k := range evicted {
		if live[k] {
			t.Errorf("key %v reported evicted but is still in the table", k)
		}
	}
}

// TestNoEvictionCallbackWhenUnderCapacity guards the other direction: a table
// that never fills must never report an eviction.
func TestNoEvictionCallbackWhenUnderCapacity(t *testing.T) {
	n := 0
	tbl := New(Options{MaxFlows: 100, OnEvict: func(model.FlowKey) { n++ }})
	for i := 0; i < 20; i++ {
		p := pkt(hostA, uint16(10000+i), hostB, 443, model.TCPSyn, time.Duration(i)*time.Second, 74)
		tbl.Observe(&p)
	}
	if n != 0 {
		t.Errorf("%d evictions reported with 20 flows in a table of 100", n)
	}
}

// TestBidirectionalFlowsShareOneEntry is the core invariant: a request and its
// response are one conversation, not two.
func TestBidirectionalFlowsShareOneEntry(t *testing.T) {
	tbl := New(Options{})

	out := pkt(hostA, 51234, hostB, 443, model.TCPSyn, 0, 74)
	in := pkt(hostB, 443, hostA, 51234, model.TCPSyn|model.TCPAck, time.Millisecond, 74)

	f1, new1 := tbl.Observe(&out)
	f2, new2 := tbl.Observe(&in)

	if !new1 {
		t.Error("first packet did not create a flow")
	}
	if new2 {
		t.Error("reply packet created a second flow; the key is not canonical")
	}
	if f1 != f2 {
		t.Error("request and reply mapped to different flow records")
	}
	if got := tbl.Len(); got != 1 {
		t.Errorf("table has %d flows, want 1", got)
	}

	if f2.Client != hostA || f2.ClientPort != 51234 {
		t.Errorf("client = %v:%d, want %v:51234", f2.Client, f2.ClientPort, hostA)
	}
	if f2.PacketsToServer != 1 || f2.PacketsToClient != 1 {
		t.Errorf("directional counts = %d/%d, want 1/1", f2.PacketsToServer, f2.PacketsToClient)
	}
	if !f2.Established() {
		t.Error("flow with SYN and SYN-ACK reported as not established")
	}
}

// TestClientCorrectedBySyn covers joining a capture mid-conversation: the first
// packet we see may be from the server, and the SYN must fix the attribution.
func TestClientCorrectedBySyn(t *testing.T) {
	tbl := New(Options{})

	// Server data seen first (capture started late).
	fromServer := pkt(hostB, 443, hostA, 51234, model.TCPAck, 0, 1500)
	tbl.Observe(&fromServer)

	// Then a retransmitted SYN from the real client.
	syn := pkt(hostA, 51234, hostB, 443, model.TCPSyn, time.Millisecond, 74)
	f, _ := tbl.Observe(&syn)

	if f.Client != hostA {
		t.Errorf("client = %v, want %v (SYN sender is authoritative)", f.Client, hostA)
	}
	if f.Server != hostB {
		t.Errorf("server = %v, want %v", f.Server, hostB)
	}
}

func TestReapExpiresIdleFlows(t *testing.T) {
	tbl := New(Options{IdleTimeout: 30 * time.Second})

	old := pkt(hostA, 1000, hostB, 80, model.TCPSyn, 0, 60)
	fresh := pkt(hostA, 1001, hostB, 80, model.TCPSyn, 25*time.Second, 60)
	tbl.Observe(&old)
	tbl.Observe(&fresh)

	// At t+40s the first flow is 40s idle (expired), the second only 15s.
	reaped := tbl.Reap(base.Add(40 * time.Second))
	if len(reaped) != 1 {
		t.Fatalf("reaped %d flows, want 1", len(reaped))
	}
	if reaped[0].ClientPort != 1000 {
		t.Errorf("reaped the wrong flow (port %d)", reaped[0].ClientPort)
	}
	if tbl.Len() != 1 {
		t.Errorf("table has %d flows after reap, want 1", tbl.Len())
	}

	if s := tbl.Stats(); s.Expired != 1 || s.Created != 2 {
		t.Errorf("stats = %+v, want Created=2 Expired=1", s)
	}
}

// TestReapStopsAtFirstLiveFlow guards the property that makes expiry cheap:
// the recency list must be ordered, so reaping touches only expired entries.
func TestReapStopsAtFirstLiveFlow(t *testing.T) {
	tbl := New(Options{IdleTimeout: 10 * time.Second})

	for i := 0; i < 100; i++ {
		p := pkt(hostA, uint16(2000+i), hostB, 80, model.TCPSyn, time.Duration(i)*time.Second, 60)
		tbl.Observe(&p)
	}
	// Reaping at t=60s with a 10s idle timeout puts the cutoff at t=50s.
	// The boundary is inclusive — a flow last seen exactly at the cutoff is
	// exactly IdleTimeout old and expires — so flows 0..50 go, 51..99 stay.
	reaped := tbl.Reap(base.Add(60 * time.Second))
	if len(reaped) != 51 {
		t.Fatalf("reaped %d flows, want 51", len(reaped))
	}
	for i, f := range reaped {
		if want := uint16(2000 + i); f.ClientPort != want {
			t.Fatalf("reaped[%d] port = %d, want %d (list is out of order)", i, f.ClientPort, want)
		}
	}
}

// TestTouchingFlowResetsExpiry checks that an active flow moves to the hot end
// of the recency list rather than aging out under continuous traffic.
func TestTouchingFlowResetsExpiry(t *testing.T) {
	tbl := New(Options{IdleTimeout: 10 * time.Second})

	first := pkt(hostA, 3000, hostB, 80, model.TCPSyn, 0, 60)
	second := pkt(hostA, 3001, hostB, 80, model.TCPSyn, time.Second, 60)
	tbl.Observe(&first)
	tbl.Observe(&second)

	// Keep the first flow alive.
	keepalive := pkt(hostA, 3000, hostB, 80, model.TCPAck, 20*time.Second, 60)
	tbl.Observe(&keepalive)

	reaped := tbl.Reap(base.Add(25 * time.Second))
	if len(reaped) != 1 {
		t.Fatalf("reaped %d flows, want 1", len(reaped))
	}
	if reaped[0].ClientPort != 3001 {
		t.Errorf("reaped port %d, want 3001 (the idle flow, not the active one)", reaped[0].ClientPort)
	}
}

func TestMaxFlowsEvictsColdest(t *testing.T) {
	const limit = 10
	tbl := New(Options{MaxFlows: limit})

	for i := 0; i < limit*5; i++ {
		p := pkt(hostA, uint16(4000+i), hostB, 80, model.TCPSyn, time.Duration(i)*time.Millisecond, 60)
		tbl.Observe(&p)
	}

	if got := tbl.Len(); got > limit {
		t.Errorf("table holds %d flows, want <= %d", got, limit)
	}
	if s := tbl.Stats(); s.Evicted == 0 {
		t.Error("no evictions recorded despite exceeding MaxFlows")
	}

	// The survivors must be the most recent ports.
	for _, f := range tbl.Snapshot(0) {
		if f.ClientPort < uint16(4000+limit*5-limit) {
			t.Errorf("cold flow (port %d) survived eviction", f.ClientPort)
		}
	}
}

func TestDrainReturnsEverything(t *testing.T) {
	tbl := New(Options{})
	for i := 0; i < 5; i++ {
		p := pkt(hostA, uint16(5000+i), hostB, 80, model.TCPSyn, time.Duration(i)*time.Second, 60)
		tbl.Observe(&p)
	}
	drained := tbl.Drain()
	if len(drained) != 5 {
		t.Errorf("drained %d flows, want 5", len(drained))
	}
	if tbl.Len() != 0 {
		t.Errorf("table not empty after Drain: %d", tbl.Len())
	}
}

func TestByteAccounting(t *testing.T) {
	tbl := New(Options{})
	up := pkt(hostA, 6000, hostB, 443, model.TCPSyn, 0, 100)
	down := pkt(hostB, 443, hostA, 6000, model.TCPSyn|model.TCPAck, time.Millisecond, 900)
	tbl.Observe(&up)
	tbl.Observe(&down)

	f := tbl.Snapshot(0)[0]
	if f.BytesToServer != 100 {
		t.Errorf("BytesToServer = %d, want 100", f.BytesToServer)
	}
	if f.BytesToClient != 900 {
		t.Errorf("BytesToClient = %d, want 900", f.BytesToClient)
	}
	if f.Bytes() != 1000 {
		t.Errorf("Bytes() = %d, want 1000", f.Bytes())
	}
}

func BenchmarkObserveExistingFlow(b *testing.B) {
	tbl := New(Options{})
	p := pkt(hostA, 51234, hostB, 443, model.TCPAck, 0, 1500)
	tbl.Observe(&p)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tbl.Observe(&p)
	}
}

func BenchmarkObserveNewFlows(b *testing.B) {
	tbl := New(Options{MaxFlows: 1 << 20})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := pkt(hostA, uint16(i), hostB, 443, model.TCPSyn, 0, 60)
		tbl.Observe(&p)
	}
}
