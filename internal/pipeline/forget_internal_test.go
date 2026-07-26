package pipeline

import (
	"net/netip"
	"testing"
	"time"

	"github.com/baldoseri/tracehound/internal/detect"
	"github.com/baldoseri/tracehound/internal/model"
)

// partialHello is a TLS record header announcing far more than it carries, so
// the reassembler buffers it and waits for a segment that never arrives. This
// is the shape that leaks: a handshake that is started and abandoned.
var partialHello = []byte{0x16, 0x03, 0x01, 0x10, 0x00}

func tcpPacketAt(sport uint16, at time.Time) model.Packet {
	return model.Packet{
		Timestamp:  at,
		Src:        netip.MustParseAddr("10.0.0.5"),
		Dst:        netip.MustParseAddr("93.184.216.34"),
		SrcPort:    sport,
		DstPort:    443,
		Proto:      model.ProtoTCP,
		TCPFlags:   model.TCPSyn,
		WireLength: 74,
	}
}

// TestEvictedFlowReleasesHandshakeState is the precise test for the leak.
//
// Reaping was the only thing that called Forget, and eviction is not reaping.
// A flow dropped for capacity left its half-finished handshake buffered for the
// life of the process, and eviction takes from the cold end of the LRU, which
// is exactly where a flow waiting for the rest of its ClientHello sits.
//
// This is deliberately not driven through a capture. The demo capture's hellos
// arrive complete in one segment, so they are parsed and dropped on the first
// feed and never become pending at all; a replay cannot produce the condition
// no matter how small the flow table is made.
func TestEvictedFlowReleasesHandshakeState(t *testing.T) {
	engine := detect.NewEngine(detect.Config{}, func(model.Alert) {})
	p := New(engine, Options{MaxFlows: 1, TickInterval: time.Second})

	at := time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)
	first := tcpPacketAt(50001, at)
	keyA, _ := model.KeyFor(&first)

	// Buffer a handshake for the flow that is about to be evicted.
	p.reasm.Feed(keyA, partialHello)
	if got := p.reasm.Pending(); got != 1 {
		t.Fatalf("Pending() = %d after feeding a partial hello, want 1", got)
	}

	// Observe the flow, then a second one. MaxFlows is 1, so the first is
	// evicted and its buffered handshake must go with it.
	p.table.Observe(&first)
	second := tcpPacketAt(50002, at.Add(time.Second))
	p.table.Observe(&second)

	if got := p.reasm.Pending(); got != 0 {
		t.Errorf("Pending() = %d after the flow was evicted, want 0: "+
			"evicted flows are leaking handshake state", got)
	}
}

// TestReapAlsoReleasesHandshakeState pins the path that already worked, so the
// refactor to a shared forget helper cannot quietly drop it.
func TestReapAlsoReleasesHandshakeState(t *testing.T) {
	engine := detect.NewEngine(detect.Config{}, func(model.Alert) {})
	p := New(engine, Options{FlowIdleTimeout: time.Minute, TickInterval: time.Second})

	at := time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)
	pkt := tcpPacketAt(50001, at)
	key, _ := model.KeyFor(&pkt)

	p.table.Observe(&pkt)
	p.reasm.Feed(key, partialHello)
	if got := p.reasm.Pending(); got != 1 {
		t.Fatalf("Pending() = %d, want 1", got)
	}

	p.reap(at.Add(2 * time.Minute))

	if got := p.reasm.Pending(); got != 0 {
		t.Errorf("Pending() = %d after the flow was reaped, want 0", got)
	}
}
