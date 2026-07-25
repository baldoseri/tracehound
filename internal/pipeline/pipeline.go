// Package pipeline wires the sensor together: capture feeds flow assembly,
// flow assembly feeds fingerprinting and detection, detection emits alerts.
//
// The whole data path runs on one goroutine. That is a deliberate choice: at
// the packet rates a single commodity core can decode (millions per second),
// the synchronisation cost of sharding across workers exceeds the work being
// sharded, and a single-threaded pipeline is dramatically easier to reason
// about and to test deterministically. Scaling out, when it is needed, belongs
// at the capture layer — one pipeline per RSS queue — not inside this loop.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/baldoseri/tracehound/internal/capture"
	"github.com/baldoseri/tracehound/internal/detect"
	"github.com/baldoseri/tracehound/internal/fingerprint"
	"github.com/baldoseri/tracehound/internal/flow"
	"github.com/baldoseri/tracehound/internal/model"
	"github.com/baldoseri/tracehound/internal/quic"
)

// Options configures a pipeline.
type Options struct {
	// FlowIdleTimeout and MaxFlows are passed to the flow table.
	FlowIdleTimeout time.Duration
	MaxFlows        int

	// TickInterval is how much *capture* time passes between detector scoring
	// cycles. Driving ticks from packet timestamps rather than the wall clock
	// is what makes a PCAP replay produce byte-identical results every run,
	// which in turn is what makes detector regressions testable.
	TickInterval time.Duration

	// Detect holds the engine-wide detection configuration.
	Detect detect.Config

	// Speed replays a capture at this multiple of real time: 1 is wall-clock
	// pace, 60 compresses an hour into a minute, and 0 (the default) runs as
	// fast as the CPU allows.
	//
	// This exists for the dashboard. Analysis finishes in milliseconds, so an
	// unpaced replay shows a finished screen and none of the behaviour that
	// produced it; pacing turns the same capture into something you can watch.
	Speed float64
}

func (o Options) withDefaults() Options {
	if o.FlowIdleTimeout <= 0 {
		o.FlowIdleTimeout = flow.DefaultIdleTimeout
	}
	if o.MaxFlows <= 0 {
		o.MaxFlows = flow.DefaultMaxFlows
	}
	if o.TickInterval <= 0 {
		o.TickInterval = 30 * time.Second
	}
	return o
}

// Stats summarises a run.
type Stats struct {
	Packets      uint64        `json:"packets"`
	Bytes        uint64        `json:"bytes"`
	Undecodable  uint64        `json:"undecodable"`
	Fingerprints uint64        `json:"fingerprints"`
	Flow         flow.Stats    `json:"flows"`
	Detect       detect.Stats  `json:"detect"`
	Capture      capture.Stats `json:"capture"`
	Elapsed      time.Duration `json:"-"`
	FirstPacket  time.Time     `json:"first_packet"`
	LastPacket   time.Time     `json:"last_packet"`
}

// PacketsPerSecond is the processing rate achieved, for benchmarking output.
func (s Stats) PacketsPerSecond() float64 {
	if s.Elapsed <= 0 {
		return 0
	}
	return float64(s.Packets) / s.Elapsed.Seconds()
}

// Pipeline owns the sensor's data path.
//
// The packet loop runs on one goroutine, but the HTTP API reads the counters
// while it runs. They are therefore atomics rather than plain fields: a struct
// copied out by Stats() while the loop was incrementing it is a data race, and
// on a 64-bit counter a torn read is a plausible outcome rather than a
// theoretical one.
//
// Atomics rather than a mutex because two of these are touched per packet, and
// a lock acquisition per packet at a million packets a second is not free.
type Pipeline struct {
	opts   Options
	table  *flow.Table
	reasm  *fingerprint.Reassembler
	qreasm *quic.Reassembler
	engine *detect.Engine

	// Hot counters, written by the packet loop and read by the API.
	nPackets      atomic.Uint64
	nBytes        atomic.Uint64
	nUndecodable  atomic.Uint64
	nFingerprints atomic.Uint64
	firstNano     atomic.Int64
	lastNano      atomic.Int64
	startNano     atomic.Int64

	// Cold fields, written once when the run ends.
	mu      sync.Mutex
	capture capture.Stats
	elapsed time.Duration

	// Touched only by the packet loop, never by a reader.
	nextTick    time.Time
	wallStart   time.Time
	firstPacket time.Time
}

// New builds a pipeline. Detectors must already be registered on the engine.
func New(engine *detect.Engine, opts Options) *Pipeline {
	opts = opts.withDefaults()
	return &Pipeline{
		opts:   opts,
		engine: engine,
		table:  flow.New(flow.Options{IdleTimeout: opts.FlowIdleTimeout, MaxFlows: opts.MaxFlows}),
		reasm:  fingerprint.NewReassembler(0),
		qreasm: quic.NewReassembler(0),
	}
}

// Table exposes the flow table for the API layer.
func (p *Pipeline) Table() *flow.Table { return p.table }

// Stats returns a snapshot of run counters. Safe to call while a run is in
// progress, which is what the dashboard does twice a second.
func (p *Pipeline) Stats() Stats {
	p.mu.Lock()
	captureStats, elapsed := p.capture, p.elapsed
	p.mu.Unlock()

	// While the run is still going there is no recorded elapsed time, so
	// measure it live rather than reporting a throughput of zero.
	if elapsed == 0 {
		if started := p.startNano.Load(); started != 0 {
			elapsed = time.Since(time.Unix(0, started))
		}
	}

	s := Stats{
		Packets:      p.nPackets.Load(),
		Bytes:        p.nBytes.Load(),
		Undecodable:  p.nUndecodable.Load(),
		Fingerprints: p.nFingerprints.Load(),
		Capture:      captureStats,
		Elapsed:      elapsed,
		Flow:         p.table.Stats(),
		Detect:       p.engine.Stats(),
	}
	if n := p.firstNano.Load(); n != 0 {
		s.FirstPacket = time.Unix(0, n).UTC()
	}
	if n := p.lastNano.Load(); n != 0 {
		s.LastPacket = time.Unix(0, n).UTC()
	}
	return s
}

// Run consumes a source to exhaustion or until ctx is cancelled.
func (p *Pipeline) Run(ctx context.Context, src capture.Source) (Stats, error) {
	start := time.Now()
	p.wallStart = start
	p.startNano.Store(start.UnixNano())

	// Cancellation is checked periodically rather than per packet: a select on
	// every packet costs more than the check is worth at line rate.
	const cancelCheckEvery = 4096

	for {
		if p.nPackets.Load()%cancelCheckEvery == 0 {
			select {
			case <-ctx.Done():
				p.finish(src, start)
				return p.Stats(), ctx.Err()
			default:
			}
		}

		pkt, err := src.Next()
		if err != nil {
			if errors.Is(err, capture.ErrDone) {
				break
			}
			p.finish(src, start)
			return p.Stats(), fmt.Errorf("pipeline: read packet: %w", err)
		}

		p.handle(&pkt)
	}

	p.finish(src, start)
	return p.Stats(), nil
}

// handle processes one decoded packet.
func (p *Pipeline) handle(pkt *model.Packet) {
	p.nPackets.Add(1)
	p.nBytes.Add(uint64(pkt.WireLength))

	if p.firstPacket.IsZero() {
		p.firstPacket = pkt.Timestamp
		p.firstNano.Store(pkt.Timestamp.UnixNano())
		p.nextTick = pkt.Timestamp.Add(p.opts.TickInterval)
	}
	// Track the maximum, not the most recent. Captures merged from several
	// sensors, or written by a tool that batches per stream, can step backwards
	// in time; taking the last value would then hand a stale "now" to the final
	// scoring pass and expire evidence that had not actually aged out.
	if n := pkt.Timestamp.UnixNano(); n > p.lastNano.Load() {
		p.lastNano.Store(n)
	}

	p.pace(pkt.Timestamp)

	f, isNew := p.table.Observe(pkt)

	p.fingerprintTLS(pkt, f)
	p.engine.Packet(pkt, f, isNew)

	// Detector scoring and flow expiry are driven by capture time.
	if pkt.Timestamp.After(p.nextTick) {
		p.reap(pkt.Timestamp)
		p.engine.Tick(pkt.Timestamp)
		p.nextTick = pkt.Timestamp.Add(p.opts.TickInterval)
	}
}

// pace throttles replay so that capture time advances at Options.Speed times
// real time. It is a no-op when Speed is zero, which is the default and the
// only mode used by tests and benchmarks.
func (p *Pipeline) pace(ts time.Time) {
	if p.opts.Speed <= 0 {
		return
	}
	target := time.Duration(float64(ts.Sub(p.firstPacket)) / p.opts.Speed)
	if wait := target - time.Since(p.wallStart); wait > 0 {
		time.Sleep(wait)
	}
}

// fingerprintTLS recovers a TLS client fingerprint from client-to-server
// payload, over TCP or over QUIC, and copies the result onto the flow.
//
// Both transports end at the same ClientHello parser, so a client that speaks
// HTTP/2 and HTTP/3 produces fingerprints that differ only in JA4's leading
// transport character. Anything else would make the two incomparable and halve
// the value of having them.
func (p *Pipeline) fingerprintTLS(pkt *model.Packet, f *model.Flow) {
	if len(pkt.Payload) == 0 {
		return
	}
	// A flow is fingerprinted once; after that neither reassembler is consulted
	// again, so an established connection's data packets cost one comparison.
	if f.JA4 != "" {
		return
	}
	// Only the client half of the conversation carries a ClientHello.
	if pkt.Src != f.Client || pkt.SrcPort != f.ClientPort {
		return
	}

	key, _ := model.KeyFor(pkt)

	var res *fingerprint.Result
	switch pkt.Proto {
	case model.ProtoTCP:
		res = p.reasm.Feed(key, pkt.Payload)
	case model.ProtoUDP:
		// QUIC Initials are padded to 1200 bytes, so ordinary UDP such as DNS
		// is rejected on a length comparison before any key derivation.
		res = p.qreasm.Feed(key, pkt.Payload)
	}
	if res == nil {
		return
	}

	// Written through the table rather than through the pointer, because the
	// API reads these same records concurrently. See Table.SetFingerprint.
	p.table.SetFingerprint(key, res.JA4, res.JA3, res.ServerName, res.ALPN)
	p.nFingerprints.Add(1)
}

// reap expires idle flows, handing each to the flow detectors before dropping
// any half-finished handshake state it left behind.
func (p *Pipeline) reap(now time.Time) {
	for _, f := range p.table.Reap(now) {
		p.engine.FlowClosed(&f)
		p.reasm.Forget(f.Key)
		p.qreasm.Forget(f.Key)
	}
}

// finish flushes everything still in flight at end of capture.
//
// Without this, a flow that was still open when the PCAP ran out would never
// reach the flow detectors — which in a short capture is most of them, and is a
// classic way for a sensor to silently under-report on exactly the traffic an
// analyst chose to capture.
func (p *Pipeline) finish(src capture.Source, start time.Time) {
	for _, f := range p.table.Drain() {
		p.engine.FlowClosed(&f)
		p.reasm.Forget(f.Key)
		p.qreasm.Forget(f.Key)
	}
	if n := p.lastNano.Load(); n != 0 {
		p.engine.Tick(time.Unix(0, n).UTC())
	}

	cs := src.Stats()
	p.nUndecodable.Store(cs.Undecode)

	p.mu.Lock()
	p.capture = cs
	p.elapsed = time.Since(start)
	p.mu.Unlock()
}
