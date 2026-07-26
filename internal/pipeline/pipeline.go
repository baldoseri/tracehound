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

	// MaxPendingHandshakes bounds how many partial handshakes each reassembler
	// buffers at once. Zero selects the package default.
	//
	// Configurable for the same reason MaxFlows is, and because a test that
	// wants to prove behaviour at the bound cannot get there through a capture:
	// filling the default would take more concurrent half-open TLS flows than
	// any fixture contains.
	MaxPendingHandshakes int

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
	Packets      uint64 `json:"packets"`
	Bytes        uint64 `json:"bytes"`
	Undecodable  uint64 `json:"undecodable"`
	Fingerprints uint64 `json:"fingerprints"`
	// ServerFingerprints counts JA4S recovered from ServerHellos. Always the
	// smaller number: a QUIC server's response is encrypted under keys an
	// observer never sees, so only TCP flows contribute.
	ServerFingerprints uint64        `json:"server_fingerprints"`
	Flow               flow.Stats    `json:"flows"`
	Detect             detect.Stats  `json:"detect"`
	Capture            capture.Stats `json:"capture"`
	Elapsed            time.Duration `json:"-"`
	FirstPacket        time.Time     `json:"first_packet"`
	LastPacket         time.Time     `json:"last_packet"`
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
	sreasm *fingerprint.ServerReassembler
	qreasm *quic.Reassembler
	engine *detect.Engine

	// Hot counters, written by the packet loop and read by the API.
	nPackets      atomic.Uint64
	nBytes        atomic.Uint64
	nUndecodable  atomic.Uint64
	nFingerprints atomic.Uint64
	nServerPrints atomic.Uint64
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
	p := &Pipeline{
		opts:   opts,
		engine: engine,
		reasm:  fingerprint.NewReassembler(opts.MaxPendingHandshakes),
		sreasm: fingerprint.NewServerReassembler(opts.MaxPendingHandshakes),
		qreasm: quic.NewReassembler(opts.MaxPendingHandshakes),
	}
	p.table = flow.New(flow.Options{
		IdleTimeout: opts.FlowIdleTimeout,
		MaxFlows:    opts.MaxFlows,
		// Reaping was the only thing that released reassembler state, and
		// eviction is not reaping. A flow dropped for capacity left its partial
		// handshake behind forever, and eviction takes from the cold end of the
		// LRU, which is exactly where a half-open TLS flow waiting for its
		// second segment sits.
		OnEvict: p.forget,
	})
	return p
}

// forget releases every piece of per-flow state held outside the flow table.
//
// Both callers matter and neither is sufficient alone: reaping handles flows
// that go idle, eviction handles flows dropped under pressure.
func (p *Pipeline) forget(key model.FlowKey) {
	p.reasm.Forget(key)
	p.sreasm.Forget(key)
	p.qreasm.Forget(key)
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

		ServerFingerprints: p.nServerPrints.Load(),

		Capture: captureStats,
		Elapsed: elapsed,
		Flow:    p.table.Stats(),
		Detect:  p.engine.Stats(),
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

	// A live source can block in a read that no amount of checking will
	// interrupt, so cancellation has to reach the socket rather than the loop.
	// Without this a cancelled sniff waits for the next packet, which on a
	// quiet link may never arrive, and is eventually killed instead of shutting
	// down: the run summary is lost and so is SaveDevices, which only runs
	// after Run returns.
	if in, ok := src.(capture.Interrupter); ok {
		stopped := make(chan struct{})
		defer close(stopped)
		go func() {
			select {
			case <-ctx.Done():
				_ = in.Interrupt()
			case <-stopped:
			}
		}()
	}

	// Cancellation is also checked periodically, which is what covers sources
	// that cannot be interrupted. The counter is local rather than nPackets,
	// because a modulo on a counter this loop does not own only fires when it
	// lands exactly on a multiple.
	const cancelCheckEvery = 512

	// The source's own counters, kernel drops among them, used to be read once
	// in finish. A live sensor therefore reported no drops for its entire run
	// however far behind it fell, and the one number that says "this sensor is
	// not seeing everything" was only available after it stopped.
	//
	// Sampled on a wall-clock interval rather than a packet count because
	// reading them is a syscall on a live handle, and once a second is plenty
	// for something a dashboard polls twice a second.
	var lastSample time.Time

	for n := uint64(0); ; n++ {
		if n%cancelCheckEvery == 0 {
			select {
			case <-ctx.Done():
				p.finish(src, start)
				return p.Stats(), ctx.Err()
			default:
			}
			if now := time.Now(); now.Sub(lastSample) >= time.Second {
				lastSample = now
				p.sampleCapture(src)
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
	key, _ := model.KeyFor(pkt)

	// Which half of the conversation this is decides which handshake message
	// could be in it: a ClientHello travels one way, a ServerHello the other.
	if pkt.Src == f.Client && pkt.SrcPort == f.ClientPort {
		p.fingerprintClient(key, pkt, f)
		return
	}
	p.fingerprintServer(key, pkt, f)
}

// fingerprintClient recovers JA4 and JA3 from a ClientHello.
func (p *Pipeline) fingerprintClient(key model.FlowKey, pkt *model.Packet, f *model.Flow) {
	// A flow is fingerprinted once; after that no reassembler is consulted
	// again, so an established connection's data packets cost one comparison.
	if f.JA4 != "" {
		return
	}

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

// fingerprintServer recovers JA4S from a ServerHello.
//
// Only over TCP. A QUIC server's response is protected with keys derived from
// its own connection ID, which a passive observer does not have, so the
// ServerHello is genuinely unreadable rather than merely unimplemented.
func (p *Pipeline) fingerprintServer(key model.FlowKey, pkt *model.Packet, f *model.Flow) {
	if f.JA4S != "" || pkt.Proto != model.ProtoTCP {
		return
	}
	res := p.sreasm.Feed(key, pkt.Payload)
	if res == nil {
		return
	}
	p.table.SetServerFingerprint(key, res.JA4S)
	p.nServerPrints.Add(1)
}

// reap expires idle flows, handing each to the flow detectors before dropping
// any half-finished handshake state it left behind.
func (p *Pipeline) reap(now time.Time) {
	for _, f := range p.table.Reap(now) {
		p.engine.FlowClosed(&f)
		p.forget(f.Key)
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
		p.forget(f.Key)
	}
	if n := p.lastNano.Load(); n != 0 {
		p.engine.Tick(time.Unix(0, n).UTC())
	}

	p.sampleCapture(src)

	p.mu.Lock()
	p.elapsed = time.Since(start)
	p.mu.Unlock()
}

// sampleCapture refreshes the counters owned by the source.
//
// Safe to call repeatedly: LiveSource accumulates the kernel's destructive
// drop counter internally, so each call returns the running total rather than
// the delta since the previous one.
func (p *Pipeline) sampleCapture(src capture.Source) {
	cs := src.Stats()
	p.nUndecodable.Store(cs.Undecode)

	p.mu.Lock()
	p.capture = cs
	p.mu.Unlock()
}
