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
	"time"

	"github.com/baldoseri/tracehound/internal/capture"
	"github.com/baldoseri/tracehound/internal/detect"
	"github.com/baldoseri/tracehound/internal/fingerprint"
	"github.com/baldoseri/tracehound/internal/flow"
	"github.com/baldoseri/tracehound/internal/model"
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
type Pipeline struct {
	opts   Options
	table  *flow.Table
	reasm  *fingerprint.Reassembler
	engine *detect.Engine

	stats     Stats
	nextTick  time.Time
	wallStart time.Time
}

// New builds a pipeline. Detectors must already be registered on the engine.
func New(engine *detect.Engine, opts Options) *Pipeline {
	opts = opts.withDefaults()
	return &Pipeline{
		opts:   opts,
		engine: engine,
		table:  flow.New(flow.Options{IdleTimeout: opts.FlowIdleTimeout, MaxFlows: opts.MaxFlows}),
		reasm:  fingerprint.NewReassembler(0),
	}
}

// Table exposes the flow table for the API layer.
func (p *Pipeline) Table() *flow.Table { return p.table }

// Stats returns a snapshot of run counters.
func (p *Pipeline) Stats() Stats {
	s := p.stats
	s.Flow = p.table.Stats()
	s.Detect = p.engine.Stats()
	return s
}

// Run consumes a source to exhaustion or until ctx is cancelled.
func (p *Pipeline) Run(ctx context.Context, src capture.Source) (Stats, error) {
	start := time.Now()
	p.wallStart = start

	// Cancellation is checked periodically rather than per packet: a select on
	// every packet costs more than the check is worth at line rate.
	const cancelCheckEvery = 4096

	for {
		if p.stats.Packets%cancelCheckEvery == 0 {
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
	p.stats.Packets++
	p.stats.Bytes += uint64(pkt.WireLength)
	if p.stats.FirstPacket.IsZero() {
		p.stats.FirstPacket = pkt.Timestamp
		p.nextTick = pkt.Timestamp.Add(p.opts.TickInterval)
	}
	// Track the maximum, not the most recent. Captures merged from several
	// sensors, or written by a tool that batches per stream, can step backwards
	// in time; taking the last value would then hand a stale "now" to the final
	// scoring pass and expire evidence that had not actually aged out.
	if pkt.Timestamp.After(p.stats.LastPacket) {
		p.stats.LastPacket = pkt.Timestamp
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
	target := time.Duration(float64(ts.Sub(p.stats.FirstPacket)) / p.opts.Speed)
	if wait := target - time.Since(p.wallStart); wait > 0 {
		time.Sleep(wait)
	}
}

// fingerprintTLS feeds client-to-server payload into the ClientHello
// reassembler and copies any completed fingerprint onto the flow.
func (p *Pipeline) fingerprintTLS(pkt *model.Packet, f *model.Flow) {
	if pkt.Proto != model.ProtoTCP || len(pkt.Payload) == 0 {
		return
	}
	// A flow is fingerprinted once; after that the reassembler is not consulted
	// again, so an established connection's data packets cost one comparison.
	if f.JA4 != "" {
		return
	}
	// Only the client half of the conversation carries a ClientHello.
	if pkt.Src != f.Client || pkt.SrcPort != f.ClientPort {
		return
	}

	key, _ := model.KeyFor(pkt)
	res := p.reasm.Feed(key, pkt.Payload)
	if res == nil {
		return
	}

	f.JA4, f.JA3 = res.JA4, res.JA3
	if res.ServerName != "" {
		f.SNI = res.ServerName
	}
	if res.ALPN != "" {
		f.ALPN = res.ALPN
	}
	p.stats.Fingerprints++
}

// reap expires idle flows, handing each to the flow detectors before dropping
// any half-finished handshake state it left behind.
func (p *Pipeline) reap(now time.Time) {
	for _, f := range p.table.Reap(now) {
		p.engine.FlowClosed(&f)
		p.reasm.Forget(f.Key)
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
	}
	if !p.stats.LastPacket.IsZero() {
		p.engine.Tick(p.stats.LastPacket)
	}

	cs := src.Stats()
	p.stats.Capture = cs
	p.stats.Undecodable = cs.Undecode
	p.stats.Elapsed = time.Since(start)
}
