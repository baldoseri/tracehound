// Package detect hosts the detection engine and the built-in detectors.
//
// Detectors are deliberately small, independent objects with one job each. The
// engine owns dispatch, alert identity, and suppression, so a detector author
// writes only the analysis and never has to think about rate limiting or
// concurrency. Adding a detector is implementing one interface and registering
// it — that is the extension point the whole tool is built around.
package detect

import (
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/baldoseri/tracehound/internal/model"
)

// Detector is the base interface every detector satisfies.
//
// A detector opts into the events it cares about by additionally implementing
// PacketDetector, FlowDetector, and/or TickDetector. Splitting the hooks like
// this means a cheap flow-level detector is never invoked per packet.
type Detector interface {
	// Name is the stable identifier used in alerts and configuration.
	Name() string
}

// PacketDetector is called for every decoded packet, with the flow it belongs
// to already updated. This is the hot path: implementations must not allocate
// per packet in the common case.
type PacketDetector interface {
	Detector
	OnPacket(c *Context, p *model.Packet, f *model.Flow, isNew bool)
}

// FlowDetector is called once per flow, when the flow is reaped. The flow is a
// copy and is safe to retain.
type FlowDetector interface {
	Detector
	OnFlowClosed(c *Context, f *model.Flow)
}

// TickDetector is called on a fixed cadence. Detectors that accumulate evidence
// over time (beaconing, tunnelling, scanning) do their scoring here rather than
// re-scoring on every packet.
type TickDetector interface {
	Detector
	OnTick(c *Context, now time.Time)
}

// Config holds engine-wide settings shared with every detector.
type Config struct {
	// HomeNets defines which addresses count as "inside". Direction matters
	// enormously for detection: 500 MB leaving the network is exfiltration,
	// 500 MB arriving is a software update.
	HomeNets []netip.Prefix

	// AlertCooldown is the minimum gap between two identical alerts. Without
	// it a host beaconing every 30 seconds would produce an alert on every
	// tick forever, and the analyst would mute the tool by the end of the day.
	AlertCooldown time.Duration
}

// DefaultHomeNets is the RFC 1918 / link-local / loopback set, which is the
// right default for the overwhelming majority of deployments.
var DefaultHomeNets = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT, common in lab setups
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::1/128"),
}

func (c Config) withDefaults() Config {
	if len(c.HomeNets) == 0 {
		c.HomeNets = DefaultHomeNets
	}
	if c.AlertCooldown <= 0 {
		c.AlertCooldown = 10 * time.Minute
	}
	return c
}

// IsInternal reports whether an address falls inside the monitored network.
func (c Config) IsInternal(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, p := range c.HomeNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Context is handed to a detector on every callback. It carries the shared
// configuration, the current time, and the channel back to the engine.
//
// One Context is allocated per detector at registration and reused, so
// dispatch itself does not allocate.
type Context struct {
	Cfg Config
	Now time.Time

	detector string
	engine   *Engine
}

// Emit publishes an alert. The detector name and timestamp are filled in
// automatically; suppression is applied by the engine.
func (c *Context) Emit(a model.Alert) {
	a.Detector = c.detector
	if a.Time.IsZero() {
		a.Time = c.Now
	}
	c.engine.emit(a)
}

// Stats reports engine counters.
type Stats struct {
	Emitted    uint64 `json:"emitted"`
	Suppressed uint64 `json:"suppressed"`
	Detectors  int    `json:"detectors"`
}

// Engine dispatches events to registered detectors and publishes their alerts.
type Engine struct {
	cfg Config
	out func(model.Alert)

	packet []packetEntry
	flow   []flowEntry
	tick   []tickEntry
	all    []Detector

	mu         sync.Mutex
	lastSeen   map[string]time.Time
	emitted    uint64
	suppressed uint64
}

type packetEntry struct {
	d   PacketDetector
	ctx *Context
}
type flowEntry struct {
	d   FlowDetector
	ctx *Context
}
type tickEntry struct {
	d   TickDetector
	ctx *Context
}

// NewEngine returns an engine that publishes alerts through out.
func NewEngine(cfg Config, out func(model.Alert)) *Engine {
	return &Engine{
		cfg:      cfg.withDefaults(),
		out:      out,
		lastSeen: make(map[string]time.Time),
	}
}

// Config returns the engine's effective configuration.
func (e *Engine) Config() Config { return e.cfg }

// Register adds a detector, wiring it to whichever hooks it implements.
func (e *Engine) Register(d Detector) {
	ctx := &Context{Cfg: e.cfg, detector: d.Name(), engine: e}
	e.all = append(e.all, d)

	if pd, ok := d.(PacketDetector); ok {
		e.packet = append(e.packet, packetEntry{pd, ctx})
	}
	if fd, ok := d.(FlowDetector); ok {
		e.flow = append(e.flow, flowEntry{fd, ctx})
	}
	if td, ok := d.(TickDetector); ok {
		e.tick = append(e.tick, tickEntry{td, ctx})
	}
}

// Detectors lists the registered detector names.
func (e *Engine) Detectors() []string {
	names := make([]string, len(e.all))
	for i, d := range e.all {
		names[i] = d.Name()
	}
	return names
}

// Packet dispatches a decoded packet and its flow to the packet detectors.
func (e *Engine) Packet(p *model.Packet, f *model.Flow, isNew bool) {
	for i := range e.packet {
		e.packet[i].ctx.Now = p.Timestamp
		e.packet[i].d.OnPacket(e.packet[i].ctx, p, f, isNew)
	}
}

// FlowClosed dispatches a completed flow to the flow detectors.
func (e *Engine) FlowClosed(f *model.Flow) {
	for i := range e.flow {
		e.flow[i].ctx.Now = f.LastSeen
		e.flow[i].d.OnFlowClosed(e.flow[i].ctx, f)
	}
}

// Tick dispatches a scoring cycle to the tick detectors.
func (e *Engine) Tick(now time.Time) {
	for i := range e.tick {
		e.tick[i].ctx.Now = now
		e.tick[i].d.OnTick(e.tick[i].ctx, now)
	}
}

// Stats returns engine counters.
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Stats{Emitted: e.emitted, Suppressed: e.suppressed, Detectors: len(e.all)}
}

// emit applies suppression and forwards surviving alerts.
func (e *Engine) emit(a model.Alert) {
	key := suppressionKey(&a)

	e.mu.Lock()
	if last, ok := e.lastSeen[key]; ok && a.Time.Sub(last) < e.cfg.AlertCooldown {
		e.suppressed++
		e.mu.Unlock()
		return
	}
	e.lastSeen[key] = a.Time
	e.emitted++
	e.mu.Unlock()

	if a.ID == "" {
		a.ID = NewAlertID()
	}
	if e.out != nil {
		e.out(a)
	}
}

// suppressionKey identifies "the same finding again": same rule, same parties.
func suppressionKey(a *model.Alert) string {
	var b []byte
	b = append(b, a.Detector...)
	b = append(b, '|')
	b = append(b, a.RuleID...)
	b = append(b, '|')
	b = a.Src.AppendTo(b)
	b = append(b, '|')
	b = a.Dst.AppendTo(b)
	b = append(b, '|')
	b = strconv.AppendUint(b, uint64(a.DstPort), 10)
	return string(b)
}

// NewAlertID returns a random 128-bit identifier rendered as hex.
func NewAlertID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not recoverable and not something an alert ID
		// should paper over silently, but neither should it stop detection;
		// fall back to a time-derived value.
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}
