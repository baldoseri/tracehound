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
	"fmt"
	"hash/fnv"
	"net/netip"
	"slices"
	"sort"
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

	// MaxSuppressionEntries bounds how many distinct findings the engine
	// remembers for duplicate suppression. Zero selects the default.
	MaxSuppressionEntries int
	// AlertCooldown is the minimum gap between two identical alerts. Without
	// it a host beaconing every 30 seconds would produce an alert on every
	// tick forever, and the analyst would mute the tool by the end of the day.
	AlertCooldown time.Duration

	// Policy is consulted for every alert before it is emitted. Returning
	// false drops the alert; the alert may also be modified in place.
	//
	// This is the seam the YAML rule pack plugs into — disabling a rule,
	// exempting a known-good host, overriding a severity, or attaching extra
	// ATT&CK techniques. The engine deliberately knows nothing about rule
	// files: detection logic and deployment policy are different concerns with
	// different rates of change, and a detector that had to parse YAML would
	// be markedly harder to test.
	//
	// Nil means allow everything.
	Policy func(*model.Alert) bool
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
	if c.MaxSuppressionEntries <= 0 {
		// Deliberately far above what a real network reaches. This is a
		// backstop against traffic that mints endpoint pairs, not a working
		// limit, and every entry it holds is one restatement kept out of the
		// output.
		c.MaxSuppressionEntries = 250_000
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
	// Filtered counts alerts dropped by rule policy: a disabled rule or a
	// matching exception. Reported separately from Suppressed so an operator
	// can tell "the tool is quiet" from "I told the tool to be quiet".
	Filtered  uint64 `json:"filtered"`
	Detectors int    `json:"detectors"`
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
	lastSeen   map[string]alertState
	emitted    uint64
	suppressed uint64
	dropped    uint64
	filtered   uint64
}

// alertState remembers what was last said about one finding, so the engine can
// tell a genuinely new observation from a restatement of the old one.
type alertState struct {
	// at is when this finding was last *reported*, and is what the cooldown
	// measures against.
	at time.Time
	// touched is when it was last seen at all, reported or suppressed, and is
	// used only to decide what to drop when the map is over its bound.
	//
	// The two have to be separate. Suppressing an alert deliberately leaves at
	// alone, or a finding that kept recurring would push its own cooldown
	// forward forever and never be restated. But that also means at stops
	// moving for exactly the findings that are most active, so evicting on it
	// throws out the busiest entries first, which is precisely backwards.
	touched  time.Time
	severity model.Severity
	digest   uint64
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
		lastSeen: make(map[string]alertState),
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

// boundSuppression drops the least recently seen findings once the suppression
// map exceeds its cap. Callers must hold e.mu.
//
// The map had no delete anywhere: one entry per distinct detector, rule and
// pair of addresses, held for the life of the process. The key includes both
// addresses, so its size is chosen by whoever is generating the traffic.
//
// Expiring by age was the obvious fix and is the wrong one. Suppression is
// deliberately not time-based: a detector whose window has not moved re-derives
// identical numbers on every tick, and TestSuppressionDropsUnchangedEvidence
// exists to keep those out of the output no matter how long the run. Dropping
// entries on age would let exactly that noise back in.
//
// Bounding by count keeps the contract for every finding the sensor is actually
// tracking and gives it up only when the map is already at a size no real
// network produces. A dropped entry means one restatement of a finding that has
// been silent longer than any other, which is the least bad thing to lose.
func (e *Engine) boundSuppression() {
	if len(e.lastSeen) <= e.cfg.MaxSuppressionEntries {
		return
	}
	// Two passes over a map that is at its cap, on an event that happens once
	// per quarter-cap insertions. Collecting the times and cutting at the
	// lower quartile avoids doing this again on the very next alert.
	times := make([]time.Time, 0, len(e.lastSeen))
	for _, s := range e.lastSeen {
		times = append(times, s.touched)
	}
	slices.SortFunc(times, func(a, b time.Time) int { return a.Compare(b) })

	cutoff := times[len(times)/4]
	for k, s := range e.lastSeen {
		if s.touched.Before(cutoff) {
			delete(e.lastSeen, k)
			e.dropped++
		}
	}
}

// touch records that a finding was seen again without reporting it. Callers
// must hold e.mu.
func (e *Engine) touch(key string, s alertState, at time.Time) {
	if at.After(s.touched) {
		s.touched = at
		e.lastSeen[key] = s
	}
}

// Stats returns engine counters.
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Stats{Emitted: e.emitted, Suppressed: e.suppressed, Filtered: e.filtered, Detectors: len(e.all)}
}

// emit applies suppression and forwards surviving alerts.
//
// Suppression is deliberately not a plain rate limit. Three cases are treated
// differently, because they mean different things to an analyst:
//
//   - Identical evidence is a restatement, not a finding. A detector whose
//     window has not moved will re-derive the same numbers on every tick;
//     printing them again tells the reader nothing and trains them to skim.
//     These are dropped regardless of how much time has passed.
//   - A finding that has become more severe is news, and waiting out a cooldown
//     to say so is exactly the wrong behaviour during an active incident.
//   - Everything else — same finding, evolving evidence — obeys the cooldown.
func (e *Engine) emit(a model.Alert) {
	// Policy runs before suppression bookkeeping. An exempted alert must not
	// leave a trace in the suppression state, or the first genuine finding
	// after an exemption lapses would be swallowed as a duplicate.
	if e.cfg.Policy != nil && !e.cfg.Policy(&a) {
		e.mu.Lock()
		e.filtered++
		e.mu.Unlock()
		return
	}

	key := suppressionKey(&a)
	digest := evidenceDigest(&a)

	e.mu.Lock()
	if prev, ok := e.lastSeen[key]; ok {
		switch {
		case prev.digest == digest:
			e.touch(key, prev, a.Time)
			e.suppressed++
			e.mu.Unlock()
			return
		case a.Severity > prev.severity:
			// Escalation: fall through and report immediately.
		case a.Time.Sub(prev.at) < e.cfg.AlertCooldown:
			e.touch(key, prev, a.Time)
			e.suppressed++
			e.mu.Unlock()
			return
		}
	}
	e.lastSeen[key] = alertState{at: a.Time, touched: a.Time, severity: a.Severity, digest: digest}
	e.boundSuppression()
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

// evidenceDigest hashes an alert's supporting measurements.
//
// Map iteration order is randomised in Go, so the keys are sorted before
// hashing; without that, the "same evidence" test would be a coin flip and the
// suppression it drives would be nondeterministic.
func evidenceDigest(a *model.Alert) uint64 {
	h := fnv.New64a()
	fmt.Fprintf(h, "%s|%s|", a.RuleID, a.Severity)

	keys := make([]string, 0, len(a.Evidence))
	for k := range a.Evidence {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(h, "%s=%v;", k, a.Evidence[k])
	}
	return h.Sum64()
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
