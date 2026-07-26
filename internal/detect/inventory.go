package detect

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/baldoseri/tracehound/internal/model"
)

// Rule identifiers for inventory-derived findings.
const (
	RuleNewDevice = "TH-0006"
	RuleRareJA4   = "TH-0007"
)

// InventoryConfig tunes the asset inventory and rare-fingerprint detector.
type InventoryConfig struct {
	// MinHostsForRarity is how many internal hosts must be known before a
	// "only one host uses this TLS stack" claim is meaningful. On a network of
	// three machines, every fingerprint is rare.
	MinHostsForRarity int
	// MinFingerprintsForRarity is the equivalent baseline for fingerprints.
	MinFingerprintsForRarity int
	// MinSharedFingerprints is how many fingerprints must be in use by two or
	// more hosts before any fingerprint may be called rare.
	//
	// This is the guard that makes the detector honest. Early in a capture
	// every host has contributed exactly one fingerprint, so *everything* looks
	// unique and the detector would indict the entire network. Requiring
	// evidence that some stacks are genuinely shared proves a baseline exists
	// before anything is measured against it.
	MinSharedFingerprints int
	// MinObservations is how many flows a fingerprint must appear on before its
	// rarity counts. One connection from one host is not evidence of anything.
	MinObservations int
	// MinAge is how long a fingerprint must have been known before it may be
	// called rare.
	//
	// Without this the detector reports the first host to use any new stack.
	// A browser that prefers HTTP/3 produces a fingerprint nobody has yet, and
	// for the few minutes before a second machine happens to use it, it is
	// indistinguishable from an implant. Rarity is a claim about the network
	// over time, so it needs time to be true.
	MinAge time.Duration
	// MaxDevices bounds the inventory.
	MaxDevices int
	// MaxFingerprints bounds the set of distinct JA4s tracked.
	//
	// Sibling to MaxDevices, and it was missing. The device map was capped
	// while the fingerprint map beside it grew without limit, which is the
	// wrong way round for a daemon: a network can only hold so many hosts,
	// but a host that varies its TLS stack, or an attacker who chooses to,
	// can mint fingerprints indefinitely.
	MaxFingerprints int
	// MaxJA4sPerDevice bounds the per-device fingerprint list.
	//
	// The list is display detail, and it is scanned linearly on the packet
	// path, so an unbounded one costs time as well as memory.
	MaxJA4sPerDevice int
	// SilenceNewDevice suppresses the informational new-host alert. Phrased as
	// an opt-out so the zero value behaves like the documented default.
	SilenceNewDevice bool
}

// DefaultInventoryConfig returns sensible baselines.
func DefaultInventoryConfig() InventoryConfig {
	return InventoryConfig{
		MinHostsForRarity: 5,
		// Three distinct TLS stacks is the point at which "everyone here looks
		// alike except this one" starts to mean something. Requiring more just
		// delays the finding on homogeneous corporate fleets, which are exactly
		// the networks where a single odd stack stands out most.
		MinFingerprintsForRarity: 3,
		MinSharedFingerprints:    2,
		MinObservations:          3,
		MinAge:                   10 * time.Minute,
		MaxDevices:               100_000,
		MaxFingerprints:          100_000,
		MaxJA4sPerDevice:         32,
	}
}

// Inventory builds the passive asset inventory and flags anomalous TLS stacks.
//
// The inventory is the part of this tool that stays useful on a quiet network:
// knowing what is on the wire, and what software it speaks, is valuable before
// anything goes wrong. The rare-fingerprint detector then falls straight out of
// it — if every workstation in the building presents the same three JA4 hashes
// because they all run the same browser build, a fourth hash appearing on
// exactly one host is worth a look. That is frequently how an implant with its
// own statically-linked TLS stack announces itself.
type Inventory struct {
	cfg InventoryConfig

	mu       sync.Mutex
	devices  map[netip.Addr]*model.Device
	ja4      map[string]*ja4Info
	reported map[string]struct{}
}

// ja4Info is what is known about one TLS fingerprint.
type ja4Info struct {
	hosts map[netip.Addr]struct{}
	flows int
	first time.Time
}

// NewInventory returns an inventory detector. A zero config selects defaults.
func NewInventory(cfg InventoryConfig) *Inventory {
	d := DefaultInventoryConfig()
	if cfg.MinHostsForRarity > 0 {
		d.MinHostsForRarity = cfg.MinHostsForRarity
	}
	if cfg.MinFingerprintsForRarity > 0 {
		d.MinFingerprintsForRarity = cfg.MinFingerprintsForRarity
	}
	if cfg.MinSharedFingerprints > 0 {
		d.MinSharedFingerprints = cfg.MinSharedFingerprints
	}
	if cfg.MinObservations > 0 {
		d.MinObservations = cfg.MinObservations
	}
	if cfg.MinAge > 0 {
		d.MinAge = cfg.MinAge
	}
	if cfg.MaxDevices > 0 {
		d.MaxDevices = cfg.MaxDevices
	}
	if cfg.MaxFingerprints > 0 {
		d.MaxFingerprints = cfg.MaxFingerprints
	}
	if cfg.MaxJA4sPerDevice > 0 {
		d.MaxJA4sPerDevice = cfg.MaxJA4sPerDevice
	}
	d.SilenceNewDevice = cfg.SilenceNewDevice
	return &Inventory{
		cfg:      d,
		devices:  make(map[netip.Addr]*model.Device),
		ja4:      make(map[string]*ja4Info),
		reported: make(map[string]struct{}),
	}
}

// Name implements Detector.
func (in *Inventory) Name() string { return "inventory" }

// OnPacket maintains the device table.
func (in *Inventory) OnPacket(c *Context, p *model.Packet, f *model.Flow, isNew bool) {
	if c.Cfg.IsInternal(p.Src) {
		if dev, created := in.touch(p.Src, p.SrcMAC, p.Timestamp); created {
			if !in.cfg.SilenceNewDevice {
				c.Emit(in.newDeviceAlert(dev))
			}
		}
		in.addBytes(p.Src, uint64(p.WireLength), 0)
	}
	if c.Cfg.IsInternal(p.Dst) {
		if dev, created := in.touch(p.Dst, p.DstMAC, p.Timestamp); created {
			if !in.cfg.SilenceNewDevice {
				c.Emit(in.newDeviceAlert(dev))
			}
		}
		in.addBytes(p.Dst, 0, uint64(p.WireLength))
	}
}

// touch upserts a device, reporting whether it was newly created.
func (in *Inventory) touch(addr netip.Addr, mac model.MAC, ts time.Time) (model.Device, bool) {
	in.mu.Lock()
	defer in.mu.Unlock()

	dev, ok := in.devices[addr]
	if !ok {
		if len(in.devices) >= in.cfg.MaxDevices {
			return model.Device{}, false
		}
		dev = &model.Device{Addr: addr, FirstSeen: ts, LastSeen: ts}
		if !mac.IsZero() {
			dev.MAC = mac.String()
		}
		in.devices[addr] = dev
		return *dev, true
	}

	if ts.After(dev.LastSeen) {
		dev.LastSeen = ts
	}
	if dev.MAC == "" && !mac.IsZero() {
		dev.MAC = mac.String()
	}
	return *dev, false
}

func (in *Inventory) addBytes(addr netip.Addr, sent, recv uint64) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if dev, ok := in.devices[addr]; ok {
		dev.BytesSent += sent
		dev.BytesRecv += recv
	}
}

// OnFlowClosed attributes TLS fingerprints and hostnames to devices.
func (in *Inventory) OnFlowClosed(c *Context, f *model.Flow) {
	if !c.Cfg.IsInternal(f.Client) {
		return
	}

	in.mu.Lock()
	defer in.mu.Unlock()

	dev, ok := in.devices[f.Client]
	if !ok {
		return
	}
	dev.Flows++

	if f.JA4 == "" {
		return
	}
	if len(dev.JA4s) < in.cfg.MaxJA4sPerDevice && !slices.Contains(dev.JA4s, f.JA4) {
		dev.JA4s = append(dev.JA4s, f.JA4)
	}
	info, ok := in.ja4[f.JA4]
	if !ok {
		// Refuse rather than evict, matching the device map. Evicting would
		// silently reshape the baseline that rarity is measured against, and a
		// baseline that quietly changes is worse than one that stops growing.
		if len(in.ja4) >= in.cfg.MaxFingerprints {
			return
		}
		info = &ja4Info{hosts: make(map[netip.Addr]struct{}), first: f.FirstSeen}
		in.ja4[f.JA4] = info
	}
	if f.FirstSeen.Before(info.first) {
		info.first = f.FirstSeen
	}
	info.hosts[f.Client] = struct{}{}
	info.flows++
}

// OnTick looks for fingerprints unique to a single host.
func (in *Inventory) OnTick(c *Context, now time.Time) {
	in.mu.Lock()

	// Without a baseline, "rare" means nothing. Wait until the network has
	// shown enough hosts and enough distinct stacks to have an opinion.
	if len(in.devices) < in.cfg.MinHostsForRarity || len(in.ja4) < in.cfg.MinFingerprintsForRarity {
		in.mu.Unlock()
		return
	}

	// And wait until some of those stacks are demonstrably shared. Until two
	// hosts have been seen using the same fingerprint, "used by exactly one
	// host" describes every fingerprint on the network — including the
	// perfectly ordinary browser that simply connected first.
	shared := 0
	for _, info := range in.ja4 {
		if len(info.hosts) >= 2 {
			shared++
		}
	}
	if shared < in.cfg.MinSharedFingerprints {
		in.mu.Unlock()
		return
	}

	type finding struct {
		ja4  string
		host netip.Addr
	}
	var found []finding

	for ja4, info := range in.ja4 {
		if len(info.hosts) != 1 {
			continue
		}
		// A single connection proves nothing; a stack used repeatedly by
		// exactly one host is the thing worth looking at.
		if info.flows < in.cfg.MinObservations {
			continue
		}
		// And it has to have been around long enough for a second host to
		// plausibly have used it. Reporting a fingerprint the moment it appears
		// means reporting whichever machine happened to upgrade its browser
		// first, which is noise dressed up as a finding.
		if now.Sub(info.first) < in.cfg.MinAge {
			continue
		}
		if _, done := in.reported[ja4]; done {
			continue
		}
		in.reported[ja4] = struct{}{}
		for h := range info.hosts {
			found = append(found, finding{ja4, h})
		}
	}
	totalJA4 := len(in.ja4)
	totalHosts := len(in.devices)
	in.mu.Unlock()

	for _, f := range found {
		c.Emit(model.Alert{
			RuleID:   RuleRareJA4,
			Title:    fmt.Sprintf("Rare TLS fingerprint on %s", f.host),
			Severity: model.SevMedium,
			Score:    0.6,
			Src:      f.host,
			Proto:    "tcp",
			Description: fmt.Sprintf(
				"%s presented TLS fingerprint %s, which no other host on this network uses "+
					"(%d fingerprints seen across %d hosts). A unique TLS stack usually means unique software — "+
					"worth confirming what on this host is making the connection.",
				f.host, f.ja4, totalJA4, totalHosts),
			Techniques: []model.Technique{model.TechEncryptedChannel},
			Evidence: map[string]any{
				"ja4":                f.ja4,
				"hosts_using":        1,
				"total_fingerprints": totalJA4,
				"total_hosts":        totalHosts,
			},
		})
	}
}

func (in *Inventory) newDeviceAlert(dev model.Device) model.Alert {
	return model.Alert{
		RuleID:      RuleNewDevice,
		Title:       fmt.Sprintf("New device observed: %s", dev.Addr),
		Severity:    model.SevInfo,
		Score:       0.2,
		Src:         dev.Addr,
		Time:        dev.FirstSeen,
		Description: fmt.Sprintf("First traffic seen from %s (MAC %s).", dev.Addr, orNone(dev.MAC)),
		Evidence: map[string]any{
			"addr": dev.Addr.String(),
			"mac":  dev.MAC,
		},
	}
}

// Devices returns a snapshot of the inventory, sorted by address, for the API.
func (in *Inventory) Devices() []model.Device {
	in.mu.Lock()
	defer in.mu.Unlock()

	out := make([]model.Device, 0, len(in.devices))
	for _, d := range in.devices {
		cp := *d
		cp.JA4s = slices.Clone(d.JA4s)
		out = append(out, cp)
	}
	slices.SortFunc(out, func(a, b model.Device) int { return a.Addr.Compare(b.Addr) })
	return out
}

func orNone(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
