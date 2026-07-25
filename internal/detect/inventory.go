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
	// MaxDevices bounds the inventory.
	MaxDevices int
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
		MaxDevices:               100_000,
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
	ja4Hosts map[string]map[netip.Addr]struct{}
	ja4Flows map[string]int
	reported map[string]struct{}
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
	if cfg.MaxDevices > 0 {
		d.MaxDevices = cfg.MaxDevices
	}
	d.SilenceNewDevice = cfg.SilenceNewDevice
	return &Inventory{
		cfg:      d,
		devices:  make(map[netip.Addr]*model.Device),
		ja4Hosts: make(map[string]map[netip.Addr]struct{}),
		ja4Flows: make(map[string]int),
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
	if !slices.Contains(dev.JA4s, f.JA4) {
		dev.JA4s = append(dev.JA4s, f.JA4)
	}
	hosts, ok := in.ja4Hosts[f.JA4]
	if !ok {
		hosts = make(map[netip.Addr]struct{})
		in.ja4Hosts[f.JA4] = hosts
	}
	hosts[f.Client] = struct{}{}
	in.ja4Flows[f.JA4]++
}

// OnTick looks for fingerprints unique to a single host.
func (in *Inventory) OnTick(c *Context, now time.Time) {
	in.mu.Lock()

	// Without a baseline, "rare" means nothing. Wait until the network has
	// shown enough hosts and enough distinct stacks to have an opinion.
	if len(in.devices) < in.cfg.MinHostsForRarity || len(in.ja4Hosts) < in.cfg.MinFingerprintsForRarity {
		in.mu.Unlock()
		return
	}

	// And wait until some of those stacks are demonstrably shared. Until two
	// hosts have been seen using the same fingerprint, "used by exactly one
	// host" describes every fingerprint on the network — including the
	// perfectly ordinary browser that simply connected first.
	shared := 0
	for _, hosts := range in.ja4Hosts {
		if len(hosts) >= 2 {
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

	for ja4, hosts := range in.ja4Hosts {
		if len(hosts) != 1 {
			continue
		}
		// A single connection proves nothing; a stack used repeatedly by
		// exactly one host is the thing worth looking at.
		if in.ja4Flows[ja4] < in.cfg.MinObservations {
			continue
		}
		if _, done := in.reported[ja4]; done {
			continue
		}
		in.reported[ja4] = struct{}{}
		for h := range hosts {
			found = append(found, finding{ja4, h})
		}
	}
	totalJA4 := len(in.ja4Hosts)
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
