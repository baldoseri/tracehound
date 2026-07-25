package detect

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/baldoseri/tracehound/internal/model"
)

// Rule identifiers for the two scan shapes.
const (
	RuleVerticalScan   = "TH-0003"
	RuleHorizontalScan = "TH-0004"
)

// ScanConfig tunes the port-scan detector.
type ScanConfig struct {
	// VerticalPorts is how many distinct ports on one target constitute a
	// vertical scan ("what is this host running?").
	VerticalPorts int
	// HorizontalHosts is how many distinct targets on one port constitute a
	// horizontal sweep ("who else runs SMB?").
	HorizontalHosts int
	// Window is the sliding period over which evidence accumulates.
	Window time.Duration
	// MaxTracked bounds the number of source hosts tracked at once.
	MaxTracked int
	// MaxPortsPerTarget and MaxTargetsPerPort bound per-source memory. A scan
	// is by definition high-cardinality, so these caps are what stop the
	// detector from becoming the denial of service it is meant to detect.
	MaxPortsPerTarget int
	MaxTargetsPerPort int
}

// DefaultScanConfig returns thresholds that catch an nmap default scan while
// ignoring a browser opening a dozen parallel connections.
func DefaultScanConfig() ScanConfig {
	return ScanConfig{
		VerticalPorts:     20,
		HorizontalHosts:   25,
		Window:            5 * time.Minute,
		MaxTracked:        10_000,
		MaxPortsPerTarget: 4096,
		MaxTargetsPerPort: 4096,
	}
}

type scanTrack struct {
	// perTarget answers "how many ports did this source touch on one host".
	perTarget map[netip.Addr]map[uint16]struct{}
	// perPort answers "how many hosts did this source touch on one port".
	perPort map[uint16]map[netip.Addr]struct{}

	syns     int
	answered int // SYN-ACKs seen: ports that were actually open

	first, last time.Time

	// The two scan shapes are independent findings from the same source, so
	// they are latched separately. A single flag would mean a host that swept
	// the subnet and then enumerated one target only ever got reported for
	// whichever happened to be scored first.
	reportedVertical   bool
	reportedHorizontal bool
}

// Scan detects port scanning and network sweeps.
//
// The signal is unanswered SYNs at high cardinality. A legitimate client knows
// which port it wants; a scanner is asking a question and most of the answers
// are "no". Distinguishing the two shapes matters for triage — a vertical scan
// against one host is reconnaissance of that host, while a horizontal sweep for
// one port across a subnet is usually an attacker looking for a specific
// exploitable service, which is a much more urgent finding.
type Scan struct {
	cfg ScanConfig

	mu     sync.Mutex
	tracks map[netip.Addr]*scanTrack
}

// NewScan returns a port-scan detector. A zero config selects the defaults.
func NewScan(cfg ScanConfig) *Scan {
	d := DefaultScanConfig()
	if cfg.VerticalPorts > 0 {
		d.VerticalPorts = cfg.VerticalPorts
	}
	if cfg.HorizontalHosts > 0 {
		d.HorizontalHosts = cfg.HorizontalHosts
	}
	if cfg.Window > 0 {
		d.Window = cfg.Window
	}
	if cfg.MaxTracked > 0 {
		d.MaxTracked = cfg.MaxTracked
	}
	if cfg.MaxPortsPerTarget > 0 {
		d.MaxPortsPerTarget = cfg.MaxPortsPerTarget
	}
	if cfg.MaxTargetsPerPort > 0 {
		d.MaxTargetsPerPort = cfg.MaxTargetsPerPort
	}
	return &Scan{cfg: d, tracks: make(map[netip.Addr]*scanTrack)}
}

// Name implements Detector.
func (s *Scan) Name() string { return "port-scan" }

// OnPacket records connection attempts and which of them were accepted.
func (s *Scan) OnPacket(c *Context, p *model.Packet, f *model.Flow, isNew bool) {
	switch {
	case p.IsSyn():
		s.recordSyn(p)
	case p.IsSynAck():
		// The SYN-ACK travels back to the scanner, so the scanner is the
		// destination here. An accepted connection means an open port, which
		// is evidence the scan succeeded rather than evidence against it.
		s.recordOpen(p.Dst)
	}
}

func (s *Scan) recordSyn(p *model.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tracks[p.Src]
	if !ok {
		if len(s.tracks) >= s.cfg.MaxTracked {
			return
		}
		t = &scanTrack{
			perTarget: make(map[netip.Addr]map[uint16]struct{}),
			perPort:   make(map[uint16]map[netip.Addr]struct{}),
			first:     p.Timestamp,
		}
		s.tracks[p.Src] = t
	}
	t.syns++
	t.last = p.Timestamp

	ports, ok := t.perTarget[p.Dst]
	if !ok {
		if len(t.perTarget) < s.cfg.MaxTargetsPerPort {
			ports = make(map[uint16]struct{})
			t.perTarget[p.Dst] = ports
		}
	}
	if ports != nil && len(ports) < s.cfg.MaxPortsPerTarget {
		ports[p.DstPort] = struct{}{}
	}

	hosts, ok := t.perPort[p.DstPort]
	if !ok {
		if len(t.perPort) < s.cfg.MaxPortsPerTarget {
			hosts = make(map[netip.Addr]struct{})
			t.perPort[p.DstPort] = hosts
		}
	}
	if hosts != nil && len(hosts) < s.cfg.MaxTargetsPerPort {
		hosts[p.Dst] = struct{}{}
	}
}

func (s *Scan) recordOpen(scanner netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tracks[scanner]; ok {
		t.answered++
	}
}

// OnTick evaluates each tracked source and expires stale evidence.
func (s *Scan) OnTick(c *Context, now time.Time) {
	cutoff := now.Add(-s.cfg.Window)

	s.mu.Lock()
	var out []model.Alert

	for src, t := range s.tracks {
		// Score before expiring, not after. A scan that finishes just before a
		// tick would otherwise have its evidence deleted on the same pass that
		// should have reported it — the detector would go quiet on exactly the
		// bursty, short-lived activity it exists to catch.
		if !t.reportedVertical {
			if target, ports := t.widestTarget(); ports >= s.cfg.VerticalPorts {
				out = append(out, s.verticalAlert(src, target, ports, t))
				t.reportedVertical = true
			}
		}
		if !t.reportedHorizontal {
			if port, hosts := t.widestPort(); hosts >= s.cfg.HorizontalHosts {
				out = append(out, s.horizontalAlert(src, port, hosts, t))
				t.reportedHorizontal = true
			}
		}

		if t.last.Before(cutoff) {
			delete(s.tracks, src)
		}
	}
	s.mu.Unlock()

	for i := range out {
		c.Emit(out[i])
	}
}

// widestTarget returns the target that received the most distinct ports.
func (t *scanTrack) widestTarget() (netip.Addr, int) {
	var best netip.Addr
	most := 0
	for addr, ports := range t.perTarget {
		if len(ports) > most {
			best, most = addr, len(ports)
		}
	}
	return best, most
}

// widestPort returns the port that was tried against the most distinct hosts.
func (t *scanTrack) widestPort() (uint16, int) {
	var best uint16
	most := 0
	for port, hosts := range t.perPort {
		if len(hosts) > most {
			best, most = port, len(hosts)
		}
	}
	return best, most
}

func (s *Scan) verticalAlert(src, target netip.Addr, ports int, t *scanTrack) model.Alert {
	sev := model.SevMedium
	if ports >= 100 {
		sev = model.SevHigh
	}
	return model.Alert{
		RuleID:   RuleVerticalScan,
		Title:    fmt.Sprintf("Port scan: %s probed %d ports on %s", src, ports, target),
		Severity: sev,
		Score:    round3(normalize(float64(ports), float64(s.cfg.VerticalPorts), 200)),
		Src:      src,
		Dst:      target,
		Proto:    "tcp",
		Description: fmt.Sprintf(
			"%s sent SYNs to %d distinct ports on %s within %s, of which %d were accepted. "+
				"Enumerating a host's listening services is reconnaissance, not normal client behaviour.",
			src, ports, target, t.last.Sub(t.first).Round(time.Second), t.answered),
		Techniques: []model.Technique{model.TechNetworkScan},
		Evidence: map[string]any{
			"scan_type":     "vertical",
			"target":        target.String(),
			"ports_probed":  ports,
			"open_ports":    t.answered,
			"syn_count":     t.syns,
			"duration_s":    round3(t.last.Sub(t.first).Seconds()),
			"targets_total": len(t.perTarget),
		},
	}
}

func (s *Scan) horizontalAlert(src netip.Addr, port uint16, hosts int, t *scanTrack) model.Alert {
	sev := model.SevMedium
	if hosts >= 100 {
		sev = model.SevHigh
	}
	return model.Alert{
		RuleID:   RuleHorizontalScan,
		Title:    fmt.Sprintf("Network sweep: %s probed port %d across %d hosts", src, port, hosts),
		Severity: sev,
		Score:    round3(normalize(float64(hosts), float64(s.cfg.HorizontalHosts), 254)),
		Src:      src,
		DstPort:  port,
		Proto:    "tcp",
		Description: fmt.Sprintf(
			"%s probed port %d on %d distinct hosts within %s, of which %d responded. "+
				"Sweeping one service across a subnet is how an attacker finds the next machine to move to.",
			src, port, hosts, t.last.Sub(t.first).Round(time.Second), t.answered),
		Techniques: []model.Technique{model.TechNetworkScan, model.TechRemoteSysDiscov},
		Evidence: map[string]any{
			"scan_type":    "horizontal",
			"port":         port,
			"hosts_probed": hosts,
			"responded":    t.answered,
			"syn_count":    t.syns,
			"duration_s":   round3(t.last.Sub(t.first).Seconds()),
		},
	}
}
