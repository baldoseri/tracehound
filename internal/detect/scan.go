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
	// Window is the sliding period over which evidence accumulates. An
	// observation older than this stops counting towards either threshold.
	Window time.Duration
	// MaxAnsweredRatio is the largest fraction of probes that may have been
	// answered for the source to still be called a scanner.
	//
	// This is what separates a scanner from a busy client, and without it the
	// cardinality thresholds alone accuse any host that talks to enough peers.
	// A browser knows the port it wants and nearly everything it opens
	// succeeds; a scanner is asking a question and most of the answers are no.
	MaxAnsweredRatio float64
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
		VerticalPorts:   20,
		HorizontalHosts: 25,
		Window:          5 * time.Minute,
		// Half is deliberately loose. A scan of a host running plenty of
		// services still comes in far below it (the demo capture's scanner sits
		// at 0.03), while ordinary client traffic sits near 1.0, so the gate
		// discriminates without needing to be tuned per network.
		MaxAnsweredRatio:  0.5,
		MaxTracked:        10_000,
		MaxPortsPerTarget: 4096,
		MaxTargetsPerPort: 4096,
	}
}

// scanKey identifies one probe: a port on a target.
type scanKey struct {
	target netip.Addr
	port   uint16
}

// scanObs is what is known about one probe.
type scanObs struct {
	// last is the most recent SYN for this key, and is what ages the
	// observation out of the window.
	last time.Time
	// open records that a SYN-ACK came back, so the port is listening.
	open bool
}

type scanTrack struct {
	// obs is the authoritative record: one entry per (target, port) probed.
	//
	// Both scan shapes are derived from this single map rather than kept in
	// two parallel ones, because the two would have to be expired in step and
	// any divergence between them would be a silent wrong answer.
	obs map[scanKey]*scanObs

	// portsPerTarget and targetsPerPort are counts derived from obs, kept
	// alongside it so scoring does not walk every probe and so each cap bounds
	// the dimension it is named after.
	portsPerTarget map[netip.Addr]int
	targetsPerPort map[uint16]int

	syns int // every SYN seen, including repeats: reported, never scored
	last time.Time

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
//
// Both halves of that sentence are load-bearing and both are enforced. Evidence
// ages out of Window, so a host is judged on what it did recently rather than
// on everything it has ever done, and MaxAnsweredRatio requires that the probes
// mostly failed. Without the first, any long-lived host eventually crosses the
// cardinality thresholds; without the second, a busy client crosses them
// legitimately.
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
	if cfg.MaxAnsweredRatio > 0 {
		d.MaxAnsweredRatio = cfg.MaxAnsweredRatio
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
		s.recordOpen(p)
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
			obs:            make(map[scanKey]*scanObs),
			portsPerTarget: make(map[netip.Addr]int),
			targetsPerPort: make(map[uint16]int),
		}
		s.tracks[p.Src] = t
	}
	t.syns++
	t.last = p.Timestamp

	key := scanKey{target: p.Dst, port: p.DstPort}
	if o, ok := t.obs[key]; ok {
		o.last = p.Timestamp
		return
	}
	// Each cap now bounds the dimension it is named after. They used to be
	// applied to the opposite map, which was invisible only because both
	// defaults are 4096.
	if t.portsPerTarget[key.target] >= s.cfg.MaxPortsPerTarget {
		return
	}
	if t.targetsPerPort[key.port] >= s.cfg.MaxTargetsPerPort {
		return
	}
	t.obs[key] = &scanObs{last: p.Timestamp}
	t.portsPerTarget[key.target]++
	t.targetsPerPort[key.port]++
}

func (s *Scan) recordOpen(p *model.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// The SYN-ACK travels back to the scanner, so the scanner is the
	// destination and the listening port is the source. Attributing it to the
	// probe it answers, rather than counting it against the source as a whole,
	// is what lets the answered ratio age out with everything else.
	t, ok := s.tracks[p.Dst]
	if !ok {
		return
	}
	if o, ok := t.obs[scanKey{target: p.Src, port: p.SrcPort}]; ok {
		o.open = true
	}
}

// OnTick evaluates each tracked source and expires stale evidence.
func (s *Scan) OnTick(c *Context, now time.Time) {
	cutoff := now.Add(-s.cfg.Window)

	s.mu.Lock()
	var out []model.Alert

	for src, t := range s.tracks {
		// Expire first. Everything below is a statement about the window, and
		// scoring stale evidence is the whole bug this ordering exists to
		// avoid: a probe from an hour ago must not help reach a threshold now.
		//
		// This is safe for short bursts in a way that expiring the whole track
		// was not. A scan that finished seconds before this tick is entirely
		// inside the window and survives intact.
		t.prune(cutoff)

		target, ports := t.widestTarget()
		port, hosts := t.widestPort()

		// Release a latch once its evidence has aged out, so a source that
		// scans, goes quiet, and scans again is reported the second time.
		if ports < s.cfg.VerticalPorts {
			t.reportedVertical = false
		}
		if hosts < s.cfg.HorizontalHosts {
			t.reportedHorizontal = false
		}

		if t.scanLike(s.cfg.MaxAnsweredRatio) {
			if !t.reportedVertical && ports >= s.cfg.VerticalPorts {
				out = append(out, s.verticalAlert(src, target, ports, t))
				t.reportedVertical = true
			}
			if !t.reportedHorizontal && hosts >= s.cfg.HorizontalHosts {
				out = append(out, s.horizontalAlert(src, port, hosts, t))
				t.reportedHorizontal = true
			}
		}

		if len(t.obs) == 0 && t.last.Before(cutoff) {
			delete(s.tracks, src)
		}
	}
	s.mu.Unlock()

	for i := range out {
		c.Emit(out[i])
	}
}

// prune drops observations that have fallen out of the window, keeping the
// derived counts in step.
func (t *scanTrack) prune(cutoff time.Time) {
	for k, o := range t.obs {
		if !o.last.Before(cutoff) {
			continue
		}
		delete(t.obs, k)
		if n := t.portsPerTarget[k.target] - 1; n > 0 {
			t.portsPerTarget[k.target] = n
		} else {
			delete(t.portsPerTarget, k.target)
		}
		if n := t.targetsPerPort[k.port] - 1; n > 0 {
			t.targetsPerPort[k.port] = n
		} else {
			delete(t.targetsPerPort, k.port)
		}
	}
}

// answered counts the probes in the window that got a SYN-ACK back.
func (t *scanTrack) answered() int {
	n := 0
	for _, o := range t.obs {
		if o.open {
			n++
		}
	}
	return n
}

// scanLike reports whether few enough probes were answered for this source to
// look like enumeration rather than use.
func (t *scanTrack) scanLike(maxRatio float64) bool {
	live := len(t.obs)
	if live == 0 {
		return false
	}
	return float64(t.answered())/float64(live) <= maxRatio
}

// span returns the period covered by the observations still in the window.
func (t *scanTrack) span() time.Duration {
	var first time.Time
	for _, o := range t.obs {
		if first.IsZero() || o.last.Before(first) {
			first = o.last
		}
	}
	if first.IsZero() {
		return 0
	}
	return t.last.Sub(first)
}

// widestTarget returns the target that received the most distinct ports.
func (t *scanTrack) widestTarget() (netip.Addr, int) {
	var best netip.Addr
	most := 0
	for addr, n := range t.portsPerTarget {
		if n > most {
			best, most = addr, n
		}
	}
	return best, most
}

// widestPort returns the port that was tried against the most distinct hosts.
func (t *scanTrack) widestPort() (uint16, int) {
	var best uint16
	most := 0
	for port, n := range t.targetsPerPort {
		if n > most {
			best, most = port, n
		}
	}
	return best, most
}

func (s *Scan) verticalAlert(src, target netip.Addr, ports int, t *scanTrack) model.Alert {
	sev := model.SevMedium
	if ports >= 100 {
		sev = model.SevHigh
	}
	open := t.answered()
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
			src, ports, target, t.span().Round(time.Second), open),
		Techniques: []model.Technique{model.TechNetworkScan},
		Evidence: map[string]any{
			"scan_type":     "vertical",
			"target":        target.String(),
			"ports_probed":  ports,
			"open_ports":    open,
			"answered_pct":  round3(100 * float64(open) / float64(len(t.obs))),
			"syn_count":     t.syns,
			"duration_s":    round3(t.span().Seconds()),
			"targets_total": len(t.portsPerTarget),
		},
	}
}

func (s *Scan) horizontalAlert(src netip.Addr, port uint16, hosts int, t *scanTrack) model.Alert {
	sev := model.SevMedium
	if hosts >= 100 {
		sev = model.SevHigh
	}
	open := t.answered()
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
			src, port, hosts, t.span().Round(time.Second), open),
		Techniques: []model.Technique{model.TechNetworkScan, model.TechRemoteSysDiscov},
		Evidence: map[string]any{
			"scan_type":    "horizontal",
			"port":         port,
			"hosts_probed": hosts,
			"responded":    open,
			"answered_pct": round3(100 * float64(open) / float64(len(t.obs))),
			"syn_count":    t.syns,
			"duration_s":   round3(t.span().Seconds()),
		},
	}
}
