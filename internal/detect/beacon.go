package detect

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/baldoseri/tracehound/internal/model"
)

// RuleBeaconing is the stable rule identifier for this detector's alerts.
const RuleBeaconing = "TH-0001"

// BeaconConfig tunes the beaconing detector.
type BeaconConfig struct {
	// MinConnections is how many connections must be observed before a verdict
	// is possible. Too low and ordinary repeated requests look periodic; the
	// default of 8 is roughly where random traffic stops producing low
	// dispersion by chance.
	MinConnections int
	// MinInterval and MaxInterval bound the beacon periods considered. Below
	// MinInterval we are looking at a chatty application, above MaxInterval
	// there is not enough evidence in a capture to call it.
	MinInterval time.Duration
	MaxInterval time.Duration
	// Threshold is the score in [0,1] at or above which an alert fires.
	Threshold float64
	// History is how far back connection times are retained.
	History time.Duration
	// MaxTracked bounds the number of (src,dst,port) triples tracked.
	MaxTracked int
}

// DefaultBeaconConfig returns tuning that finds typical C2 check-ins without
// firing on ordinary periodic infrastructure traffic.
func DefaultBeaconConfig() BeaconConfig {
	return BeaconConfig{
		MinConnections: 8,
		MinInterval:    2 * time.Second,
		MaxInterval:    6 * time.Hour,
		Threshold:      0.75,
		History:        6 * time.Hour,
		MaxTracked:     50_000,
	}
}

type beaconKey struct {
	src   netip.Addr
	dst   netip.Addr
	port  uint16
	proto model.Protocol
}

type beaconTrack struct {
	// starts holds connection start times as Unix seconds. Stored as float64
	// rather than time.Time because every consumer is arithmetic.
	starts []float64
	// sizes holds bytes sent to the server per completed connection.
	sizes []float64
}

// Beacon detects command-and-control check-in patterns.
//
// The intuition: a human browsing generates connections at irregular intervals,
// while an implant polling for tasking generates them on a timer. Malware
// authors know this and add jitter, so the detector cannot simply look for
// identical gaps — it measures *dispersion* and accepts anything tight enough,
// using a robust measure so a few missed check-ins do not mask the pattern.
//
// Payload size is a second, independent axis: a beacon with nothing to report
// sends near-identical bytes every time, which is a signal that survives even
// when the timing jitter is wide.
type Beacon struct {
	cfg BeaconConfig

	mu     sync.Mutex
	tracks map[beaconKey]*beaconTrack
}

// NewBeacon returns a beaconing detector. A zero config selects the defaults.
func NewBeacon(cfg BeaconConfig) *Beacon {
	d := DefaultBeaconConfig()
	if cfg.MinConnections > 0 {
		d.MinConnections = cfg.MinConnections
	}
	if cfg.MinInterval > 0 {
		d.MinInterval = cfg.MinInterval
	}
	if cfg.MaxInterval > 0 {
		d.MaxInterval = cfg.MaxInterval
	}
	if cfg.Threshold > 0 {
		d.Threshold = cfg.Threshold
	}
	if cfg.History > 0 {
		d.History = cfg.History
	}
	if cfg.MaxTracked > 0 {
		d.MaxTracked = cfg.MaxTracked
	}
	return &Beacon{cfg: d, tracks: make(map[beaconKey]*beaconTrack)}
}

// Name implements Detector.
func (b *Beacon) Name() string { return "beaconing" }

// OnPacket records the start of each new outbound connection.
func (b *Beacon) OnPacket(c *Context, p *model.Packet, f *model.Flow, isNew bool) {
	if !isNew {
		return
	}
	// Only outbound conversations are interesting: an inbound connection to a
	// server is a client's business, not a beacon.
	if !c.Cfg.IsInternal(f.Client) || c.Cfg.IsInternal(f.Server) {
		return
	}

	k := beaconKey{src: f.Client, dst: f.Server, port: f.ServerPort, proto: f.Proto}

	b.mu.Lock()
	defer b.mu.Unlock()

	t, ok := b.tracks[k]
	if !ok {
		if len(b.tracks) >= b.cfg.MaxTracked {
			return
		}
		t = &beaconTrack{}
		b.tracks[k] = t
	}
	t.starts = append(t.starts, float64(p.Timestamp.UnixNano())/1e9)
}

// OnFlowClosed records how much was sent on each completed connection, which
// gives the size-consistency half of the score.
func (b *Beacon) OnFlowClosed(c *Context, f *model.Flow) {
	if !c.Cfg.IsInternal(f.Client) || c.Cfg.IsInternal(f.Server) {
		return
	}
	k := beaconKey{src: f.Client, dst: f.Server, port: f.ServerPort, proto: f.Proto}

	b.mu.Lock()
	defer b.mu.Unlock()
	if t, ok := b.tracks[k]; ok {
		t.sizes = append(t.sizes, float64(f.BytesToServer))
		if len(t.sizes) > 512 {
			t.sizes = t.sizes[len(t.sizes)-512:]
		}
	}
}

// OnTick scores every tracked destination.
func (b *Beacon) OnTick(c *Context, now time.Time) {
	cutoff := float64(now.Add(-b.cfg.History).UnixNano()) / 1e9

	b.mu.Lock()
	type candidate struct {
		key beaconKey
		res beaconResult
	}
	var hits []candidate

	for k, t := range b.tracks {
		t.starts = trimBefore(t.starts, cutoff)
		if len(t.starts) == 0 {
			delete(b.tracks, k)
			continue
		}
		res, ok := b.score(t)
		if ok {
			hits = append(hits, candidate{k, res})
		}
	}
	b.mu.Unlock()

	for _, h := range hits {
		c.Emit(b.alert(h.key, h.res))
	}
}

// beaconResult carries the scoring detail so the alert can show its work.
type beaconResult struct {
	connections int
	meanSec     float64
	stddevSec   float64
	cv          float64
	madRatio    float64
	periodicity float64
	sizeScore   float64
	meanBytes   float64
	score       float64
}

// score evaluates one tracked destination.
func (b *Beacon) score(t *beaconTrack) (beaconResult, bool) {
	if len(t.starts) < b.cfg.MinConnections {
		return beaconResult{}, false
	}
	intervals := diffsSeconds(t.starts)
	if len(intervals) == 0 {
		return beaconResult{}, false
	}

	m := mean(intervals)
	if m < b.cfg.MinInterval.Seconds() || m > b.cfg.MaxInterval.Seconds() {
		return beaconResult{}, false
	}

	cv := coeffVar(intervals)
	mad := madRatio(intervals)

	// Take the more favourable dispersion measure: madRatio forgives a missed
	// check-in, cv catches drift that the median would hide.
	dispersion := cv
	if mad < dispersion {
		dispersion = mad
	}
	periodicity := 1 - clamp(dispersion, 0, 1)

	// Size consistency is a bonus signal, not a requirement: with too few
	// completed flows to judge, stay neutral rather than guessing.
	sizeScore := 0.5
	var meanBytes float64
	if len(t.sizes) >= 3 {
		meanBytes = mean(t.sizes)
		sizeScore = 1 - clamp(coeffVar(t.sizes), 0, 1)
	}

	res := beaconResult{
		connections: len(t.starts),
		meanSec:     m,
		stddevSec:   stdDev(intervals),
		cv:          cv,
		madRatio:    mad,
		periodicity: periodicity,
		sizeScore:   sizeScore,
		meanBytes:   meanBytes,
		score:       0.75*periodicity + 0.25*sizeScore,
	}
	return res, res.score >= b.cfg.Threshold
}

func (b *Beacon) alert(k beaconKey, r beaconResult) model.Alert {
	sev := model.SevMedium
	if r.score >= 0.9 && r.connections >= 20 {
		sev = model.SevHigh
	}

	techniques := []model.Technique{model.TechAppLayerWebProto, model.TechEncryptedChannel}
	switch k.port {
	case 80, 443, 8080, 8443:
	default:
		techniques = []model.Technique{model.TechNonStandardPort, model.TechEncryptedChannel}
	}

	return model.Alert{
		RuleID:   RuleBeaconing,
		Title:    fmt.Sprintf("Periodic beaconing to %s:%d", k.dst, k.port),
		Severity: sev,
		Score:    round3(r.score),
		Src:      k.src,
		Dst:      k.dst,
		DstPort:  k.port,
		Proto:    k.proto.String(),
		Description: fmt.Sprintf(
			"%s opened %d connections to %s:%d at a mean interval of %.1fs with %.0f%% jitter. "+
				"Regularity at this level is characteristic of automated check-in rather than user activity.",
			k.src, r.connections, k.dst, k.port, r.meanSec, r.cv*100),
		Techniques: techniques,
		Evidence: map[string]any{
			"connections":          r.connections,
			"interval_mean_s":      round3(r.meanSec),
			"interval_stddev_s":    round3(r.stddevSec),
			"interval_cv":          round3(r.cv),
			"interval_mad_ratio":   round3(r.madRatio),
			"jitter_pct":           round3(r.cv * 100),
			"periodicity_score":    round3(r.periodicity),
			"size_consistency":     round3(r.sizeScore),
			"mean_bytes_to_server": round3(r.meanBytes),
		},
	}
}

// trimBefore drops leading entries older than cutoff. The slice is sorted by
// construction (packets arrive in time order), so this is a prefix scan.
func trimBefore(xs []float64, cutoff float64) []float64 {
	i := 0
	for i < len(xs) && xs[i] < cutoff {
		i++
	}
	if i == 0 {
		return xs
	}
	return append(xs[:0], xs[i:]...)
}

// round3 keeps evidence values readable in JSON.
func round3(f float64) float64 {
	return float64(int64(f*1000+0.5)) / 1000
}
