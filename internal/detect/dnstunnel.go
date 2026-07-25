package detect

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/baldoseri/tracehound/internal/model"
)

// RuleDNSTunnel is the stable rule identifier for DNS tunnelling alerts.
const RuleDNSTunnel = "TH-0002"

// DNSTunnelConfig tunes the DNS tunnelling detector.
type DNSTunnelConfig struct {
	MinQueries     int           // evidence required before scoring
	Threshold      float64       // score in [0,1] at which an alert fires
	History        time.Duration // how long a domain's evidence is retained
	MaxTracked     int           // bound on tracked (client, domain) pairs
	MaxUniqueNames int           // bound on the per-domain unique-name set
}

// DefaultDNSTunnelConfig returns tuning that catches iodine/dnscat2-style
// tunnels and DNS exfiltration without firing on CDN or antivirus lookups.
func DefaultDNSTunnelConfig() DNSTunnelConfig {
	return DNSTunnelConfig{
		MinQueries:     30,
		Threshold:      0.7,
		History:        1 * time.Hour,
		MaxTracked:     20_000,
		MaxUniqueNames: 2_000,
	}
}

type dnsKey struct {
	client netip.Addr
	domain string
}

type dnsTrack struct {
	server     netip.Addr
	queries    int
	unique     map[string]struct{}
	uniqueOver bool // the unique-name set hit its cap

	subLenSum  float64
	entropySum float64
	maxSubLen  int
	highSignal int

	first, last time.Time
}

// DNSTunnel detects data smuggled through DNS queries.
//
// DNS is the ideal covert channel: it is allowed out of nearly every network,
// it is rarely inspected, and recursive resolvers will faithfully deliver an
// attacker's query to an attacker's authoritative server. Tunnelling tools
// encode data into subdomain labels, which produces a signature no legitimate
// resolution pattern matches — thousands of never-repeated, high-entropy,
// unusually long names under a single domain.
//
// Each of those properties alone has innocent explanations (CDNs generate long
// names, antivirus lookups generate high-entropy ones, and a busy host
// generates volume). Requiring all of them together is what keeps this quiet.
type DNSTunnel struct {
	cfg DNSTunnelConfig

	mu     sync.Mutex
	tracks map[dnsKey]*dnsTrack
}

// NewDNSTunnel returns a DNS tunnelling detector.
func NewDNSTunnel(cfg DNSTunnelConfig) *DNSTunnel {
	d := DefaultDNSTunnelConfig()
	if cfg.MinQueries > 0 {
		d.MinQueries = cfg.MinQueries
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
	if cfg.MaxUniqueNames > 0 {
		d.MaxUniqueNames = cfg.MaxUniqueNames
	}
	return &DNSTunnel{cfg: d, tracks: make(map[dnsKey]*dnsTrack)}
}

// Name implements Detector.
func (d *DNSTunnel) Name() string { return "dns-tunnel" }

// OnPacket accumulates evidence from outbound DNS queries.
func (d *DNSTunnel) OnPacket(c *Context, p *model.Packet, f *model.Flow, isNew bool) {
	if p.Proto != model.ProtoUDP || p.DstPort != 53 || len(p.Payload) == 0 {
		return
	}
	if !c.Cfg.IsInternal(p.Src) {
		return
	}
	q, ok := parseDNSQuestion(p.Payload)
	if !ok {
		return
	}

	domain := registeredDomain(q.Labels)
	if domain == "" {
		return
	}
	sub := subdomainOf(q.Labels)

	k := dnsKey{client: p.Src, domain: domain}

	d.mu.Lock()
	defer d.mu.Unlock()

	t, ok := d.tracks[k]
	if !ok {
		if len(d.tracks) >= d.cfg.MaxTracked {
			return
		}
		t = &dnsTrack{
			server: p.Dst,
			unique: make(map[string]struct{}),
			first:  p.Timestamp,
		}
		d.tracks[k] = t
	}

	t.queries++
	t.last = p.Timestamp
	t.subLenSum += float64(len(sub))
	if len(sub) > t.maxSubLen {
		t.maxSubLen = len(sub)
	}
	t.entropySum += shannonEntropy(sub)
	if isHighSignalType(q.Type) {
		t.highSignal++
	}
	if len(t.unique) < d.cfg.MaxUniqueNames {
		t.unique[q.Name] = struct{}{}
	} else {
		t.uniqueOver = true
	}
}

// OnTick scores every tracked domain.
func (d *DNSTunnel) OnTick(c *Context, now time.Time) {
	cutoff := now.Add(-d.cfg.History)

	d.mu.Lock()
	type candidate struct {
		key dnsKey
		trk dnsTrack
		res dnsResult
	}
	var hits []candidate

	for k, t := range d.tracks {
		if t.last.Before(cutoff) {
			delete(d.tracks, k)
			continue
		}
		if res, ok := d.score(t); ok {
			hits = append(hits, candidate{k, *t, res})
		}
	}
	d.mu.Unlock()

	for _, h := range hits {
		c.Emit(d.alert(h.key, &h.trk, h.res))
	}
}

type dnsResult struct {
	uniqueRatio float64
	avgSubLen   float64
	avgEntropy  float64
	typeRatio   float64
	ratePerMin  float64
	score       float64
}

func (d *DNSTunnel) score(t *dnsTrack) (dnsResult, bool) {
	if t.queries < d.cfg.MinQueries {
		return dnsResult{}, false
	}

	unique := len(t.unique)
	if t.uniqueOver {
		unique = t.queries // capped set: treat as fully unique
	}

	r := dnsResult{
		uniqueRatio: float64(unique) / float64(t.queries),
		avgSubLen:   t.subLenSum / float64(t.queries),
		avgEntropy:  t.entropySum / float64(t.queries),
		typeRatio:   float64(t.highSignal) / float64(t.queries),
	}
	if mins := t.last.Sub(t.first).Minutes(); mins > 0 {
		r.ratePerMin = float64(t.queries) / mins
	}

	// Four weighted axes. Uniqueness carries the most weight because it is the
	// hardest for a tunnel to avoid: every packet of smuggled data has to be a
	// new name, or caching would swallow it and the channel would not work.
	r.score = 0.35*r.uniqueRatio +
		0.25*normalize(r.avgSubLen, 15, 50) +
		0.25*normalize(r.avgEntropy, 3.2, 4.6) +
		0.15*r.typeRatio

	return r, r.score >= d.cfg.Threshold
}

func (d *DNSTunnel) alert(k dnsKey, t *dnsTrack, r dnsResult) model.Alert {
	sev := model.SevHigh
	if r.score < 0.85 {
		sev = model.SevMedium
	}

	return model.Alert{
		RuleID:   RuleDNSTunnel,
		Title:    fmt.Sprintf("Probable DNS tunnelling to %s", k.domain),
		Severity: sev,
		Score:    round3(r.score),
		Src:      k.client,
		Dst:      t.server,
		DstPort:  53,
		Proto:    "udp",
		Description: fmt.Sprintf(
			"%s issued %d queries under %s, %.0f%% of them for names never repeated, "+
				"averaging %.0f characters of subdomain at %.2f bits/char entropy. "+
				"Legitimate resolution reuses names and caches; this pattern only makes sense if the name itself is the payload.",
			k.client, t.queries, k.domain, r.uniqueRatio*100, r.avgSubLen, r.avgEntropy),
		Techniques: []model.Technique{model.TechAppLayerDNS, model.TechExfilDNS, model.TechProtocolTunnel},
		Evidence: map[string]any{
			"domain":            k.domain,
			"queries":           t.queries,
			"unique_names":      len(t.unique),
			"unique_ratio":      round3(r.uniqueRatio),
			"avg_subdomain_len": round3(r.avgSubLen),
			"max_subdomain_len": t.maxSubLen,
			"avg_entropy_bits":  round3(r.avgEntropy),
			"txt_null_ratio":    round3(r.typeRatio),
			"queries_per_min":   round3(r.ratePerMin),
		},
	}
}
