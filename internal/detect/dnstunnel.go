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

// dnsBuckets is how many slices History is divided into. Evidence leaves the
// window a bucket at a time, so this trades granularity against per-track cost;
// twelve puts the error at under a tenth of the window.
const dnsBuckets = 12

// dnsBucket holds the evidence from one slice of the window.
type dnsBucket struct {
	at        time.Time // start of the slice this bucket covers
	firstSeen time.Time // first query recorded in it

	queries    int
	subLenSum  float64
	entropySum float64
	maxSubLen  int
	highSignal int
}

type dnsTrack struct {
	server netip.Addr

	// buckets is ordered oldest first and is trimmed from the front as time
	// passes, which is what makes History a window rather than an idle timeout.
	// The counters used to be plain totals that only ever grew: a tunnel that
	// burst at 400 queries a minute and stopped was still reported at that
	// domain hours later, with a rate averaged over the whole run.
	buckets []dnsBucket

	// unique maps a name to when it was last asked, so names age out with
	// everything else rather than making the uniqueness ratio a lifetime
	// figure.
	unique     map[string]time.Time
	uniqueOver bool // the unique-name set is at its cap

	last time.Time
}

// dnsTotals is the evidence still inside the window.
type dnsTotals struct {
	queries    int
	subLenSum  float64
	entropySum float64
	maxSubLen  int
	highSignal int
	first      time.Time
}

// bucketFor returns the bucket covering now, creating it if needed.
func (t *dnsTrack) bucketFor(now time.Time, width time.Duration) *dnsBucket {
	start := now.Truncate(width)
	if n := len(t.buckets); n > 0 {
		if last := &t.buckets[n-1]; !start.After(last.at) {
			// The current bucket, or a query that arrived out of order.
			// Captures merged from several sensors do step backwards, and
			// folding those into the newest bucket keeps the slice ordered at
			// a cost of at most one bucket's worth of skew.
			return last
		}
	}
	t.buckets = append(t.buckets, dnsBucket{at: start, firstSeen: now})
	return &t.buckets[len(t.buckets)-1]
}

// prune drops evidence that has fallen out of the window.
func (t *dnsTrack) prune(cutoff time.Time, width time.Duration, maxUnique int) {
	i := 0
	for i < len(t.buckets) && !t.buckets[i].at.Add(width).After(cutoff) {
		i++
	}
	if i > 0 {
		// Copied down rather than resliced so the backing array cannot grow
		// without bound over a long run.
		t.buckets = append(t.buckets[:0], t.buckets[i:]...)
	}

	for name, at := range t.unique {
		if at.Before(cutoff) {
			delete(t.unique, name)
		}
	}
	if len(t.unique) < maxUnique {
		t.uniqueOver = false
	}
}

// totals sums whatever is still in the window.
func (t *dnsTrack) totals() dnsTotals {
	var s dnsTotals
	for i := range t.buckets {
		b := &t.buckets[i]
		s.queries += b.queries
		s.subLenSum += b.subLenSum
		s.entropySum += b.entropySum
		s.highSignal += b.highSignal
		if b.maxSubLen > s.maxSubLen {
			s.maxSubLen = b.maxSubLen
		}
		if s.first.IsZero() || b.firstSeen.Before(s.first) {
			s.first = b.firstSeen
		}
	}
	return s
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
			unique: make(map[string]time.Time),
		}
		d.tracks[k] = t
	}

	t.last = p.Timestamp

	b := t.bucketFor(p.Timestamp, d.bucketWidth())
	b.queries++
	b.subLenSum += float64(len(sub))
	if len(sub) > b.maxSubLen {
		b.maxSubLen = len(sub)
	}
	b.entropySum += shannonEntropy(sub)
	if isHighSignalType(q.Type) {
		b.highSignal++
	}

	if _, seen := t.unique[q.Name]; seen || len(t.unique) < d.cfg.MaxUniqueNames {
		t.unique[q.Name] = p.Timestamp
	} else {
		t.uniqueOver = true
	}
}

// bucketWidth is how much time one bucket covers.
func (d *DNSTunnel) bucketWidth() time.Duration {
	if w := d.cfg.History / dnsBuckets; w > 0 {
		return w
	}
	return time.Second
}

// OnTick scores every tracked domain.
func (d *DNSTunnel) OnTick(c *Context, now time.Time) {
	cutoff := now.Add(-d.cfg.History)

	d.mu.Lock()
	type candidate struct {
		key dnsKey
		trk dnsTrack
		tot dnsTotals
		res dnsResult
	}
	var hits []candidate

	width := d.bucketWidth()
	for k, t := range d.tracks {
		// Expire before scoring. Evidence outside the window must not help
		// reach a threshold, and the rate reported has to describe the window
		// rather than the whole run.
		t.prune(cutoff, width, d.cfg.MaxUniqueNames)

		if len(t.buckets) == 0 && t.last.Before(cutoff) {
			delete(d.tracks, k)
			continue
		}
		if res, tot, ok := d.score(t); ok {
			hits = append(hits, candidate{k, *t, tot, res})
		}
	}
	d.mu.Unlock()

	for _, h := range hits {
		c.Emit(d.alert(h.key, &h.trk, h.tot, h.res))
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

func (d *DNSTunnel) score(t *dnsTrack) (dnsResult, dnsTotals, bool) {
	tot := t.totals()
	if tot.queries < d.cfg.MinQueries {
		return dnsResult{}, tot, false
	}

	unique := len(t.unique)
	if t.uniqueOver {
		unique = tot.queries // capped set: treat as fully unique
	}
	if unique > tot.queries {
		// Names live in one map while queries are bucketed, so a name last
		// asked inside the window can outlive the bucket that counted it.
		// Clamping keeps the ratio a ratio.
		unique = tot.queries
	}

	r := dnsResult{
		uniqueRatio: float64(unique) / float64(tot.queries),
		avgSubLen:   tot.subLenSum / float64(tot.queries),
		avgEntropy:  tot.entropySum / float64(tot.queries),
		typeRatio:   float64(tot.highSignal) / float64(tot.queries),
	}
	if mins := t.last.Sub(tot.first).Minutes(); mins > 0 {
		r.ratePerMin = float64(tot.queries) / mins
	}

	// Four weighted axes. Uniqueness carries the most weight because it is the
	// hardest for a tunnel to avoid: every packet of smuggled data has to be a
	// new name, or caching would swallow it and the channel would not work.
	r.score = 0.35*r.uniqueRatio +
		0.25*normalize(r.avgSubLen, 15, 50) +
		0.25*normalize(r.avgEntropy, 3.2, 4.6) +
		0.15*r.typeRatio

	return r, tot, r.score >= d.cfg.Threshold
}

func (d *DNSTunnel) alert(k dnsKey, t *dnsTrack, tot dnsTotals, r dnsResult) model.Alert {
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
			k.client, tot.queries, k.domain, r.uniqueRatio*100, r.avgSubLen, r.avgEntropy),
		Techniques: []model.Technique{model.TechAppLayerDNS, model.TechExfilDNS, model.TechProtocolTunnel},
		Evidence: map[string]any{
			"domain":            k.domain,
			"queries":           tot.queries,
			"unique_names":      len(t.unique),
			"unique_ratio":      round3(r.uniqueRatio),
			"avg_subdomain_len": round3(r.avgSubLen),
			"max_subdomain_len": tot.maxSubLen,
			"avg_entropy_bits":  round3(r.avgEntropy),
			"txt_null_ratio":    round3(r.typeRatio),
			"queries_per_min":   round3(r.ratePerMin),
		},
	}
}
