package detect

import (
	"fmt"
	"math"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baldoseri/tracehound/internal/model"
)

// --- harness ----------------------------------------------------------------

var (
	inside  = netip.MustParseAddr("10.0.0.5")
	inside2 = netip.MustParseAddr("10.0.0.6")
	dnsSrv  = netip.MustParseAddr("10.0.0.1")
	outside = netip.MustParseAddr("203.0.113.10")
	t0      = time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
)

type collector struct {
	mu     sync.Mutex
	alerts []model.Alert
}

func (c *collector) emit(a model.Alert) {
	c.mu.Lock()
	c.alerts = append(c.alerts, a)
	c.mu.Unlock()
}

func (c *collector) byRule(id string) []model.Alert {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []model.Alert
	for _, a := range c.alerts {
		if a.RuleID == id {
			out = append(out, a)
		}
	}
	return out
}

func (c *collector) all() []model.Alert {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]model.Alert(nil), c.alerts...)
}

func newTestEngine(ds ...Detector) (*Engine, *collector) {
	col := &collector{}
	// A long cooldown in tests makes duplicate-suppression failures obvious
	// rather than timing-dependent.
	e := NewEngine(Config{AlertCooldown: time.Hour}, col.emit)
	for _, d := range ds {
		e.Register(d)
	}
	return e, col
}

func outboundFlow(client netip.Addr, cport uint16, server netip.Addr, sport uint16) model.Flow {
	return model.Flow{
		Client: client, ClientPort: cport,
		Server: server, ServerPort: sport,
		Proto: model.ProtoTCP,
	}
}

func tcpPacket(src netip.Addr, sport uint16, dst netip.Addr, dport uint16, flags uint8, at time.Time) model.Packet {
	return model.Packet{
		Timestamp: at, Src: src, Dst: dst,
		SrcPort: sport, DstPort: dport,
		Proto: model.ProtoTCP, TCPFlags: flags, WireLength: 74,
	}
}

// lcg is a deterministic pseudo-random source. Tests must not depend on
// math/rand's global state, or a detector regression becomes a flaky test.
type lcg uint64

func (r *lcg) next() uint64 {
	*r = lcg(uint64(*r)*6364136223846793005 + 1442695040888963407)
	return uint64(*r)
}

// frac returns a deterministic value in [-1, 1).
//
// Note the shift: the low-order bits of a linear congruential generator have a
// period of only 2^k, so `next() % n` cycles almost immediately. Every consumer
// here must draw from the high bits.
func (r *lcg) frac() float64 {
	return float64(int64(r.next()>>11))/float64(int64(1)<<52) - 1
}

// intn returns a deterministic value in [0, n), drawn from the high bits.
func (r *lcg) intn(n int) int {
	return int(r.next() >> 33 % uint64(n))
}

// dnsQuery builds a DNS query message for one name.
func dnsQuery(name string, qtype uint16) []byte {
	b := []byte{
		0x12, 0x34, // transaction id
		0x01, 0x00, // flags: standard query, recursion desired
		0x00, 0x01, // qdcount
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar
	}
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = append(b, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return b
}

func dnsPacket(name string, qtype uint16, at time.Time) model.Packet {
	payload := dnsQuery(name, qtype)
	return model.Packet{
		Timestamp: at, Src: inside, Dst: dnsSrv,
		SrcPort: 51000, DstPort: 53,
		Proto: model.ProtoUDP, WireLength: len(payload) + 42,
		Payload: payload,
	}
}

// --- statistics -------------------------------------------------------------

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		in   string
		want float64
	}{
		{"", 0},
		{"aaaa", 0},     // no information
		{"abcd", 2},     // 4 symbols, uniform: log2(4)
		{"aabb", 1},     // 2 symbols, uniform
		{"abcdefgh", 3}, // 8 symbols, uniform
	}
	for _, tc := range tests {
		if got := shannonEntropy(tc.in); math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("shannonEntropy(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}

	// The property the DNS detector actually relies on: encoded data carries
	// more entropy per character than a real hostname.
	hostname := shannonEntropy("mail.google.com")
	encoded := shannonEntropy("k7fj2mq9xz4bwv8hn3ptr6ycs5gd1a0e")
	if encoded <= hostname {
		t.Errorf("encoded entropy %.3f should exceed hostname entropy %.3f", encoded, hostname)
	}
}

func TestCoeffVarIsScaleFree(t *testing.T) {
	// The same relative jitter at two very different scales must score the
	// same, otherwise slow beacons would always look more regular than fast ones.
	fast := []float64{10, 11, 9, 10, 11, 9}
	slow := make([]float64, len(fast))
	for i, v := range fast {
		slow[i] = v * 360 // hours instead of seconds
	}
	if a, b := coeffVar(fast), coeffVar(slow); math.Abs(a-b) > 1e-9 {
		t.Errorf("coeffVar not scale-free: %v vs %v", a, b)
	}
}

// TestMADRatioSurvivesMissedCheckIn is the reason madRatio exists at all.
func TestMADRatioSurvivesMissedCheckIn(t *testing.T) {
	// Perfect 60s beacon that skipped one check-in, producing a 120s gap.
	intervals := []float64{60, 60, 60, 120, 60, 60, 60, 60}

	cv := coeffVar(intervals)
	mad := madRatio(intervals)

	if mad >= cv {
		t.Errorf("madRatio (%.4f) should be lower than coeffVar (%.4f) when a single outlier is present", mad, cv)
	}
	if mad > 0.05 {
		t.Errorf("madRatio = %.4f; one missed check-in should barely move a robust measure", mad)
	}
}

func TestNormalizeSaturates(t *testing.T) {
	for _, tc := range []struct{ x, lo, hi, want float64 }{
		{5, 10, 20, 0},
		{10, 10, 20, 0},
		{15, 10, 20, 0.5},
		{20, 10, 20, 1},
		{99, 10, 20, 1},
	} {
		if got := normalize(tc.x, tc.lo, tc.hi); math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("normalize(%v,%v,%v) = %v, want %v", tc.x, tc.lo, tc.hi, got, tc.want)
		}
	}
}

// --- beaconing --------------------------------------------------------------

// feedBeacon opens n outbound connections at the given mean interval with
// proportional jitter.
func feedBeacon(e *Engine, n int, meanSec float64, jitterFrac float64) {
	f := outboundFlow(inside, 51000, outside, 443)
	r := lcg(42)
	at := t0
	for i := 0; i < n; i++ {
		p := tcpPacket(inside, 51000, outside, 443, model.TCPSyn, at)
		e.Packet(&p, &f, true)
		gap := meanSec * (1 + jitterFrac*r.frac())
		at = at.Add(time.Duration(gap * float64(time.Second)))
	}
}

func TestBeaconDetectsJitteredCheckIn(t *testing.T) {
	b := NewBeacon(BeaconConfig{})
	e, col := newTestEngine(b)

	// 24 check-ins, 60s apart, ±10% jitter — a conventional implant profile.
	feedBeacon(e, 24, 60, 0.10)
	e.Tick(t0.Add(30 * time.Minute))

	alerts := col.byRule(RuleBeaconing)
	if len(alerts) != 1 {
		t.Fatalf("got %d beaconing alerts, want 1", len(alerts))
	}
	a := alerts[0]
	if a.Src != inside || a.Dst != outside || a.DstPort != 443 {
		t.Errorf("alert endpoints = %v -> %v:%d, want %v -> %v:443", a.Src, a.Dst, a.DstPort, inside, outside)
	}
	if a.Score < 0.75 {
		t.Errorf("score = %.3f, want >= 0.75", a.Score)
	}
	if got := a.Evidence["connections"]; got != 24 {
		t.Errorf("evidence connections = %v, want 24", got)
	}
	// The alert must justify itself with a plausible interval.
	if mean, ok := a.Evidence["interval_mean_s"].(float64); !ok || mean < 50 || mean > 70 {
		t.Errorf("interval_mean_s = %v, want ~60", a.Evidence["interval_mean_s"])
	}
	if len(a.Techniques) == 0 {
		t.Error("alert carries no ATT&CK techniques")
	}
}

func TestBeaconIgnoresIrregularTraffic(t *testing.T) {
	b := NewBeacon(BeaconConfig{})
	e, col := newTestEngine(b)

	// Human browsing: bursts and long idle gaps.
	f := outboundFlow(inside, 51000, outside, 443)
	gaps := []float64{3, 240, 8, 900, 15, 1200, 5, 60, 700, 12, 480, 30}
	at := t0
	for _, g := range gaps {
		p := tcpPacket(inside, 51000, outside, 443, model.TCPSyn, at)
		e.Packet(&p, &f, true)
		at = at.Add(time.Duration(g * float64(time.Second)))
	}
	e.Tick(at)

	if got := col.byRule(RuleBeaconing); len(got) != 0 {
		t.Errorf("irregular traffic produced %d beaconing alerts: %+v", len(got), got[0].Evidence)
	}
}

func TestBeaconRequiresMinimumEvidence(t *testing.T) {
	b := NewBeacon(BeaconConfig{})
	e, col := newTestEngine(b)

	feedBeacon(e, 5, 60, 0) // perfectly periodic but too few samples
	e.Tick(t0.Add(time.Hour))

	if got := col.byRule(RuleBeaconing); len(got) != 0 {
		t.Errorf("5 perfectly periodic connections alerted; minimum evidence not enforced")
	}
}

func TestBeaconIgnoresInboundConnections(t *testing.T) {
	b := NewBeacon(BeaconConfig{})
	e, col := newTestEngine(b)

	// External client hitting an internal server: not a beacon by definition.
	f := outboundFlow(outside, 40000, inside, 443)
	at := t0
	for i := 0; i < 30; i++ {
		p := tcpPacket(outside, 40000, inside, 443, model.TCPSyn, at)
		e.Packet(&p, &f, true)
		at = at.Add(60 * time.Second)
	}
	e.Tick(at)

	if got := col.byRule(RuleBeaconing); len(got) != 0 {
		t.Errorf("inbound traffic produced %d beaconing alerts", len(got))
	}
}

// --- DNS --------------------------------------------------------------------

func TestParseDNSQuestion(t *testing.T) {
	q, ok := parseDNSQuestion(dnsQuery("data.tunnel.example.com", dnsTypeTXT))
	if !ok {
		t.Fatal("failed to parse a well-formed query")
	}
	if q.Name != "data.tunnel.example.com" {
		t.Errorf("Name = %q", q.Name)
	}
	if q.Type != dnsTypeTXT {
		t.Errorf("Type = %d, want %d", q.Type, dnsTypeTXT)
	}
	if got, want := registeredDomain(q.Labels), "example.com"; got != want {
		t.Errorf("registeredDomain = %q, want %q", got, want)
	}
	if got, want := subdomainOf(q.Labels), "data.tunnel"; got != want {
		t.Errorf("subdomainOf = %q, want %q", got, want)
	}
}

func TestParseDNSRejectsResponsesAndGarbage(t *testing.T) {
	resp := dnsQuery("example.com", dnsTypeA)
	resp[2] |= 0x80 // set QR: this is now a response
	if _, ok := parseDNSQuestion(resp); ok {
		t.Error("parsed a response as a question")
	}

	// A compression pointer in the question section must be rejected, not
	// followed — following them is how DNS parsers get infinite loops.
	ptr := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c}
	if _, ok := parseDNSQuestion(ptr); ok {
		t.Error("accepted a compression pointer in the question section")
	}

	// Truncations must never panic.
	full := dnsQuery("a.b.example.com", dnsTypeA)
	for i := 0; i <= len(full); i++ {
		_, _ = parseDNSQuestion(full[:i])
	}
}

func TestDNSTunnelDetectsEncodedSubdomains(t *testing.T) {
	d := NewDNSTunnel(DNSTunnelConfig{})
	e, col := newTestEngine(d)

	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	r := lcg(7)
	at := t0
	for i := 0; i < 60; i++ {
		// 40 characters of base32-looking payload, never repeated.
		var sb strings.Builder
		for j := 0; j < 40; j++ {
			sb.WriteByte(alphabet[r.intn(len(alphabet))])
		}
		p := dnsPacket(sb.String()+".tunnel.example.net", dnsTypeTXT, at)
		e.Packet(&p, nil, false)
		at = at.Add(500 * time.Millisecond)
	}
	e.Tick(at)

	alerts := col.byRule(RuleDNSTunnel)
	if len(alerts) != 1 {
		t.Fatalf("got %d DNS tunnelling alerts, want 1", len(alerts))
	}
	a := alerts[0]
	if a.Evidence["domain"] != "example.net" {
		t.Errorf("domain = %v, want example.net", a.Evidence["domain"])
	}
	if ratio, ok := a.Evidence["unique_ratio"].(float64); !ok || ratio < 0.95 {
		t.Errorf("unique_ratio = %v, want ~1.0", a.Evidence["unique_ratio"])
	}
	if a.Severity < model.SevMedium {
		t.Errorf("severity = %s, want at least medium", a.Severity)
	}
}

// tunnelQueries sends n never-repeated high-entropy TXT lookups under one
// domain, starting at from and spaced by gap, and returns the time after the
// last one.
func tunnelQueries(e *Engine, r *lcg, from time.Time, gap time.Duration, n int) time.Time {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	at := from
	for i := 0; i < n; i++ {
		var sb strings.Builder
		for j := 0; j < 40; j++ {
			sb.WriteByte(alphabet[r.intn(len(alphabet))])
		}
		p := dnsPacket(sb.String()+".tunnel.example.net", dnsTypeTXT, at)
		e.Packet(&p, nil, false)
		at = at.Add(gap)
	}
	return at
}

// TestDNSTunnelRateDescribesTheWindow is the reported-number half of the
// windowing bug.
//
// queries_per_min is what an analyst reads to judge how much data is moving.
// It used to be lifetime queries divided by the span since the track was
// created, so a burst that stopped was averaged over everything that followed:
// a tunnel running at over a hundred queries a minute for thirty seconds was
// reported at single digits an hour later, on the same evidence.
func TestDNSTunnelRateDescribesTheWindow(t *testing.T) {
	d := NewDNSTunnel(DNSTunnelConfig{History: 10 * time.Minute})
	e, col := newTestEngine(d)

	r := lcg(7)
	// 60 queries in 30 seconds: 120 a minute.
	at := tunnelQueries(e, &r, t0, 500*time.Millisecond, 60)
	e.Tick(at)

	alerts := col.byRule(RuleDNSTunnel)
	if len(alerts) == 0 {
		t.Fatal("no alert for a burst of encoded lookups")
	}
	rate, _ := alerts[0].Evidence["queries_per_min"].(float64)
	if rate < 100 {
		t.Errorf("queries_per_min = %v immediately after a 120/min burst, want at least 100", rate)
	}
	t.Logf("rate reported at the burst: %v per minute", rate)
}

// TestDNSTunnelEvidenceLeavesTheWindow is the threshold half.
//
// History was documented as how long a domain's evidence is retained, but the
// only expiry deleted a track that had gone entirely silent. A domain that kept
// a trickle of traffic alive accumulated evidence for the life of the process,
// so a burst that ended hours ago still counted toward MinQueries and still
// scored.
func TestDNSTunnelEvidenceLeavesTheWindow(t *testing.T) {
	d := NewDNSTunnel(DNSTunnelConfig{History: time.Minute, MinQueries: 30})
	e, col := newTestEngine(d)

	r := lcg(11)
	// A burst well past MinQueries, then silence long enough to leave it behind.
	at := tunnelQueries(e, &r, t0, 100*time.Millisecond, 40)
	e.Tick(at)
	if len(col.byRule(RuleDNSTunnel)) == 0 {
		t.Fatal("the burst itself did not alert, so the rest proves nothing")
	}
	before := len(col.byRule(RuleDNSTunnel))

	// Two hours later, a few more queries: nowhere near MinQueries on their own.
	// The old code still held all 40 from the burst and would score them again.
	//
	// The gap has to clear the engine's duplicate cooldown as well as History.
	// At ten minutes this test passed against the unwindowed code, because the
	// engine suppressed the second alert and the detector was never the reason
	// nothing appeared.
	at = at.Add(2 * time.Hour)
	at = tunnelQueries(e, &r, at, 100*time.Millisecond, 5)
	e.Tick(at)

	if got := len(col.byRule(RuleDNSTunnel)); got != before {
		t.Errorf("%d alerts after the burst aged out, want the original %d: "+
			"expired evidence is still counting toward the threshold", got, before)
	}
}

func TestDNSTunnelIgnoresNormalResolution(t *testing.T) {
	d := NewDNSTunnel(DNSTunnelConfig{})
	e, col := newTestEngine(d)

	// Real browsing: a handful of names, resolved repeatedly, short and
	// low-entropy. This is the false-positive case that matters most.
	names := []string{
		"www.google.com", "mail.google.com", "drive.google.com",
		"apis.google.com", "fonts.google.com",
	}
	at := t0
	for i := 0; i < 100; i++ {
		p := dnsPacket(names[i%len(names)], dnsTypeA, at)
		e.Packet(&p, nil, false)
		at = at.Add(2 * time.Second)
	}
	e.Tick(at)

	if got := col.byRule(RuleDNSTunnel); len(got) != 0 {
		t.Errorf("ordinary DNS produced %d tunnelling alerts: %+v", len(got), got[0].Evidence)
	}
}

func TestDNSTunnelIgnoresLowVolume(t *testing.T) {
	d := NewDNSTunnel(DNSTunnelConfig{})
	e, col := newTestEngine(d)

	// Tunnel-shaped but only a handful of queries: not enough evidence.
	at := t0
	for i := 0; i < 5; i++ {
		p := dnsPacket(fmt.Sprintf("k7fj2mq9xz4bwv8hn3ptr6ycs5gd1a%02d.t.example.net", i), dnsTypeTXT, at)
		e.Packet(&p, nil, false)
		at = at.Add(time.Second)
	}
	e.Tick(at)

	if got := col.byRule(RuleDNSTunnel); len(got) != 0 {
		t.Error("alerted on 5 queries; minimum evidence not enforced")
	}
}

// --- scanning ---------------------------------------------------------------

func TestScanDetectsVertical(t *testing.T) {
	s := NewScan(ScanConfig{})
	e, col := newTestEngine(s)

	at := t0
	for port := 1; port <= 40; port++ {
		p := tcpPacket(inside, 40000, outside, uint16(port), model.TCPSyn, at)
		e.Packet(&p, nil, false)
		at = at.Add(20 * time.Millisecond)
	}
	// Two ports answered. They have to be two different ports: open_ports
	// counts listening services, so sending the same SYN-ACK twice is one open
	// port observed twice, not two. The earlier version of this test sent
	// port 22 twice and asserted 2, which is what a retransmitted SYN-ACK would
	// have inflated.
	for _, port := range []uint16{22, 25} {
		p := tcpPacket(outside, port, inside, 40000, model.TCPSyn|model.TCPAck, at)
		e.Packet(&p, nil, false)
	}
	e.Tick(at)

	alerts := col.byRule(RuleVerticalScan)
	if len(alerts) != 1 {
		t.Fatalf("got %d vertical scan alerts, want 1", len(alerts))
	}
	a := alerts[0]
	if got := a.Evidence["ports_probed"]; got != 40 {
		t.Errorf("ports_probed = %v, want 40", got)
	}
	if got := a.Evidence["open_ports"]; got != 2 {
		t.Errorf("open_ports = %v, want 2", got)
	}
	if col.byRule(RuleHorizontalScan) != nil {
		t.Error("a vertical scan also fired the horizontal rule")
	}
}

func TestScanDetectsHorizontalSweep(t *testing.T) {
	s := NewScan(ScanConfig{})
	e, col := newTestEngine(s)

	at := t0
	for host := 1; host <= 40; host++ {
		dst := netip.AddrFrom4([4]byte{10, 0, 1, byte(host)})
		p := tcpPacket(inside, 40000, dst, 445, model.TCPSyn, at)
		e.Packet(&p, nil, false)
		at = at.Add(20 * time.Millisecond)
	}
	e.Tick(at)

	alerts := col.byRule(RuleHorizontalScan)
	if len(alerts) != 1 {
		t.Fatalf("got %d horizontal scan alerts, want 1", len(alerts))
	}
	if got := alerts[0].Evidence["hosts_probed"]; got != 40 {
		t.Errorf("hosts_probed = %v, want 40", got)
	}
	if got := alerts[0].DstPort; got != 445 {
		t.Errorf("DstPort = %d, want 445", got)
	}
}

func TestScanIgnoresOrdinaryClient(t *testing.T) {
	s := NewScan(ScanConfig{})
	e, col := newTestEngine(s)

	// A browser opening many parallel connections to one site.
	at := t0
	for i := 0; i < 30; i++ {
		p := tcpPacket(inside, uint16(40000+i), outside, 443, model.TCPSyn, at)
		e.Packet(&p, nil, false)
		at = at.Add(5 * time.Millisecond)
	}
	e.Tick(at)

	if got := col.all(); len(got) != 0 {
		t.Errorf("ordinary client traffic produced %d scan alerts: %s", len(got), got[0].Title)
	}
}

// TestScanIgnoresClientWithManyDestinations is the false positive the
// cardinality thresholds cannot rule out on their own.
//
// One page load reaches dozens of hosts on 443, which is more distinct targets
// than HorizontalHosts. What separates it from a sweep is that the connections
// succeed. The previous test did not cover this: thirty connections to a single
// host on a single port means one entry in each map, so it crossed no threshold
// and would have passed against a detector with no thresholds at all.
func TestScanIgnoresClientWithManyDestinations(t *testing.T) {
	s := NewScan(ScanConfig{})
	e, col := newTestEngine(s)

	at := t0
	for host := 1; host <= 40; host++ {
		dst := netip.AddrFrom4([4]byte{93, 184, 216, byte(host)})
		syn := tcpPacket(inside, uint16(40000+host), dst, 443, model.TCPSyn, at)
		e.Packet(&syn, nil, false)
		ack := tcpPacket(dst, 443, inside, uint16(40000+host), model.TCPSyn|model.TCPAck, at)
		e.Packet(&ack, nil, false)
		at = at.Add(20 * time.Millisecond)
	}
	e.Tick(at)

	if got := col.all(); len(got) != 0 {
		t.Errorf("a client reaching 40 hosts on 443, all answering, produced %d alerts: %s",
			len(got), got[0].Title)
	}
}

// TestScanWindowExpiresEvidence is the property the Window setting claims and
// did not have. Evidence used to be dropped only after a period of total
// silence, so a host that kept talking accumulated distinct destinations
// forever and eventually crossed the threshold on ordinary traffic alone.
func TestScanWindowExpiresEvidence(t *testing.T) {
	s := NewScan(ScanConfig{Window: time.Minute})
	e, col := newTestEngine(s)

	// Nineteen ports, one short of the vertical threshold.
	at := t0
	for port := 1; port <= 19; port++ {
		p := tcpPacket(inside, 40000, outside, uint16(port), model.TCPSyn, at)
		e.Packet(&p, nil, false)
		at = at.Add(time.Second)
	}
	e.Tick(at)
	if got := col.byRule(RuleVerticalScan); len(got) != 0 {
		t.Fatalf("19 ports crossed the threshold of 20")
	}

	// Five minutes later, well outside the window, five more. Lifetime that is
	// 24 distinct ports; inside the window it is five, so nothing should fire.
	at = at.Add(5 * time.Minute)
	for port := 100; port <= 104; port++ {
		p := tcpPacket(inside, 40000, outside, uint16(port), model.TCPSyn, at)
		e.Packet(&p, nil, false)
		at = at.Add(time.Second)
	}
	e.Tick(at)

	if got := col.byRule(RuleVerticalScan); len(got) != 0 {
		t.Errorf("expired evidence still counted towards the threshold: %s", got[0].Title)
	}
}

// TestScanReportsAgainAfterEvidenceAgesOut covers the other half of expiry: the
// latch that stops a finding repeating has to be released once the evidence
// behind it is gone, or a host is reported for its first scan and never again.
func TestScanReportsAgainAfterEvidenceAgesOut(t *testing.T) {
	s := NewScan(ScanConfig{Window: time.Minute})
	e, col := newTestEngine(s)

	scan := func(at time.Time, firstPort, ports int) time.Time {
		for i := 0; i < ports; i++ {
			p := tcpPacket(inside, 40000, outside, uint16(firstPort+i), model.TCPSyn, at)
			e.Packet(&p, nil, false)
			at = at.Add(100 * time.Millisecond)
		}
		e.Tick(at)
		return at
	}

	at := scan(t0, 1, 25)
	if got := col.byRule(RuleVerticalScan); len(got) != 1 {
		t.Fatalf("first scan produced %d alerts, want 1", len(got))
	}

	// Quiet long enough for every probe to leave the window, then scan again.
	//
	// Two things about the gap. It has to clear the engine's duplicate cooldown
	// as well as the detector's window, or the latch can release correctly and
	// the alert still be collapsed on its way out. And the second scan covers a
	// different number of ports on purpose: the engine drops an alert whose
	// evidence digest is unchanged regardless of how much time has passed, so
	// an identical repeat would be suppressed no matter what this detector did,
	// and the test would be measuring the engine rather than the latch.
	at = at.Add(2 * time.Hour)
	e.Tick(at)
	scan(at, 200, 30)

	if got := col.byRule(RuleVerticalScan); len(got) != 2 {
		t.Errorf("second scan after the window cleared produced %d alerts in total, want 2", len(got))
	}
}

// --- exfiltration -----------------------------------------------------------

func TestExfilDetectsAsymmetricUpload(t *testing.T) {
	x := NewExfil(ExfilConfig{})
	e, col := newTestEngine(x)

	f := outboundFlow(inside, 51000, outside, 443)
	f.FirstSeen, f.LastSeen = t0, t0.Add(4*time.Minute)
	f.BytesToServer = 250 << 20 // 250 MiB out
	f.BytesToClient = 300 << 10 // 300 KiB in
	f.SNI = "storage.example.net"
	e.FlowClosed(&f)

	alerts := col.byRule(RuleExfil)
	if len(alerts) != 1 {
		t.Fatalf("got %d exfil alerts, want 1", len(alerts))
	}
	a := alerts[0]
	if a.Severity != model.SevHigh {
		t.Errorf("severity = %s, want high for a 250 MiB transfer", a.Severity)
	}
	if !strings.Contains(a.Title, "storage.example.net") {
		t.Errorf("title should name the SNI destination, got %q", a.Title)
	}
	if ratio, ok := a.Evidence["ratio"].(float64); !ok || ratio < 100 {
		t.Errorf("ratio = %v, want >= 100", a.Evidence["ratio"])
	}
}

func TestExfilIgnoresDownloadsAndSmallFlows(t *testing.T) {
	x := NewExfil(ExfilConfig{})
	e, col := newTestEngine(x)

	// A large download: the same volume, the opposite direction.
	download := outboundFlow(inside, 51000, outside, 443)
	download.BytesToServer = 300 << 10
	download.BytesToClient = 250 << 20
	e.FlowClosed(&download)

	// Lopsided but tiny: a POST, not an exfil.
	small := outboundFlow(inside, 51001, outside, 443)
	small.BytesToServer = 200 << 10
	small.BytesToClient = 1 << 10
	e.FlowClosed(&small)

	// Large and lopsided, but inbound to an internal server.
	inbound := outboundFlow(outside, 40000, inside, 443)
	inbound.BytesToServer = 250 << 20
	inbound.BytesToClient = 1 << 10
	e.FlowClosed(&inbound)

	if got := col.byRule(RuleExfil); len(got) != 0 {
		t.Errorf("got %d exfil alerts, want 0: %s", len(got), got[0].Title)
	}
}

// --- inventory --------------------------------------------------------------

// Fingerprints used across the inventory tests. Only their distinctness
// matters, not their internal structure.
const (
	ja4Chrome  = "t13d1516h2_chrome0000000_chrome0000000"
	ja4Firefox = "t13d1715h2_firefox00000_firefox00000"
	ja4Implant = "t12i040400_implant00000_implant00000"
)

// seedTLSHost registers a host and attributes n completed TLS flows to it,
// starting at t0.
func seedTLSHost(e *Engine, host netip.Addr, ja4 string, n int) {
	seedTLSHostAt(e, host, ja4, n, t0)
}

// seedTLSHostAt is the same but lets a test control when the fingerprint was
// first observed, which the rarity age guard depends on.
func seedTLSHostAt(e *Engine, host netip.Addr, ja4 string, n int, first time.Time) {
	p := tcpPacket(host, 51000, outside, 443, model.TCPSyn, first)
	e.Packet(&p, nil, true)
	for i := 0; i < n; i++ {
		f := outboundFlow(host, uint16(51000+i), outside, 443)
		f.FirstSeen, f.LastSeen = first, first
		f.JA4 = ja4
		e.FlowClosed(&f)
	}
}

// TestSuppressionMemoryIsBounded covers the map that had no delete anywhere.
//
// One entry per distinct detector, rule and pair of addresses, kept for the life
// of the process. The key includes both addresses, so its size is chosen by
// whoever generates the traffic rather than by the sensor.
func TestSuppressionMemoryIsBounded(t *testing.T) {
	col := &collector{}
	const cap = 100
	e := NewEngine(Config{AlertCooldown: time.Hour, MaxSuppressionEntries: cap}, col.emit)

	for i := 0; i < 2000; i++ {
		a := baseAlert()
		a.Detector = "test"
		a.Src = netip.AddrFrom4([4]byte{10, 1, byte(i / 256), byte(i % 256)})
		a.Time = t0.Add(time.Duration(i) * time.Second)
		e.emit(a)
	}

	e.mu.Lock()
	held := len(e.lastSeen)
	dropped := e.dropped
	e.mu.Unlock()

	if held > cap {
		t.Errorf("suppression memory holds %d entries with a cap of %d", held, cap)
	}
	if held == 0 {
		t.Error("suppression memory was emptied entirely; nothing would ever be suppressed")
	}
	if dropped == 0 {
		t.Error("dropped = 0 after 2000 distinct findings through a cap of 100")
	}
	t.Logf("held %d of 2000 distinct findings, dropped %d", held, dropped)
}

// TestSuppressionSurvivesTheBoundForActiveFindings is the property that makes
// bounding by count rather than by age the right choice: a finding that keeps
// recurring must stay suppressed even while unrelated ones churn through the
// map, or the noise TestSuppressionDropsUnchangedEvidence exists to stop comes
// straight back.
func TestSuppressionSurvivesTheBoundForActiveFindings(t *testing.T) {
	col := &collector{}
	e := NewEngine(Config{AlertCooldown: time.Hour, MaxSuppressionEntries: 100}, col.emit)

	hot := baseAlert()
	hot.Detector = "test"
	hot.Time = t0

	e.emit(hot) // first sighting: reported
	for i := 0; i < 500; i++ {
		a := baseAlert()
		a.Detector = "test"
		a.Src = netip.AddrFrom4([4]byte{10, 2, byte(i / 256), byte(i % 256)})
		a.Time = t0.Add(time.Duration(i+1) * time.Second)
		e.emit(a)

		// Keep restating the same finding. It must never be reported twice.
		hot.Time = a.Time
		e.emit(hot)
	}

	var n int
	for _, a := range col.all() {
		if a.Src == hot.Src && a.Dst == hot.Dst {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the recurring finding was reported %d times, want 1", n)
	}
}

// TestBeaconEvidenceIsBounded documents that beaconTrack.starts is trimmed to
// History on every tick, and that a track with nothing left is dropped.
//
// Worth pinning: starts is appended to on the packet path with no cap beside
// it, which reads like the unbounded twin of the 512-entry cap on sizes. It is
// not — trimBefore in OnTick is what bounds it — and the next person to audit
// this file should not have to re-derive that.
func TestBeaconEvidenceIsBounded(t *testing.T) {
	b := NewBeacon(BeaconConfig{History: 5 * time.Minute})
	e, _ := newTestEngine(b)

	f := outboundFlow(inside, 51000, outside, 443)
	at := t0
	for i := 0; i < 5000; i++ {
		p := tcpPacket(inside, 51000, outside, 443, model.TCPSyn, at)
		e.Packet(&p, &f, true)
		at = at.Add(time.Second)
	}
	e.Tick(at)

	b.mu.Lock()
	defer b.mu.Unlock()
	for k, tr := range b.tracks {
		// 5000 seconds of connections through a five minute window.
		if len(tr.starts) > 400 {
			t.Errorf("track %v holds %d starts after a 5m window; evidence is not being trimmed", k, len(tr.starts))
		}
	}
}

func TestInventoryFlagsRareJA4(t *testing.T) {
	in := NewInventory(InventoryConfig{SilenceNewDevice: true})
	e, col := newTestEngine(in)

	// A managed fleet: two browser builds shared across five machines...
	seedTLSHost(e, netip.MustParseAddr("10.0.0.11"), ja4Chrome, 4)
	seedTLSHost(e, netip.MustParseAddr("10.0.0.12"), ja4Chrome, 4)
	seedTLSHost(e, netip.MustParseAddr("10.0.0.13"), ja4Chrome, 4)
	seedTLSHost(e, netip.MustParseAddr("10.0.0.14"), ja4Firefox, 4)
	seedTLSHost(e, netip.MustParseAddr("10.0.0.15"), ja4Firefox, 4)
	// ...and one host repeatedly running something nothing else runs.
	implant := netip.MustParseAddr("10.0.0.66")
	seedTLSHost(e, implant, ja4Implant, 5)

	// Well past the age guard: every fingerprint here has been known since t0.
	e.Tick(t0.Add(30 * time.Minute))

	if got := len(in.Devices()); got != 6 {
		t.Errorf("inventory holds %d devices, want 6", got)
	}

	alerts := col.byRule(RuleRareJA4)
	if len(alerts) != 1 {
		for _, a := range alerts {
			t.Logf("  accused %v (%v)", a.Src, a.Evidence["ja4"])
		}
		t.Fatalf("got %d rare-JA4 alerts, want exactly 1", len(alerts))
	}
	if alerts[0].Src != implant {
		t.Errorf("rare fingerprint attributed to %v, want %v", alerts[0].Src, implant)
	}

	// Ticking again must not re-report the same fingerprint.
	e.Tick(t0.Add(40 * time.Minute))
	if got := col.byRule(RuleRareJA4); len(got) != 1 {
		t.Errorf("rare fingerprint reported %d times across two ticks, want 1", len(got))
	}
}

// TestInventoryWaitsForFingerprintToAge is the regression test for a false
// positive found by adding HTTP/3 traffic to the demo capture.
//
// Three workstations used a browser preferring QUIC, but they did not all start
// at once. The first one to do so presented a fingerprint no other host had yet,
// the network baseline already existed from the TCP stacks, and the detector
// reported an ordinary browser as an implant. A new stack is not a rare stack.
// TestInventoryFingerprintMapIsBounded covers the map that sat beside a capped
// one and had no cap of its own.
//
// MaxDevices bounds the device map because a network holds only so many hosts.
// Nothing bounded the fingerprint map, and that is the wrong way round: a host
// that varies its TLS stack, or an attacker who chooses to, can mint
// fingerprints indefinitely.
func TestInventoryFingerprintMapIsBounded(t *testing.T) {
	const cap = 50
	in := NewInventory(InventoryConfig{SilenceNewDevice: true, MaxFingerprints: cap})
	e, _ := newTestEngine(in)

	host := netip.MustParseAddr("10.0.0.77")
	for i := 0; i < 500; i++ {
		seedTLSHost(e, host, fmt.Sprintf("t13d1516h2_%012x_%012x", i, i), 1)
	}

	in.mu.Lock()
	defer in.mu.Unlock()
	if got := len(in.ja4); got > cap {
		t.Errorf("fingerprint map holds %d entries with a cap of %d", got, cap)
	}
	if got := len(in.devices[host].JA4s); got > in.cfg.MaxJA4sPerDevice {
		t.Errorf("device holds %d fingerprints with a per-device cap of %d",
			got, in.cfg.MaxJA4sPerDevice)
	}
}

func TestInventoryWaitsForFingerprintToAge(t *testing.T) {
	in := NewInventory(InventoryConfig{SilenceNewDevice: true})
	e, col := newTestEngine(in)

	// An established fleet, known since the start of the capture.
	seedTLSHost(e, netip.MustParseAddr("10.0.0.41"), ja4Chrome, 4)
	seedTLSHost(e, netip.MustParseAddr("10.0.0.42"), ja4Chrome, 4)
	seedTLSHost(e, netip.MustParseAddr("10.0.0.43"), ja4Chrome, 4)
	seedTLSHost(e, netip.MustParseAddr("10.0.0.44"), ja4Firefox, 4)
	seedTLSHost(e, netip.MustParseAddr("10.0.0.45"), ja4Firefox, 4)

	// A stack that only turns up 25 minutes in, on one host so far.
	newcomer := netip.MustParseAddr("10.0.0.46")
	seedTLSHostAt(e, newcomer, ja4Implant, 5, t0.Add(25*time.Minute))

	e.Tick(t0.Add(26 * time.Minute)) // one minute old
	if got := col.byRule(RuleRareJA4); len(got) != 0 {
		t.Errorf("reported a fingerprint %v after it first appeared", time.Minute)
	}

	e.Tick(t0.Add(40 * time.Minute)) // now fifteen minutes old
	if got := col.byRule(RuleRareJA4); len(got) != 1 {
		t.Errorf("got %d alerts once the fingerprint had aged, want 1", len(got))
	}
}

// TestInventoryWaitsForSharedBaseline is the regression test for a false
// positive found by replaying the demo capture.
//
// Early in any capture, every host has contributed exactly one fingerprint, so
// *every* fingerprint is used by exactly one host. Without evidence that some
// stacks are genuinely shared, the detector indicted three ordinary browsers
// on the grounds that they happened to connect first.
func TestInventoryWaitsForSharedBaseline(t *testing.T) {
	in := NewInventory(InventoryConfig{SilenceNewDevice: true})
	e, col := newTestEngine(in)

	// Eight hosts, eight distinct fingerprints, nothing shared by anyone.
	for i := 0; i < 8; i++ {
		host := netip.AddrFrom4([4]byte{10, 0, 0, byte(20 + i)})
		seedTLSHost(e, host, fmt.Sprintf("t13d1516h2_uniq%07d_uniq%07d", i, i), 5)
	}
	e.Tick(t0.Add(time.Minute))

	if got := col.byRule(RuleRareJA4); len(got) != 0 {
		t.Errorf("called %d fingerprints rare before any stack was shown to be shared; "+
			"on this evidence every host on the network is equally 'unique'", len(got))
	}
}

// TestInventoryRequiresRepeatedObservations checks the second guard: a stack
// seen once is not evidence, however unusual it looks.
func TestInventoryRequiresRepeatedObservations(t *testing.T) {
	in := NewInventory(InventoryConfig{SilenceNewDevice: true})
	e, col := newTestEngine(in)

	seedTLSHost(e, netip.MustParseAddr("10.0.0.31"), ja4Chrome, 4)
	seedTLSHost(e, netip.MustParseAddr("10.0.0.32"), ja4Chrome, 4)
	seedTLSHost(e, netip.MustParseAddr("10.0.0.33"), ja4Firefox, 4)
	seedTLSHost(e, netip.MustParseAddr("10.0.0.34"), ja4Firefox, 4)
	seedTLSHost(e, netip.MustParseAddr("10.0.0.35"), ja4Firefox, 4)
	// One host, one connection, an unusual stack: not enough to accuse anyone.
	seedTLSHost(e, netip.MustParseAddr("10.0.0.36"), ja4Implant, 1)

	// Ticked well past the age guard so this test fails on the observation
	// count rather than passing for an unrelated reason.
	e.Tick(t0.Add(30 * time.Minute))

	if got := col.byRule(RuleRareJA4); len(got) != 0 {
		t.Errorf("alerted on a fingerprint observed exactly once")
	}
}

func TestInventoryWaitsForBaseline(t *testing.T) {
	in := NewInventory(InventoryConfig{SilenceNewDevice: true}) // defaults: needs 5 hosts / 5 fingerprints
	e, col := newTestEngine(in)

	p := tcpPacket(inside, 51000, outside, 443, model.TCPSyn, t0)
	e.Packet(&p, nil, true)
	f := outboundFlow(inside, 51000, outside, 443)
	f.JA4 = "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"
	e.FlowClosed(&f)
	e.Tick(t0.Add(time.Minute))

	if got := col.byRule(RuleRareJA4); len(got) != 0 {
		t.Error("called a fingerprint rare on a network of one host")
	}
}

func TestInventoryReportsNewDevices(t *testing.T) {
	in := NewInventory(InventoryConfig{})
	e, col := newTestEngine(in)

	for _, h := range []netip.Addr{inside, inside2, inside} { // third is a repeat
		p := tcpPacket(h, 51000, outside, 443, model.TCPSyn, t0)
		e.Packet(&p, nil, true)
	}

	if got := col.byRule(RuleNewDevice); len(got) != 2 {
		t.Errorf("got %d new-device alerts, want 2 (the repeat must not re-alert)", len(got))
	}
}

// --- engine -----------------------------------------------------------------

func TestConfigIsInternal(t *testing.T) {
	cfg := Config{}.withDefaults()
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"10.0.0.5", true},
		{"192.168.1.1", true},
		{"172.16.5.5", true},
		{"172.32.5.5", false}, // just outside the /12
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"203.0.113.10", false},
		{"fe80::1", true},
		{"2606:4700::1111", false},
	} {
		if got := cfg.IsInternal(netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Errorf("IsInternal(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}
	if cfg.IsInternal(netip.Addr{}) {
		t.Error("the zero address must not be internal")
	}
}

// TestSuppressionCollapsesRepeats guards the property that keeps an analyst
// willing to look at the alert feed.
func TestSuppressionCollapsesRepeats(t *testing.T) {
	b := NewBeacon(BeaconConfig{})
	e, col := newTestEngine(b)

	feedBeacon(e, 24, 60, 0.05)
	for i := 0; i < 5; i++ {
		e.Tick(t0.Add(time.Duration(30+i) * time.Minute))
	}

	if got := col.byRule(RuleBeaconing); len(got) != 1 {
		t.Errorf("got %d alerts across 5 ticks, want 1", len(got))
	}
	if s := e.Stats(); s.Suppressed == 0 {
		t.Error("suppression counter did not move")
	}
}

// fixedDetector emits a caller-controlled alert on every tick, which lets the
// suppression rules be tested without going through a real detector.
type fixedDetector struct{ alert model.Alert }

func (f *fixedDetector) Name() string                     { return "fixed" }
func (f *fixedDetector) OnTick(c *Context, now time.Time) { c.Emit(f.alert) }

func baseAlert() model.Alert {
	return model.Alert{
		RuleID:   "TEST-0001",
		Title:    "test finding",
		Severity: model.SevMedium,
		Src:      inside,
		Dst:      outside,
		DstPort:  443,
		Evidence: map[string]any{"queries": 90, "ratio": 1.0},
	}
}

// TestSuppressionDropsUnchangedEvidence covers the case that motivated
// evidence-aware suppression: a detector whose window has not moved re-derives
// identical numbers on every tick, and printing them again says nothing.
func TestSuppressionDropsUnchangedEvidence(t *testing.T) {
	d := &fixedDetector{alert: baseAlert()}
	e, col := newTestEngine(d) // 1h cooldown

	// Every tick here is far beyond the cooldown, so a purely time-based rule
	// would emit three times.
	e.Tick(t0)
	e.Tick(t0.Add(2 * time.Hour))
	e.Tick(t0.Add(4 * time.Hour))

	if got := len(col.all()); got != 1 {
		t.Errorf("got %d alerts, want 1: identical evidence is a restatement no matter how much time passes", got)
	}
	if s := e.Stats(); s.Suppressed != 2 {
		t.Errorf("suppressed = %d, want 2", s.Suppressed)
	}
}

// TestSuppressionReportsEscalationImmediately checks that a finding getting
// worse is not held back by a cooldown — during an incident that is exactly
// the wrong moment to go quiet.
func TestSuppressionReportsEscalationImmediately(t *testing.T) {
	d := &fixedDetector{alert: baseAlert()}
	e, col := newTestEngine(d)

	e.Tick(t0)

	d.alert.Severity = model.SevHigh
	d.alert.Evidence = map[string]any{"queries": 400, "ratio": 1.0}
	e.Tick(t0.Add(time.Minute)) // deep inside the cooldown

	alerts := col.all()
	if len(alerts) != 2 {
		t.Fatalf("got %d alerts, want 2 (escalation must bypass the cooldown)", len(alerts))
	}
	if alerts[1].Severity != model.SevHigh {
		t.Errorf("second alert severity = %s, want high", alerts[1].Severity)
	}
}

// TestSuppressionHoldsEvolvingEvidenceToCooldown is the other half: evidence
// that grows but does not worsen the verdict still waits its turn.
func TestSuppressionHoldsEvolvingEvidenceToCooldown(t *testing.T) {
	d := &fixedDetector{alert: baseAlert()}
	e, col := newTestEngine(d)

	e.Tick(t0)
	d.alert.Evidence = map[string]any{"queries": 120, "ratio": 1.0} // changed, same severity
	e.Tick(t0.Add(time.Minute))

	if got := len(col.all()); got != 1 {
		t.Errorf("got %d alerts, want 1 within the cooldown", got)
	}

	// Past the cooldown with new evidence, it may speak again.
	d.alert.Evidence = map[string]any{"queries": 300, "ratio": 1.0}
	e.Tick(t0.Add(2 * time.Hour))
	if got := len(col.all()); got != 2 {
		t.Errorf("got %d alerts, want 2 after the cooldown elapsed", got)
	}
}

// TestEvidenceDigestIsOrderIndependent guards against a subtle failure: Go
// randomises map iteration, so hashing evidence without sorting would make
// suppression a coin flip.
func TestEvidenceDigestIsOrderIndependent(t *testing.T) {
	a := baseAlert()
	a.Evidence = map[string]any{"alpha": 1, "beta": 2, "gamma": 3, "delta": 4, "epsilon": 5}
	first := evidenceDigest(&a)
	for i := 0; i < 200; i++ {
		if got := evidenceDigest(&a); got != first {
			t.Fatalf("digest changed between calls on iteration %d", i)
		}
	}

	b := a
	b.Evidence = map[string]any{"alpha": 1, "beta": 2, "gamma": 3, "delta": 4, "epsilon": 6}
	if evidenceDigest(&b) == first {
		t.Error("digest ignored a changed evidence value")
	}
}

// --- public suffix handling -------------------------------------------------

func TestRegisteredDomainAndSubdomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		sub    string
	}{
		{"example.com", "example.com", ""},
		{"www.example.com", "example.com", "www"},
		{"a.b.c.example.com", "example.com", "a.b.c"},
		{"localhost", "localhost", ""},
		{"co.uk", "co.uk", ""},
		// Without the suffix table these would all collapse onto "co.uk",
		// merging every unrelated British domain into one bucket.
		{"example.co.uk", "example.co.uk", ""},
		{"www.example.co.uk", "example.co.uk", "www"},
		{"payload.tunnel.example.co.uk", "example.co.uk", "payload.tunnel"},
		{"shop.example.com.au", "example.com.au", "shop"},
		{"a.example.co.jp", "example.co.jp", "a"},
		// "uk.example.com" must NOT be treated as a suffix match.
		{"uk.example.com", "example.com", "uk"},
	}

	for _, tc := range tests {
		labels := strings.Split(tc.name, ".")
		if got := registeredDomain(labels); got != tc.domain {
			t.Errorf("registeredDomain(%q) = %q, want %q", tc.name, got, tc.domain)
		}
		if got := subdomainOf(labels); got != tc.sub {
			t.Errorf("subdomainOf(%q) = %q, want %q", tc.name, got, tc.sub)
		}
	}
}

// TestDNSTunnelGroupsUnderTwoLabelSuffix proves the fix matters end to end: a
// tunnel beneath a .co.uk domain must be scored as one domain, not scattered.
func TestDNSTunnelGroupsUnderTwoLabelSuffix(t *testing.T) {
	d := NewDNSTunnel(DNSTunnelConfig{})
	e, col := newTestEngine(d)

	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	r := lcg(11)
	at := t0
	for i := 0; i < 60; i++ {
		var sb strings.Builder
		for j := 0; j < 40; j++ {
			sb.WriteByte(alphabet[r.intn(len(alphabet))])
		}
		p := dnsPacket(sb.String()+".tunnel.evil.co.uk", dnsTypeTXT, at)
		e.Packet(&p, nil, false)
		at = at.Add(500 * time.Millisecond)
	}
	e.Tick(at)

	alerts := col.byRule(RuleDNSTunnel)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if got := alerts[0].Evidence["domain"]; got != "evil.co.uk" {
		t.Errorf("domain = %v, want evil.co.uk", got)
	}
}

func TestAlertIDsAreUniqueAndPopulated(t *testing.T) {
	e, col := newTestEngine(NewInventory(InventoryConfig{}))

	for i := 0; i < 50; i++ {
		addr := netip.AddrFrom4([4]byte{10, 0, 2, byte(i)})
		p := tcpPacket(addr, 51000, outside, 443, model.TCPSyn, t0)
		e.Packet(&p, nil, true)
	}

	seen := make(map[string]struct{})
	for _, a := range col.all() {
		if a.ID == "" {
			t.Fatal("alert emitted without an ID")
		}
		if _, dup := seen[a.ID]; dup {
			t.Fatalf("duplicate alert ID %s", a.ID)
		}
		seen[a.ID] = struct{}{}
		if a.Detector == "" {
			t.Error("alert emitted without a detector name")
		}
		if a.Time.IsZero() {
			t.Error("alert emitted without a timestamp")
		}
	}
	if len(seen) != 50 {
		t.Errorf("got %d alerts, want 50", len(seen))
	}
}

func TestSeverityRoundTrip(t *testing.T) {
	for _, s := range []model.Severity{model.SevInfo, model.SevLow, model.SevMedium, model.SevHigh, model.SevCritical} {
		text, err := s.MarshalText()
		if err != nil {
			t.Fatalf("marshal %v: %v", s, err)
		}
		var got model.Severity
		if err := got.UnmarshalText(text); err != nil {
			t.Fatalf("unmarshal %q: %v", text, err)
		}
		if got != s {
			t.Errorf("round trip %v -> %q -> %v", s, text, got)
		}
	}
	var bad model.Severity
	if err := bad.UnmarshalText([]byte("catastrophic")); err == nil {
		t.Error("accepted an unknown severity name")
	}
}

// --- benchmarks -------------------------------------------------------------

func BenchmarkEngineDispatch(b *testing.B) {
	e, _ := newTestEngine(
		NewBeacon(BeaconConfig{}),
		NewDNSTunnel(DNSTunnelConfig{}),
		NewScan(ScanConfig{}),
		NewInventory(InventoryConfig{SilenceNewDevice: true}),
	)
	f := outboundFlow(inside, 51000, outside, 443)
	p := tcpPacket(inside, 51000, outside, 443, model.TCPAck, t0)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Packet(&p, &f, false)
	}
}
