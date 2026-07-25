// Package pcapgen writes a synthetic capture containing known, labelled
// attacker behaviour.
//
// This exists for two reasons that turn out to be the same reason.
//
// The demo reason: anyone who clones this repository can watch the sensor find
// real detections in one command, without needing a network to sniff, without
// downloading a malware sample, and without the legal and privacy problems that
// come with shipping a capture of somebody's actual traffic.
//
// The engineering reason: the generator declares what it planted. That turns
// "does the detector work?" from an opinion into an assertion — the integration
// test replays this capture and requires that every planted behaviour is found
// and that nothing else fires. A detector that stops working, or starts crying
// wolf on the benign background traffic, fails the build.
package pcapgen

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Snaplen is the capture length recorded in the file header. Bulk-transfer
// packets are truncated to headerSnap, mirroring what a real sensor running
// with a small snaplen produces: full byte accounting, minimal file size.
const (
	Snaplen    = 2048
	headerSnap = 96
)

// Expectation is a behaviour deliberately planted in the capture.
type Expectation struct {
	RuleID string `json:"rule_id"`
	Src    string `json:"src"`
	Dst    string `json:"dst,omitempty"`
	Note   string `json:"note"`
}

// Summary describes what was written.
type Summary struct {
	Packets  int           `json:"packets"`
	Bytes    uint64        `json:"bytes"`
	Start    time.Time     `json:"start"`
	Duration time.Duration `json:"duration"`
	Expected []Expectation `json:"expected"`
	Hosts    []string      `json:"hosts"`
}

// The cast. Addresses are from RFC 5737 documentation ranges so the capture
// can never be mistaken for, or replayed against, real infrastructure.
var (
	gateway = netip.MustParseAddr("10.0.0.1")
	benign  = []netip.Addr{
		netip.MustParseAddr("10.0.0.10"),
		netip.MustParseAddr("10.0.0.11"),
		netip.MustParseAddr("10.0.0.12"),
		netip.MustParseAddr("10.0.0.13"),
		netip.MustParseAddr("10.0.0.14"),
		netip.MustParseAddr("10.0.0.15"),
	}
	victim  = netip.MustParseAddr("10.0.0.66") // compromised workstation
	scanner = netip.MustParseAddr("10.0.0.99") // host performing recon

	c2Server   = netip.MustParseAddr("198.51.100.23")
	exfilHost  = netip.MustParseAddr("203.0.113.77")
	webServers = []netip.Addr{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("151.101.1.140"),
		netip.MustParseAddr("140.82.121.4"),
		netip.MustParseAddr("104.16.132.229"),
	}
)

// Write generates the scenario capture.
func Write(w io.Writer, start time.Time) (Summary, error) {
	pw := pcapgo.NewWriter(w)
	if err := pw.WriteFileHeader(Snaplen, layers.LinkTypeEthernet); err != nil {
		return Summary{}, fmt.Errorf("pcapgen: write header: %w", err)
	}

	g := &gen{rnd: lcg(20260725), start: start}

	// Each segment lays down its own timeline, so frames are generated wildly
	// out of order — the beacon runs to 09:34 before the DNS tunnel starts at
	// 09:12. They are sorted before writing because a real capture is always
	// chronological, and a sensor is entitled to rely on that: timestamps drive
	// flow expiry and detector scoring, so an unsorted file silently starves
	// whole detectors of their scoring cycle.
	g.benignBrowsing()
	g.c2Beacon()
	g.dnsTunnel()
	g.portScan()
	g.dataExfil()

	if g.err != nil {
		return Summary{}, g.err
	}

	sort.SliceStable(g.frames, func(i, j int) bool {
		return g.frames[i].ci.Timestamp.Before(g.frames[j].ci.Timestamp)
	})
	for _, fr := range g.frames {
		if err := pw.WritePacket(fr.ci, fr.data); err != nil {
			return Summary{}, fmt.Errorf("pcapgen: write packet: %w", err)
		}
	}

	hosts := make([]string, 0, len(benign)+2)
	for _, h := range benign {
		hosts = append(hosts, h.String())
	}
	hosts = append(hosts, victim.String(), scanner.String())

	return Summary{
		Packets:  g.packets,
		Bytes:    g.bytes,
		Start:    start,
		Duration: g.last.Sub(start),
		Hosts:    hosts,
		Expected: []Expectation{
			{RuleID: "TH-0001", Src: victim.String(), Dst: c2Server.String(),
				Note: "HTTPS beacon every ~60s with 10% jitter and near-constant request size"},
			{RuleID: "TH-0002", Src: victim.String(), Dst: gateway.String(),
				Note: "base32-encoded data smuggled through TXT queries under exfil.example"},
			{RuleID: "TH-0003", Src: scanner.String(), Dst: benign[0].String(),
				Note: "vertical scan: 120 ports on a single host"},
			{RuleID: "TH-0004", Src: scanner.String(),
				Note: "horizontal sweep: TCP/445 across the /24"},
			{RuleID: "TH-0005", Src: victim.String(), Dst: exfilHost.String(),
				Note: "~18 MiB uploaded against ~90 KiB downloaded"},
			{RuleID: "TH-0007", Src: victim.String(),
				Note: "implant presents a TLS stack no other host on the network uses"},
		},
	}, nil
}

// --- scenario segments ------------------------------------------------------

// benignBrowsing lays down the background the detectors must NOT alert on:
// ordinary hosts making irregular HTTPS connections to popular sites, sharing
// two common browser fingerprints between them.
func (g *gen) benignBrowsing() {
	at := g.start

	for round := 0; round < 90 && g.err == nil; round++ {
		host := benign[g.rnd.intn(len(benign))]
		server := webServers[g.rnd.intn(len(webServers))]
		port := uint16(443)
		sport := uint16(40000 + g.rnd.intn(20000))

		// Two shared fingerprints across six hosts: a managed fleet running
		// two browser builds. This is the baseline that makes the implant's
		// unique stack visible later.
		hello := chromeHello
		if host.As4()[3] >= 13 {
			hello = firefoxHello
		}

		g.handshake(at, host, sport, server, port, hello("www.example.com"))

		// A few KB of encrypted response, then teardown.
		g.tcpData(at.Add(80*time.Millisecond), server, port, host, sport, nil, 1400)
		g.tcpData(at.Add(90*time.Millisecond), server, port, host, sport, nil, 1400)
		g.tcpFlags(at.Add(200*time.Millisecond), host, sport, server, port, tcpFin|tcpAck)

		// Irregular gaps: this is what human-driven traffic looks like, and is
		// the negative case for the beaconing detector.
		gap := time.Duration(500+g.rnd.intn(25_000)) * time.Millisecond
		at = at.Add(gap)
	}
}

// c2Beacon plants a textbook implant check-in: same destination, ~60s period,
// 10% jitter, near-identical request size, and its own TLS stack.
func (g *gen) c2Beacon() {
	at := g.start.Add(30 * time.Second)

	for i := 0; i < 34 && g.err == nil; i++ {
		sport := uint16(49000 + i)
		g.handshake(at, victim, sport, c2Server, 443, implantHello("cdn.update-service.example"))

		// Task poll: a small, near-constant request. The 2% size wobble is what
		// a real beacon's variable-length nonce or cookie produces.
		size := 512 + g.rnd.intn(12)
		g.tcpData(at.Add(60*time.Millisecond), victim, sport, c2Server, 443, nil, size)
		g.tcpData(at.Add(120*time.Millisecond), c2Server, 443, victim, sport, nil, 220)
		g.tcpFlags(at.Add(180*time.Millisecond), victim, sport, c2Server, 443, tcpFin|tcpAck)

		// 60s ± 10%.
		jitter := 1 + 0.10*g.rnd.frac()
		at = at.Add(time.Duration(60 * jitter * float64(time.Second)))
	}
}

// dnsTunnel plants base32-encoded payload in TXT queries under one domain.
func (g *gen) dnsTunnel() {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	at := g.start.Add(12 * time.Minute)

	for i := 0; i < 90 && g.err == nil; i++ {
		label := make([]byte, 42)
		for j := range label {
			label[j] = alphabet[g.rnd.intn(len(alphabet))]
		}
		name := string(label) + ".x" + fmt.Sprint(i) + ".exfil.example"

		g.udp(at, victim, uint16(52000+i%500), gateway, 53, dnsQuery(name, 16 /* TXT */))
		// A plausible short response so the flow is bidirectional.
		g.udp(at.Add(8*time.Millisecond), gateway, 53, victim, uint16(52000+i%500), dnsResponse(name))

		at = at.Add(time.Duration(300+g.rnd.intn(700)) * time.Millisecond)
	}
}

// portScan plants both scan shapes from one host.
func (g *gen) portScan() {
	at := g.start.Add(20 * time.Minute)

	// Horizontal: TCP/445 across the subnet, mostly unanswered.
	for host := 1; host <= 60 && g.err == nil; host++ {
		dst := netip.AddrFrom4([4]byte{10, 0, 0, byte(host)})
		g.tcpFlags(at, scanner, 44000, dst, 445, tcpSyn)
		if host%20 == 0 { // a couple of hosts actually listen
			g.tcpFlags(at.Add(3*time.Millisecond), dst, 445, scanner, 44000, tcpSyn|tcpAck)
		} else {
			g.tcpFlags(at.Add(3*time.Millisecond), dst, 445, scanner, 44000, tcpRst|tcpAck)
		}
		at = at.Add(25 * time.Millisecond)
	}

	// Vertical: a full sweep of one host's low ports.
	at = at.Add(30 * time.Second)
	target := benign[0]
	for port := 1; port <= 120 && g.err == nil; port++ {
		g.tcpFlags(at, scanner, 45000, target, uint16(port), tcpSyn)
		switch port {
		case 22, 80, 443:
			g.tcpFlags(at.Add(2*time.Millisecond), target, uint16(port), scanner, 45000, tcpSyn|tcpAck)
		default:
			g.tcpFlags(at.Add(2*time.Millisecond), target, uint16(port), scanner, 45000, tcpRst|tcpAck)
		}
		at = at.Add(15 * time.Millisecond)
	}
}

// dataExfil plants a large, lopsided upload.
//
// The packets are written truncated: full 1500-byte wire length is recorded in
// the per-packet header while only the first 96 bytes are stored. That is
// exactly what a sensor running a small snaplen produces, and it keeps an
// 18 MiB transfer inside a ~1 MB file.
func (g *gen) dataExfil() {
	at := g.start.Add(26 * time.Minute)
	const sport = uint16(53100)

	g.handshake(at, victim, sport, exfilHost, 443, implantHello("files.storage-sync.example"))
	at = at.Add(50 * time.Millisecond)

	for i := 0; i < 12_500 && g.err == nil; i++ {
		g.tcpData(at, victim, sport, exfilHost, 443, nil, 1500)
		if i%160 == 0 { // sparse ACKs coming back: ~90 KiB total
			g.tcpData(at, exfilHost, 443, victim, sport, nil, 1150)
		}
		at = at.Add(12 * time.Millisecond)
	}
	g.tcpFlags(at, victim, sport, exfilHost, 443, tcpFin|tcpAck)
}

// --- packet construction ----------------------------------------------------

type tcpFlagSet uint8

const (
	tcpFin tcpFlagSet = 1 << 0
	tcpSyn tcpFlagSet = 1 << 1
	tcpRst tcpFlagSet = 1 << 2
	tcpPsh tcpFlagSet = 1 << 3
	tcpAck tcpFlagSet = 1 << 4
)

// framed is one generated packet, held until every segment has run so the
// whole capture can be sorted into chronological order before it is written.
type framed struct {
	ci   gopacket.CaptureInfo
	data []byte
}

type gen struct {
	frames  []framed
	rnd     lcg
	start   time.Time
	last    time.Time
	packets int
	bytes   uint64
	err     error
}

// handshake writes SYN, SYN-ACK, ACK and then the ClientHello.
func (g *gen) handshake(at time.Time, client netip.Addr, sport uint16, server netip.Addr, dport uint16, hello []byte) {
	g.tcpFlags(at, client, sport, server, dport, tcpSyn)
	g.tcpFlags(at.Add(2*time.Millisecond), server, dport, client, sport, tcpSyn|tcpAck)
	g.tcpFlags(at.Add(3*time.Millisecond), client, sport, server, dport, tcpAck)
	g.tcpData(at.Add(4*time.Millisecond), client, sport, server, dport, hello, 0)
}

func (g *gen) tcpFlags(at time.Time, src netip.Addr, sport uint16, dst netip.Addr, dport uint16, flags tcpFlagSet) {
	g.writeTCP(at, src, sport, dst, dport, flags, nil, 0)
}

// tcpData writes a PSH/ACK segment. When wireLen exceeds the payload, the frame
// is recorded as truncated: wireLen bytes on the wire, headerSnap captured.
func (g *gen) tcpData(at time.Time, src netip.Addr, sport uint16, dst netip.Addr, dport uint16, payload []byte, wireLen int) {
	g.writeTCP(at, src, sport, dst, dport, tcpPsh|tcpAck, payload, wireLen)
}

func (g *gen) writeTCP(at time.Time, src netip.Addr, sport uint16, dst netip.Addr, dport uint16, flags tcpFlagSet, payload []byte, wireLen int) {
	if g.err != nil {
		return
	}
	eth, ip := g.l2l3(src, dst, layers.IPProtocolTCP)
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(sport),
		DstPort: layers.TCPPort(dport),
		Seq:     g.rnd.next32(),
		Ack:     g.rnd.next32(),
		Window:  64240,
		SYN:     flags&tcpSyn != 0,
		ACK:     flags&tcpAck != 0,
		PSH:     flags&tcpPsh != 0,
		FIN:     flags&tcpFin != 0,
		RST:     flags&tcpRst != 0,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		g.err = fmt.Errorf("pcapgen: checksum setup: %w", err)
		return
	}
	g.serialize(at, wireLen, eth, ip, tcp, gopacket.Payload(payload))
}

func (g *gen) udp(at time.Time, src netip.Addr, sport uint16, dst netip.Addr, dport uint16, payload []byte) {
	if g.err != nil {
		return
	}
	eth, ip := g.l2l3(src, dst, layers.IPProtocolUDP)
	udp := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		g.err = fmt.Errorf("pcapgen: checksum setup: %w", err)
		return
	}
	g.serialize(at, 0, eth, ip, udp, gopacket.Payload(payload))
}

func (g *gen) l2l3(src, dst netip.Addr, proto layers.IPProtocol) (*layers.Ethernet, *layers.IPv4) {
	eth := &layers.Ethernet{
		SrcMAC:       macFor(src),
		DstMAC:       macFor(dst),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Id:       uint16(g.rnd.intn(65535)),
		SrcIP:    net.IP(src.AsSlice()),
		DstIP:    net.IP(dst.AsSlice()),
		Protocol: proto,
	}
	return eth, ip
}

func (g *gen) serialize(at time.Time, wireLen int, ls ...gopacket.SerializableLayer) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		g.err = fmt.Errorf("pcapgen: serialize: %w", err)
		return
	}
	data := buf.Bytes()

	length := len(data)
	if wireLen > length {
		length = wireLen
	}
	captured := data
	if len(captured) > headerSnap && wireLen > 0 {
		captured = captured[:headerSnap]
	}

	g.frames = append(g.frames, framed{
		ci: gopacket.CaptureInfo{
			Timestamp:     at,
			CaptureLength: len(captured),
			Length:        length,
		},
		data: captured,
	})
	g.packets++
	g.bytes += uint64(length)
	if at.After(g.last) {
		g.last = at
	}
}

// macFor derives a stable locally-administered MAC from an address, so the
// inventory has something to display without inventing a lookup table.
func macFor(a netip.Addr) net.HardwareAddr {
	b := a.As16()
	return net.HardwareAddr{0x02, 0x00, b[12], b[13], b[14], b[15]}
}

// --- deterministic randomness ----------------------------------------------

// lcg is a small linear congruential generator. The capture must be
// bit-identical on every machine and every run, so nothing here may touch
// math/rand's global state or the clock.
type lcg uint64

func (r *lcg) next() uint64 {
	*r = lcg(uint64(*r)*6364136223846793005 + 1442695040888963407)
	return uint64(*r)
}

// intn draws from the high bits. The low bits of an LCG have a period of only
// 2^k, so `next() % n` would cycle almost immediately — which would silently
// produce a capture full of duplicate DNS names and nothing to detect.
func (r *lcg) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.next() >> 33 % uint64(n))
}

func (r *lcg) next32() uint32 { return uint32(r.next() >> 32) }

// frac returns a deterministic value in [-1, 1).
func (r *lcg) frac() float64 {
	return float64(int64(r.next()>>11))/float64(int64(1)<<52) - 1
}
