package capture

import (
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/baldoseri/tracehound/internal/model"
)

// build serialises a layer stack into wire bytes.
func build(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func eth(next layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: next,
	}
}

func decodeOne(t *testing.T, data []byte) (model.Packet, error) {
	t.Helper()
	d := newDecoder(layers.LinkTypeEthernet)
	var p model.Packet
	err := d.decode(data, gopacket.CaptureInfo{
		Timestamp:     time.Unix(1_774_000_000, 0).UTC(),
		CaptureLength: len(data),
		Length:        len(data),
	}, &p)
	return p, err
}

func TestDecodeIPv4TCP(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: net.IPv4(10, 0, 0, 5), DstIP: net.IPv4(93, 184, 216, 34),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{SrcPort: 51234, DstPort: 443, SYN: true, Window: 64240}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}

	p, err := decodeOne(t, build(t, eth(layers.EthernetTypeIPv4), ip, tcp))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.Src.String() != "10.0.0.5" || p.Dst.String() != "93.184.216.34" {
		t.Errorf("addresses = %v -> %v", p.Src, p.Dst)
	}
	if p.SrcPort != 51234 || p.DstPort != 443 {
		t.Errorf("ports = %d -> %d", p.SrcPort, p.DstPort)
	}
	if p.Proto != model.ProtoTCP {
		t.Errorf("proto = %v, want tcp", p.Proto)
	}
	if !p.IsSyn() {
		t.Error("SYN flag lost in decode")
	}
	if p.SrcMAC.String() != "02:00:00:00:00:01" {
		t.Errorf("SrcMAC = %q", p.SrcMAC.String())
	}
}

func TestDecodeIPv6UDP(t *testing.T) {
	ip := &layers.IPv6{
		Version: 6, HopLimit: 64,
		SrcIP: net.ParseIP("fd00::5"), DstIP: net.ParseIP("fd00::1"),
		NextHeader: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{SrcPort: 51000, DstPort: 53}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}

	p, err := decodeOne(t, build(t, eth(layers.EthernetTypeIPv6), ip, udp, gopacket.Payload([]byte("query"))))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.Src.String() != "fd00::5" || p.Dst.String() != "fd00::1" {
		t.Errorf("addresses = %v -> %v", p.Src, p.Dst)
	}
	if p.Proto != model.ProtoUDP || p.DstPort != 53 {
		t.Errorf("proto/port = %v/%d, want udp/53", p.Proto, p.DstPort)
	}
	if string(p.Payload) != "query" {
		t.Errorf("payload = %q", p.Payload)
	}
}

// TestDecodeIPv6WithExtensionHeader is the regression test for a real gap: the
// parser used to stop at the IPv6 header whenever an extension header followed,
// so fragmented IPv6 was counted as undecodable and its transport layer never
// reached the detectors.
func TestDecodeIPv6WithExtensionHeader(t *testing.T) {
	ip := &layers.IPv6{
		Version: 6, HopLimit: 64,
		SrcIP: net.ParseIP("fd00::5"), DstIP: net.ParseIP("fd00::1"),
		NextHeader: layers.IPProtocolIPv6Fragment,
	}
	frag := &layers.IPv6Fragment{
		NextHeader:     layers.IPProtocolTCP,
		FragmentOffset: 0,
		MoreFragments:  false,
		Identification: 0xdeadbeef,
	}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 8443, SYN: true, Window: 64240}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}

	p, err := decodeOne(t, build(t, eth(layers.EthernetTypeIPv6), ip, frag, tcp))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.Proto != model.ProtoTCP {
		t.Errorf("proto = %v, want tcp: the extension header was not traversed", p.Proto)
	}
	if p.DstPort != 8443 {
		t.Errorf("dst port = %d, want 8443", p.DstPort)
	}
	if p.Src.String() != "fd00::5" {
		t.Errorf("src = %v", p.Src)
	}
}

func TestDecodeVLANTagged(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: net.IPv4(10, 0, 0, 5), DstIP: net.IPv4(10, 0, 0, 6),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 445, SYN: true}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	dot1q := &layers.Dot1Q{VLANIdentifier: 100, Type: layers.EthernetTypeIPv4}

	p, err := decodeOne(t, build(t, eth(layers.EthernetTypeDot1Q), dot1q, ip, tcp))
	if err != nil {
		t.Fatalf("decode VLAN-tagged frame: %v", err)
	}
	if p.DstPort != 445 || p.Proto != model.ProtoTCP {
		t.Errorf("VLAN tag not skipped: proto=%v port=%d", p.Proto, p.DstPort)
	}
}

// TestDecodeNonIPIsSkipped checks that link-layer chatter is reported as
// "not IP" rather than as a failure, so one ARP frame never stops a capture.
func TestDecodeNonIPIsSkipped(t *testing.T) {
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: 1,
		SourceHwAddress: []byte{2, 0, 0, 0, 0, 1}, SourceProtAddress: []byte{10, 0, 0, 5},
		DstHwAddress: make([]byte, 6), DstProtAddress: []byte{10, 0, 0, 1},
	}
	if _, err := decodeOne(t, build(t, eth(layers.EthernetTypeARP), arp)); err != errNotIP {
		t.Errorf("ARP decode error = %v, want errNotIP", err)
	}
}

func TestDecodeTruncatedNeverPanics(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: net.IPv4(10, 0, 0, 5), DstIP: net.IPv4(10, 0, 0, 6),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 443, PSH: true, ACK: true}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	full := build(t, eth(layers.EthernetTypeIPv4), ip, tcp, gopacket.Payload(make([]byte, 200)))

	// Every prefix, as a snaplen would produce.
	for i := 0; i <= len(full); i++ {
		_, _ = decodeOne(t, full[:i])
	}
	// And every single-byte corruption.
	for i := 0; i < len(full); i++ {
		mutated := append([]byte(nil), full...)
		mutated[i] ^= 0xff
		_, _ = decodeOne(t, mutated)
	}
}

func TestTCPFlagsRoundTrip(t *testing.T) {
	tcp := &layers.TCP{FIN: true, SYN: true, RST: true, PSH: true, ACK: true, URG: true}
	got := tcpFlags(tcp)
	want := model.TCPFin | model.TCPSyn | model.TCPRst | model.TCPPsh | model.TCPAck | model.TCPUrg
	if got != want {
		t.Errorf("tcpFlags = %#08b, want %#08b", got, want)
	}
	if tcpFlags(&layers.TCP{}) != 0 {
		t.Error("empty TCP header produced non-zero flags")
	}
}

func BenchmarkDecodeIPv4TCP(b *testing.B) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: net.IPv4(10, 0, 0, 5), DstIP: net.IPv4(93, 184, 216, 34),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{SrcPort: 51234, DstPort: 443, PSH: true, ACK: true, Window: 64240}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth(layers.EthernetTypeIPv4), ip, tcp, gopacket.Payload(make([]byte, 1400)))
	data := buf.Bytes()

	d := newDecoder(layers.LinkTypeEthernet)
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: len(data), Length: len(data)}
	var p model.Packet

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := d.decode(data, ci, &p); err != nil {
			b.Fatal(err)
		}
	}
}
