package capture

import (
	"errors"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/baldoseri/tracehound/internal/model"
)

// errNotIP is returned internally when a frame carries no IP payload we care
// about (ARP, STP, LLDP, ...). These are counted, not reported.
var errNotIP = errors.New("capture: no IP layer")

// decoder converts raw frames into model.Packet.
//
// It uses gopacket's DecodingLayerParser rather than gopacket.NewPacket. The
// difference is not cosmetic: NewPacket allocates a fresh layer object per
// layer per packet, which at line rate dominates the profile and keeps the GC
// busy. DecodingLayerParser decodes into these pre-allocated struct fields, so
// steady-state packet decoding allocates nothing at all.
//
// A decoder is not safe for concurrent use; give each capture goroutine its own.
type decoder struct {
	eth   layers.Ethernet
	dot1q layers.Dot1Q
	sll   layers.LinuxSLL
	ip4   layers.IPv4
	ip6   layers.IPv6
	tcp   layers.TCP
	udp   layers.UDP
	icmp4 layers.ICMPv4
	icmp6 layers.ICMPv6

	// ip6ext walks IPv6 extension header chains. Without it the parser stops at
	// the IPv6 header whenever an extension follows, and the packet is counted
	// as undecodable — silently blinding the sensor to fragmented IPv6 and to
	// anything carrying a hop-by-hop or destination option.
	//
	// The concrete extension types (IPv6HopByHop, IPv6Fragment, ...) cannot be
	// used here: they implement DecodeFromBytes but not CanDecode, so they do
	// not satisfy gopacket.DecodingLayer. The skipper exists for this case and
	// chains straight through to the transport layer.
	//
	// Note it only skips: a non-initial fragment (offset > 0) carries no
	// transport header, so what follows is payload rather than TCP. Reassembling
	// IP fragments is out of scope, and such packets fall out as undecodable.
	ip6ext layers.IPv6ExtensionSkipper

	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
}

// newDecoder builds a decoder whose first layer matches the source's link type.
func newDecoder(link layers.LinkType) *decoder {
	d := &decoder{decoded: make([]gopacket.LayerType, 0, 8)}

	first := firstLayerFor(link)
	d.parser = gopacket.NewDecodingLayerParser(first,
		&d.eth, &d.dot1q, &d.sll,
		&d.ip4, &d.ip6,
		&d.ip6ext,
		&d.tcp, &d.udp, &d.icmp4, &d.icmp6,
	)
	// A capture is a hostile input: it contains protocols we have never heard
	// of, and truncated frames from snaplen. Neither should stop the sensor.
	d.parser.IgnoreUnsupported = true
	return d
}

// firstLayerFor maps a libpcap link type to the layer the parser should start
// with. Ethernet covers almost everything; SLL appears on Linux "any" captures
// and raw IP on tunnel interfaces.
func firstLayerFor(link layers.LinkType) gopacket.LayerType {
	switch link {
	case layers.LinkTypeEthernet:
		return layers.LayerTypeEthernet
	case layers.LinkTypeLinuxSLL:
		return layers.LayerTypeLinuxSLL
	case layers.LinkTypeRaw, layers.LinkTypeIPv4:
		return layers.LayerTypeIPv4
	case layers.LinkTypeIPv6:
		return layers.LayerTypeIPv6
	default:
		return layers.LayerTypeEthernet
	}
}

// decode fills out from a raw frame. It returns errNotIP for frames with no
// IP layer, which callers treat as "skip", not "fail".
func (d *decoder) decode(data []byte, ci gopacket.CaptureInfo, out *model.Packet) error {
	d.decoded = d.decoded[:0]

	// A decode error still populates the layers that parsed successfully, which
	// is exactly what we want for truncated frames: a snaplen-clipped packet
	// still yields usable addresses and ports. So the error is inspected only
	// after we check what we got.
	_ = d.parser.DecodeLayers(data, &d.decoded)

	*out = model.Packet{
		Timestamp:     ci.Timestamp,
		CaptureLength: ci.CaptureLength,
		WireLength:    ci.Length,
	}
	if out.WireLength == 0 {
		out.WireLength = len(data)
	}

	var haveIP bool
	for _, lt := range d.decoded {
		switch lt {
		case layers.LayerTypeEthernet:
			copy(out.SrcMAC[:], d.eth.SrcMAC)
			copy(out.DstMAC[:], d.eth.DstMAC)

		case layers.LayerTypeIPv4:
			out.Src = addrFromSlice(d.ip4.SrcIP)
			out.Dst = addrFromSlice(d.ip4.DstIP)
			out.Proto = model.Protocol(d.ip4.Protocol)
			haveIP = true

		case layers.LayerTypeIPv6:
			out.Src = addrFromSlice(d.ip6.SrcIP)
			out.Dst = addrFromSlice(d.ip6.DstIP)
			out.Proto = model.Protocol(d.ip6.NextHeader)
			haveIP = true

		case layers.LayerTypeTCP:
			out.SrcPort = uint16(d.tcp.SrcPort)
			out.DstPort = uint16(d.tcp.DstPort)
			out.Proto = model.ProtoTCP
			out.TCPFlags = tcpFlags(&d.tcp)
			out.Payload = d.tcp.Payload

		case layers.LayerTypeUDP:
			out.SrcPort = uint16(d.udp.SrcPort)
			out.DstPort = uint16(d.udp.DstPort)
			out.Proto = model.ProtoUDP
			out.Payload = d.udp.Payload

		case layers.LayerTypeICMPv4:
			out.Proto = model.ProtoICMP
			out.Payload = d.icmp4.Payload

		case layers.LayerTypeICMPv6:
			out.Proto = model.ProtoICMPv6
			out.Payload = d.icmp6.Payload
		}
	}

	if !haveIP || !out.Src.IsValid() {
		return errNotIP
	}
	return nil
}

// tcpFlags packs gopacket's boolean flag fields back into the wire octet, which
// is how model.Packet stores them (compact, and cheap to OR into a flow).
func tcpFlags(t *layers.TCP) uint8 {
	var f uint8
	if t.FIN {
		f |= model.TCPFin
	}
	if t.SYN {
		f |= model.TCPSyn
	}
	if t.RST {
		f |= model.TCPRst
	}
	if t.PSH {
		f |= model.TCPPsh
	}
	if t.ACK {
		f |= model.TCPAck
	}
	if t.URG {
		f |= model.TCPUrg
	}
	return f
}

// addrFromSlice converts a net.IP to a netip.Addr, unmapping IPv4-in-IPv6 so
// that 10.0.0.1 and ::ffff:10.0.0.1 compare equal and hash to the same flow.
func addrFromSlice(ip []byte) netip.Addr {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return a.Unmap()
}
