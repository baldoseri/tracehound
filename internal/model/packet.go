// Package model defines the core domain types shared by every stage of the
// tracehound pipeline: capture, flow assembly, fingerprinting, and detection.
//
// This package deliberately has no dependencies outside the standard library.
// Everything above it (decoders, detectors, storage, API) depends on model, and
// model depends on nothing, which keeps the detection logic trivially testable
// without a network interface or a capture library in the loop.
package model

import (
	"net/netip"
	"time"
)

// Protocol is an IANA IP protocol number. We define our own rather than reuse
// the capture library's type so that detectors never import gopacket.
type Protocol uint8

const (
	ProtoICMP   Protocol = 1
	ProtoTCP    Protocol = 6
	ProtoUDP    Protocol = 17
	ProtoICMPv6 Protocol = 58
)

func (p Protocol) String() string {
	switch p {
	case ProtoICMP:
		return "icmp"
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMPv6:
		return "icmpv6"
	default:
		return "ip/" + itoa(int(p))
	}
}

// TCP flag bits, matching the wire layout of the TCP header's flag octet.
const (
	TCPFin uint8 = 1 << 0
	TCPSyn uint8 = 1 << 1
	TCPRst uint8 = 1 << 2
	TCPPsh uint8 = 1 << 3
	TCPAck uint8 = 1 << 4
	TCPUrg uint8 = 1 << 5
)

// MAC is a link-layer address. Stored as a fixed array so Packet stays
// allocation-free and usable as a map key component.
type MAC [6]byte

// IsZero reports whether the address is unset, which happens for capture
// sources with no Ethernet layer (e.g. raw IP or Linux cooked captures).
func (m MAC) IsZero() bool { return m == MAC{} }

func (m MAC) String() string {
	if m.IsZero() {
		return ""
	}
	const hexd = "0123456789abcdef"
	buf := make([]byte, 0, 17)
	for i, b := range m {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexd[b>>4], hexd[b&0x0f])
	}
	return string(buf)
}

// Packet is a decoded network packet reduced to the fields tracehound reasons
// about. It is passed by value through the pipeline; Payload aliases the
// capture buffer and is only valid until the next read from the same source.
// Anything that needs to outlive the current packet must copy it.
type Packet struct {
	Timestamp time.Time

	SrcMAC MAC
	DstMAC MAC

	Src     netip.Addr
	Dst     netip.Addr
	SrcPort uint16
	DstPort uint16
	Proto   Protocol

	// TCPFlags is the raw flag octet; zero for non-TCP packets.
	TCPFlags uint8

	// CaptureLength is the number of bytes actually captured, WireLength the
	// size of the frame on the wire. They differ when a snaplen truncates.
	CaptureLength int
	WireLength    int

	// Payload is the transport-layer payload (TCP/UDP data), not including
	// headers. Nil when the packet carries no payload or was truncated.
	Payload []byte
}

// IsSyn reports whether the packet is a bare SYN, i.e. a connection attempt
// rather than a SYN-ACK response. Port-scan detection keys off this.
func (p *Packet) IsSyn() bool {
	return p.Proto == ProtoTCP && p.TCPFlags&TCPSyn != 0 && p.TCPFlags&TCPAck == 0
}

// IsSynAck reports whether the packet accepts a connection, which is the
// signal that a scanned port was actually open.
func (p *Packet) IsSynAck() bool {
	return p.Proto == ProtoTCP && p.TCPFlags&TCPSyn != 0 && p.TCPFlags&TCPAck != 0
}

// itoa is a tiny strconv.Itoa so this package can stay import-light.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
