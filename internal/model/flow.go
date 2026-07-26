package model

import (
	"net/netip"
	"time"
)

// FlowKey identifies a bidirectional conversation.
//
// The two endpoints are stored in a canonical order (A < B by address, then by
// port) so that packets travelling in either direction hash to the same key.
// This is what lets a single map lookup find the flow regardless of who sent
// the packet — the alternative, keying on (src,dst) and probing twice, doubles
// the hash cost on the hottest path in the program.
type FlowKey struct {
	A     netip.Addr
	B     netip.Addr
	APort uint16
	BPort uint16
	Proto Protocol
}

// Direction indicates which way a packet is travelling relative to the flow's
// canonical A/B ordering.
type Direction uint8

const (
	// DirAToB means the packet travelled from FlowKey.A to FlowKey.B.
	DirAToB Direction = iota
	// DirBToA means the packet travelled from FlowKey.B to FlowKey.A.
	DirBToA
)

// NewFlowKey builds the canonical key for a packet's endpoints and reports
// which direction the packet is travelling in that canonical frame.
func NewFlowKey(src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16, proto Protocol) (FlowKey, Direction) {
	if endpointLess(src, srcPort, dst, dstPort) {
		return FlowKey{A: src, B: dst, APort: srcPort, BPort: dstPort, Proto: proto}, DirAToB
	}
	return FlowKey{A: dst, B: src, APort: dstPort, BPort: srcPort, Proto: proto}, DirBToA
}

// KeyFor derives the canonical key and direction for an already-decoded packet.
func KeyFor(p *Packet) (FlowKey, Direction) {
	return NewFlowKey(p.Src, p.SrcPort, p.Dst, p.DstPort, p.Proto)
}

func endpointLess(a netip.Addr, aPort uint16, b netip.Addr, bPort uint16) bool {
	if c := a.Compare(b); c != 0 {
		return c < 0
	}
	return aPort < bPort
}

// Flow is an accumulating record of one bidirectional conversation.
//
// Client/Server are assigned from the first packet observed: the sender of the
// first packet is treated as the client. For TCP this is corrected when a SYN
// is seen, since the SYN sender is authoritatively the client even if we joined
// the capture mid-conversation.
type Flow struct {
	Key FlowKey `json:"-"`

	Client     netip.Addr `json:"client"`
	ClientPort uint16     `json:"client_port"`
	Server     netip.Addr `json:"server"`
	ServerPort uint16     `json:"server_port"`
	Proto      Protocol   `json:"-"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	PacketsToServer uint64 `json:"packets_to_server"`
	PacketsToClient uint64 `json:"packets_to_client"`
	BytesToServer   uint64 `json:"bytes_to_server"`
	BytesToClient   uint64 `json:"bytes_to_client"`

	// TCPFlagsSeen is the union of every TCP flag octet observed on the flow.
	// A flow with SYN but no SYN-ACK, for example, was never established.
	TCPFlagsSeen uint8 `json:"-"`

	// clientIdentified records whether Client/Server were fixed by observing a
	// TCP SYN, as opposed to guessed from packet ordering.
	clientIdentified bool

	// Application-layer attributes, populated opportunistically by decoders.
	SNI  string `json:"sni,omitempty"`
	ALPN string `json:"alpn,omitempty"`
	JA4  string `json:"ja4,omitempty"`
	JA3  string `json:"ja3,omitempty"`
	// JA4S fingerprints the server's response. On its own it is weaker than
	// JA4, but the pair is considerably stronger than either: a client
	// fingerprint says what software connected, and adding the server's says
	// what it connected to. The same pair seen across several victims is a
	// command-and-control framework rather than one unusual host.
	JA4S string `json:"ja4s,omitempty"`
}

// ProtoString renders the flow's protocol for JSON and display.
func (f *Flow) ProtoString() string { return f.Proto.String() }

// Duration is the wall-clock span between the first and last observed packet.
func (f *Flow) Duration() time.Duration { return f.LastSeen.Sub(f.FirstSeen) }

// Packets is the total packet count in both directions.
func (f *Flow) Packets() uint64 { return f.PacketsToServer + f.PacketsToClient }

// Bytes is the total byte count in both directions.
func (f *Flow) Bytes() uint64 { return f.BytesToServer + f.BytesToClient }

// Established reports whether a TCP handshake was completed on this flow.
// Non-TCP flows are always reported as established.
func (f *Flow) Established() bool {
	if f.Proto != ProtoTCP {
		return true
	}
	return f.TCPFlagsSeen&TCPSyn != 0 && f.TCPFlagsSeen&TCPAck != 0
}

// Observe folds a packet into the flow record.
func (f *Flow) Observe(p *Packet) {
	if f.FirstSeen.IsZero() {
		f.FirstSeen = p.Timestamp
		f.Client, f.ClientPort = p.Src, p.SrcPort
		f.Server, f.ServerPort = p.Dst, p.DstPort
		f.Proto = p.Proto
	}
	if p.Timestamp.After(f.LastSeen) {
		f.LastSeen = p.Timestamp
	}

	// A bare SYN is definitive proof of who opened the connection. If we
	// guessed wrong from packet ordering (which happens when a capture starts
	// mid-flow, or when packets are reordered), correct it now.
	if !f.clientIdentified && p.IsSyn() {
		f.Client, f.ClientPort = p.Src, p.SrcPort
		f.Server, f.ServerPort = p.Dst, p.DstPort
		f.clientIdentified = true
	}

	f.TCPFlagsSeen |= p.TCPFlags

	if p.Src == f.Client && p.SrcPort == f.ClientPort {
		f.PacketsToServer++
		f.BytesToServer += uint64(p.WireLength)
	} else {
		f.PacketsToClient++
		f.BytesToClient += uint64(p.WireLength)
	}
}

// Device is a host observed on the monitored network, keyed by IP address.
// The passive fingerprints collected here are what turn a packet firehose into
// an asset inventory: JA4 hashes identify the TLS stack, which in practice
// identifies the application (and often the malware family).
type Device struct {
	Addr      netip.Addr `json:"addr"`
	MAC       string     `json:"mac,omitempty"`
	Hostname  string     `json:"hostname,omitempty"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`

	// JA4s is the set of distinct TLS client fingerprints this host has
	// presented. More than a handful usually means a multi-tenant host — or an
	// implant using a different TLS stack than the browser next to it.
	//
	// Serialised as client_ja4s rather than ja4s. JA4S is a term of art for the
	// *server* fingerprint, which is a different value carried on a flow, and
	// an audience that knows the difference is exactly the audience reading
	// this API.
	JA4s []string `json:"client_ja4s,omitempty"`

	BytesSent uint64 `json:"bytes_sent"`
	BytesRecv uint64 `json:"bytes_recv"`
	Flows     uint64 `json:"flows"`
}
