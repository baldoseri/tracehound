package quic

import (
	"errors"
	"sort"
)

// Errors reported by ParseInitial.
var (
	// ErrNotInitial means the datagram is not a client Initial packet in a
	// version we understand. This is the overwhelmingly common outcome on a
	// real network, where most UDP is DNS, QUIC short-header packets, or
	// something else entirely, so it carries no diagnostic weight.
	ErrNotInitial = errors.New("quic: not a supported Initial packet")
	// ErrMalformed means the packet claims to be an Initial but does not parse.
	ErrMalformed = errors.New("quic: malformed Initial packet")
)

// MaxCryptoBytes bounds how much handshake data will be buffered for one
// connection. A ClientHello with a hybrid post-quantum key share runs to a few
// kilobytes; anything past this is not a handshake we need to see.
const MaxCryptoBytes = 16384

// Long header bit layout, RFC 9000 section 17.2.
const (
	headerFormLong = 0x80
	fixedBit       = 0x40
	longTypeMask   = 0x30
	// The type field is renumbered in v2. RFC 9369 section 3.2 makes Initial
	// 0b01 where RFC 9000 makes it 0b00, so the same two bits mean different
	// packets depending on the version four bytes further along.
	longTypeInitialV1 = 0x00 // 0b00 << 4
	longTypeInitialV2 = 0x10 // 0b01 << 4
	pnLengthMask      = 0x03
	sampleOffset      = 4  // sample starts 4 bytes past the packet number offset
	sampleLength      = 16 // AES block size
)

// CryptoFrame is one fragment of the TLS handshake stream.
type CryptoFrame struct {
	Offset uint64
	Data   []byte
}

// InitialPacket is a decrypted client Initial.
type InitialPacket struct {
	Version uint32
	DCID    []byte
	SCID    []byte
	Frames  []CryptoFrame
}

// ParseInitial decrypts every client Initial packet in a datagram and returns
// the CRYPTO frames they carry.
//
// QUIC version 1 (RFC 9000) and version 2 (RFC 9369) are both handled. They
// differ by more than a version number: the Initial salt, all three
// key-derivation labels and the long-header packet type numbering all change,
// so the version field selects a set of parameters rather than just a constant.
//
// A datagram can coalesce several QUIC packets, so this walks the whole thing
// rather than stopping after the first. Non-Initial packets and packets that
// fail authentication are skipped, because a passive observer sees plenty of
// both and neither is an error worth reporting.
func ParseInitial(datagram []byte) (*InitialPacket, error) {
	if len(datagram) < 7 {
		return nil, ErrNotInitial
	}
	// A client's first flight is padded to at least 1200 bytes by RFC 9000
	// section 14.1. Checking it here rejects almost all non-QUIC UDP before any
	// crypto is attempted.
	if len(datagram) < 1200 {
		return nil, ErrNotInitial
	}

	var out *InitialPacket
	offset := 0

	for offset < len(datagram) {
		pkt, consumed, err := parseOnePacket(datagram, offset)
		if err != nil || consumed <= 0 {
			break
		}
		offset += consumed
		if pkt == nil {
			continue // a coalesced packet of some other type
		}
		if out == nil {
			out = pkt
		} else {
			out.Frames = append(out.Frames, pkt.Frames...)
		}
	}

	if out == nil {
		return nil, ErrNotInitial
	}
	return out, nil
}

// parseOnePacket handles the packet starting at off, returning how many bytes
// it occupied so a coalesced datagram can be walked.
func parseOnePacket(datagram []byte, off int) (*InitialPacket, int, error) {
	buf := datagram[off:]
	r := &reader{b: buf}

	first := r.u8()
	if !r.ok() {
		return nil, 0, ErrTruncated
	}
	// Short header packets carry no length field, so a coalesced walk cannot
	// continue past one. That is fine: they never carry an Initial.
	if first&headerFormLong == 0 || first&fixedBit == 0 {
		return nil, 0, ErrNotInitial
	}

	version := r.u32()
	dcid := r.bytes(int(r.u8()))
	scid := r.bytes(int(r.u8()))
	if !r.ok() {
		return nil, 0, ErrTruncated
	}

	// A version we do not know is not merely a packet we skip: its header
	// layout is undefined to us, so we cannot even measure it to find the next
	// packet in the datagram.
	params, known := paramsFor(version)

	isInitial := known && first&longTypeMask == params.initialType
	if !isInitial {
		// Skip it if we can measure it. Version Negotiation and Retry packets
		// have no Length field, so the walk simply stops.
		if !known {
			return nil, 0, ErrNotInitial
		}
		tokenSkip := r.varint()
		_ = r.bytes(int(tokenSkip))
		length := r.varint()
		if !r.ok() {
			return nil, 0, ErrTruncated
		}
		return nil, r.pos + int(length), nil
	}

	tokenLen := r.varint()
	_ = r.bytes(int(tokenLen))
	length := r.varint()
	if !r.ok() || length < 4 {
		return nil, 0, ErrMalformed
	}

	pnOffset := r.pos
	packetEnd := pnOffset + int(length)
	if packetEnd > len(buf) {
		return nil, 0, ErrTruncated
	}

	// --- remove header protection (RFC 9001 section 5.4) ---

	keys, err := deriveClientInitialKeys(version, dcid)
	if err != nil {
		return nil, 0, ErrNotInitial
	}

	sampleStart := pnOffset + sampleOffset
	if sampleStart+sampleLength > len(buf) {
		return nil, 0, ErrTruncated
	}
	mask, err := headerMask(keys.hp, buf[sampleStart:sampleStart+sampleLength])
	if err != nil {
		return nil, 0, ErrMalformed
	}

	// The header is copied before unmasking: the input aliases the capture
	// buffer, and a sensor that rewrites the packets it is observing is a
	// sensor that corrupts every later stage.
	header := make([]byte, pnOffset)
	copy(header, buf[:pnOffset])
	header[0] = first ^ (mask[0] & 0x0f)

	pnLen := int(header[0]&pnLengthMask) + 1
	if pnOffset+pnLen > packetEnd {
		return nil, 0, ErrMalformed
	}

	var packetNumber uint64
	for i := 0; i < pnLen; i++ {
		b := buf[pnOffset+i] ^ mask[1+i]
		header = append(header, b)
		packetNumber = packetNumber<<8 | uint64(b)
	}

	// --- authenticate and decrypt (RFC 9001 section 5.3) ---
	//
	// The packet number is used unreconstructed. Full decoding needs the
	// largest packet number already acknowledged, which an observer of a first
	// flight does not have; for a client's opening Initial the truncated value
	// is the real one, and a wrong guess simply fails the AEAD tag.
	plaintext, err := keys.open(header, buf[pnOffset+pnLen:packetEnd], packetNumber)
	if err != nil {
		return nil, packetEnd, nil // not ours, but we know where it ended
	}

	frames, err := parseFrames(plaintext)
	if err != nil {
		return nil, packetEnd, nil
	}

	return &InitialPacket{
		Version: version,
		DCID:    append([]byte(nil), dcid...),
		SCID:    append([]byte(nil), scid...),
		Frames:  frames,
	}, packetEnd, nil
}

// QUIC frame types we need to walk past to reach CRYPTO (RFC 9000 section 19).
const (
	framePadding    = 0x00
	framePing       = 0x01
	frameACK        = 0x02
	frameACKECN     = 0x03
	frameCrypto     = 0x06
	frameConnClose  = 0x1c
	frameConnClose2 = 0x1d
)

// parseFrames extracts CRYPTO frames from a decrypted Initial payload.
//
// Only the frame types that can legitimately precede CRYPTO in a client's first
// flight are decoded. Anything else stops the walk rather than guessing at a
// length, since misreading a frame length would resynchronise on garbage.
func parseFrames(payload []byte) ([]CryptoFrame, error) {
	r := &reader{b: payload}
	var frames []CryptoFrame

	for r.remaining() > 0 && r.ok() {
		switch t := r.varint(); t {
		case framePadding, framePing:
			// No body.

		case frameACK, frameACKECN:
			r.varint() // largest acknowledged
			r.varint() // ack delay
			rangeCount := r.varint()
			r.varint() // first ack range
			if rangeCount > uint64(len(payload)) {
				return frames, ErrMalformed // absurd count, refuse to loop
			}
			for i := uint64(0); i < rangeCount && r.ok(); i++ {
				r.varint() // gap
				r.varint() // range length
			}
			if t == frameACKECN {
				r.varint()
				r.varint()
				r.varint()
			}

		case frameCrypto:
			offset := r.varint()
			length := r.varint()
			data := r.bytes(int(length))
			if !r.ok() {
				return frames, ErrTruncated
			}
			if offset > MaxCryptoBytes || length > MaxCryptoBytes {
				return frames, ErrMalformed
			}
			frames = append(frames, CryptoFrame{
				Offset: offset,
				Data:   append([]byte(nil), data...),
			})

		case frameConnClose, frameConnClose2:
			return frames, nil

		default:
			// An unknown frame type means we cannot find the next one.
			return frames, nil
		}
	}
	return frames, nil
}

// --- handshake reassembly ---------------------------------------------------

// span is a received byte range of the handshake stream.
type span struct{ start, end uint64 }

// cryptoStream reassembles CRYPTO frames into the TLS handshake byte stream.
//
// Frames can arrive out of order and can span several datagrams, which is not
// an edge case: a QUIC ClientHello offering a hybrid post-quantum key share
// exceeds the 1200-byte Initial and is routinely split. Treating only the
// single-packet case would repeat, in a new protocol, exactly the mistake that
// the TCP-side reassembler exists to avoid.
type cryptoStream struct {
	data  []byte
	spans []span
}

func (c *cryptoStream) add(f CryptoFrame) bool {
	end := f.Offset + uint64(len(f.Data))
	if end > MaxCryptoBytes {
		return false
	}
	if uint64(len(c.data)) < end {
		grown := make([]byte, end)
		copy(grown, c.data)
		c.data = grown
	}
	copy(c.data[f.Offset:], f.Data)

	c.spans = append(c.spans, span{f.Offset, end})
	c.merge()
	return true
}

// merge coalesces overlapping ranges so contiguous() is a single lookup.
func (c *cryptoStream) merge() {
	if len(c.spans) < 2 {
		return
	}
	sort.Slice(c.spans, func(i, j int) bool { return c.spans[i].start < c.spans[j].start })
	out := c.spans[:1]
	for _, s := range c.spans[1:] {
		last := &out[len(out)-1]
		if s.start <= last.end {
			if s.end > last.end {
				last.end = s.end
			}
			continue
		}
		out = append(out, s)
	}
	c.spans = out
}

// contiguous returns how many bytes are available from offset zero.
func (c *cryptoStream) contiguous() uint64 {
	if len(c.spans) == 0 || c.spans[0].start != 0 {
		return 0
	}
	return c.spans[0].end
}

// handshake returns the complete handshake message, or nil if more is needed.
//
// A TLS handshake message is a one-byte type and a 24-bit length, so
// completeness is knowable as soon as four bytes have arrived.
func (c *cryptoStream) handshake() []byte {
	have := c.contiguous()
	if have < 4 {
		return nil
	}
	msgLen := uint64(c.data[1])<<16 | uint64(c.data[2])<<8 | uint64(c.data[3])
	total := 4 + msgLen
	if total > MaxCryptoBytes || have < total {
		return nil
	}
	return c.data[:total]
}
