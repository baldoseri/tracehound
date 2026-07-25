// Package quic decrypts QUIC Initial packets far enough to recover the TLS
// ClientHello inside them.
//
// This exists because roughly a third of web traffic is now HTTP/3, and a
// sensor that only fingerprints TLS over TCP is blind to all of it. QUIC
// encrypts its Initial packets, but not secretly: the keys are derived from the
// Destination Connection ID, which travels in the clear precisely so that
// middleboxes, load balancers, and observers can do this. Decrypting one is a
// key schedule and an AEAD open, not an attack.
package quic

import "errors"

// ErrTruncated means the buffer ended in the middle of a field.
var ErrTruncated = errors.New("quic: truncated")

// reader is a bounds-checked cursor over a packet.
//
// Same shape as the one in internal/fingerprint, and for the same reason: every
// read past the end fails rather than panics, so the parser reads as
// straight-line code and one check at the end catches malformed input.
type reader struct {
	b   []byte
	pos int
	bad bool
}

func (r *reader) ok() bool       { return !r.bad }
func (r *reader) remaining() int { return len(r.b) - r.pos }
func (r *reader) fail()          { r.bad = true; r.pos = len(r.b) }

func (r *reader) u8() uint8 {
	if r.remaining() < 1 {
		r.fail()
		return 0
	}
	v := r.b[r.pos]
	r.pos++
	return v
}

func (r *reader) u32() uint32 {
	if r.remaining() < 4 {
		r.fail()
		return 0
	}
	v := uint32(r.b[r.pos])<<24 | uint32(r.b[r.pos+1])<<16 |
		uint32(r.b[r.pos+2])<<8 | uint32(r.b[r.pos+3])
	r.pos += 4
	return v
}

func (r *reader) bytes(n int) []byte {
	if n < 0 || r.remaining() < n {
		r.fail()
		return nil
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v
}

// varint reads a QUIC variable-length integer (RFC 9000 section 16).
//
// The top two bits of the first byte give the encoded length: 1, 2, 4, or 8
// bytes, carrying a 6, 14, 30, or 62-bit value. It is a neat encoding, and it
// is also why a QUIC parser cannot skip fields it does not understand without
// decoding them first.
func (r *reader) varint() uint64 {
	first := r.u8()
	if !r.ok() {
		return 0
	}
	length := 1 << (first >> 6) // 00->1, 01->2, 10->4, 11->8
	v := uint64(first & 0x3f)
	for i := 1; i < length; i++ {
		b := r.u8()
		if !r.ok() {
			return 0
		}
		v = v<<8 | uint64(b)
	}
	return v
}

// appendVarint encodes v using the shortest form that fits. Used by the tests
// to build packets, and by the demo capture generator.
func appendVarint(dst []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(dst, byte(v))
	case v < 1<<14:
		return append(dst, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return append(dst, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(dst,
			byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}
