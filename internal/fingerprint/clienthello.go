// Package fingerprint derives passive TLS client fingerprints (JA4 and JA3)
// from raw ClientHello bytes.
//
// Why this matters: TLS encrypts the payload, not the handshake. The exact set
// and ordering of cipher suites, extensions, and signature algorithms a client
// offers is a property of its TLS *stack*, not its traffic — so it survives
// encryption, proxies, and domain fronting. In practice a JA4 hash identifies
// the application: Chrome looks different from curl, which looks different from
// the Go runtime, which looks different from a Cobalt Strike beacon. Detecting
// "a host on this network started speaking TLS with a stack no other host uses"
// is one of the highest-signal, lowest-noise things a passive sensor can do.
//
// The parser here is hand-written against the wire format rather than delegated
// to crypto/tls, because crypto/tls will only parse handshakes it is willing to
// negotiate — and the handshakes we most want to fingerprint are the weird ones.
package fingerprint

import (
	"errors"
)

// Errors returned by ParseClientHello.
var (
	// ErrIncomplete means the buffer holds a well-formed prefix but not the
	// whole ClientHello. Callers should buffer more bytes and retry; this is
	// the normal case for large post-quantum hellos, which routinely span two
	// TCP segments.
	ErrIncomplete = errors.New("fingerprint: incomplete ClientHello")
	// ErrNotClientHello means the bytes are not a TLS handshake at all.
	ErrNotClientHello = errors.New("fingerprint: not a TLS ClientHello")
	// ErrMalformed means the bytes claim to be a ClientHello but violate the
	// wire format (a length that overruns its container, usually).
	ErrMalformed = errors.New("fingerprint: malformed ClientHello")
)

// MaxClientHello bounds how many bytes we will buffer for one handshake.
// RFC 8446 caps a handshake message at 2^24-1, which is not a bound we want to
// honour for untrusted input; real hellos are under 4 KiB even with hybrid
// post-quantum key shares.
const MaxClientHello = 16384

// MaxServerName bounds the SNI copied out of a hello. RFC 6066 carries a DNS
// hostname there, and a DNS name cannot exceed 253 characters, so anything
// longer is not a name a client could resolve. Without this the peer chooses
// the length, up to MaxClientHello, of a string that reaches an alert title, a
// database row and a dashboard cell.
const MaxServerName = 253

// TLS record and handshake constants.
const (
	recordTypeHandshake  = 0x16
	handshakeClientHello = 0x01
	recordHeaderLen      = 5
)

// Extension type numbers we decode. Everything else is recorded by number only.
const (
	extServerName          uint16 = 0x0000
	extSupportedGroups     uint16 = 0x000a
	extECPointFormats      uint16 = 0x000b
	extSignatureAlgorithms uint16 = 0x000d
	extALPN                uint16 = 0x0010
	extSupportedVersions   uint16 = 0x002b
)

// ClientHello is the decoded subset of a TLS ClientHello needed to fingerprint
// the client.
//
// GREASE values (RFC 8701) are stripped from every list at parse time. Both JA3
// and JA4 exclude them by definition, and leaving them in would make a
// fingerprint unstable across connections from the same client — which is
// precisely what GREASE was designed to cause for anyone who ignores it.
type ClientHello struct {
	// LegacyVersion is the ClientHello.legacy_version field. Since TLS 1.3 this
	// is pinned to 0x0303 and the real version lives in supported_versions.
	LegacyVersion uint16

	CipherSuites        []uint16
	Extensions          []uint16 // in the order they appeared on the wire
	SupportedGroups     []uint16
	PointFormats        []uint8
	SignatureAlgorithms []uint16
	SupportedVersions   []uint16

	ALPN       []string
	ServerName string
	HasSNI     bool
}

// NegotiatedVersion returns the highest TLS version the client offered: the
// maximum of supported_versions when present, otherwise legacy_version.
func (ch *ClientHello) NegotiatedVersion() uint16 {
	best := uint16(0)
	for _, v := range ch.SupportedVersions {
		if v > best {
			best = v
		}
	}
	if best != 0 {
		return best
	}
	return ch.LegacyVersion
}

// isGREASE reports whether a 16-bit code point is one of the 16 reserved GREASE
// values from RFC 8701 (0x0a0a, 0x1a1a, ... 0xfafa). Clients inject these at
// random into cipher, extension, group, and version lists specifically to catch
// middleboxes that choke on unknown values.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0x00ff
}

// ParseClientHello decodes a ClientHello from the start of a TCP payload.
//
// buf must begin at a TLS record boundary. Handshake messages fragmented across
// multiple consecutive handshake records are reassembled, as are records split
// across TCP segments (signalled to the caller via ErrIncomplete).
func ParseClientHello(buf []byte) (*ClientHello, error) {
	body, err := collectHandshake(buf)
	if err != nil {
		return nil, err
	}
	return ParseHandshake(body)
}

// ParseHandshake decodes a bare TLS handshake message, with no record layer
// wrapped around it.
//
// QUIC needs this. It carries the TLS handshake in CRYPTO frames rather than
// TLS records, so by the time the frames are reassembled there is no 0x16
// record header to strip: the bytes begin directly at the ClientHello. Both
// entry points share everything below, which is what keeps a QUIC fingerprint
// and a TCP fingerprint of the same client comparable.
func ParseHandshake(body []byte) (*ClientHello, error) {
	hs := &cursor{b: body}
	if hs.u8() != handshakeClientHello {
		return nil, ErrNotClientHello
	}
	msgLen := int(hs.u24())
	if !hs.ok() {
		return nil, ErrIncomplete
	}
	if hs.remaining() < msgLen {
		return nil, ErrIncomplete
	}
	c := hs.sub(msgLen)

	ch := &ClientHello{}
	ch.LegacyVersion = c.u16()
	c.skip(32)          // random
	c.skip(int(c.u8())) // legacy_session_id
	ch.CipherSuites = readU16List(c.sub(int(c.u16())))
	c.skip(int(c.u8())) // legacy_compression_methods

	// Extensions are optional in the wire format (SSLv3-era hellos have none).
	if c.remaining() > 0 {
		exts := c.sub(int(c.u16()))
		for exts.remaining() >= 4 && exts.ok() {
			etype := exts.u16()
			elen := int(exts.u16())
			data := exts.sub(elen)
			if !exts.ok() {
				break
			}
			if !isGREASE(etype) {
				ch.Extensions = append(ch.Extensions, etype)
			}
			parseExtension(ch, etype, data)
		}
	}

	if !c.ok() {
		return nil, ErrMalformed
	}
	return ch, nil
}

// collectHandshake walks the TLS record layer and concatenates the payloads of
// consecutive handshake records, returning the handshake byte stream.
func collectHandshake(buf []byte) ([]byte, error) {
	if len(buf) < recordHeaderLen {
		return nil, ErrIncomplete
	}
	if buf[0] != recordTypeHandshake {
		return nil, ErrNotClientHello
	}
	// buf[1] is the record-layer major version; every TLS/SSL3 version uses 3.
	if buf[1] != 0x03 {
		return nil, ErrNotClientHello
	}

	var out []byte
	off := 0
	for off+recordHeaderLen <= len(buf) {
		if buf[off] != recordTypeHandshake {
			break // a different content type ends the handshake stream
		}
		n := int(buf[off+3])<<8 | int(buf[off+4])
		if n == 0 || n > MaxClientHello {
			return nil, ErrMalformed
		}
		end := off + recordHeaderLen + n
		if end > len(buf) {
			// The record is announced but not fully arrived.
			return nil, ErrIncomplete
		}
		out = append(out, buf[off+recordHeaderLen:end]...)
		off = end

		// One record is the overwhelmingly common case; stop as soon as the
		// handshake message it carries is complete.
		if complete, err := handshakeComplete(out); err != nil {
			return nil, err
		} else if complete {
			return out, nil
		}
	}
	if len(out) == 0 {
		return nil, ErrIncomplete
	}
	if complete, err := handshakeComplete(out); err != nil {
		return nil, err
	} else if !complete {
		return nil, ErrIncomplete
	}
	return out, nil
}

// handshakeComplete reports whether out holds a whole handshake message.
func handshakeComplete(out []byte) (bool, error) {
	if len(out) < 4 {
		return false, nil
	}
	n := int(out[1])<<16 | int(out[2])<<8 | int(out[3])
	if n > MaxClientHello {
		return false, ErrMalformed
	}
	return len(out) >= 4+n, nil
}

func parseExtension(ch *ClientHello, etype uint16, data *cursor) {
	switch etype {
	case extServerName:
		ch.HasSNI = true
		list := data.sub(int(data.u16()))
		for list.remaining() >= 3 && list.ok() {
			nameType := list.u8()
			name := list.bytes(int(list.u16()))
			// RFC 6066 says this is a DNS hostname, and a DNS name cannot
			// exceed 253 characters. Nothing else bounds it: the record can
			// carry MaxClientHello bytes, so without this a peer chooses the
			// length of a string that ends up in an alert title, a database
			// row and a dashboard cell. Truncating rather than rejecting
			// keeps the fingerprint, which cares only that an SNI was
			// present, not what it said.
			if nameType == 0 && ch.ServerName == "" {
				if len(name) > MaxServerName {
					name = name[:MaxServerName]
				}
				ch.ServerName = string(name)
			}
		}

	case extSupportedGroups:
		ch.SupportedGroups = readU16List(data.sub(int(data.u16())))

	case extECPointFormats:
		pf := data.sub(int(data.u8()))
		for pf.remaining() > 0 && pf.ok() {
			ch.PointFormats = append(ch.PointFormats, pf.u8())
		}

	case extSignatureAlgorithms:
		ch.SignatureAlgorithms = readU16List(data.sub(int(data.u16())))

	case extALPN:
		list := data.sub(int(data.u16()))
		for list.remaining() > 0 && list.ok() {
			p := list.bytes(int(list.u8()))
			if len(p) > 0 {
				ch.ALPN = append(ch.ALPN, string(p))
			}
		}

	case extSupportedVersions:
		vs := data.sub(int(data.u8()))
		for vs.remaining() >= 2 && vs.ok() {
			if v := vs.u16(); !isGREASE(v) {
				ch.SupportedVersions = append(ch.SupportedVersions, v)
			}
		}
	}
}

// readU16List drains a cursor as a list of big-endian uint16s, dropping GREASE.
func readU16List(c *cursor) []uint16 {
	out := make([]uint16, 0, c.remaining()/2)
	for c.remaining() >= 2 && c.ok() {
		if v := c.u16(); !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// cursor is a bounds-checked reader over a byte slice.
//
// Every read past the end sets err and returns zero rather than panicking, so
// the parser can be written in a straight line without an `if err != nil` after
// every field. Malformed input is then caught by one ok() check at the end.
// This is the pattern that keeps a binary parser both readable and safe against
// the hostile input a network parser is guaranteed to receive.
type cursor struct {
	b   []byte
	pos int
	bad bool
}

func (c *cursor) ok() bool       { return !c.bad }
func (c *cursor) remaining() int { return len(c.b) - c.pos }
func (c *cursor) fail()          { c.bad = true; c.pos = len(c.b) }

func (c *cursor) u8() uint8 {
	if c.remaining() < 1 {
		c.fail()
		return 0
	}
	v := c.b[c.pos]
	c.pos++
	return v
}

func (c *cursor) u16() uint16 {
	if c.remaining() < 2 {
		c.fail()
		return 0
	}
	v := uint16(c.b[c.pos])<<8 | uint16(c.b[c.pos+1])
	c.pos += 2
	return v
}

func (c *cursor) u24() uint32 {
	if c.remaining() < 3 {
		c.fail()
		return 0
	}
	v := uint32(c.b[c.pos])<<16 | uint32(c.b[c.pos+1])<<8 | uint32(c.b[c.pos+2])
	c.pos += 3
	return v
}

func (c *cursor) bytes(n int) []byte {
	if n < 0 || c.remaining() < n {
		c.fail()
		return nil
	}
	v := c.b[c.pos : c.pos+n]
	c.pos += n
	return v
}

func (c *cursor) skip(n int) { c.bytes(n) }

// sub returns a cursor over the next n bytes and advances the parent past them.
// A sub-cursor that overruns marks itself bad but not its parent, so one
// corrupt extension does not discard the rest of the hello.
func (c *cursor) sub(n int) *cursor {
	b := c.bytes(n)
	if b == nil {
		return &cursor{bad: true}
	}
	return &cursor{b: b}
}
