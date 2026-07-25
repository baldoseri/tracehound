package fingerprint

import (
	"bytes"
	"errors"
)

// ErrNotServerHello means the handshake bytes are not a ServerHello.
var ErrNotServerHello = errors.New("fingerprint: not a TLS ServerHello")

const handshakeServerHello = 0x02

// helloRetryRequest is the fixed Random value that marks a ServerHello as a
// HelloRetryRequest (RFC 8446 section 4.1.3).
//
// A HelloRetryRequest is a ServerHello on the wire but not a server's real
// answer: it asks the client to try again with a different key share, and the
// genuine ServerHello follows. Fingerprinting the retry would produce a
// near-identical hash for every server that ever asks for one, which is noise
// rather than identity.
var helloRetryRequest = [32]byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02,
	0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// ServerHello is the decoded subset of a TLS ServerHello needed to fingerprint
// the server.
//
// It is much smaller than a ClientHello because a server states decisions
// rather than offers. One cipher suite instead of a list, one ALPN instead of a
// preference order. That makes the fingerprint narrower than JA4 but also
// harder to vary: a server cannot randomise its way out of it the way a browser
// shuffles its extension order.
type ServerHello struct {
	// LegacyVersion is the ServerHello.legacy_version field, pinned to 0x0303
	// since TLS 1.3 moved the real version into supported_versions.
	LegacyVersion uint16
	// CipherSuite is the single suite the server selected.
	CipherSuite uint16
	// Extensions are recorded in wire order, GREASE removed. Unlike a client,
	// a server's ordering is a stable property of its implementation.
	Extensions []uint16
	// SupportedVersion is the version echoed in the supported_versions
	// extension, zero when absent.
	SupportedVersion uint16
	// ALPN is the single protocol the server chose, empty when it chose none.
	ALPN string
}

// NegotiatedVersion returns the version the server actually selected.
func (sh *ServerHello) NegotiatedVersion() uint16 {
	if sh.SupportedVersion != 0 {
		return sh.SupportedVersion
	}
	return sh.LegacyVersion
}

// ParseServerHello decodes a ServerHello from the start of a TCP payload.
func ParseServerHello(buf []byte) (*ServerHello, error) {
	body, err := collectHandshake(buf)
	if err != nil {
		return nil, err
	}
	return ParseServerHandshake(body)
}

// ParseServerHandshake decodes a bare ServerHello handshake message, with no
// record layer around it, which is how QUIC carries it.
func ParseServerHandshake(body []byte) (*ServerHello, error) {
	hs := &cursor{b: body}
	if hs.u8() != handshakeServerHello {
		return nil, ErrNotServerHello
	}
	msgLen := int(hs.u24())
	if !hs.ok() {
		return nil, ErrIncomplete
	}
	if hs.remaining() < msgLen {
		return nil, ErrIncomplete
	}
	c := hs.sub(msgLen)

	sh := &ServerHello{}
	sh.LegacyVersion = c.u16()

	random := c.bytes(32)
	if !c.ok() {
		return nil, ErrIncomplete
	}
	if bytes.Equal(random, helloRetryRequest[:]) {
		// Not the server's real answer; the genuine ServerHello follows.
		return nil, ErrNotServerHello
	}

	c.skip(int(c.u8())) // legacy_session_id_echo
	sh.CipherSuite = c.u16()
	c.skip(1) // legacy_compression_method

	if c.remaining() > 0 {
		exts := c.sub(int(c.u16()))
		for exts.remaining() >= 4 && exts.ok() {
			etype := exts.u16()
			elen := int(exts.u16())
			data := exts.sub(elen)
			if !exts.ok() {
				break
			}
			// GREASE is kept, unlike in a ClientHello. This is the one place
			// the two algorithms genuinely disagree: FoxIO's reference strips
			// GREASE from JA4 and leaves it in JA4S. It is not obviously
			// principled, but a fingerprint exists to be compared against other
			// tools, so matching the reference beats being tidy.
			sh.Extensions = append(sh.Extensions, etype)
			if !isGREASE(etype) {
				parseServerExtension(sh, etype, data)
			}
		}
	}

	if !c.ok() {
		return nil, ErrMalformed
	}
	return sh, nil
}

func parseServerExtension(sh *ServerHello, etype uint16, data *cursor) {
	switch etype {
	case extSupportedVersions:
		// A server echoes exactly one version here, not a list.
		if v := data.u16(); data.ok() && !isGREASE(v) {
			sh.SupportedVersion = v
		}

	case extALPN:
		list := data.sub(int(data.u16()))
		if p := list.bytes(int(list.u8())); list.ok() && len(p) > 0 {
			sh.ALPN = string(p)
		}
	}
}
