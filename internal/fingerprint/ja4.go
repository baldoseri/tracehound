package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
)

// Transport identifies the protocol carrying the handshake, which is the first
// character of a JA4 fingerprint.
type Transport byte

const (
	TransportTCP  Transport = 't'
	TransportQUIC Transport = 'q'
	TransportDTLS Transport = 'd'
)

// ja4TruncLen is the number of hex characters retained from each SHA-256 digest
// in the JA4_b and JA4_c fields.
const ja4TruncLen = 12

// zeroHash is the placeholder used when the list being hashed is empty.
const zeroHash = "000000000000"

// JA4 computes the JA4 TLS client fingerprint as specified by FoxIO.
//
// The output has three underscore-separated parts:
//
//	t13d1516h2_8daaf6152771_e5627efa2ab1
//	^^^^^^^^^^ ^^^^^^^^^^^^ ^^^^^^^^^^^^
//	    a            b            c
//
//	a: transport, TLS version, SNI present, cipher count, extension count, ALPN
//	b: truncated SHA-256 of the sorted cipher suite list
//	c: truncated SHA-256 of the sorted extension list plus the signature
//	   algorithms in their original order
//
// The design is deliberately part-human-readable: JA4_a alone tells an analyst
// "TLS 1.3, has SNI, 15 ciphers, 16 extensions, ALPN h2" without a lookup
// table, and the sorting in JA4_b/c makes the hash stable against clients that
// shuffle their cipher and extension order between connections — the specific
// weakness that made JA3 progressively less useful as browsers randomised.
// JA4 is on the per-flow path rather than the per-packet path, but it is still
// written to allocate a handful of times rather than once per cipher suite:
// the whole fingerprint is assembled into one buffer, and the two digests are
// computed over a reusable scratch slice.
func JA4(ch *ClientHello, transport Transport) string {
	out := make([]byte, 0, ja4Len)
	out = appendJA4A(out, ch, transport)

	// One scratch buffer, reused for both hash inputs. Sized for a typical
	// hello (roughly 20 ciphers plus 20 extensions plus 10 sig algs at five
	// bytes each) so it rarely grows.
	scratch := make([]byte, 0, 256)

	out = append(out, '_')
	out = appendTruncHash(out, ja4CipherList(scratch, ch))

	out = append(out, '_')
	out = appendTruncHash(out, ja4ExtensionList(scratch, ch))

	return string(out)
}

// ja4Len is the exact width of a JA4 string: 10 + 1 + 12 + 1 + 12.
const ja4Len = 36

// appendJA4A writes the 10-character human-readable prefix.
func appendJA4A(dst []byte, ch *ClientHello, transport Transport) []byte {
	dst = append(dst, byte(transport))
	dst = append(dst, tlsVersionCode(ch.NegotiatedVersion())...)

	// 'd' for domain (SNI present), 'i' for IP (no SNI). A client connecting by
	// bare IP with no SNI is unusual for a browser and routine for an implant.
	if ch.HasSNI {
		dst = append(dst, 'd')
	} else {
		dst = append(dst, 'i')
	}

	dst = appendTwoDigit(dst, len(ch.CipherSuites))
	// The extension count includes SNI and ALPN even though JA4_c excludes them
	// from its hash. This is intentional in the spec: the count stays sensitive
	// to their presence while the hash stays stable across destinations.
	dst = appendTwoDigit(dst, len(ch.Extensions))
	dst = appendALPNCode(dst, ch.ALPN)

	return dst
}

// ja4CipherList renders the sorted cipher suite list, or nil when empty.
func ja4CipherList(dst []byte, ch *ClientHello) []byte {
	if len(ch.CipherSuites) == 0 {
		return nil
	}
	sorted := slices.Clone(ch.CipherSuites)
	slices.Sort(sorted)
	return appendHexList(dst[:0], sorted)
}

// ja4B hashes the sorted cipher suite list. Retained as a named step for
// readability and for direct testing.
func ja4B(ch *ClientHello) string {
	return string(appendTruncHash(nil, ja4CipherList(nil, ch)))
}

// ja4C hashes the sorted extension list joined with the unsorted signature
// algorithm list.
//
// Signature algorithms are deliberately NOT sorted: their order is a stable
// property of the client's stack that survives the extension shuffling modern
// browsers perform, so it carries real discriminating power.
func ja4ExtensionList(dst []byte, ch *ClientHello) []byte {
	exts := make([]uint16, 0, len(ch.Extensions))
	for _, e := range ch.Extensions {
		// SNI and ALPN vary with the destination, not the client, so excluding
		// them makes one client produce one fingerprint across every site it
		// visits rather than a new one per hostname.
		if e == extServerName || e == extALPN {
			continue
		}
		exts = append(exts, e)
	}
	if len(exts) == 0 {
		return nil
	}
	slices.Sort(exts)

	out := appendHexList(dst[:0], exts)
	if len(ch.SignatureAlgorithms) > 0 {
		out = append(out, '_')
		out = appendHexList(out, ch.SignatureAlgorithms)
	}
	return out
}

// ja4C hashes the sorted extension list joined with the unsorted signature
// algorithm list. Retained as a named step for readability and direct testing.
func ja4C(ch *ClientHello) string {
	return string(appendTruncHash(nil, ja4ExtensionList(nil, ch)))
}

// tlsVersionCode maps a protocol version to its two-character JA4 code.
func tlsVersionCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	default:
		return "00"
	}
}

// appendTwoDigit writes a count as exactly two digits, saturating at 99 as the
// spec requires (a hello with 150 ciphers reports 99, not 150 or "50").
func appendTwoDigit(dst []byte, n int) []byte {
	if n > 99 {
		n = 99
	}
	if n < 0 {
		n = 0
	}
	return append(dst, byte('0'+n/10), byte('0'+n%10))
}

func twoDigit(n int) string { return string(appendTwoDigit(nil, n)) }

// appendALPNCode writes the ALPN field. Shared by JA4 and JA4S, because
// FoxIO's reference implementation encodes both identically.
//
//	none        -> "00"
//	"h2"        -> "h2"   (one or two bytes are used verbatim)
//	"a"         -> "a"    (one byte stays one byte, so this field is not
//	                       always two characters wide)
//	"http/1.1"  -> "h1"   (longer values collapse to first and last)
//	non-ASCII   -> "99"
//
// Both the single-character and the non-ASCII case were wrong here until this
// was checked against the reference: it used to double a one-character value
// and hex-encode anything non-alphanumeric. Neither matches, and a fingerprint
// that disagrees with every other tool is worse than useless, since being
// comparable is the only reason to compute one.
func appendALPNCode(dst []byte, alpn []string) []byte {
	if len(alpn) == 0 || len(alpn[0]) == 0 {
		return append(dst, '0', '0')
	}
	v := alpn[0]

	// Tested before truncating, which is equivalent to the reference: it
	// collapses to first-and-last and then checks that same first byte.
	if v[0] > 0x7f {
		return append(dst, '9', '9')
	}
	if len(v) > 2 {
		return append(dst, v[0], v[len(v)-1])
	}
	return append(dst, v...)
}

func alpnCode(alpn []string) string { return string(appendALPNCode(nil, alpn)) }

const hexDigits = "0123456789abcdef"

// appendHexList renders a uint16 list as comma-separated lowercase 4-digit hex.
//
// Written by hand rather than with fmt.Sprintf("%04x"): Sprintf allocates a
// string per value, which for a 20-cipher hello meant 20 allocations to build
// one hash input. Formatting the nibbles directly makes the whole list a single
// append into a caller-supplied buffer.
func appendHexList(dst []byte, vs []uint16) []byte {
	for i, v := range vs {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst,
			hexDigits[v>>12&0x0f],
			hexDigits[v>>8&0x0f],
			hexDigits[v>>4&0x0f],
			hexDigits[v&0x0f],
		)
	}
	return dst
}

// appendTruncHash writes the first ja4TruncLen hex characters of the SHA-256
// digest of in, or the all-zero placeholder when in is empty.
//
// Only the first ja4TruncLen/2 digest bytes are hex-encoded, rather than
// encoding all 32 and slicing, which halves the work and avoids a 64-byte
// throwaway string.
func appendTruncHash(dst []byte, in []byte) []byte {
	if len(in) == 0 {
		return append(dst, zeroHash...)
	}
	sum := sha256.Sum256(in)
	var enc [ja4TruncLen]byte
	hex.Encode(enc[:], sum[:ja4TruncLen/2])
	return append(dst, enc[:]...)
}
