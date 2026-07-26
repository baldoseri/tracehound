package fingerprint

// JA4S computes the JA4S server fingerprint from a ServerHello.
//
// The output has three underscore-separated parts:
//
//	t130200_1301_234ea6891581
//	^^^^^^^ ^^^^ ^^^^^^^^^^^^
//	   a     b        c
//
//	a: transport, TLS version, extension count, chosen ALPN
//	b: the selected cipher suite, in hex
//	c: truncated SHA-256 of the extension list, in wire order
//
// Two differences from JA4 fall out of what a ServerHello is. The cipher suite
// is not hashed, because a server picks exactly one and printing it plainly is
// strictly more useful than hashing a single value. And the extension list is
// not sorted, because a server has no reason to shuffle it: the ordering is a
// stable property of the implementation and throwing it away would discard
// signal that browsers force JA4 to give up.
//
// Paired with a JA4 this is considerably stronger than either alone. A client
// fingerprint says what software connected; adding the server's says what it
// connected to, and a matching pair across several victims identifies a
// command-and-control framework rather than a single odd host.
//
// A third difference is harder to justify but has to be honoured: GREASE is
// retained here, in both the extension count and the hash, while JA4 strips it.
// That asymmetry is real in FoxIO's reference implementation, which routes JA4S
// through a formatting helper and JA4 through one that filters GREASE first.
//
// Note on provenance, and it is weaker than the one for JA4. This was checked
// line by line against that reference rather than against the prose
// specification, which is not public in the detail needed to settle GREASE
// handling, and no ServerHello has been run through both implementations and
// diffed. Conformance here is established by reading.
//
// JA4 no longer relies on that: TestJA4AgainstFoxIOVectors runs real hellos
// from FoxIO's own capture and requires the fingerprints FoxIO's implementation
// produces. The same is not yet possible for JA4S, because FoxIO publish
// expected JA4S values only as part of JA4+, which carries a different and
// non-commercial licence. See testdata/foxio_ja4_vectors.txt.
func JA4S(sh *ServerHello, transport Transport) string {
	out := make([]byte, 0, ja4sLen)

	out = append(out, byte(transport))
	out = append(out, tlsVersionCode(sh.NegotiatedVersion())...)
	out = appendTwoDigit(out, len(sh.Extensions))
	out = appendALPNCode(out, alpnList(sh.ALPN))

	out = append(out, '_')
	out = appendHexList(out, []uint16{sh.CipherSuite})

	out = append(out, '_')
	if len(sh.Extensions) == 0 {
		out = append(out, zeroHash...)
	} else {
		// Reuse one buffer for the hash input; it never escapes.
		scratch := make([]byte, 0, len(sh.Extensions)*5)
		out = appendTruncHash(out, appendHexList(scratch, sh.Extensions))
	}
	return string(out)
}

// ja4sLen is a capacity hint, not a guarantee: 7 + 1 + 4 + 1 + 12 for the usual
// two-character ALPN, one shorter when the server picks a one-byte protocol.
const ja4sLen = 25

// alpnList adapts a single chosen protocol to the slice form appendALPNCode
// expects, so client and server ALPN encoding cannot drift apart.
func alpnList(alpn string) []string {
	if alpn == "" {
		return nil
	}
	return []string{alpn}
}
