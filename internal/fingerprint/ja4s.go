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
// Note on provenance: unlike JA4, which this package validates against a real
// ClientHello produced by crypto/tls and against hand-computed vectors, JA4S
// here is implemented from the specification without a third-party fingerprint
// to cross-check against. The structure and the inputs are tested; agreement
// with other JA4S implementations is not independently verified.
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

// ja4sLen is the exact width of a JA4S string: 7 + 1 + 4 + 1 + 12.
const ja4sLen = 25

// alpnList adapts a single chosen protocol to the slice form appendALPNCode
// expects, so client and server ALPN encoding cannot drift apart.
func alpnList(alpn string) []string {
	if alpn == "" {
		return nil
	}
	return []string{alpn}
}
