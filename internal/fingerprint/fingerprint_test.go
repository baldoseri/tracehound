package fingerprint

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/baldoseri/tracehound/internal/model"
)

// --- test helpers: build ClientHello bytes ---------------------------------

type helloSpec struct {
	legacyVersion     uint16
	ciphers           []uint16
	sni               string
	alpn              []string
	sigAlgs           []uint16
	groups            []uint16
	pointFormats      []uint8
	supportedVersions []uint16
	greaseExt         bool
}

type builder struct{ b []byte }

func (w *builder) u8(v uint8)   { w.b = append(w.b, v) }
func (w *builder) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *builder) raw(p []byte) { w.b = append(w.b, p...) }

// lenPrefixed appends f's output prefixed by its length in n bytes.
func (w *builder) lenPrefixed(n int, f func(*builder)) {
	var inner builder
	f(&inner)
	switch n {
	case 1:
		w.u8(uint8(len(inner.b)))
	case 2:
		w.u16(uint16(len(inner.b)))
	case 3:
		w.u8(uint8(len(inner.b) >> 16))
		w.u16(uint16(len(inner.b)))
	}
	w.raw(inner.b)
}

// buildHello renders a spec into a complete TLS record containing a ClientHello.
func buildHello(s helloSpec) []byte {
	var body builder
	body.u16(s.legacyVersion)
	body.raw(make([]byte, 32)) // random
	body.u8(0)                 // empty session id
	body.lenPrefixed(2, func(w *builder) {
		for _, c := range s.ciphers {
			w.u16(c)
		}
	})
	body.u8(1)
	body.u8(0) // compression: null

	body.lenPrefixed(2, func(exts *builder) {
		if s.sni != "" {
			exts.u16(extServerName)
			exts.lenPrefixed(2, func(e *builder) {
				e.lenPrefixed(2, func(list *builder) {
					list.u8(0) // host_name
					list.lenPrefixed(2, func(n *builder) { n.raw([]byte(s.sni)) })
				})
			})
		}
		if len(s.groups) > 0 {
			exts.u16(extSupportedGroups)
			exts.lenPrefixed(2, func(e *builder) {
				e.lenPrefixed(2, func(l *builder) {
					for _, g := range s.groups {
						l.u16(g)
					}
				})
			})
		}
		if len(s.pointFormats) > 0 {
			exts.u16(extECPointFormats)
			exts.lenPrefixed(2, func(e *builder) {
				e.lenPrefixed(1, func(l *builder) {
					for _, p := range s.pointFormats {
						l.u8(p)
					}
				})
			})
		}
		if len(s.sigAlgs) > 0 {
			exts.u16(extSignatureAlgorithms)
			exts.lenPrefixed(2, func(e *builder) {
				e.lenPrefixed(2, func(l *builder) {
					for _, a := range s.sigAlgs {
						l.u16(a)
					}
				})
			})
		}
		if len(s.alpn) > 0 {
			exts.u16(extALPN)
			exts.lenPrefixed(2, func(e *builder) {
				e.lenPrefixed(2, func(l *builder) {
					for _, p := range s.alpn {
						l.lenPrefixed(1, func(n *builder) { n.raw([]byte(p)) })
					}
				})
			})
		}
		if len(s.supportedVersions) > 0 {
			exts.u16(extSupportedVersions)
			exts.lenPrefixed(2, func(e *builder) {
				e.lenPrefixed(1, func(l *builder) {
					for _, v := range s.supportedVersions {
						l.u16(v)
					}
				})
			})
		}
		if s.greaseExt {
			exts.u16(0x1a1a) // GREASE extension, must be ignored entirely
			exts.u16(0)
		}
	})

	var hs builder
	hs.u8(handshakeClientHello)
	hs.lenPrefixed(3, func(w *builder) { w.raw(body.b) })

	var rec builder
	rec.u8(recordTypeHandshake)
	rec.u16(0x0301)
	rec.lenPrefixed(2, func(w *builder) { w.raw(hs.b) })
	return rec.b
}

// goldenSpec is a fully-specified hello whose fingerprint we assert exactly.
// It deliberately includes one GREASE cipher and one GREASE extension.
func goldenSpec() helloSpec {
	return helloSpec{
		legacyVersion:     0x0303,
		ciphers:           []uint16{0x0a0a, 0x1301, 0x1302, 0xc02b}, // 0x0a0a is GREASE
		sni:               "example.com",
		alpn:              []string{"h2", "http/1.1"},
		sigAlgs:           []uint16{0x0403, 0x0804, 0x0401},
		groups:            []uint16{0x001d, 0x0017},
		pointFormats:      []uint8{0x00},
		supportedVersions: []uint16{0x0304, 0x0303},
		greaseExt:         true,
	}
}

func trunc12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// --- parser tests ----------------------------------------------------------

func TestParseClientHelloFields(t *testing.T) {
	ch, err := ParseClientHello(buildHello(goldenSpec()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got, want := ch.ServerName, "example.com"; got != want {
		t.Errorf("ServerName = %q, want %q", got, want)
	}
	if !ch.HasSNI {
		t.Error("HasSNI = false, want true")
	}
	if got, want := strings.Join(ch.ALPN, ","), "h2,http/1.1"; got != want {
		t.Errorf("ALPN = %q, want %q", got, want)
	}
	if got, want := ch.NegotiatedVersion(), uint16(0x0304); got != want {
		t.Errorf("NegotiatedVersion = %#04x, want %#04x", got, want)
	}

	// GREASE must be gone from the cipher list...
	if got, want := len(ch.CipherSuites), 3; got != want {
		t.Errorf("len(CipherSuites) = %d, want %d (GREASE should be stripped)", got, want)
	}
	for _, c := range ch.CipherSuites {
		if isGREASE(c) {
			t.Errorf("GREASE cipher %#04x survived parsing", c)
		}
	}
	// ...and from the extension list.
	for _, e := range ch.Extensions {
		if isGREASE(e) {
			t.Errorf("GREASE extension %#04x survived parsing", e)
		}
	}
	if got, want := len(ch.Extensions), 6; got != want {
		t.Errorf("len(Extensions) = %d, want %d", got, want)
	}
}

// TestServerNameIsBounded covers the one field a peer can make arbitrarily long.
// The record may carry MaxClientHello bytes, so without a cap the sender chooses
// the length of a string that reaches an alert title, a database row and a
// dashboard cell.
func TestServerNameIsBounded(t *testing.T) {
	s := goldenSpec()
	s.sni = strings.Repeat("a", 4000) + ".example"

	ch, err := ParseClientHello(buildHello(s))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := len(ch.ServerName); got != MaxServerName {
		t.Errorf("len(ServerName) = %d, want it truncated to %d", got, MaxServerName)
	}
	// Truncation must not cost the fingerprint anything: JA4 records only that
	// an SNI was present, which is the "d" in the first field.
	if !ch.HasSNI {
		t.Error("HasSNI = false after truncation")
	}
	if got := JA4(ch, TransportTCP); got[3] != 'd' {
		t.Errorf("JA4 %q does not report SNI present after truncation", got)
	}
}

// TestServerNameOfLegalLengthIsUntouched guards the other side of the bound.
func TestServerNameOfLegalLengthIsUntouched(t *testing.T) {
	name := strings.Repeat("a", 60) + ".example.com"
	s := goldenSpec()
	s.sni = name

	ch, err := ParseClientHello(buildHello(s))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ch.ServerName != name {
		t.Errorf("ServerName = %q, want %q", ch.ServerName, name)
	}
}

func TestIsGREASE(t *testing.T) {
	// The 16 reserved values from RFC 8701, all of which must be recognised.
	for i := 0; i < 16; i++ {
		v := uint16(i)<<12 | 0x0a0a | uint16(i)<<4
		if !isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = false, want true", v)
		}
	}
	for _, v := range []uint16{0x0000, 0x1301, 0xc02b, 0x0a0b, 0x1a2a, 0xabab} {
		if isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = true, want false", v)
		}
	}
}

// --- fingerprint tests -----------------------------------------------------

func TestJA4Golden(t *testing.T) {
	ch, err := ParseClientHello(buildHello(goldenSpec()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Expected values are derived from the spec by hand rather than from the
	// implementation, so this test fails if the implementation drifts.
	//
	//   t  = TCP
	//   13 = highest supported_versions entry is 0x0304
	//   d  = SNI present
	//   03 = 3 non-GREASE cipher suites
	//   06 = 6 non-GREASE extensions (SNI and ALPN *are* counted here)
	//   h2 = first and last char of the first ALPN value
	const wantA = "t13d0306h2"
	// Ciphers sorted ascending, GREASE removed.
	wantB := trunc12("1301,1302,c02b")
	// Extensions sorted ascending with SNI (0000) and ALPN (0010) removed,
	// then signature algorithms in their original wire order.
	wantC := trunc12("000a,000b,000d,002b_0403,0804,0401")

	want := wantA + "_" + wantB + "_" + wantC
	if got := JA4(ch, TransportTCP); got != want {
		t.Errorf("JA4 mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestJA3Golden(t *testing.T) {
	ch, err := ParseClientHello(buildHello(goldenSpec()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	const wantRaw = "771,4865-4866-49195,0-10-11-13-16-43,29-23,0"
	got, raw := JA3(ch)
	if raw != wantRaw {
		t.Errorf("JA3 raw mismatch\n got: %s\nwant: %s", raw, wantRaw)
	}
	sum := md5.Sum([]byte(wantRaw))
	if want := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("JA3 = %s, want %s", got, want)
	}
}

// TestJA4Fields pins each field separately, so a golden-test failure points at
// which part of the fingerprint drifted instead of just "the string changed".
func TestJA4Fields(t *testing.T) {
	ch, err := ParseClientHello(buildHello(goldenSpec()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got, want := ja4B(ch), trunc12("1301,1302,c02b"); got != want {
		t.Errorf("ja4B = %s, want %s", got, want)
	}
	if got, want := ja4C(ch), trunc12("000a,000b,000d,002b_0403,0804,0401"); got != want {
		t.Errorf("ja4C = %s, want %s", got, want)
	}

	// The whole string must be exactly the three fields joined by underscores.
	if got, want := JA4(ch, TransportTCP), "t13d0306h2_"+ja4B(ch)+"_"+ja4C(ch); got != want {
		t.Errorf("JA4 = %s, want %s", got, want)
	}
}

// TestJA4EmptyLists checks the all-zero placeholders for a hello with no
// ciphers and no extensions, which is the degenerate case the spec calls out.
func TestJA4EmptyLists(t *testing.T) {
	ch := &ClientHello{LegacyVersion: 0x0303}
	if got := ja4B(ch); got != zeroHash {
		t.Errorf("ja4B with no ciphers = %s, want %s", got, zeroHash)
	}
	if got := ja4C(ch); got != zeroHash {
		t.Errorf("ja4C with no extensions = %s, want %s", got, zeroHash)
	}
	if got, want := JA4(ch, TransportTCP), "t12i0000"+"00"+"_"+zeroHash+"_"+zeroHash; got != want {
		t.Errorf("JA4 = %s, want %s", got, want)
	}
}

func TestJA4NoSNINoALPN(t *testing.T) {
	s := goldenSpec()
	s.sni = ""
	s.alpn = nil
	ch, err := ParseClientHello(buildHello(s))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// 'i' for no SNI, 3 ciphers, 4 remaining extensions, "00" for no ALPN.
	if got, want := JA4(ch, TransportTCP)[:10], "t13i030400"; got != want {
		t.Errorf("JA4_a = %q, want %q", got, want)
	}
}

func TestALPNCode(t *testing.T) {
	tests := []struct {
		alpn []string
		want string
	}{
		{nil, "00"},
		{[]string{"h2"}, "h2"},
		{[]string{"http/1.1"}, "h1"},
		{[]string{"h3", "h2"}, "h3"}, // only the first ALPN counts
		// Checked against FoxIO's reference implementation: a one-character
		// value stays one character rather than being doubled, and a
		// non-ASCII first byte becomes 99 rather than a hex rendering.
		{[]string{"a"}, "a"},
		{[]string{"\xc3\xa9"}, "99"},
		{[]string{"\xff"}, "99"},
		// Two ASCII bytes are used verbatim whatever they are.
		{[]string{"\x00\x0b"}, "\x00\x0b"},
		// Including the field delimiter. A client picks its own ALPN strings,
		// so this is reachable by anyone who wants it, and the reference
		// implementation passes it through too. See splitFingerprint.
		{[]string{"_"}, "_"},
		{[]string{"0_"}, "0_"},
		{[]string{"0abcdef_"}, "0_"}, // arrives via the first-and-last collapse
	}
	for _, tc := range tests {
		if got := alpnCode(tc.alpn); got != tc.want {
			t.Errorf("alpnCode(%q) = %q, want %q", tc.alpn, got, tc.want)
		}
	}
}

func TestTwoDigitSaturates(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want string
	}{{0, "00"}, {7, "07"}, {42, "42"}, {99, "99"}, {150, "99"}} {
		if got := twoDigit(tc.in); got != tc.want {
			t.Errorf("twoDigit(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --- real-client test ------------------------------------------------------

// realClientHello returns the bytes Go's own crypto/tls puts on the wire.
//
// Testing against a synthetic hello proves the parser matches our reading of
// the spec; testing against a real stack proves it matches reality, including
// whatever extensions the current Go release happens to send.
func realClientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// This handshake never completes — we read the ClientHello and hang up.
		_ = tls.Client(client, cfg).Handshake()
	}()

	if err := server.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, MaxClientHello)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("read ClientHello: %v", err)
	}
	return buf[:n]
}

func TestParseRealGoClientHello(t *testing.T) {
	raw := realClientHello(t, &tls.Config{
		ServerName: "example.com",
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	})

	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("parse real ClientHello (%d bytes): %v", len(raw), err)
	}

	if ch.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want %q", ch.ServerName, "example.com")
	}
	if len(ch.ALPN) == 0 || ch.ALPN[0] != "h2" {
		t.Errorf("ALPN = %v, want first element h2", ch.ALPN)
	}
	if len(ch.CipherSuites) == 0 {
		t.Error("no cipher suites parsed from a real ClientHello")
	}
	if len(ch.SignatureAlgorithms) == 0 {
		t.Error("no signature algorithms parsed from a real ClientHello")
	}

	ja4 := JA4(ch, TransportTCP)
	// Shape check: 10 chars, then two 12-char lowercase hex fields.
	shape := regexp.MustCompile(`^t(13|12|11|10)[di]\d{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)
	if !shape.MatchString(ja4) {
		t.Errorf("JA4 %q does not match expected shape", ja4)
	}
	// Go advertises TLS 1.3 by default, so the version field must say 13.
	if !strings.HasPrefix(ja4, "t13d") {
		t.Errorf("JA4 = %q, want prefix t13d (TLS 1.3 with SNI)", ja4)
	}
	t.Logf("Go %d-byte ClientHello -> JA4 %s", len(raw), ja4)
}

// TestFingerprintIsStable is the property that makes JA4 useful at all: the
// same client must produce the same fingerprint on every connection, and a
// different destination must not change it.
func TestFingerprintIsStable(t *testing.T) {
	fp := func(server string) string {
		raw := realClientHello(t, &tls.Config{
			ServerName: server,
			NextProtos: []string{"h2"},
			MinVersion: tls.VersionTLS12,
		})
		ch, err := ParseClientHello(raw)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return JA4(ch, TransportTCP)
	}

	a, b := fp("example.com"), fp("a-completely-different-host.example.net")
	if a != b {
		t.Errorf("JA4 changed with destination:\n %s\n %s", a, b)
	}
}

// --- reassembly tests ------------------------------------------------------

func testKey(t *testing.T) model.FlowKey {
	t.Helper()
	k, _ := model.NewFlowKey(
		netip.MustParseAddr("10.0.0.5"), 51234,
		netip.MustParseAddr("93.184.216.34"), 443,
		model.ProtoTCP,
	)
	return k
}

// TestReassemblerSplitAcrossSegments is the regression test for the bug this
// component exists to prevent: a ClientHello that arrives in two TCP segments
// must produce the same fingerprint as one that arrives whole.
func TestReassemblerSplitAcrossSegments(t *testing.T) {
	raw := buildHello(goldenSpec())
	key := testKey(t)

	whole := NewReassembler(0)
	want := whole.Feed(key, raw)
	if want == nil {
		t.Fatal("unsplit ClientHello produced no fingerprint")
	}

	for _, split := range []int{1, 5, 6, 20, len(raw) - 1} {
		r := NewReassembler(0)
		if got := r.Feed(key, raw[:split]); got != nil {
			t.Fatalf("split at %d: fingerprint emitted before the hello was complete", split)
		}
		if r.Pending() != 1 {
			t.Fatalf("split at %d: expected 1 pending handshake, got %d", split, r.Pending())
		}
		got := r.Feed(key, raw[split:])
		if got == nil {
			t.Fatalf("split at %d: no fingerprint after final segment", split)
		}
		if got.JA4 != want.JA4 {
			t.Errorf("split at %d: JA4 = %s, want %s", split, got.JA4, want.JA4)
		}
		if r.Pending() != 0 {
			t.Errorf("split at %d: reassembler leaked state (%d pending)", split, r.Pending())
		}
	}
}

func TestReassemblerIgnoresNonTLS(t *testing.T) {
	r := NewReassembler(0)
	key := testKey(t)

	for _, payload := range [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("SSH-2.0-OpenSSH_9.6\r\n"),
		{0x00, 0x00, 0x00, 0x01},
		{0x17, 0x03, 0x03, 0x00, 0x05}, // application data, not a handshake
	} {
		if got := r.Feed(key, payload); got != nil {
			t.Errorf("non-TLS payload produced a fingerprint: %x", payload)
		}
	}
	if r.Pending() != 0 {
		t.Errorf("non-TLS traffic left %d buffered flows; should allocate nothing", r.Pending())
	}
}

// TestReassemblerResistsByteSplitEvasion feeds a ClientHello one byte per
// segment.
//
// Splitting a handshake into minimal segments is a long-standing way to evade
// inline inspection: any sensor that insists on seeing a whole TLS record in a
// single packet silently stops fingerprinting the connection, which is exactly
// the outcome an implant wants. Reassembly has to survive the degenerate case,
// not just the common two-segment one.
func TestReassemblerResistsByteSplitEvasion(t *testing.T) {
	raw := buildHello(goldenSpec())
	key := testKey(t)

	ref := NewReassembler(0)
	want := ref.Feed(key, raw)
	if want == nil {
		t.Fatal("unsplit ClientHello produced no fingerprint")
	}

	r := NewReassembler(0)
	var got *Result
	for i := 0; i < len(raw); i++ {
		if res := r.Feed(key, raw[i:i+1]); res != nil {
			if got != nil {
				t.Fatalf("fingerprint emitted twice (second at byte %d)", i)
			}
			got = res
			if i != len(raw)-1 {
				t.Errorf("fingerprint emitted at byte %d, before the hello was complete", i)
			}
		}
	}
	if got == nil {
		t.Fatal("byte-at-a-time ClientHello never produced a fingerprint")
	}
	if got.JA4 != want.JA4 {
		t.Errorf("JA4 = %s, want %s", got.JA4, want.JA4)
	}
	if got.ServerName != want.ServerName {
		t.Errorf("ServerName = %q, want %q", got.ServerName, want.ServerName)
	}
	if r.Pending() != 0 {
		t.Errorf("reassembler leaked state after completion: %d pending", r.Pending())
	}
}

func TestReassemblerBoundsPending(t *testing.T) {
	const limit = 4
	r := NewReassembler(limit)
	partial := buildHello(goldenSpec())[:10]

	for i := 0; i < limit*4; i++ {
		k, _ := model.NewFlowKey(
			netip.MustParseAddr("10.0.0.5"), uint16(40000+i),
			netip.MustParseAddr("93.184.216.34"), 443,
			model.ProtoTCP,
		)
		r.Feed(k, partial)
	}
	if r.Pending() > limit {
		t.Errorf("pending = %d, want <= %d; the bound is what stops a half-open flood from eating memory", r.Pending(), limit)
	}
}

// --- robustness ------------------------------------------------------------

// TestParseMalformedNeverPanics feeds every prefix of a valid hello plus a set
// of hand-crafted corruptions. A network parser that panics is a remote DoS.
func TestParseMalformedNeverPanics(t *testing.T) {
	raw := buildHello(goldenSpec())

	for i := 0; i < len(raw); i++ {
		if _, err := ParseClientHello(raw[:i]); err == nil {
			t.Errorf("prefix of length %d parsed as a complete hello", i)
		}
	}

	corruptions := [][]byte{
		nil,
		{},
		{0x16},
		{0x16, 0x03},
		{0x16, 0x03, 0x01, 0xff, 0xff},
		{0x16, 0x03, 0x01, 0x00, 0x00},
		{0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5},
		{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0xff, 0xff, 0xff},
	}
	for _, c := range corruptions {
		_, _ = ParseClientHello(c) // must not panic
	}

	// Length fields that overrun their container, injected at every offset.
	for i := 0; i < len(raw); i++ {
		mutated := append([]byte(nil), raw...)
		mutated[i] = 0xff
		if ch, err := ParseClientHello(mutated); err == nil && ch != nil {
			_ = JA4(ch, TransportTCP) // fingerprinting must also survive
			_, _ = JA3(ch)
		}
	}
}

// FuzzParseClientHello proves the parser terminates without panicking on
// arbitrary input. Run with:
//
//	go test -fuzz=FuzzParseClientHello ./internal/fingerprint
//
// splitFingerprint separates a JA4 or JA4S into its three fields, scanning from
// the right because that is the only way that always works. The ALPN is copied
// from the wire into the first field, so a client offering "_" as a protocol
// name, or any name whose first and last bytes collapse to include one, puts a
// delimiter inside field a. FoxIO's reference implementation does not filter
// that and neither does this package, on the grounds that a fingerprint which
// disagrees with other tooling is worse than an awkward one. Splitting from the
// left would mis-parse those; splitting from the right cannot, because the two
// trailing fields are fixed-width hex.
//
// Nothing in tracehound outside these tests parses a fingerprint. It is a map
// key and a stored string, which is why this lives in the test file: it exists
// to state the invariant, not to be called in anger.
func splitFingerprint(fp string) (a, b, c string, ok bool) {
	i := strings.LastIndexByte(fp, '_')
	if i < 0 {
		return "", "", "", false
	}
	j := strings.LastIndexByte(fp[:i], '_')
	if j < 0 {
		return "", "", "", false
	}
	return fp[:j], fp[j+1 : i], fp[i+1:], true
}

// TestFingerprintSurvivesDelimiterInALPN pins the behaviour the fuzzer found:
// a hostile ALPN puts a literal underscore in field a, and the fingerprint is
// still recoverable as long as it is parsed from the right.
func TestFingerprintSurvivesDelimiterInALPN(t *testing.T) {
	for _, alpn := range []string{"_", "0_", "0abcdef_", "__"} {
		s := goldenSpec()
		s.alpn = []string{alpn}
		ch, err := ParseClientHello(buildHello(s))
		if err != nil {
			t.Fatalf("ALPN %q: %v", alpn, err)
		}
		ja4 := JA4(ch, TransportTCP)
		a, b, c, ok := splitFingerprint(ja4)
		if !ok {
			t.Fatalf("ALPN %q: JA4 %q has fewer than three fields", alpn, ja4)
		}
		if !strings.Contains(a, "_") {
			t.Errorf("ALPN %q: expected a delimiter inside field a, got %q", alpn, a)
		}
		if len(b) != 12 || len(c) != 12 {
			t.Errorf("ALPN %q: JA4 %q hashes are %d and %d characters", alpn, ja4, len(b), len(c))
		}
	}
}

func FuzzParseClientHello(f *testing.F) {
	f.Add(buildHello(goldenSpec()))
	s := goldenSpec()
	s.sni, s.alpn = "", nil
	f.Add(buildHello(s))
	// The input that caught the delimiter case, kept so it stays covered.
	d := goldenSpec()
	d.alpn = []string{"0_"}
	f.Add(buildHello(d))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	f.Add([]byte("not tls at all"))

	f.Fuzz(func(t *testing.T, data []byte) {
		ch, err := ParseClientHello(data)
		if err != nil {
			return
		}
		if ch == nil {
			t.Fatal("nil ClientHello with nil error")
		}
		// Whatever came back must be safe to fingerprint. The width is checked
		// structurally rather than as a fixed number, because a
		// one-character ALPN legitimately makes the first field one shorter.
		ja4 := JA4(ch, TransportTCP)
		a, b, c, ok := splitFingerprint(ja4)
		if !ok {
			t.Fatalf("JA4 %q does not have three fields", ja4)
		}
		if len(a) < 9 || len(a) > 10 {
			t.Fatalf("JA4 %q: first field is %d characters", ja4, len(a))
		}
		if len(b) != 12 || len(c) != 12 {
			t.Fatalf("JA4 %q: hash fields are %d and %d characters", ja4, len(b), len(c))
		}
		_, _ = JA3(ch)
	})
}

// --- benchmarks ------------------------------------------------------------

func BenchmarkParseAndFingerprint(b *testing.B) {
	raw := buildHello(goldenSpec())
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch, err := ParseClientHello(raw)
		if err != nil {
			b.Fatal(err)
		}
		_ = JA4(ch, TransportTCP)
	}
}

func BenchmarkReassemblerRejectsNonTLS(b *testing.B) {
	r := NewReassembler(0)
	k, _ := model.NewFlowKey(
		netip.MustParseAddr("10.0.0.5"), 1234,
		netip.MustParseAddr("10.0.0.6"), 80,
		model.ProtoTCP,
	)
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Feed(k, payload)
	}
}
