package quic

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"github.com/baldoseri/tracehound/internal/fingerprint"
	"github.com/baldoseri/tracehound/internal/model"
)

// --- key schedule -----------------------------------------------------------

// TestInitialKeySchedule checks the derivation against the worked example in
// RFC 9001 Appendix A.1.
//
// These expectations come from the specification, not from this implementation,
// which is the entire point: a key schedule that only agrees with itself proves
// nothing. If this fails, the implementation is wrong.
func TestInitialKeySchedule(t *testing.T) {
	dcid, err := hex.DecodeString("8394c8f03e515708")
	if err != nil {
		t.Fatal(err)
	}

	const (
		wantInitialSecret = "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"
		wantClientSecret  = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
		wantKey           = "1f369613dd76d5467730efcbe3b1a22d"
		wantIV            = "fa044b2f42a3fd3b46fb255c"
		wantHP            = "9f50449e04a0e810283a1e9933adedd2"
	)

	if got := hex.EncodeToString(hkdfExtract(initialSaltV1, dcid)); got != wantInitialSecret {
		t.Errorf("initial_secret\n got: %s\nwant: %s", got, wantInitialSecret)
	}

	k, err := deriveClientInitialKeys(Version1, dcid)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	for _, tc := range []struct{ name, got, want string }{
		{"client_initial_secret", hex.EncodeToString(k.secret), wantClientSecret},
		{"key", hex.EncodeToString(k.key), wantKey},
		{"iv", hex.EncodeToString(k.iv), wantIV},
		{"hp", hex.EncodeToString(k.hp), wantHP},
	} {
		if tc.got != tc.want {
			t.Errorf("%s\n got: %s\nwant: %s", tc.name, tc.got, tc.want)
		}
	}
}

func TestUnsupportedVersionIsRejected(t *testing.T) {
	// Draft versions and QUIC v2 use different salts, so deriving v1 keys for
	// them would silently produce wrong keys rather than an honest failure.
	if _, err := deriveClientInitialKeys(0x6b3343cf, []byte{1, 2, 3, 4}); err == nil {
		t.Error("a non-v1 version was accepted")
	}
}

// --- varints ----------------------------------------------------------------

func TestVarintRoundTrip(t *testing.T) {
	for _, v := range []uint64{
		0, 1, 37, 63, // 1-byte form
		64, 1000, 16383, // 2-byte
		16384, 494878333, 1073741823, // 4-byte
		1073741824, 151288809941952652, // 8-byte
	} {
		enc := appendVarint(nil, v)
		r := &reader{b: enc}
		got := r.varint()
		if !r.ok() {
			t.Errorf("varint(%d): decode failed", v)
			continue
		}
		if got != v {
			t.Errorf("varint round trip: %d -> %x -> %d", v, enc, got)
		}
		if r.remaining() != 0 {
			t.Errorf("varint(%d): %d bytes left over", v, r.remaining())
		}
	}
}

func TestVarintEncodingLengths(t *testing.T) {
	for _, tc := range []struct {
		v    uint64
		want int
	}{{63, 1}, {64, 2}, {16383, 2}, {16384, 4}, {1073741823, 4}, {1073741824, 8}} {
		if got := len(appendVarint(nil, tc.v)); got != tc.want {
			t.Errorf("appendVarint(%d) used %d bytes, want %d", tc.v, got, tc.want)
		}
	}
}

// --- building a real Initial packet ----------------------------------------

// clientHelloBody builds a bare TLS ClientHello handshake message, with no
// record layer, which is how QUIC carries it.
func clientHelloBody(sni string, pad int) []byte {
	u16 := func(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }

	var body []byte
	body = u16(body, 0x0303)                 // legacy_version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // empty session id

	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0xc02b}
	body = u16(body, uint16(len(ciphers)*2))
	for _, c := range ciphers {
		body = u16(body, c)
	}
	body = append(body, 1, 0) // compression: null

	var exts []byte
	// server_name
	exts = u16(exts, 0x0000)
	name := append([]byte{0}, append(binary.BigEndian.AppendUint16(nil, uint16(len(sni))), sni...)...)
	exts = u16(exts, uint16(len(name)+2))
	exts = u16(exts, uint16(len(name)))
	exts = append(exts, name...)
	// ALPN advertising h3, which is what makes this QUIC rather than TCP TLS
	alpn := []byte{2, 'h', '3'}
	exts = u16(exts, 0x0010)
	exts = u16(exts, uint16(len(alpn)+2))
	exts = u16(exts, uint16(len(alpn)))
	exts = append(exts, alpn...)
	// supported_versions: TLS 1.3
	exts = u16(exts, 0x002b)
	exts = u16(exts, 3)
	exts = append(exts, 2)
	exts = u16(exts, 0x0304)
	// signature_algorithms
	exts = u16(exts, 0x000d)
	exts = u16(exts, 6)
	exts = u16(exts, 4)
	exts = u16(exts, 0x0403)
	exts = u16(exts, 0x0804)
	// padding, to make the hello large enough to span packets when asked
	if pad > 0 {
		exts = u16(exts, 0x0015)
		exts = u16(exts, uint16(pad))
		exts = append(exts, make([]byte, pad)...)
	}

	body = u16(body, uint16(len(exts)))
	body = append(body, exts...)

	msg := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(msg, body...)
}

// sealInitial wraps the exported builder so the round-trip tests exercise the
// same code the capture generator uses, rather than a parallel implementation
// that could drift away from it.
func sealInitial(t *testing.T, dcid, scid []byte, cryptoOffset uint64, crypto []byte, datagramSize int) []byte {
	t.Helper()
	pkt, err := BuildClientInitial(dcid, scid, cryptoOffset, crypto, datagramSize)
	if err != nil {
		t.Fatalf("build Initial: %v", err)
	}
	return pkt
}

// --- parsing ----------------------------------------------------------------

func TestParseInitialRecoversClientHello(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{1, 2, 3, 4}
	hello := clientHelloBody("example.com", 0)

	datagram := sealInitial(t, dcid, scid, 0, hello, 1250)
	if len(datagram) < 1200 {
		t.Fatalf("built datagram is %d bytes; a client Initial must be padded to 1200", len(datagram))
	}

	pkt, err := ParseInitial(datagram)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pkt.Version != Version1 {
		t.Errorf("version = %#08x", pkt.Version)
	}
	if !bytes.Equal(pkt.DCID, dcid) {
		t.Errorf("DCID = %x, want %x", pkt.DCID, dcid)
	}
	if !bytes.Equal(pkt.SCID, scid) {
		t.Errorf("SCID = %x, want %x", pkt.SCID, scid)
	}
	if len(pkt.Frames) != 1 {
		t.Fatalf("got %d CRYPTO frames, want 1", len(pkt.Frames))
	}
	if !bytes.Equal(pkt.Frames[0].Data, hello) {
		t.Error("recovered CRYPTO payload does not match what was sealed")
	}
}

func TestJA4OverQUICUsesQuicTransport(t *testing.T) {
	dcid := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	datagram := sealInitial(t, dcid, []byte{1, 1, 1, 1}, 0, clientHelloBody("example.com", 0), 1250)

	r := NewReassembler(0)
	res := r.Feed(testKey(), datagram)
	if res == nil {
		t.Fatal("no fingerprint produced from a valid Initial")
	}

	// The leading character is the whole reason JA4 encodes transport: a
	// fingerprint taken over QUIC must never be silently compared against one
	// taken over TCP.
	if !strings.HasPrefix(res.JA4, "q") {
		t.Errorf("JA4 = %q, want it to start with q", res.JA4)
	}
	if res.ServerName != "example.com" {
		t.Errorf("ServerName = %q", res.ServerName)
	}
	if res.ALPN != "h3" {
		t.Errorf("ALPN = %q, want h3", res.ALPN)
	}
	if r.Pending() != 0 {
		t.Errorf("reassembler leaked state: %d pending", r.Pending())
	}

	// The same hello over TCP must differ only in that first character.
	ch, err := fingerprint.ParseHandshake(clientHelloBody("example.com", 0))
	if err != nil {
		t.Fatal(err)
	}
	overTCP := fingerprint.JA4(ch, fingerprint.TransportTCP)
	if res.JA4[1:] != overTCP[1:] {
		t.Errorf("QUIC and TCP fingerprints of one client differ beyond the transport byte:\n  quic %s\n  tcp  %s", res.JA4, overTCP)
	}
}

// TestReassemblyAcrossDatagrams is the QUIC counterpart of the TCP
// segment-splitting test. A ClientHello offering a post-quantum key share
// exceeds the 1200-byte Initial and is split, so handling only the
// single-packet case would go blind on exactly the modern clients worth seeing.
func TestReassemblyAcrossDatagrams(t *testing.T) {
	dcid := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	hello := clientHelloBody("split.example.com", 1400) // deliberately oversized
	if len(hello) < 1300 {
		t.Fatalf("test hello is only %d bytes; it needs to span packets", len(hello))
	}

	half := len(hello) / 2
	first := sealInitial(t, dcid, []byte{1, 2, 3, 4}, 0, hello[:half], 1250)
	second := sealInitial(t, dcid, []byte{1, 2, 3, 4}, uint64(half), hello[half:], 1250)

	r := NewReassembler(0)
	key := testKey()

	if res := r.Feed(key, first); res != nil {
		t.Fatal("fingerprint emitted before the ClientHello was complete")
	}
	if r.Pending() != 1 {
		t.Fatalf("pending = %d, want 1", r.Pending())
	}
	res := r.Feed(key, second)
	if res == nil {
		t.Fatal("no fingerprint after the second datagram")
	}
	if res.ServerName != "split.example.com" {
		t.Errorf("ServerName = %q", res.ServerName)
	}
	if r.Pending() != 0 {
		t.Errorf("reassembler leaked state: %d pending", r.Pending())
	}
}

func TestReassemblyOutOfOrder(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	hello := clientHelloBody("reorder.example.com", 1400)
	half := len(hello) / 2

	first := sealInitial(t, dcid, []byte{9, 9, 9, 9}, 0, hello[:half], 1250)
	second := sealInitial(t, dcid, []byte{9, 9, 9, 9}, uint64(half), hello[half:], 1250)

	r := NewReassembler(0)
	key := testKey()

	// Deliver the tail first. UDP offers no ordering guarantee at all.
	if res := r.Feed(key, second); res != nil {
		t.Fatal("emitted a fingerprint from the trailing fragment alone")
	}
	if res := r.Feed(key, first); res == nil {
		t.Fatal("out-of-order fragments were not reassembled")
	}
}

// --- rejection and robustness ----------------------------------------------

func TestRejectsNonQUIC(t *testing.T) {
	pad := func(b []byte) []byte {
		out := make([]byte, 1300)
		copy(out, b)
		return out
	}
	cases := map[string][]byte{
		"empty":             {},
		"short":             {0xc0, 0, 0, 0, 1},
		"dns query":         pad([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01}),
		"short header quic": pad([]byte{0x40, 1, 2, 3, 4}),
		"random":            pad([]byte("this is definitely not a QUIC initial packet")),
		"wrong version":     pad([]byte{0xc0, 0xff, 0x00, 0x00, 0x1d, 8}),
	}
	for name, data := range cases {
		if _, err := ParseInitial(data); err == nil {
			t.Errorf("%s was accepted as a QUIC Initial", name)
		}
	}
}

func TestUndersizedDatagramRejectedBeforeCrypto(t *testing.T) {
	// RFC 9000 section 14.1 requires a client Initial datagram to be padded to
	// 1200 bytes. Enforcing that first means the common case of ordinary UDP
	// costs a length comparison rather than a key derivation.
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	valid := sealInitial(t, dcid, []byte{1, 2, 3, 4}, 0, clientHelloBody("x.example", 0), 1250)

	if _, err := ParseInitial(valid[:MinInitialDatagram-1]); err == nil {
		t.Error("a datagram below the 1200-byte floor was accepted")
	}
	if _, err := ParseInitial(valid); err != nil {
		t.Errorf("the same packet at full length was rejected: %v", err)
	}
}

func TestMalformedNeverPanics(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	valid := sealInitial(t, dcid, []byte{1, 2, 3, 4}, 0, clientHelloBody("example.com", 0), 1250)

	for i := 0; i <= len(valid); i++ {
		_, _ = ParseInitial(valid[:i])
	}
	// Corrupting any single byte must fail the AEAD tag or the parse, never crash.
	for i := 0; i < len(valid); i += 7 {
		mutated := append([]byte(nil), valid...)
		mutated[i] ^= 0xff
		_, _ = ParseInitial(mutated)
	}
}

func FuzzParseInitial(f *testing.F) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	f.Add(make([]byte, 1200))
	f.Fuzz(func(t *testing.T, data []byte) {
		pkt, err := ParseInitial(data)
		if err == nil && pkt == nil {
			t.Fatal("nil packet with nil error")
		}
	})
	_ = dcid
}

// --- helpers ----------------------------------------------------------------

func testKey() model.FlowKey {
	k, _ := model.NewFlowKey(
		netip.MustParseAddr("10.0.0.5"), 54321,
		netip.MustParseAddr("142.250.187.206"), 443,
		model.ProtoUDP,
	)
	return k
}

func BenchmarkRejectNonQUIC(b *testing.B) {
	payload := make([]byte, 1300)
	copy(payload, []byte{0x12, 0x34, 0x01, 0x00})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseInitial(payload)
	}
}

func BenchmarkParseInitial(b *testing.B) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	k, err := deriveClientInitialKeys(Version1, dcid)
	if err != nil {
		b.Fatal(err)
	}
	_ = k

	var t testing.T
	datagram := sealInitial(&t, dcid, []byte{1, 2, 3, 4}, 0, clientHelloBody("example.com", 0), 1250)

	b.SetBytes(int64(len(datagram)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseInitial(datagram); err != nil {
			b.Fatal(err)
		}
	}
}
