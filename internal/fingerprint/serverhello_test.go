package fingerprint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

// --- building ServerHello bytes ---------------------------------------------

type shSpec struct {
	legacyVersion    uint16
	cipher           uint16
	alpn             string
	supportedVersion uint16
	extras           []uint16
	retryRequest     bool
}

func buildServerHello(s shSpec) []byte {
	var body builder
	body.u16(s.legacyVersion)
	if s.retryRequest {
		body.raw(helloRetryRequest[:])
	} else {
		body.raw(make([]byte, 32))
	}
	body.u8(0) // empty session id echo
	body.u16(s.cipher)
	body.u8(0) // null compression

	body.lenPrefixed(2, func(exts *builder) {
		if s.supportedVersion != 0 {
			exts.u16(extSupportedVersions)
			exts.lenPrefixed(2, func(e *builder) { e.u16(s.supportedVersion) })
		}
		if s.alpn != "" {
			exts.u16(extALPN)
			exts.lenPrefixed(2, func(e *builder) {
				e.lenPrefixed(2, func(l *builder) {
					l.lenPrefixed(1, func(n *builder) { n.raw([]byte(s.alpn)) })
				})
			})
		}
		for _, ext := range s.extras {
			exts.u16(ext)
			exts.u16(0)
		}
	})

	var hs builder
	hs.u8(handshakeServerHello)
	hs.lenPrefixed(3, func(w *builder) { w.raw(body.b) })

	var rec builder
	rec.u8(recordTypeHandshake)
	rec.u16(0x0303)
	rec.lenPrefixed(2, func(w *builder) { w.raw(hs.b) })
	return rec.b
}

func goldenServerSpec() shSpec {
	return shSpec{
		legacyVersion:    0x0303,
		cipher:           0x1301,
		alpn:             "h2",
		supportedVersion: 0x0304,
		extras:           []uint16{0x0033, 0x1a1a}, // key_share plus one GREASE
	}
}

// --- parsing ----------------------------------------------------------------

func TestParseServerHelloFields(t *testing.T) {
	sh, err := ParseServerHello(buildServerHello(goldenServerSpec()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if sh.CipherSuite != 0x1301 {
		t.Errorf("CipherSuite = %#04x, want 0x1301", sh.CipherSuite)
	}
	if sh.ALPN != "h2" {
		t.Errorf("ALPN = %q, want h2", sh.ALPN)
	}
	if got, want := sh.NegotiatedVersion(), uint16(0x0304); got != want {
		t.Errorf("NegotiatedVersion = %#04x, want %#04x", got, want)
	}
	// supported_versions, ALPN and key_share survive; the GREASE entry does not.
	if len(sh.Extensions) != 3 {
		t.Errorf("Extensions = %v, want 3 with GREASE stripped", sh.Extensions)
	}
	for _, e := range sh.Extensions {
		if isGREASE(e) {
			t.Errorf("GREASE extension %#04x survived parsing", e)
		}
	}
}

// TestHelloRetryRequestIsNotAServerHello covers a message that is a ServerHello
// on the wire but not the server's real answer. Fingerprinting it would give
// every server that ever asks for a different key share the same hash.
func TestHelloRetryRequestIsNotAServerHello(t *testing.T) {
	s := goldenServerSpec()
	s.retryRequest = true
	if _, err := ParseServerHello(buildServerHello(s)); err != ErrNotServerHello {
		t.Errorf("error = %v, want ErrNotServerHello", err)
	}
}

func TestParseServerHelloRejectsClientHello(t *testing.T) {
	if _, err := ParseServerHello(buildHello(goldenSpec())); err != ErrNotServerHello {
		t.Errorf("a ClientHello parsed as a ServerHello: %v", err)
	}
}

// --- JA4S -------------------------------------------------------------------

func TestJA4SGolden(t *testing.T) {
	sh, err := ParseServerHello(buildServerHello(goldenServerSpec()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Derived from the spec by hand rather than from the implementation:
	//   t  = TCP
	//   13 = supported_versions says 0x0304
	//   03 = three non-GREASE extensions
	//   h2 = first and last character of the chosen ALPN
	//   1301 = the selected cipher suite, printed rather than hashed
	//   then the extensions in wire order, unsorted
	want := "t1303h2_1301_" + trunc12("002b,0010,0033")

	if got := JA4S(sh, TransportTCP); got != want {
		t.Errorf("JA4S mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestJA4SWithoutALPNOrExtensions(t *testing.T) {
	sh, err := ParseServerHello(buildServerHello(shSpec{
		legacyVersion: 0x0303,
		cipher:        0xc030,
	}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// TLS 1.2, no extensions, no ALPN, and the all-zero hash placeholder.
	want := "t120000_c030_" + zeroHash
	if got := JA4S(sh, TransportTCP); got != want {
		t.Errorf("JA4S = %s, want %s", got, want)
	}
}

// TestJA4SExtensionOrderMatters is the deliberate difference from JA4_c, which
// sorts. A server has no reason to shuffle its extensions, so the ordering is
// signal rather than noise and discarding it would weaken the fingerprint.
func TestJA4SExtensionOrderMatters(t *testing.T) {
	a, err := ParseServerHello(buildServerHello(shSpec{
		legacyVersion: 0x0303, cipher: 0x1301, extras: []uint16{0x0033, 0x000b},
	}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseServerHello(buildServerHello(shSpec{
		legacyVersion: 0x0303, cipher: 0x1301, extras: []uint16{0x000b, 0x0033},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if JA4S(a, TransportTCP) == JA4S(b, TransportTCP) {
		t.Error("reordering the server's extensions produced the same JA4S")
	}
}

func TestJA4SCipherChangesFingerprint(t *testing.T) {
	s := goldenServerSpec()
	first, err := ParseServerHello(buildServerHello(s))
	if err != nil {
		t.Fatal(err)
	}
	s.cipher = 0x1302
	second, err := ParseServerHello(buildServerHello(s))
	if err != nil {
		t.Fatal(err)
	}
	if JA4S(first, TransportTCP) == JA4S(second, TransportTCP) {
		t.Error("a different cipher suite produced the same JA4S")
	}
}

// --- against a real Go TLS server -------------------------------------------

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tracehound-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tls12ClientHello offers only TLS 1.2, so the server answers with a real
// ServerHello rather than a HelloRetryRequest asking for a key share.
func tls12ClientHello() []byte {
	return buildHello(helloSpec{
		legacyVersion: 0x0303,
		ciphers:       []uint16{0xc02b, 0xc02f, 0xc030, 0x009c},
		sni:           "example.com",
		alpn:          []string{"h2"},
		sigAlgs:       []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0603},
		groups:        []uint16{0x0017, 0x001d},
		pointFormats:  []uint8{0x00},
	})
}

// TestParseRealGoServerHello checks the parser against bytes a real TLS
// implementation put on the wire, which is the same standard the ClientHello
// parser is held to.
func TestParseRealGoServerHello(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		srv := tls.Server(serverConn, &tls.Config{
			Certificates: []tls.Certificate{selfSignedCert(t)},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2"},
		})
		_ = srv.Handshake() // never completes; we hang up after the first flight
		srv.Close()
	}()

	if err := clientConn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Write(tls12ClientHello()); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}

	buf := make([]byte, MaxClientHello)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("read server flight: %v", err)
	}

	sh, err := ParseServerHello(buf[:n])
	if err != nil {
		t.Fatalf("parse real ServerHello (%d bytes): %v", n, err)
	}

	if got := sh.NegotiatedVersion(); got != tls.VersionTLS12 {
		t.Errorf("NegotiatedVersion = %#04x, want TLS 1.2", got)
	}
	// Go must have chosen one of the suites offered, and it is an ECDSA one
	// because the certificate is ECDSA.
	switch sh.CipherSuite {
	case 0xc02b, 0xc02f, 0xc030, 0x009c:
	default:
		t.Errorf("server chose %#04x, which was not offered", sh.CipherSuite)
	}
	if sh.ALPN != "h2" {
		t.Errorf("ALPN = %q, want h2", sh.ALPN)
	}

	ja4s := JA4S(sh, TransportTCP)
	shape := regexp.MustCompile(`^t(13|12|11|10)\d{2}[a-z0-9]{2}_[0-9a-f]{4}_[0-9a-f]{12}$`)
	if !shape.MatchString(ja4s) {
		t.Errorf("JA4S %q does not match the expected shape", ja4s)
	}
	if !strings.HasPrefix(ja4s, "t12") {
		t.Errorf("JA4S = %q, want a TLS 1.2 prefix", ja4s)
	}
	t.Logf("Go %d-byte server flight -> JA4S %s", n, ja4s)
}

// --- reassembly and robustness ----------------------------------------------

func TestServerReassemblerSplitAcrossSegments(t *testing.T) {
	raw := buildServerHello(goldenServerSpec())
	key := testKey(t)

	whole := NewServerReassembler(0)
	want := whole.Feed(key, raw)
	if want == nil {
		t.Fatal("unsplit ServerHello produced no fingerprint")
	}

	for _, split := range []int{1, 5, 6, 20, len(raw) - 1} {
		r := NewServerReassembler(0)
		if got := r.Feed(key, raw[:split]); got != nil {
			t.Fatalf("split at %d: fingerprint emitted before the hello was complete", split)
		}
		got := r.Feed(key, raw[split:])
		if got == nil {
			t.Fatalf("split at %d: no fingerprint after the final segment", split)
		}
		if got.JA4S != want.JA4S {
			t.Errorf("split at %d: JA4S = %s, want %s", split, got.JA4S, want.JA4S)
		}
		if r.Pending() != 0 {
			t.Errorf("split at %d: reassembler leaked state", split)
		}
	}
}

func TestServerReassemblerIgnoresNonTLS(t *testing.T) {
	r := NewServerReassembler(0)
	key := testKey(t)

	for _, payload := range [][]byte{
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
		[]byte("SSH-2.0-OpenSSH_9.6\r\n"),
		{0x17, 0x03, 0x03, 0x00, 0x05}, // application data
	} {
		if got := r.Feed(key, payload); got != nil {
			t.Errorf("non-TLS payload produced a fingerprint: %x", payload)
		}
	}
	if r.Pending() != 0 {
		t.Errorf("non-TLS traffic left %d buffered flows", r.Pending())
	}
}

func TestParseServerHelloMalformedNeverPanics(t *testing.T) {
	raw := buildServerHello(goldenServerSpec())

	for i := 0; i < len(raw); i++ {
		if _, err := ParseServerHello(raw[:i]); err == nil {
			t.Errorf("prefix of length %d parsed as a complete ServerHello", i)
		}
	}
	for i := 0; i < len(raw); i++ {
		mutated := append([]byte(nil), raw...)
		mutated[i] = 0xff
		if sh, err := ParseServerHello(mutated); err == nil && sh != nil {
			_ = JA4S(sh, TransportTCP) // fingerprinting must also survive
		}
	}
}

func FuzzParseServerHello(f *testing.F) {
	f.Add(buildServerHello(goldenServerSpec()))
	f.Add(buildServerHello(shSpec{legacyVersion: 0x0303, cipher: 0xc030}))
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		sh, err := ParseServerHello(data)
		if err != nil {
			return
		}
		if sh == nil {
			t.Fatal("nil ServerHello with nil error")
		}
		if got := JA4S(sh, TransportTCP); len(got) != ja4sLen {
			t.Fatalf("JA4S %q has length %d, want %d", got, len(got), ja4sLen)
		}
	})
}

func BenchmarkParseAndFingerprintServer(b *testing.B) {
	raw := buildServerHello(goldenServerSpec())
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sh, err := ParseServerHello(raw)
		if err != nil {
			b.Fatal(err)
		}
		_ = JA4S(sh, TransportTCP)
	}
}
