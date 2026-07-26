package quic

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readHexFixture decodes a testdata file of hex, ignoring blank lines and
// lines beginning with #, which is where each fixture records where its bytes
// came from.
func readHexFixture(t *testing.T, name string) []byte {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sb.WriteString(line)
	}
	b, err := hex.DecodeString(sb.String())
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return b
}

// TestParseInitialAgainstRFC9001A2 decrypts the client Initial packet published
// in RFC 9001 Appendix A.2 and checks the handshake bytes that come out.
//
// This is the test the QUIC path was missing. Everything else here is a round
// trip against BuildClientInitial, so the parser was only ever checked against
// this project's own encoder: a shared misreading of the specification would
// have passed every one of those tests. The RFC's vector was produced by
// someone else, from the specification itself, and it exercises the whole path
// at once, which is what makes it worth the awkwardness of a 1200-byte fixture.
//
// Nothing about it is negotiable. Header protection, the key schedule, the
// nonce construction, the AEAD, the frame walk and the varint decoder all have
// to be right simultaneously or the authentication tag fails, and it fails
// without saying which of them was wrong.
func TestParseInitialAgainstRFC9001A2(t *testing.T) {
	packet := readHexFixture(t, "rfc9001_a2_packet.hex")
	frame := readHexFixture(t, "rfc9001_a2_crypto_frame.hex")

	if len(packet) != 1200 {
		t.Fatalf("fixture is %d bytes, want the 1200 the RFC publishes", len(packet))
	}

	pkt, err := ParseInitial(packet)
	if err != nil {
		t.Fatalf("ParseInitial: %v", err)
	}
	if pkt == nil {
		t.Fatal("no packet recovered from the RFC's own vector")
	}

	// Appendix A.1 fixes the connection ID this packet's keys derive from.
	wantDCID := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	if !bytes.Equal(pkt.DCID, wantDCID) {
		t.Errorf("DCID = %x, want %x", pkt.DCID, wantDCID)
	}
	if len(pkt.SCID) != 0 {
		t.Errorf("SCID = %x, want empty", pkt.SCID)
	}
	if pkt.Version != Version1 {
		t.Errorf("Version = %#08x, want %#08x", pkt.Version, Version1)
	}

	// The fixture is the whole CRYPTO frame: type 06, offset 0, length 40f1.
	// The handshake bytes are what follows that four-byte header.
	const cryptoHeader = 4
	wantHello := frame[cryptoHeader:]
	if len(wantHello) != 241 {
		t.Fatalf("fixture carries a %d byte ClientHello, want the 241 the RFC states", len(wantHello))
	}

	if len(pkt.Frames) != 1 {
		t.Fatalf("recovered %d CRYPTO frames, want 1", len(pkt.Frames))
	}
	got := pkt.Frames[0]
	if got.Offset != 0 {
		t.Errorf("CRYPTO offset = %d, want 0", got.Offset)
	}
	if !bytes.Equal(got.Data, wantHello) {
		t.Errorf("recovered handshake bytes do not match the RFC\n got %d bytes: %x...\nwant %d bytes: %x...",
			len(got.Data), got.Data[:min(16, len(got.Data))],
			len(wantHello), wantHello[:16])
	}
}

// TestParseInitialAgainstRFC9369A2 is the same check for QUIC version 2.
//
// Version 2 exists to exercise version negotiation and defeat ossification, so
// it changes things deliberately rather than incidentally: the Initial salt
// (RFC 9369 section 3.3.1), all three packet-protection labels (3.3.2), and the
// long-header type numbering, which makes an Initial 0b01 where version 1 makes
// it 0b00 (3.2). Any one of those left at its version 1 value fails the tag.
//
// The RFC pairs its vector with the same ClientHello as RFC 9001, so the
// expected plaintext fixture is shared. That is what makes this test sharp: the
// input and the output are held constant and only the version machinery varies,
// so a failure can only be in the parameters this change introduced.
func TestParseInitialAgainstRFC9369A2(t *testing.T) {
	packet := readHexFixture(t, "rfc9369_a2_packet.hex")
	frame := readHexFixture(t, "rfc9001_a2_crypto_frame.hex")

	if len(packet) != 1200 {
		t.Fatalf("fixture is %d bytes, want the 1200 the RFC publishes", len(packet))
	}

	pkt, err := ParseInitial(packet)
	if err != nil {
		t.Fatalf("ParseInitial: %v", err)
	}
	if pkt.Version != Version2 {
		t.Errorf("Version = %#08x, want %#08x", pkt.Version, Version2)
	}
	wantDCID := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	if !bytes.Equal(pkt.DCID, wantDCID) {
		t.Errorf("DCID = %x, want %x", pkt.DCID, wantDCID)
	}

	if len(pkt.Frames) != 1 {
		t.Fatalf("recovered %d CRYPTO frames, want 1", len(pkt.Frames))
	}
	if wantHello := frame[4:]; !bytes.Equal(pkt.Frames[0].Data, wantHello) {
		t.Errorf("recovered handshake bytes do not match the RFC\n got %d bytes\nwant %d bytes",
			len(pkt.Frames[0].Data), len(wantHello))
	}
}

// TestVersionParametersAreDistinct guards against the failure this change is
// most likely to produce later: copying the version 1 parameters for version 2
// and updating only the salt. Every field has to differ except the packet type
// mask itself, and a shared value here would authenticate nothing.
func TestVersionParametersAreDistinct(t *testing.T) {
	v1, ok := paramsFor(Version1)
	if !ok {
		t.Fatal("version 1 is not recognised")
	}
	v2, ok := paramsFor(Version2)
	if !ok {
		t.Fatal("version 2 is not recognised")
	}

	if bytes.Equal(v1.salt, v2.salt) {
		t.Error("both versions share an Initial salt")
	}
	if v1.keyLabel == v2.keyLabel || v1.ivLabel == v2.ivLabel || v1.hpLabel == v2.hpLabel {
		t.Errorf("shared key-derivation label: v1=%q/%q/%q v2=%q/%q/%q",
			v1.keyLabel, v1.ivLabel, v1.hpLabel, v2.keyLabel, v2.ivLabel, v2.hpLabel)
	}
	if v1.initialType == v2.initialType {
		t.Error("both versions expect the same long-header type for Initial")
	}

	// A draft or future version must still be refused rather than guessed at.
	for _, v := range []uint32{0x00000000, 0xff00001d, 0x6b3343ce, 0x00000002} {
		if _, ok := paramsFor(v); ok {
			t.Errorf("version %#08x was accepted", v)
		}
	}
}

// TestRFC9001A2CarriesTheExpectedHandshake reads the recovered bytes as a TLS
// ClientHello, without involving the fingerprint package, which would make this
// a test of two things at once.
//
// The RFC's hello is a real one: it negotiates TLS 1.3, offers "example.com" as
// its server name, and carries an ALPN. Checking that those survive decryption
// is what turns "the tag verified" into "the right plaintext came out".
func TestRFC9001A2CarriesTheExpectedHandshake(t *testing.T) {
	pkt, err := ParseInitial(readHexFixture(t, "rfc9001_a2_packet.hex"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt.Frames) != 1 {
		t.Fatalf("recovered %d CRYPTO frames, want 1", len(pkt.Frames))
	}
	hello := pkt.Frames[0].Data

	// Handshake type 1 is client_hello, then a 3-byte length covering the rest.
	if hello[0] != 0x01 {
		t.Fatalf("handshake type = %#02x, want 0x01 (client_hello)", hello[0])
	}
	if n := int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3]); n != len(hello)-4 {
		t.Errorf("declared body length %d, have %d", n, len(hello)-4)
	}
	// legacy_version is TLS 1.2 on the wire for a TLS 1.3 hello.
	if hello[4] != 0x03 || hello[5] != 0x03 {
		t.Errorf("legacy_version = %#02x%02x, want 0x0303", hello[4], hello[5])
	}
	if !bytes.Contains(hello, []byte("example.com")) {
		t.Error("the server name from the RFC's hello did not survive decryption")
	}
	if !bytes.Contains(hello, []byte("alpn")) {
		t.Error("the ALPN from the RFC's hello did not survive decryption")
	}
}
