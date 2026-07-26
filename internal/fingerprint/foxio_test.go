package fingerprint

import (
	"bufio"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestJA4AgainstFoxIOVectors checks this implementation against the one every
// other tool is calibrated to.
//
// This is the gap that mattered most in this package. TestJA4Golden derives its
// expected value by hand, from a reading of the specification, against a hello
// this same package builds — so a misreading of the spec produces a wrong
// fingerprint and a passing test, and nothing in the repository would notice.
// The QUIC code has had external ground truth since the RFC 9001 vectors landed;
// the capability the project is named around had none.
//
// The inputs are real Chrome ClientHellos from FoxIO's own test capture, and the
// expected values are what FoxIO's implementation produces for them. The four
// rows are chosen to disagree with each other: ALPN h2, ALPN http/1.1 collapsed
// to h1, no ALPN at all encoded as 00, and a hello with a different extension
// count. A single vector could pass by coincidence; these four cannot.
//
// See testdata/foxio_ja4_vectors.txt for provenance and licence.
func TestJA4AgainstFoxIOVectors(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "foxio_ja4_vectors.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	seen := map[string]bool{}
	rows := 0

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // hello records run past the default
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		parts := strings.Fields(text)
		if len(parts) != 3 {
			t.Fatalf("line %d: want 'port ja4 hex', got %d fields", line, len(parts))
		}
		port, want, raw := parts[0], parts[1], parts[2]

		record, err := hex.DecodeString(raw)
		if err != nil {
			t.Fatalf("line %d: %v", line, err)
		}

		ch, err := ParseClientHello(record)
		if err != nil {
			t.Errorf("port %s: parse: %v", port, err)
			continue
		}
		if got := JA4(ch, TransportTCP); got != want {
			t.Errorf("port %s (%s)\n got: %s\nwant: %s", port, ch.ServerName, got, want)
		}
		seen[want] = true
		rows++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	if rows < 4 {
		t.Fatalf("only %d vectors ran; the fixture should carry four", rows)
	}
	// If every row expected the same fingerprint the test would prove far less
	// than it appears to.
	if len(seen) < 4 {
		t.Errorf("the %d vectors cover only %d distinct fingerprints", rows, len(seen))
	}
}

// TestJA4VectorsExerciseTheALPNRule states in one place what the fixture is for,
// so a later reader does not have to reverse it out of four hex blobs.
func TestJA4VectorsExerciseTheALPNRule(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "foxio_ja4_vectors.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	alpn := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		parts := strings.Fields(text)
		if len(parts) != 3 {
			continue
		}
		// The ALPN code is the last two characters of JA4's first field.
		a, _, _ := strings.Cut(parts[1], "_")
		if len(a) >= 2 {
			alpn[a[len(a)-2:]] = true
		}
	}

	for _, want := range []string{"h2", "h1", "00"} {
		if !alpn[want] {
			t.Errorf("no vector covers ALPN code %q; the fixture has lost its point", want)
		}
	}
}
