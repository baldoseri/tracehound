package main

import (
	"strings"
	"testing"
)

func TestSanitizeTerminalLeavesOrdinaryTextAlone(t *testing.T) {
	for _, s := range []string{
		"",
		"Port scan: 10.0.0.99 probed 121 ports on 10.0.0.10",
		"t13d1516h2_8daaf6152771_02713d6af862",
		"files.storage-sync.example",
		// Multi-byte UTF-8 must survive: every byte of a sequence is >= 0x80,
		// so the byte-wise check cannot mistake one for a control character.
		"café.example",
		"日本.example",
	} {
		if got := sanitizeTerminal(s); got != s {
			t.Errorf("sanitizeTerminal(%q) = %q, want it unchanged", s, got)
		}
	}
}

func TestSanitizeTerminalEscapesControlBytes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			// The reachable case: a two-byte ALPN is copied into the JA4
			// verbatim, so ESC c (RIS, a full terminal reset) lands in a
			// fingerprint that query -devices prints to a console.
			name: "escape in a fingerprint",
			in:   "t13d1516\x1bc_8daaf6152771_02713d6af862",
			want: `t13d1516\x1bc_8daaf6152771_02713d6af862`,
		},
		{
			name: "carriage return overwriting the line",
			in:   "evil.example\rSAFE",
			want: `evil.example\x0dSAFE`,
		},
		{
			name: "newline forging another alert line",
			in:   "a.example\n[HIGH    ] TH-9999  fabricated",
			want: `a.example\x0a[HIGH    ] TH-9999  fabricated`,
		},
		{
			name: "backspace and delete",
			in:   "abc\x08\x7f",
			want: `abc\x08\x7f`,
		},
		{
			name: "nul",
			in:   "a\x00b",
			want: `a\x00b`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeTerminal(tc.in)
			if got != tc.want {
				t.Errorf("sanitizeTerminal(%q)\n got: %s\nwant: %s", tc.in, got, tc.want)
			}
			if strings.ContainsAny(got, "\x1b\r\n\x00\x08\x7f") {
				t.Errorf("sanitizeTerminal(%q) = %q still contains a control byte", tc.in, got)
			}
		})
	}
}

// TestSanitizeTerminalIsIdempotent matters because the escaped form is itself
// printable: running it twice must not double up the backslashes.
func TestSanitizeTerminalIsIdempotent(t *testing.T) {
	once := sanitizeTerminal("a\x1bb")
	if twice := sanitizeTerminal(once); twice != once {
		t.Errorf("not idempotent: %q then %q", once, twice)
	}
}
