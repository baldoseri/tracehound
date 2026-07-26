package quic

import (
	"bytes"
	"errors"
	"testing"
)

// frame builders. The package has appendVarint but nothing that assembles
// frames, because the only producer in the tree is BuildClientInitial and it
// emits PADDING and CRYPTO only. That is exactly why most of parseFrames had
// never run: every QUIC input in the suite came from this project.

func padding(n int) []byte { return make([]byte, n) }

func ping() []byte { return appendVarint(nil, framePing) }

func crypto(offset uint64, data []byte) []byte {
	b := appendVarint(nil, frameCrypto)
	b = appendVarint(b, offset)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

// ack builds an ACK frame with the given gap/length range pairs. ecnCounts adds
// the three ECN counters, turning it into an ACK_ECN.
func ack(largest, delay uint64, ranges [][2]uint64, ecnCounts bool) []byte {
	t := uint64(frameACK)
	if ecnCounts {
		t = frameACKECN
	}
	b := appendVarint(nil, t)
	b = appendVarint(b, largest)
	b = appendVarint(b, delay)
	b = appendVarint(b, uint64(len(ranges)))
	b = appendVarint(b, 0) // first ack range
	for _, r := range ranges {
		b = appendVarint(b, r[0])
		b = appendVarint(b, r[1])
	}
	if ecnCounts {
		b = appendVarint(b, 1)
		b = appendVarint(b, 2)
		b = appendVarint(b, 3)
	}
	return b
}

func connClose() []byte {
	b := appendVarint(nil, frameConnClose)
	b = appendVarint(b, 0) // error code
	b = appendVarint(b, 0) // frame type
	return append(b, 0x00) // reason length
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestParseFrames(t *testing.T) {
	hello := []byte("this stands in for a ClientHello")

	tests := []struct {
		name    string
		payload []byte
		want    []CryptoFrame
		wantErr error
	}{
		{
			name:    "padding and ping carry no body",
			payload: concat(padding(8), ping(), padding(4), crypto(0, hello)),
			want:    []CryptoFrame{{Offset: 0, Data: hello}},
		},
		{
			// The realistic case this whole branch exists for: after a Retry,
			// a client's second flight acknowledges the Retry before its
			// CRYPTO. Skipping the ACK wrongly loses the ClientHello entirely.
			name:    "ACK before CRYPTO is skipped correctly",
			payload: concat(ack(10, 3, [][2]uint64{{1, 2}, {3, 4}}, false), crypto(0, hello)),
			want:    []CryptoFrame{{Offset: 0, Data: hello}},
		},
		{
			name:    "ACK_ECN consumes its three extra counters",
			payload: concat(ack(10, 3, [][2]uint64{{1, 2}}, true), crypto(0, hello)),
			want:    []CryptoFrame{{Offset: 0, Data: hello}},
		},
		{
			name:    "ACK with no ranges",
			payload: concat(ack(1, 0, nil, false), crypto(0, hello)),
			want:    []CryptoFrame{{Offset: 0, Data: hello}},
		},
		{
			name:    "two CRYPTO frames in one packet",
			payload: concat(crypto(0, hello[:10]), crypto(10, hello[10:])),
			want: []CryptoFrame{
				{Offset: 0, Data: hello[:10]},
				{Offset: 10, Data: hello[10:]},
			},
		},
		{
			// A frame count large enough to loop for a very long time on a
			// payload far too small to contain it.
			name:    "absurd ACK range count is refused",
			payload: ack(1, 0, nil, false)[:0:0], // replaced below
			wantErr: ErrMalformed,
		},
		{
			name:    "CRYPTO claiming more than it carries is truncated",
			payload: concat(appendVarint(appendVarint(appendVarint(nil, frameCrypto), 0), 9999), []byte("short")),
			wantErr: ErrTruncated,
		},
		{
			name:    "CRYPTO offset beyond the buffering limit is refused",
			payload: crypto(MaxCryptoBytes+1, []byte("x")),
			wantErr: ErrMalformed,
		},
		{
			name:    "CONNECTION_CLOSE ends the walk and keeps what came before",
			payload: concat(crypto(0, hello), connClose(), crypto(99, []byte("never reached"))),
			want:    []CryptoFrame{{Offset: 0, Data: hello}},
		},
		{
			name:    "an unknown frame type stops rather than guessing",
			payload: concat(crypto(0, hello), appendVarint(nil, 0x77), []byte("garbage")),
			want:    []CryptoFrame{{Offset: 0, Data: hello}},
		},
		{
			name:    "empty payload yields nothing",
			payload: nil,
		},
	}

	// Built here rather than inline so the range count can exceed the payload.
	absurd := appendVarint(nil, frameACK)
	absurd = appendVarint(absurd, 1)      // largest acknowledged
	absurd = appendVarint(absurd, 0)      // delay
	absurd = appendVarint(absurd, 100000) // range count, far beyond the payload
	absurd = appendVarint(absurd, 0)      // first range
	tests[5].payload = absurd

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseFrames(tc.payload)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d CRYPTO frames, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i].Offset != tc.want[i].Offset {
					t.Errorf("frame %d offset = %d, want %d", i, got[i].Offset, tc.want[i].Offset)
				}
				if !bytes.Equal(got[i].Data, tc.want[i].Data) {
					t.Errorf("frame %d data = %q, want %q", i, got[i].Data, tc.want[i].Data)
				}
			}
		})
	}
}

// TestParseFramesDoesNotAliasItsInput guards the copy in the CRYPTO branch. The
// payload is a decryption buffer that the caller is free to reuse, so a frame
// holding a slice of it would see its own contents change underneath.
func TestParseFramesDoesNotAliasItsInput(t *testing.T) {
	payload := crypto(0, []byte("original"))
	frames, err := parseFrames(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}

	for i := range payload {
		payload[i] = 0xff
	}
	if string(frames[0].Data) != "original" {
		t.Errorf("frame data changed with the buffer: %q", frames[0].Data)
	}
}

// FuzzParseFrames fuzzes the frame walk on plaintext directly.
//
// Worth doing separately from FuzzParseInitial because Initial keys are derived
// from the packet's own destination connection ID, which is public and
// attacker-chosen. Anyone able to send a UDP datagram can therefore hand this
// parser authenticated plaintext of their choosing, so the frame walk is
// reachable with arbitrary input rather than protected by the AEAD.
func FuzzParseFrames(f *testing.F) {
	hello := []byte("this stands in for a ClientHello")
	f.Add(concat(padding(8), ping(), crypto(0, hello)))
	f.Add(concat(ack(10, 3, [][2]uint64{{1, 2}}, false), crypto(0, hello)))
	f.Add(concat(ack(10, 3, [][2]uint64{{1, 2}}, true), crypto(0, hello)))
	f.Add(connClose())
	f.Add([]byte{0x06, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		frames, err := parseFrames(data)
		if err != nil {
			return
		}
		total := 0
		for _, fr := range frames {
			if fr.Offset > MaxCryptoBytes {
				t.Fatalf("frame accepted with offset %d beyond the limit", fr.Offset)
			}
			total += len(fr.Data)
		}
		// Frame data is copied out of the payload, so it can never exceed it.
		if total > len(data) {
			t.Fatalf("frames carry %d bytes from a %d byte payload", total, len(data))
		}
	})
}
