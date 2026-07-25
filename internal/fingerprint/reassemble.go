package fingerprint

import (
	"sync"

	"github.com/baldoseri/tracehound/internal/model"
)

// Result is a completed fingerprint for one flow.
type Result struct {
	JA4        string
	JA3        string
	JA3Raw     string
	ServerName string
	ALPN       string
}

// Reassembler collects the leading client bytes of TCP flows until a complete
// ClientHello can be parsed.
//
// This exists because a ClientHello no longer reliably fits in one segment. A
// current Chrome or Firefox hello carrying a hybrid post-quantum key share
// (X25519MLKEM768) runs past 1500 bytes and is split across two TCP segments,
// so the naive "parse the first payload packet" approach silently stops
// fingerprinting exactly the modern clients you most want to see.
//
// It is intentionally not a general TCP reassembler: it buffers only the first
// MaxClientHello bytes of the client→server direction, only for flows whose
// first byte looks like a TLS handshake, and forgets a flow as soon as it
// either parses or gives up. That bounds memory to a few KiB per candidate flow
// and keeps the cost off the hot path for the 99% of flows that are not TLS.
type Reassembler struct {
	mu      sync.Mutex
	pending map[model.FlowKey][]byte
	// maxPending bounds how many partial handshakes we track at once, so a
	// flood of half-open TLS connections cannot grow the map without limit.
	maxPending int
}

// DefaultMaxPending is the number of in-progress handshakes tracked at once.
const DefaultMaxPending = 8192

// NewReassembler returns a ready Reassembler. maxPending <= 0 selects the
// default.
func NewReassembler(maxPending int) *Reassembler {
	if maxPending <= 0 {
		maxPending = DefaultMaxPending
	}
	return &Reassembler{
		pending:    make(map[model.FlowKey][]byte),
		maxPending: maxPending,
	}
}

// Feed supplies client→server payload bytes for a flow.
//
// It returns a non-nil Result exactly once per flow, on the call that completes
// the ClientHello. Callers may feed every client payload packet unconditionally;
// non-TLS flows are rejected on their first byte and never allocate.
func (r *Reassembler) Feed(key model.FlowKey, payload []byte) *Result {
	if len(payload) == 0 {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	buf, tracking := r.pending[key]
	if !tracking {
		// Cheap rejection: a TLS handshake record always starts 0x16 0x03.
		// Everything else — HTTP, SSH, DNS-over-TCP, SMB — exits here having
		// touched two bytes and allocated nothing.
		//
		// The second byte is only checked when we actually have it. A segment
		// carrying a single 0x16 is not a malformed handshake, it is a
		// handshake split across segments — historically a standard way to
		// evade inline inspection, since a sensor that demands the whole record
		// in one packet simply stops seeing the connection. We buffer and wait.
		if payload[0] != recordTypeHandshake {
			return nil
		}
		if len(payload) >= 2 && payload[1] != 0x03 {
			return nil
		}
		if len(r.pending) >= r.maxPending {
			return nil
		}
	}

	buf = append(buf, payload...)
	if len(buf) > MaxClientHello {
		// Oversized: either not really a handshake or deliberately abusive.
		delete(r.pending, key)
		return nil
	}

	ch, err := ParseClientHello(buf)
	switch {
	case err == ErrIncomplete:
		r.pending[key] = buf // keep buffering
		return nil
	case err != nil:
		delete(r.pending, key) // not TLS after all, or malformed: stop tracking
		return nil
	}

	delete(r.pending, key)

	ja3, ja3raw := JA3(ch)
	res := &Result{
		JA4:        JA4(ch, TransportTCP),
		JA3:        ja3,
		JA3Raw:     ja3raw,
		ServerName: ch.ServerName,
	}
	if len(ch.ALPN) > 0 {
		res.ALPN = ch.ALPN[0]
	}
	return res
}

// Forget drops any partial state for a flow. The pipeline calls this when a
// flow is reaped so that handshakes that never completed do not linger.
func (r *Reassembler) Forget(key model.FlowKey) {
	r.mu.Lock()
	delete(r.pending, key)
	r.mu.Unlock()
}

// Pending reports how many partial handshakes are currently buffered.
func (r *Reassembler) Pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}
