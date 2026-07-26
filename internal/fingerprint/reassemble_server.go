package fingerprint

import (
	"sync"

	"github.com/baldoseri/tracehound/internal/model"
)

// ServerResult is a completed server fingerprint for one flow.
type ServerResult struct {
	JA4S string
	ALPN string
}

// ServerReassembler collects the leading server bytes of TCP flows until a
// complete ServerHello can be parsed.
//
// Deliberately a mirror of Reassembler rather than a shared abstraction over
// it. The two track opposite directions of the same flow with different
// lifetimes and different give-up conditions, and a parser that decides which
// side of a conversation it is looking at from a callback is harder to reason
// about than two that each only ever do one thing.
//
// A ServerHello is far smaller than a modern ClientHello, so it almost always
// arrives in one segment. Buffering anyway costs nothing on the common path and
// means a server that fragments its first flight is still fingerprinted.
type ServerReassembler struct {
	mu         sync.Mutex
	pending    map[model.FlowKey][]byte
	maxPending int
	// dropped counts handshakes discarded to stay under maxPending.
	dropped uint64
}

// NewServerReassembler returns a ready ServerReassembler. maxPending <= 0
// selects the default.
func NewServerReassembler(maxPending int) *ServerReassembler {
	if maxPending <= 0 {
		maxPending = DefaultMaxPending
	}
	return &ServerReassembler{
		pending:    make(map[model.FlowKey][]byte),
		maxPending: maxPending,
	}
}

// Feed supplies server-to-client payload bytes for a flow.
//
// It returns a non-nil result exactly once per flow, on the call that completes
// the ServerHello. Callers may feed every server payload packet
// unconditionally; anything that is not a handshake record exits on its first
// two bytes without allocating.
func (r *ServerReassembler) Feed(key model.FlowKey, payload []byte) *ServerResult {
	if len(payload) == 0 {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	buf, tracking := r.pending[key]
	if !tracking {
		if payload[0] != recordTypeHandshake {
			return nil
		}
		// Only check the version byte once it has actually arrived, so a
		// handshake split across minimal segments is still followed.
		if len(payload) >= 2 && payload[1] != 0x03 {
			return nil
		}
		if len(r.pending) >= r.maxPending {
			// Make room rather than refuse: see Reassembler.evictOne. This
			// check sits before parsing, so refusing turned a full map into a
			// permanent stop instead of a bound.
			for k := range r.pending {
				delete(r.pending, k)
				r.dropped++
				break
			}
		}
	}

	buf = append(buf, payload...)
	if len(buf) > MaxClientHello {
		delete(r.pending, key)
		return nil
	}

	sh, err := ParseServerHello(buf)
	switch {
	case err == ErrIncomplete:
		r.pending[key] = buf
		return nil
	case err != nil:
		// Not a ServerHello after all. A TLS 1.2 server sends Certificate and
		// friends in the same flight, and a TLS 1.3 server encrypts everything
		// after the ServerHello, so there is nothing further worth buffering.
		delete(r.pending, key)
		return nil
	}

	delete(r.pending, key)
	return &ServerResult{
		JA4S: JA4S(sh, TransportTCP),
		ALPN: sh.ALPN,
	}
}

// Forget drops any partial state for a flow.
func (r *ServerReassembler) Forget(key model.FlowKey) {
	r.mu.Lock()
	delete(r.pending, key)
	r.mu.Unlock()
}

// Pending reports how many partial ServerHellos are buffered.
func (r *ServerReassembler) Pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}
