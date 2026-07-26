package quic

import (
	"sync"

	"github.com/baldoseri/tracehound/internal/fingerprint"
	"github.com/baldoseri/tracehound/internal/model"
)

// DefaultMaxPending is how many in-progress QUIC handshakes are tracked at once.
const DefaultMaxPending = 8192

// Reassembler turns a stream of UDP datagrams into TLS client fingerprints.
//
// It mirrors fingerprint.Reassembler, which handles the same job over TCP, and
// deliberately so: a client that speaks both HTTP/2 and HTTP/3 should produce
// fingerprints that can be compared, and the only difference in the output is
// the transport character at the front of the JA4.
type Reassembler struct {
	mu         sync.Mutex
	pending    map[model.FlowKey]*cryptoStream
	maxPending int
	// dropped counts CRYPTO streams discarded to stay under maxPending.
	dropped uint64
}

// NewReassembler returns a ready Reassembler. max <= 0 selects the default.
func NewReassembler(max int) *Reassembler {
	if max <= 0 {
		max = DefaultMaxPending
	}
	return &Reassembler{
		pending:    make(map[model.FlowKey]*cryptoStream),
		maxPending: max,
	}
}

// Feed supplies one UDP datagram.
//
// It returns a non-nil result on the datagram that completes the ClientHello.
// Callers may feed every UDP payload unconditionally: anything that is not a
// QUIC Initial is rejected by a length check and a header bit before any
// cryptography happens.
func (r *Reassembler) Feed(key model.FlowKey, datagram []byte) *fingerprint.Result {
	pkt, err := ParseInitial(datagram)
	if err != nil || pkt == nil || len(pkt.Frames) == 0 {
		return nil
	}

	r.mu.Lock()
	stream, tracking := r.pending[key]
	if !tracking {
		if len(r.pending) >= r.maxPending {
			// Make room rather than refuse, mirroring the TCP reassembler.
			// Refusing turned a full map into a permanent stop: the check runs
			// before any parsing, so nothing new could ever be fingerprinted
			// again while the map stayed full.
			for k := range r.pending {
				delete(r.pending, k)
				r.dropped++
				break
			}
		}
		stream = &cryptoStream{}
		r.pending[key] = stream
	}
	for _, f := range pkt.Frames {
		if !stream.add(f) {
			delete(r.pending, key)
			r.mu.Unlock()
			return nil
		}
	}
	body := stream.handshake()
	if body == nil {
		r.mu.Unlock()
		return nil // more datagrams needed
	}
	delete(r.pending, key)
	r.mu.Unlock()

	ch, err := fingerprint.ParseHandshake(body)
	if err != nil {
		return nil
	}

	ja3, ja3raw := fingerprint.JA3(ch)
	res := &fingerprint.Result{
		// TransportQUIC is what puts a 'q' rather than a 't' at the front of
		// the fingerprint, so a JA4 recorded over QUIC is never silently
		// compared against one recorded over TCP.
		JA4:        fingerprint.JA4(ch, fingerprint.TransportQUIC),
		JA3:        ja3,
		JA3Raw:     ja3raw,
		ServerName: ch.ServerName,
		HasECH:     ch.HasECH,
	}
	if len(ch.ALPN) > 0 {
		res.ALPN = ch.ALPN[0]
	}
	return res
}

// Forget drops any partial state for a flow.
func (r *Reassembler) Forget(key model.FlowKey) {
	r.mu.Lock()
	delete(r.pending, key)
	r.mu.Unlock()
}

// Pending reports how many partial handshakes are buffered.
func (r *Reassembler) Pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}
