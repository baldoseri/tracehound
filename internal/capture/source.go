// Package capture turns bytes off the wire (or off disk) into decoded
// model.Packet values.
//
// Everything here is pure Go. There is no libpcap/Npcap dependency and no cgo,
// which means `CGO_ENABLED=0 go build` produces a single static binary that
// runs in a scratch container and cross-compiles from any host. File replay
// works on every platform; live capture uses Linux AF_PACKET and is compiled
// out elsewhere.
package capture

import (
	"errors"

	"github.com/baldoseri/tracehound/internal/model"
)

// ErrDone is returned by Source.Next when the source is exhausted (end of a
// capture file, or a closed handle).
var ErrDone = errors.New("capture: source exhausted")

// Stats reports what a source has read so far.
type Stats struct {
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
	Dropped  uint64 `json:"dropped"`
	Decoded  uint64 `json:"decoded"`
	Undecode uint64 `json:"undecodable"`
}

// Source yields decoded packets.
//
// Next returns packets by value, but Packet.Payload aliases an internal read
// buffer that is reused on the following call. Consumers that need the bytes
// after the next Next must copy them. This is the standard zero-copy contract
// for packet sources and is what keeps the hot path allocation-free.
type Source interface {
	// Next returns the next decoded packet, or ErrDone when exhausted.
	// Packets that cannot be decoded are skipped internally rather than
	// surfaced as errors, so a single malformed frame never stops a capture.
	Next() (model.Packet, error)

	// LinkType describes the link layer of the source, for diagnostics.
	LinkType() string

	// Stats returns counters accumulated so far.
	Stats() Stats

	// Close releases the underlying handle.
	Close() error
}
