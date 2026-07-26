//go:build linux

package capture

import (
	"fmt"
	"net"
	"sync/atomic"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/baldoseri/tracehound/internal/model"
)

// LiveSource captures from a network interface using AF_PACKET.
//
// This is gopacket's pure-Go capture path, not a libpcap binding, which is what
// lets the whole binary build with CGO_ENABLED=0 and ship in a scratch
// container. The tradeoff is that it is Linux-only — which is the right
// tradeoff for a sensor, since that is where sensors run.
//
// Capturing requires CAP_NET_RAW. Grant it narrowly rather than running as
// root: setcap cap_net_raw,cap_net_admin=eip ./tracehound
type LiveSource struct {
	h     *pcapgo.EthernetHandle
	dec   *decoder
	iface string
	stats Stats
	pkt   model.Packet

	// dropped accumulates the kernel's destructive-read drop counter.
	dropped uint64

	// closed distinguishes a socket we shut down from one that failed. It is
	// read on the capture goroutine and written by Interrupt or Close, which
	// may be called from another, so it has to be atomic.
	closed atomic.Bool
}

// OpenLive begins capturing on iface.
func OpenLive(iface string, promiscuous bool) (*LiveSource, error) {
	if _, err := net.InterfaceByName(iface); err != nil {
		return nil, fmt.Errorf("capture: interface %q: %w", iface, err)
	}

	h, err := pcapgo.NewEthernetHandle(iface)
	if err != nil {
		return nil, fmt.Errorf("capture: open %q (need CAP_NET_RAW): %w", iface, err)
	}
	if promiscuous {
		if err := h.SetPromiscuous(true); err != nil {
			h.Close()
			return nil, fmt.Errorf("capture: set promiscuous on %q: %w", iface, err)
		}
	}

	return &LiveSource{
		h:     h,
		iface: iface,
		dec:   newDecoder(layers.LinkTypeEthernet),
	}, nil
}

// Next implements Source.
func (s *LiveSource) Next() (model.Packet, error) {
	for {
		data, ci, err := s.h.ZeroCopyReadPacketData()
		if err != nil {
			// Whether this is a shutdown or a real failure is decided by our
			// own flag rather than by inspecting the error, because the error
			// cannot be inspected: pcapgo formats it with %s, not %w, so the
			// chain is broken and errors.Is can never match anything through
			// it. The io.EOF check that used to be here was unreachable for
			// that reason.
			if s.closed.Load() {
				return model.Packet{}, ErrDone
			}
			return model.Packet{}, err
		}

		s.stats.Packets++
		s.stats.Bytes += uint64(ci.Length)

		if err := s.dec.decode(data, ci, &s.pkt); err != nil {
			s.stats.Undecode++
			continue
		}
		s.stats.Decoded++
		return s.pkt, nil
	}
}

// LinkType implements Source.
func (s *LiveSource) LinkType() string { return "Ethernet" }

// Stats implements Source, folding in the kernel's drop counter so that a
// sensor which cannot keep up says so rather than silently under-reporting.
//
// AF_PACKET's TPACKET_GET_STATS is destructive: each call returns the counts
// *since the previous call* and resets them. Assigning the result would
// therefore report "0 dropped" on any call that happens to follow another
// closely, so the deltas are accumulated instead.
func (s *LiveSource) Stats() Stats {
	if ks, err := s.h.Stats(); err == nil && ks != nil {
		s.dropped += uint64(ks.Drops)
	}
	st := s.stats
	st.Dropped = s.dropped
	return st
}

// Interrupt implements Interrupter.
//
// AF_PACKET offers no read deadline and EthernetHandle exposes no way to set
// one, so closing the socket is the only thing that will wake a read that is
// waiting on a link with no traffic. The flag is set first: the reader has to
// see "we did this" before it sees the error the close produces, or a clean
// shutdown is reported as a capture failure.
//
// Safe to call repeatedly, and safe to call alongside Close.
func (s *LiveSource) Interrupt() error {
	if s.closed.Swap(true) {
		return nil
	}
	return s.h.Close()
}

// Close implements Source.
func (s *LiveSource) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	return s.h.Close()
}
