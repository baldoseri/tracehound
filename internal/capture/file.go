package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/baldoseri/tracehound/internal/model"
)

// Magic numbers identifying the two capture container formats we accept.
const (
	magicPCAPMicro = 0xa1b2c3d4 // classic libpcap, microsecond timestamps
	magicPCAPNano  = 0xa1b23c4d // classic libpcap, nanosecond timestamps
	magicPCAPNG    = 0x0a0d0d0a // pcapng Section Header Block
)

// packetReader is the subset of pcapgo's readers we use, so FileSource can hold
// either a *pcapgo.Reader or a *pcapgo.NgReader behind one field.
type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// FileSource replays a PCAP or PCAPNG file.
//
// Replay is the backbone of the project's testing story: detections are
// deterministic functions of a capture file, so every detector has a regression
// test that is just "run this PCAP, expect these alerts". It is also what makes
// the demo runnable by someone with no network to sniff.
type FileSource struct {
	f     *os.File
	rd    packetReader
	dec   *decoder
	link  layers.LinkType
	stats Stats
	pkt   model.Packet
}

// OpenFile opens a capture file, sniffing the container format from its magic
// bytes rather than trusting the extension.
func OpenFile(path string) (*FileSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	magic, err := peekMagic(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}

	// A large buffered reader matters here: without it every packet costs a
	// syscall, and replaying a million-packet capture becomes IO-bound rather
	// than CPU-bound, which makes the throughput benchmark meaningless.
	br := bufio.NewReaderSize(f, 1<<20)

	src := &FileSource{f: f}
	switch magic {
	case magicPCAPNG:
		ng, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("read pcapng %s: %w", path, err)
		}
		src.rd = ng
		src.link = layers.LinkType(ng.LinkType())
	case magicPCAPMicro, magicPCAPNano:
		r, err := pcapgo.NewReader(br)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("read pcap %s: %w", path, err)
		}
		src.rd = r
		src.link = r.LinkType()
	default:
		f.Close()
		return nil, fmt.Errorf("capture: %s is not a pcap or pcapng file (magic %#08x)", path, magic)
	}

	src.dec = newDecoder(src.link)
	return src, nil
}

// peekMagic reads the first four bytes and normalises byte order, so that both
// endiannesses of the classic pcap header map onto one constant.
func peekMagic(f *os.File) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(f, b[:]); err != nil {
		return 0, fmt.Errorf("capture: read magic: %w", err)
	}
	be := binary.BigEndian.Uint32(b[:])
	le := binary.LittleEndian.Uint32(b[:])
	switch {
	case be == magicPCAPNG || le == magicPCAPNG:
		return magicPCAPNG, nil
	case le == magicPCAPMicro || be == magicPCAPMicro:
		return magicPCAPMicro, nil
	case le == magicPCAPNano || be == magicPCAPNano:
		return magicPCAPNano, nil
	}
	return be, nil
}

// Next implements Source.
func (s *FileSource) Next() (model.Packet, error) {
	for {
		data, ci, err := s.rd.ReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return model.Packet{}, ErrDone
			}
			// Truncated or corrupt trailing record: treat as end of capture
			// rather than propagating, so a partially-written file still
			// yields everything that was complete.
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return model.Packet{}, ErrDone
			}
			return model.Packet{}, err
		}

		s.stats.Packets++
		s.stats.Bytes += uint64(ci.Length)

		if err := s.dec.decode(data, ci, &s.pkt); err != nil {
			s.stats.Undecode++
			continue // ARP, LLDP, and friends: counted, not an error
		}
		s.stats.Decoded++
		return s.pkt, nil
	}
}

// LinkType implements Source.
func (s *FileSource) LinkType() string { return s.link.String() }

// Stats implements Source.
func (s *FileSource) Stats() Stats { return s.stats }

// Close implements Source.
func (s *FileSource) Close() error { return s.f.Close() }
