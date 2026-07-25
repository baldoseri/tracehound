package pcapgen

import (
	"encoding/binary"
	"strings"
)

// Application-layer payloads for the synthetic capture.
//
// The TLS hellos here are hand-built rather than captured from real clients,
// which keeps the repository free of anyone's actual traffic while still
// producing three genuinely distinct JA4 fingerprints: two "browser" profiles
// shared across the benign fleet, and one minimal profile for the implant.
//
// The implant profile is drawn from what statically-linked malware TLS stacks
// actually look like — TLS 1.2 only, a short cipher list, no ALPN, no GREASE,
// no session tickets. That combination is unusual enough on a modern network
// that the fingerprint alone is a lead.

// --- TLS ClientHello --------------------------------------------------------

type helloSpec struct {
	legacyVersion     uint16
	ciphers           []uint16
	sni               string
	alpn              []string
	sigAlgs           []uint16
	groups            []uint16
	pointFormats      []uint8
	supportedVersions []uint16
	padTo             int // extra padding extension to reach a realistic size
	grease            bool
}

// chromeHello is a TLS 1.3 profile with GREASE and a wide extension set.
func chromeHello(sni string) []byte {
	return buildHello(helloSpec{
		legacyVersion: 0x0303,
		grease:        true,
		ciphers: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
			0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},
		sni:               sni,
		alpn:              []string{"h2", "http/1.1"},
		sigAlgs:           []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
		groups:            []uint16{0x001d, 0x0017, 0x0018},
		pointFormats:      []uint8{0x00},
		supportedVersions: []uint16{0x0304, 0x0303},
		padTo:             517,
	})
}

// firefoxHello is a second TLS 1.3 profile: same era, different stack.
func firefoxHello(sni string) []byte {
	return buildHello(helloSpec{
		legacyVersion: 0x0303,
		ciphers: []uint16{
			0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8,
			0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x002f, 0x0035, 0x000a,
		},
		sni:               sni,
		alpn:              []string{"h2", "http/1.1"},
		sigAlgs:           []uint16{0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201},
		groups:            []uint16{0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101},
		pointFormats:      []uint8{0x00},
		supportedVersions: []uint16{0x0304, 0x0303},
		padTo:             400,
	})
}

// implantHello is a minimal TLS 1.2 profile with no ALPN — the shape a
// statically-linked, hand-rolled client produces.
func implantHello(sni string) []byte {
	return buildHello(helloSpec{
		legacyVersion: 0x0303,
		ciphers:       []uint16{0xc02f, 0xc030, 0x009c, 0x009d},
		sni:           sni,
		sigAlgs:       []uint16{0x0401, 0x0501, 0x0601},
		groups:        []uint16{0x0017},
		pointFormats:  []uint8{0x00},
	})
}

// buildHello renders a spec into a complete TLS record containing a ClientHello.
func buildHello(s helloSpec) []byte {
	var body builder
	body.u16(s.legacyVersion)
	body.raw(make([]byte, 32)) // random; zeros keep the capture reproducible
	body.u8(0)                 // empty legacy_session_id

	body.lenPrefixed(2, func(w *builder) {
		if s.grease {
			w.u16(0x0a0a)
		}
		for _, c := range s.ciphers {
			w.u16(c)
		}
	})
	body.u8(1)
	body.u8(0) // compression: null

	body.lenPrefixed(2, func(exts *builder) {
		if s.grease {
			exts.u16(0x1a1a)
			exts.u16(0)
		}
		if s.sni != "" {
			exts.u16(0x0000)
			exts.lenPrefixed(2, func(e *builder) {
				e.lenPrefixed(2, func(list *builder) {
					list.u8(0) // host_name
					list.lenPrefixed(2, func(n *builder) { n.raw([]byte(s.sni)) })
				})
			})
		}
		if len(s.groups) > 0 {
			exts.u16(0x000a)
			exts.lenPrefixed(2, func(e *builder) {
				e.lenPrefixed(2, func(l *builder) {
					for _, g := range s.groups {
						l.u16(g)
					}
				})
			})
		}
		if len(s.pointFormats) > 0 {
			exts.u16(0x000b)
			exts.lenPrefixed(2, func(e *builder) {
				e.lenPrefixed(1, func(l *builder) {
					for _, p := range s.pointFormats {
						l.u8(p)
					}
				})
			})
		}
		if len(s.sigAlgs) > 0 {
			exts.u16(0x000d)
			exts.lenPrefixed(2, func(e *builder) {
				e.lenPrefixed(2, func(l *builder) {
					for _, a := range s.sigAlgs {
						l.u16(a)
					}
				})
			})
		}
		if len(s.alpn) > 0 {
			exts.u16(0x0010)
			exts.lenPrefixed(2, func(e *builder) {
				e.lenPrefixed(2, func(l *builder) {
					for _, p := range s.alpn {
						l.lenPrefixed(1, func(n *builder) { n.raw([]byte(p)) })
					}
				})
			})
		}
		if len(s.supportedVersions) > 0 {
			exts.u16(0x002b)
			exts.lenPrefixed(2, func(e *builder) {
				e.lenPrefixed(1, func(l *builder) {
					for _, v := range s.supportedVersions {
						l.u16(v)
					}
				})
			})
		}
		if s.padTo > 0 && len(exts.b) < s.padTo {
			pad := s.padTo - len(exts.b) - 4
			if pad > 0 {
				exts.u16(0x0015) // padding
				exts.lenPrefixed(2, func(e *builder) { e.raw(make([]byte, pad)) })
			}
		}
	})

	var hs builder
	hs.u8(0x01) // ClientHello
	hs.lenPrefixed(3, func(w *builder) { w.raw(body.b) })

	var rec builder
	rec.u8(0x16) // handshake
	rec.u16(0x0301)
	rec.lenPrefixed(2, func(w *builder) { w.raw(hs.b) })
	return rec.b
}

// --- DNS --------------------------------------------------------------------

// dnsQuery builds a standard query for one name.
func dnsQuery(name string, qtype uint16) []byte {
	b := []byte{
		0x12, 0x34, // transaction id
		0x01, 0x00, // standard query, recursion desired
		0x00, 0x01, // qdcount = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	b = appendName(b, name)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1) // class IN
	return b
}

// dnsResponse builds a minimal NXDOMAIN-style reply, enough to make the flow
// bidirectional without pretending to carry real answer data.
func dnsResponse(name string) []byte {
	b := []byte{
		0x12, 0x34,
		0x81, 0x83, // response, recursion available, NXDOMAIN
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	b = appendName(b, name)
	b = binary.BigEndian.AppendUint16(b, 16)
	b = binary.BigEndian.AppendUint16(b, 1)
	return b
}

// appendName encodes a dotted name as length-prefixed labels. Labels longer
// than the 63-byte wire maximum are truncated rather than emitted invalid.
func appendName(b []byte, name string) []byte {
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 {
			label = label[:63]
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0)
}

// --- byte builder -----------------------------------------------------------

type builder struct{ b []byte }

func (w *builder) u8(v uint8)   { w.b = append(w.b, v) }
func (w *builder) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *builder) raw(p []byte) { w.b = append(w.b, p...) }

// lenPrefixed appends f's output prefixed by its length in n bytes.
func (w *builder) lenPrefixed(n int, f func(*builder)) {
	var inner builder
	f(&inner)
	switch n {
	case 1:
		w.u8(uint8(len(inner.b)))
	case 2:
		w.u16(uint16(len(inner.b)))
	case 3:
		w.u8(uint8(len(inner.b) >> 16))
		w.u16(uint16(len(inner.b)))
	}
	w.raw(inner.b)
}
