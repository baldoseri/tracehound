package detect

import "strings"

// Minimal DNS question parsing.
//
// Only the question section is decoded, and only the first question at that,
// because that is all the tunnelling detector needs: the query name carries the
// smuggled data. Answers, authority, and additional sections are ignored, which
// keeps this immune to most of the parsing bugs that DNS libraries are famous
// for.

// DNS query types the tunnelling detector treats as high-signal. TXT and NULL
// carry the most bytes per response and are the classic tunnel carriers; CNAME
// is the usual fallback when TXT is filtered.
const (
	dnsTypeA     uint16 = 1
	dnsTypeCNAME uint16 = 5
	dnsTypeNULL  uint16 = 10
	dnsTypeTXT   uint16 = 16
	dnsTypeAAAA  uint16 = 28
)

const dnsHeaderLen = 12

// dnsQuestion is the decoded first question of a DNS message.
type dnsQuestion struct {
	Name   string // fully-qualified, dot-separated, no trailing dot
	Labels []string
	Type   uint16
}

// parseDNSQuestion decodes the first question from a DNS message.
//
// It returns false for anything that is not a well-formed query with at least
// one question, including responses — the tunnelling detector scores what the
// client asks for, not what the server answers.
func parseDNSQuestion(b []byte) (dnsQuestion, bool) {
	if len(b) < dnsHeaderLen {
		return dnsQuestion{}, false
	}

	// Byte 2 bit 7 is QR: 0 = query. Ignore responses.
	if b[2]&0x80 != 0 {
		return dnsQuestion{}, false
	}
	qdcount := int(b[4])<<8 | int(b[5])
	if qdcount < 1 {
		return dnsQuestion{}, false
	}

	labels, off, ok := readName(b, dnsHeaderLen)
	if !ok || len(labels) == 0 {
		return dnsQuestion{}, false
	}
	if off+4 > len(b) {
		return dnsQuestion{}, false
	}
	qtype := uint16(b[off])<<8 | uint16(b[off+1])

	return dnsQuestion{
		Name:   strings.Join(labels, "."),
		Labels: labels,
		Type:   qtype,
	}, true
}

// readName decodes a DNS name at off, returning the labels and the offset just
// past the name.
//
// Compression pointers are rejected rather than followed. A pointer has no
// legitimate use in a question section, and following them is where DNS parsers
// acquire their infinite-loop vulnerabilities.
func readName(b []byte, off int) (labels []string, next int, ok bool) {
	const maxName = 255
	total := 0

	for off < len(b) {
		n := int(b[off])
		off++

		switch {
		case n == 0:
			return labels, off, true
		case n&0xc0 != 0:
			return nil, 0, false // compression pointer or reserved form
		}

		if off+n > len(b) {
			return nil, 0, false
		}
		total += n + 1
		if total > maxName {
			return nil, 0, false
		}
		labels = append(labels, string(b[off:off+n]))
		off += n
	}
	return nil, 0, false // ran off the end without a terminator
}

// registeredDomain returns the last two labels of a name, which is the level at
// which tunnelling is scored: an attacker controls one domain and varies the
// subdomains beneath it, so grouping by anything more specific would split one
// tunnel into thousands of unrelated observations.
//
// This is a deliberate approximation. A public-suffix list would place
// "example.co.uk" correctly where this returns "co.uk"; the tradeoff is a
// megabyte of embedded data and a periodic update obligation, for a detector
// whose scoring is dominated by subdomain entropy either way.
func registeredDomain(labels []string) string {
	switch len(labels) {
	case 0:
		return ""
	case 1:
		return labels[0]
	default:
		return labels[len(labels)-2] + "." + labels[len(labels)-1]
	}
}

// subdomainOf returns everything to the left of the registered domain.
func subdomainOf(labels []string) string {
	if len(labels) <= 2 {
		return ""
	}
	return strings.Join(labels[:len(labels)-2], ".")
}

// isHighSignalType reports whether a query type is one commonly used to carry
// tunnelled data.
func isHighSignalType(t uint16) bool {
	return t == dnsTypeTXT || t == dnsTypeNULL || t == dnsTypeCNAME
}
