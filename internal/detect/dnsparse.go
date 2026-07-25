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

// twoLabelSuffixes are public suffixes that are themselves two labels long.
//
// This is not the full Public Suffix List. That file is roughly a megabyte,
// changes continuously, and would impose an update obligation on a detector
// whose scoring is dominated by subdomain entropy regardless. What it buys is
// grouping "a.example.co.uk" under "example.co.uk" rather than "co.uk", and the
// handful of suffixes below covers the overwhelming majority of real traffic.
//
// Getting this wrong in the naive direction is not merely cosmetic: collapsing
// every British site onto "co.uk" merges unrelated domains into one bucket,
// which both dilutes a real tunnel's signal and manufactures apparent
// high-entropy diversity under a suffix nobody controls.
var twoLabelSuffixes = map[string]struct{}{
	"ac.uk": {}, "co.uk": {}, "gov.uk": {}, "ltd.uk": {}, "me.uk": {},
	"net.uk": {}, "org.uk": {}, "plc.uk": {}, "sch.uk": {},
	"com.au": {}, "edu.au": {}, "gov.au": {}, "id.au": {}, "net.au": {}, "org.au": {},
	"ac.jp": {}, "co.jp": {}, "go.jp": {}, "ne.jp": {}, "or.jp": {},
	"ac.nz": {}, "co.nz": {}, "govt.nz": {}, "net.nz": {}, "org.nz": {},
	"co.za": {}, "gov.za": {}, "net.za": {}, "org.za": {},
	"com.br": {}, "net.br": {}, "org.br": {}, "gov.br": {},
	"com.cn": {}, "net.cn": {}, "org.cn": {}, "gov.cn": {}, "edu.cn": {},
	"com.hk": {}, "com.tw": {}, "com.sg": {}, "com.my": {}, "com.vn": {},
	"com.mx": {}, "com.ar": {}, "com.co": {}, "com.pe": {}, "com.ph": {},
	"com.tr": {}, "com.pk": {}, "com.eg": {}, "com.sa": {}, "com.ua": {},
	"co.in": {}, "co.kr": {}, "co.il": {}, "co.id": {}, "co.th": {}, "co.ke": {},
	"or.kr": {}, "ne.kr": {}, "go.kr": {},
	"gov.in": {}, "net.in": {}, "org.in": {}, "edu.in": {},
	"eu.org": {}, "us.com": {}, "uk.com": {}, "gov.us": {},
}

// registeredDomain returns the registrable portion of a name: the label a
// registrant actually controls, plus its public suffix.
//
// This is the level at which tunnelling is scored. An attacker controls one
// domain and varies the subdomains beneath it, so grouping by anything more
// specific would split a single tunnel into thousands of unrelated
// observations and hide it.
func registeredDomain(labels []string) string {
	n := len(labels)
	switch {
	case n == 0:
		return ""
	case n == 1:
		return labels[0]
	}

	if n >= 3 {
		if _, ok := twoLabelSuffixes[labels[n-2]+"."+labels[n-1]]; ok {
			return labels[n-3] + "." + labels[n-2] + "." + labels[n-1]
		}
	}
	return labels[n-2] + "." + labels[n-1]
}

// registeredLabels reports how many trailing labels registeredDomain consumed.
func registeredLabels(labels []string) int {
	n := len(labels)
	if n >= 3 {
		if _, ok := twoLabelSuffixes[labels[n-2]+"."+labels[n-1]]; ok {
			return 3
		}
	}
	return min(n, 2)
}

// subdomainOf returns everything to the left of the registered domain — the
// part an attacker is free to fill with encoded payload.
func subdomainOf(labels []string) string {
	keep := len(labels) - registeredLabels(labels)
	if keep <= 0 {
		return ""
	}
	return strings.Join(labels[:keep], ".")
}

// isHighSignalType reports whether a query type is one commonly used to carry
// tunnelled data.
func isHighSignalType(t uint16) bool {
	return t == dnsTypeTXT || t == dnsTypeNULL || t == dnsTypeCNAME
}
