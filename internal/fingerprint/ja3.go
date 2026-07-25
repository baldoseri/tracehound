package fingerprint

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

// JA3 computes the legacy JA3 fingerprint (Salesforce, 2017).
//
// JA3 is strictly worse than JA4 — it hashes the cipher and extension lists in
// wire order, so Chrome's extension-order randomisation (shipped 2023) gives
// the same browser a different JA3 on every connection. It is implemented here
// anyway for one practical reason: essentially every existing threat-intel
// feed, IDS ruleset, and malware report published before 2024 is indexed by
// JA3. Emitting both means tracehound can be joined against that decade of
// public intelligence while still using JA4 for its own detection logic.
//
// The pre-hash string is:
//
//	SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
//
// with each list dash-separated and rendered in decimal.
func JA3(ch *ClientHello) (fingerprint, raw string) {
	var b strings.Builder

	b.WriteString(strconv.Itoa(int(ch.LegacyVersion)))
	b.WriteByte(',')
	writeDecList16(&b, ch.CipherSuites)
	b.WriteByte(',')
	writeDecList16(&b, ch.Extensions)
	b.WriteByte(',')
	writeDecList16(&b, ch.SupportedGroups)
	b.WriteByte(',')
	writeDecList8(&b, ch.PointFormats)

	raw = b.String()
	sum := md5.Sum([]byte(raw))
	return hex.EncodeToString(sum[:]), raw
}

func writeDecList16(b *strings.Builder, vs []uint16) {
	for i, v := range vs {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.Itoa(int(v)))
	}
}

func writeDecList8(b *strings.Builder, vs []uint8) {
	for i, v := range vs {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.Itoa(int(v)))
	}
}
