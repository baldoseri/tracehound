package quic

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// MinInitialDatagram is the padding floor RFC 9000 section 14.1 imposes on a
// client's Initial datagram, so that a server never amplifies traffic toward an
// unvalidated address.
const MinInitialDatagram = 1200

// BuildClientInitial constructs a client Initial packet carrying handshake
// bytes in a CRYPTO frame.
//
// This is the exact inverse of ParseInitial: seal with the AEAD, then apply
// header protection. It exists so the synthetic capture generator can produce
// genuine QUIC traffic rather than a plausible-looking imitation, and so the
// tests can round-trip through both directions instead of only agreeing with
// themselves.
//
// size is the target datagram length; the payload is padded to reach it.
func BuildClientInitial(dcid, scid []byte, cryptoOffset uint64, crypto []byte, size int) ([]byte, error) {
	if len(dcid) == 0 || len(dcid) > 20 || len(scid) > 20 {
		return nil, errors.New("quic: connection ID must be 1..20 bytes")
	}
	if size < MinInitialDatagram {
		size = MinInitialDatagram
	}

	k, err := deriveClientInitialKeys(Version1, dcid)
	if err != nil {
		return nil, err
	}

	const pnLen = 4
	const packetNumber = 0

	payload := appendVarint(nil, frameCrypto)
	payload = appendVarint(payload, cryptoOffset)
	payload = appendVarint(payload, uint64(len(crypto)))
	payload = append(payload, crypto...)

	// The Length field is a 2-byte varint for every datagram in the size range
	// a client Initial occupies, so the header size is known before it is built.
	headerLen := 1 + 4 + 1 + len(dcid) + 1 + len(scid) + 1 + 2 + pnLen
	if pad := size - headerLen - k.aead.Overhead() - len(payload); pad > 0 {
		// PADDING frames are literally zero bytes (RFC 9000 section 19.1).
		payload = append(payload, make([]byte, pad)...)
	}

	length := uint64(pnLen + len(payload) + k.aead.Overhead())
	lenField := appendVarint(nil, length)
	if len(lenField) != 2 {
		return nil, fmt.Errorf("quic: payload of %d bytes is outside the supported Initial size range", len(payload))
	}

	header := []byte{0xc0 | (pnLen - 1)} // long header, fixed bit, Initial type
	header = binary.BigEndian.AppendUint32(header, Version1)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = appendVarint(header, 0) // empty token
	header = append(header, lenField...)

	pnOffset := len(header)
	header = binary.BigEndian.AppendUint32(header, packetNumber)

	ciphertext := k.aead.Seal(nil, k.nonce(packetNumber), payload, header)

	// The protection sample sits four bytes past the packet number offset,
	// which lands inside the ciphertext for any packet number shorter than
	// four bytes and exactly at its start for a four-byte one.
	sampleStart := sampleOffset - pnLen
	if sampleStart+sampleLength > len(ciphertext) {
		return nil, ErrTruncated
	}
	mask, err := headerMask(k.hp, ciphertext[sampleStart:sampleStart+sampleLength])
	if err != nil {
		return nil, err
	}

	out := append([]byte(nil), header...)
	out[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		out[pnOffset+i] ^= mask[1+i]
	}
	return append(out, ciphertext...), nil
}
