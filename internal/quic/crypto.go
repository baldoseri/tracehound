package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Version1 is the only QUIC version handled here (RFC 9000). Draft versions and
// QUIC v2 use different initial salts, so treating them as v1 would derive
// wrong keys and produce garbage rather than a clean failure.
const Version1 uint32 = 0x00000001

// initialSaltV1 is the salt for deriving Initial keys in QUIC v1, from
// RFC 9001 section 5.2. It is a constant published in the specification, not a
// secret: every QUIC endpoint and every observer uses the same value.
var initialSaltV1 = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// keys holds the client Initial secrets for one connection.
type keys struct {
	secret []byte // client_initial_secret, kept for tests
	key    []byte // AEAD key, 16 bytes for AES-128-GCM
	iv     []byte // AEAD nonce base, 12 bytes
	hp     []byte // header protection key, 16 bytes
	aead   cipher.AEAD
}

// deriveClientInitialKeys computes the client's Initial packet protection keys
// from the Destination Connection ID.
//
// The whole security argument for Initial packets is that they are not secret,
// only integrity-protected against off-path attackers. RFC 9001 section 5.2:
//
//	initial_secret        = HKDF-Extract(initial_salt, client_dst_connection_id)
//	client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
//	key                   = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)
//	iv                    = HKDF-Expand-Label(client_initial_secret, "quic iv",  "", 12)
//	hp                    = HKDF-Expand-Label(client_initial_secret, "quic hp",  "", 16)
func deriveClientInitialKeys(version uint32, dcid []byte) (*keys, error) {
	if version != Version1 {
		return nil, fmt.Errorf("quic: unsupported version %#08x", version)
	}

	initialSecret := hkdfExtract(initialSaltV1, dcid)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", 32)

	k := &keys{
		secret: clientSecret,
		key:    hkdfExpandLabel(clientSecret, "quic key", 16),
		iv:     hkdfExpandLabel(clientSecret, "quic iv", 12),
		hp:     hkdfExpandLabel(clientSecret, "quic hp", 16),
	}

	block, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, err
	}
	if k.aead, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}
	return k, nil
}

// hkdfExtract is HKDF-Extract with SHA-256 (RFC 5869 section 2.2).
//
// Written out rather than pulled from a library because it is four lines, and
// because the whole point of this file is to show the key schedule rather than
// hide it behind a helper.
func hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpandLabel is the TLS 1.3 labelled HKDF-Expand (RFC 8446 section 7.1),
// which QUIC reuses verbatim. The label is always prefixed with "tls13 ".
//
//	struct {
//	    uint16 length;
//	    opaque label<7..255>   = "tls13 " + Label;
//	    opaque context<0..255> = Context;
//	} HkdfLabel;
func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label

	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // zero-length context

	return hkdfExpand(secret, info, length)
}

// hkdfExpand is HKDF-Expand with SHA-256 (RFC 5869 section 2.3).
func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var block []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(block)
		mac.Write(info)
		mac.Write([]byte{counter})
		block = mac.Sum(nil)
		out = append(out, block...)
	}
	return out[:length]
}

// headerMask computes the header protection mask for a sample of ciphertext
// (RFC 9001 section 5.4.3). For AES-based suites the mask is simply the sample
// encrypted with the header protection key in ECB mode, which is the one place
// a single AES block cipher call is the correct construction rather than a
// mistake.
func headerMask(hp, sample []byte) ([]byte, error) {
	if len(sample) < aes.BlockSize {
		return nil, ErrTruncated
	}
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, aes.BlockSize)
	block.Encrypt(mask, sample[:aes.BlockSize])
	return mask, nil
}

// nonce builds the AEAD nonce: the packet number, left-padded to the IV length,
// XORed with the static IV (RFC 9001 section 5.3).
func (k *keys) nonce(packetNumber uint64) []byte {
	n := make([]byte, len(k.iv))
	binary.BigEndian.PutUint64(n[len(n)-8:], packetNumber)
	for i := range n {
		n[i] ^= k.iv[i]
	}
	return n
}

// open authenticates and decrypts a packet payload. The header, including the
// unprotected packet number, is the associated data.
func (k *keys) open(header, ciphertext []byte, packetNumber uint64) ([]byte, error) {
	if len(ciphertext) < k.aead.Overhead() {
		return nil, ErrTruncated
	}
	plain, err := k.aead.Open(nil, k.nonce(packetNumber), ciphertext, header)
	if err != nil {
		// A failure here is expected and common: any packet that is not
		// actually a client Initial for this version decrypts to noise, and the
		// tag check is what tells us so.
		return nil, errors.New("quic: AEAD authentication failed")
	}
	return plain, nil
}
