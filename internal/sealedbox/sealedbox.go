// Package sealedbox implements the hybrid public-key encryption used to store
// mailbox contents end-to-end encrypted.
//
// The scheme (ECIES-style sealed box) is:
//
//	seal(plaintext, recipientPublic R):
//	  (e_sk, e_pk) = ephemeral X25519 key pair, fresh per message
//	  shared = X25519(e_sk, R)
//	  key    = HKDF-SHA256(ikm=shared, salt=e_pk‖R, info="senderreport-content-v1", 32)
//	  nonce  = 12 random bytes
//	  ct     = AES-256-GCM.Seal(key, nonce, plaintext, aad=e_pk)
//	  blob   = "MPE1" ‖ e_pk[32] ‖ nonce[12] ‖ ct
//
//	open(blob, recipientSecret r):
//	  shared = X25519(r, e_pk)
//	  R      = X25519.base(r)
//	  key    = HKDF-SHA256(shared, salt=e_pk‖R, info="senderreport-content-v1", 32)
//	  plaintext = AES-256-GCM.Open(key, nonce, ct, aad=e_pk)
//
// The server only ever holds recipient *public* keys, so it can Seal but never
// Open. Only the holder of the token (which carries the X25519 secret) can Open.
//
// The byte layout is identical to static/crypto.js so both sides interoperate.
// See docs/ENCRYPTION.md for the full architecture.
package sealedbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// Magic prefix identifying the blob format / version.
	magic = "MPE1"

	// HKDF info string. Changing this breaks compatibility with existing blobs.
	hkdfInfo = "senderreport-content-v1"

	// Domain separator for the identifier hash.
	identDomain = "senderreport-id-v1"

	keySize   = 32 // X25519 key size
	nonceSize = 12 // AES-GCM nonce
	tagSize   = 16 // AES-GCM tag
	identLen  = 10 // bytes of SHA-256 used for the identifier (16 base32 chars)
)

var (
	ErrBadKeySize    = errors.New("sealedbox: key must be 32 bytes")
	ErrBadBlob       = errors.New("sealedbox: malformed ciphertext blob")
	ErrOpenFailed    = errors.New("sealedbox: decryption failed")
	identEncoding    = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// KeyPair holds an X25519 key pair. The browser normally generates these;
// this type exists mainly for tests and tooling.
type KeyPair struct {
	Secret [keySize]byte
	Public [keySize]byte
}

// GenerateKeyPair creates a new random X25519 key pair.
func GenerateKeyPair() (KeyPair, error) {
	var kp KeyPair
	if _, err := io.ReadFull(rand.Reader, kp.Secret[:]); err != nil {
		return KeyPair{}, err
	}
	pub, err := curve25519.X25519(kp.Secret[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, err
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// PublicFromSecret derives the X25519 public key from a 32-byte secret.
func PublicFromSecret(secret []byte) ([]byte, error) {
	if len(secret) != keySize {
		return nil, ErrBadKeySize
	}
	return curve25519.X25519(secret, curve25519.Basepoint)
}

// Identifier derives the lowercase base32 mailbox identifier from a public key.
// It is a one-way hash: the identifier reveals neither public nor secret key.
// Used as the email local-part and the database lookup key.
func Identifier(public []byte) string {
	sum := sha256.Sum256(append([]byte(identDomain), public...))
	return toLower(identEncoding.EncodeToString(sum[:identLen]))
}

// Seal encrypts plaintext to the recipient's public key using a fresh ephemeral
// key pair. The result can only be decrypted with the matching secret key.
func Seal(plaintext, recipientPublic []byte) ([]byte, error) {
	if len(recipientPublic) != keySize {
		return nil, ErrBadKeySize
	}
	var ephSecret [keySize]byte
	if _, err := io.ReadFull(rand.Reader, ephSecret[:]); err != nil {
		return nil, err
	}
	return sealWithEphemeral(plaintext, recipientPublic, ephSecret[:])
}

// sealWithEphemeral is Seal with a caller-provided ephemeral secret. It exists
// so tests can produce deterministic vectors; production code must use Seal.
func sealWithEphemeral(plaintext, recipientPublic, ephSecret []byte) ([]byte, error) {
	if len(recipientPublic) != keySize || len(ephSecret) != keySize {
		return nil, ErrBadKeySize
	}
	ephPublic, err := curve25519.X25519(ephSecret, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(ephSecret, recipientPublic)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(shared, ephPublic, recipientPublic)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	var nonce [nonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce[:], plaintext, ephPublic)

	blob := make([]byte, 0, len(magic)+keySize+nonceSize+len(ct))
	blob = append(blob, magic...)
	blob = append(blob, ephPublic...)
	blob = append(blob, nonce[:]...)
	blob = append(blob, ct...)
	return blob, nil
}

// Open decrypts a blob produced by Seal using the recipient's secret key.
func Open(blob, recipientSecret []byte) ([]byte, error) {
	if len(recipientSecret) != keySize {
		return nil, ErrBadKeySize
	}
	if len(blob) < len(magic)+keySize+nonceSize+tagSize {
		return nil, ErrBadBlob
	}
	if string(blob[:len(magic)]) != magic {
		return nil, ErrBadBlob
	}
	off := len(magic)
	ephPublic := blob[off : off+keySize]
	off += keySize
	nonce := blob[off : off+nonceSize]
	off += nonceSize
	ct := blob[off:]

	recipientPublic, err := curve25519.X25519(recipientSecret, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(recipientSecret, ephPublic)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(shared, ephPublic, recipientPublic)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, ephPublic)
	if err != nil {
		return nil, ErrOpenFailed
	}
	return pt, nil
}

func deriveKey(shared, ephPublic, recipientPublic []byte) ([]byte, error) {
	salt := make([]byte, 0, len(ephPublic)+len(recipientPublic))
	salt = append(salt, ephPublic...)
	salt = append(salt, recipientPublic...)
	r := hkdf.New(sha256.New, shared, salt, []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sealedbox: aes: %w", err)
	}
	return cipher.NewGCM(block)
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
