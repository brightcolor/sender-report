package sealedbox

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	plaintext := []byte("Subject: Hallo\r\n\r\nGeheimer Mailinhalt äöü 🚀")

	blob, err := Seal(plaintext, kp.Public[:])
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if string(blob[:4]) != magic {
		t.Fatalf("missing magic prefix")
	}
	got, err := Open(blob, kp.Secret[:])
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: %q != %q", got, plaintext)
	}
}

func TestWrongKeyFails(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	blob, err := Seal([]byte("secret"), kp1.Public[:])
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := Open(blob, kp2.Secret[:]); err == nil {
		t.Fatalf("expected open with wrong key to fail")
	}
}

func TestTamperFails(t *testing.T) {
	kp, _ := GenerateKeyPair()
	blob, _ := Seal([]byte("authentic message"), kp.Public[:])
	blob[len(blob)-1] ^= 0x01 // flip a bit in the GCM tag
	if _, err := Open(blob, kp.Secret[:]); err == nil {
		t.Fatalf("expected tampered blob to fail authentication")
	}
}

func TestEmptyPlaintext(t *testing.T) {
	kp, _ := GenerateKeyPair()
	blob, err := Seal(nil, kp.Public[:])
	if err != nil {
		t.Fatalf("seal empty: %v", err)
	}
	got, err := Open(blob, kp.Secret[:])
	if err != nil {
		t.Fatalf("open empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(got))
	}
}

func TestIdentifierFromPublic(t *testing.T) {
	kp, _ := GenerateKeyPair()
	id1 := Identifier(kp.Public[:])
	id2 := Identifier(kp.Public[:])
	if id1 != id2 {
		t.Fatalf("identifier not deterministic")
	}
	if len(id1) != 16 {
		t.Fatalf("expected 16-char identifier, got %d (%q)", len(id1), id1)
	}
	// All lowercase base32 (a-z2-7)
	for _, c := range id1 {
		if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
			t.Fatalf("identifier has invalid char %q in %q", c, id1)
		}
	}
	kp2, _ := GenerateKeyPair()
	if Identifier(kp2.Public[:]) == id1 {
		t.Fatalf("different keys produced same identifier")
	}
}

func TestPublicFromSecretMatches(t *testing.T) {
	kp, _ := GenerateKeyPair()
	pub, err := PublicFromSecret(kp.Secret[:])
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if !bytes.Equal(pub, kp.Public[:]) {
		t.Fatalf("derived public key does not match generated one")
	}
}

func TestBadKeySizes(t *testing.T) {
	if _, err := Seal([]byte("x"), make([]byte, 10)); err != ErrBadKeySize {
		t.Fatalf("expected ErrBadKeySize for short public key")
	}
	if _, err := Open(make([]byte, 100), make([]byte, 10)); err != ErrBadKeySize {
		t.Fatalf("expected ErrBadKeySize for short secret key")
	}
}

// TestVector produces a deterministic blob from fixed inputs. The same vector is
// embedded in static/crypto.js (cryptoSelfTest) to prove Go↔JS interop. Run with
//   go test ./internal/sealedbox/ -run TestVector -v
// and copy the printed values into crypto.js if the construction ever changes.
func TestVector(t *testing.T) {
	recipientSecret := mustHex("0101010101010101010101010101010101010101010101010101010101010101")
	ephemeralSecret := mustHex("0202020202020202020202020202020202020202020202020202020202020202")
	plaintext := []byte("sender.report e2e test vector")

	recipientPublic, err := PublicFromSecret(recipientSecret)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	blob, err := sealWithEphemeral(plaintext, recipientPublic, ephemeralSecret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Confirm it round-trips.
	got, err := Open(blob, recipientSecret)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("vector does not round-trip")
	}

	t.Logf("recipient_secret = %s", hex.EncodeToString(recipientSecret))
	t.Logf("recipient_public = %s", hex.EncodeToString(recipientPublic))
	t.Logf("identifier       = %s", Identifier(recipientPublic))
	t.Logf("plaintext        = %q", plaintext)
	t.Logf("blob (hex)       = %s", hex.EncodeToString(blob))
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
