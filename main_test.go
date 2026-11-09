package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestEncryptionRoundTrip(t *testing.T) {
	curve := ecdh.X25519()
	recipient, err := curve.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	shared, err := eph.ECDH(recipient.PublicKey())
	if err != nil { t.Fatal(err) }
	key, err := deriveKey(shared)
	if err != nil { t.Fatal(err) }
	aead, err := chacha20poly1305.NewX(key)
	if err != nil { t.Fatal(err) }
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil { t.Fatal(err) }
	plain := []byte("BYANOVA test message")
	aad := append([]byte(formatMagic), eph.PublicKey().Bytes()...)
	aad = append(aad, recipient.PublicKey().Bytes()...)
	sealed := aead.Seal(nil, nonce, plain, aad)
	shared2, err := recipient.ECDH(eph.PublicKey())
	if err != nil { t.Fatal(err) }
	key2, err := deriveKey(shared2)
	if err != nil { t.Fatal(err) }
	aead2, err := chacha20poly1305.NewX(key2)
	if err != nil { t.Fatal(err) }
	got, err := aead2.Open(nil, nonce, sealed, aad)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(got, plain) { t.Fatalf("got %q, want %q", got, plain) }
}

func TestTamperingIsRejected(t *testing.T) {
	curve := ecdh.X25519()
	recipient, _ := curve.GenerateKey(rand.Reader)
	eph, _ := curve.GenerateKey(rand.Reader)
	shared, _ := eph.ECDH(recipient.PublicKey())
	key, _ := deriveKey(shared)
	aead, _ := chacha20poly1305.NewX(key)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	_, _ = rand.Read(nonce)
	aad := append([]byte(formatMagic), eph.PublicKey().Bytes()...)
	aad = append(aad, recipient.PublicKey().Bytes()...)
	sealed := aead.Seal(nil, nonce, []byte("secret"), aad)
	sealed[0] ^= 1
	if _, err := aead.Open(nil, nonce, sealed, aad); err == nil { t.Fatal("tampered ciphertext was accepted") }
}
