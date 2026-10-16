package interactsh

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"testing"
)

func TestKeyFormats(t *testing.T) {
	keys, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	if keys.PrivateKey.N.BitLen() != 2048 {
		t.Fatalf("expected 2048-bit key, got %d", keys.PrivateKey.N.BitLen())
	}
	// Public key must be base64 of a PEM SPKI block.
	raw, err := base64.StdEncoding.DecodeString(keys.PublicKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("-----BEGIN PUBLIC KEY-----")) {
		t.Fatalf("public key not PEM SPKI: %q", raw[:40])
	}
	if !bytes.Contains([]byte(keys.PrivateKeyPEM), []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("private key not PKCS#8 PEM")
	}
}

func TestDecryptRoundTrip(t *testing.T) {
	keys, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the interactsh server: random AES-256 key, OAEP(SHA-256) wrapped.
	aesKey := make([]byte, 32)
	rand.Read(aesKey)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &keys.PrivateKey.PublicKey, aesKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := `{"protocol":"http","raw-request":"GET /x?flag=1 HTTP/1.1\r\nHost: h\r\n"}`
	block, _ := aes.NewCipher(aesKey)
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)
	ct := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(ct, []byte(plaintext)) // current fleet: AES-CTR
	payload := base64.StdEncoding.EncodeToString(append(append([]byte{}, iv...), ct...))

	unwrapped, err := DecryptAESKey(keys.PrivateKey, base64.StdEncoding.EncodeToString(wrapped))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unwrapped, aesKey) {
		t.Fatal("aes key mismatch after OAEP unwrap")
	}
	got, err := DecryptPayload(unwrapped, payload)
	if err != nil {
		t.Fatal(err)
	}
	if got != plaintext {
		t.Fatalf("plaintext mismatch:\n got %q\nwant %q", got, plaintext)
	}
}

// Older interactsh fleets encrypted events with AES-256-CFB (full-block CFB128,
// Node's default for 'aes-256-cfb'). The fallback path must still decrypt those.
func TestDecryptPayloadCFBFallback(t *testing.T) {
	aesKey := make([]byte, 32)
	rand.Read(aesKey)
	block, _ := aes.NewCipher(aesKey)
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	plaintext := `{"protocol":"smtp","raw":"MAIL FROM:<x@y>"}` // >16 bytes: crosses the first block
	ct := make([]byte, len(plaintext))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ct, []byte(plaintext))
	payload := base64.StdEncoding.EncodeToString(append(append([]byte{}, iv...), ct...))

	got, err := DecryptPayload(aesKey, payload)
	if err != nil {
		t.Fatal(err)
	}
	if got != plaintext {
		t.Fatalf("cfb fallback mismatch:\n got %q\nwant %q", got, plaintext)
	}
}

func TestRandomIdentifiers(t *testing.T) {
	cid, err := RandomCorrelationID()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{20}$`).MatchString(cid) {
		t.Fatalf("correlation id format: %q", cid)
	}

	secret, err := RandomSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]{24}$`).MatchString(secret) {
		t.Fatalf("secret key format: %q", secret)
	}

	nonce := RandomNonce13()
	if !regexp.MustCompile(`^[a-z0-9]{13}$`).MatchString(nonce) {
		t.Fatalf("nonce format: %q", nonce)
	}
}
