package interactsh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"unicode/utf8"
)

// KeyMaterial holds an interactsh session keypair in the exact wire formats
// expected by the interactsh server and mirrored by the reference Node bridge.
type KeyMaterial struct {
	PrivateKey    *rsa.PrivateKey // RSA-2048
	PublicKeyB64  string          // base64(PEM(SPKI public key)) — sent to /register
	PrivateKeyPEM string          // PEM(PKCS#8 private key) — returned to the MCP client
}

// GenerateKeys creates a fresh RSA-2048 key pair for a session.
func GenerateKeys() (*KeyMaterial, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	return &KeyMaterial{
		PrivateKey:    priv,
		PublicKeyB64:  base64.StdEncoding.EncodeToString(pubPEM),
		PrivateKeyPEM: string(privPEM),
	}, nil
}

// DecryptAESKey unwraps the per-poll AES key: RSA-OAEP with SHA-256.
func DecryptAESKey(priv *rsa.PrivateKey, aesKeyB64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(aesKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode aes_key: %w", err)
	}
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa-oaep unwrap: %w", err)
	}
	return key, nil
}

// DecryptPayload decrypts one interaction event: base64 → IV(16) || AES-256
// ciphertext. The current interactsh server uses AES-256-CTR (see the official
// client's decryptMessage); older fleets used AES-256-CFB. CTR is tried first
// and CFB128 as a fallback, discriminated by UTF-8 validity: interactsh events
// are JSON text, while a wrong mode yields mojibake.
func DecryptPayload(aesKey []byte, payloadB64 string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	if len(data) < aes.BlockSize {
		return "", fmt.Errorf("payload shorter than IV")
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}
	iv, ciphertext := data[:aes.BlockSize], data[aes.BlockSize:]

	ctrPlaintext := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(ctrPlaintext, ciphertext)
	if utf8.Valid(ctrPlaintext) {
		return string(ctrPlaintext), nil
	}

	cfbPlaintext := make([]byte, len(ciphertext))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(cfbPlaintext, ciphertext)
	if utf8.Valid(cfbPlaintext) {
		return string(cfbPlaintext), nil
	}

	return string(ctrPlaintext), nil
}

// RandomCorrelationID mirrors the interactsh default: 10 random bytes → 20 lowercase hex chars.
func RandomCorrelationID() (string, error) {
	buf := make([]byte, 10)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

const secretAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// RandomSecretKey returns exactly 24 alphanumeric chars. The reference Node
// bridge drew 18 random bytes through base64 + alphanumeric filtering + a
// 24-char slice, which shrinks below 24 whenever '+', '/' or '=' show up;
// drawing directly from the alphabet keeps the length deterministic while
// staying in the exact same character class the interactsh server accepts.
func RandomSecretKey() (string, error) {
	buf := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	out := make([]byte, 24)
	for i, b := range buf {
		out[i] = secretAlphabet[int(b)%len(secretAlphabet)]
	}
	return string(out), nil
}

const nonceAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// RandomNonce13 returns exactly 13 lowercase alphanumeric chars for probe hosts.
// The nonce is a public label, so crypto/rand bytes reduced modulo the alphabet
// are more than enough (and avoid legacy math/rand entirely).
func RandomNonce13() string {
	buf := make([]byte, 13)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		for i := range buf {
			buf[i] = byte(i)
		}
	}
	for i := range buf {
		buf[i] = nonceAlphabet[int(buf[i])%len(nonceAlphabet)]
	}
	return string(buf)
}
