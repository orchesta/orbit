package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Encryptor handles AES-256-GCM encryption/decryption for sensitive data like auth tokens.
type Encryptor struct {
	gcm cipher.AEAD
}

// NewEncryptor creates a new Encryptor with the given hex-encoded AES-256 key.
// Key must be 64 hex characters (32 bytes = 256 bits).
func NewEncryptor(hexKey string) (*Encryptor, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &Encryptor{gcm: gcm}, nil
}

// Encrypt encrypts plaintext and returns a base64-encoded ciphertext string.
// Format: base64(nonce + ciphertext + tag)
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal appends ciphertext + authentication tag to nonce
	ciphertext := e.gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded ciphertext string and returns the plaintext.
func (e *Encryptor) Decrypt(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	nonceSize := e.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed (invalid key or corrupted data): %w", err)
	}

	return string(plaintext), nil
}

// sealedPrefix marks values produced by Seal. Stored values without it are
// legacy plaintext written before encryption at rest was enabled.
const sealedPrefix = "enc:v1:"

// IsSealed reports whether a stored value was produced by Seal.
func IsSealed(stored string) bool {
	return strings.HasPrefix(stored, sealedPrefix)
}

// IsSealed reports whether a stored value was produced by Seal.
func (e *Encryptor) IsSealed(stored string) bool {
	return IsSealed(stored)
}

// Seal encrypts a secret for storage. An empty secret stays empty so that
// "no token" remains distinguishable in the database.
func (e *Encryptor) Seal(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	ciphertext, err := e.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return sealedPrefix + ciphertext, nil
}

// Open decrypts a value produced by Seal. Legacy plaintext (no prefix) is
// returned unchanged so rows written before encryption keep working until
// they are sealed.
func (e *Encryptor) Open(stored string) (string, error) {
	if !IsSealed(stored) {
		return stored, nil
	}
	return e.Decrypt(strings.TrimPrefix(stored, sealedPrefix))
}

// GenerateKey generates a random 256-bit encryption key and returns it as hex.
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}
