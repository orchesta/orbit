package crypto

import (
	"strings"
	"testing"
)

const keyA = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
const keyB = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"

func mustEncryptor(t *testing.T, key string) *Encryptor {
	t.Helper()
	e, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestSealOpenRoundTrip(t *testing.T) {
	e := mustEncryptor(t, keyA)
	sealed, err := e.Seal("ghp_supersecret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "enc:v1:") || strings.Contains(sealed, "supersecret") {
		t.Fatalf("sealed value %q must carry the prefix and hide the plaintext", sealed)
	}
	if !e.IsSealed(sealed) || !IsSealed(sealed) {
		t.Fatal("IsSealed should recognise a sealed value")
	}
	got, err := e.Open(sealed)
	if err != nil || got != "ghp_supersecret" {
		t.Fatalf("Open = %q, %v", got, err)
	}
}

func TestSealEmptyStaysEmpty(t *testing.T) {
	e := mustEncryptor(t, keyA)
	sealed, err := e.Seal("")
	if err != nil || sealed != "" {
		t.Fatalf("Seal(\"\") = %q, %v; want empty", sealed, err)
	}
}

func TestOpenPassesLegacyPlaintextThrough(t *testing.T) {
	e := mustEncryptor(t, keyA)
	got, err := e.Open("ghp_legacyplaintext")
	if err != nil || got != "ghp_legacyplaintext" {
		t.Fatalf("Open(legacy) = %q, %v", got, err)
	}
	if e.IsSealed("ghp_legacyplaintext") {
		t.Fatal("legacy plaintext must not be reported as sealed")
	}
}

func TestOpenWithWrongKeyFails(t *testing.T) {
	sealed, err := mustEncryptor(t, keyA).Seal("ghp_supersecret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mustEncryptor(t, keyB).Open(sealed); err == nil {
		t.Fatal("opening with a different key must fail")
	}
}

func TestOpenRejectsTamperedValue(t *testing.T) {
	e := mustEncryptor(t, keyA)
	sealed, err := e.Seal("ghp_supersecret")
	if err != nil {
		t.Fatal(err)
	}
	tampered := sealed[:len(sealed)-2] + "AA"
	if tampered == sealed {
		tampered = sealed[:len(sealed)-2] + "BB"
	}
	if _, err := e.Open(tampered); err == nil {
		t.Fatal("tampered ciphertext must fail authentication")
	}
}

func TestNewEncryptorRejectsBadKeys(t *testing.T) {
	for _, key := range []string{"", "zz", keyA[:62]} {
		if _, err := NewEncryptor(key); err == nil {
			t.Fatalf("key %q: expected error", key)
		}
	}
}
