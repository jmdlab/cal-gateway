package atrest

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestSealOpenRoundTrip: a sealed blob reopens identically, and does carry the
// magic (so IsSealed recognizes it).
func TestSealOpenRoundTrip(t *testing.T) {
	c, err := Load(KeyPath(t.TempDir()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	plain := []byte(`{"uid":"abc","token":"secret"}`)
	sealed, err := c.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !IsSealed(sealed) {
		t.Fatal("a sealed blob must carry the magic")
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("the plaintext must NEVER appear in the sealed blob")
	}
	got, err := c.Open(sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip = %q, want %q", got, plain)
	}
}

// TestNonceUnique: two Seals of the same plaintext give two different blobs
// (random nonce) — this is what forces hashing the PLAINTEXT on the store side.
func TestNonceUnique(t *testing.T) {
	c, _ := Load(KeyPath(t.TempDir()))
	plain := []byte("same plaintext")
	a, _ := c.Seal(plain)
	b, _ := c.Seal(plain)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext must differ (random nonce)")
	}
}

// TestWrongKeyFails: a blob sealed with one key does not open with another
// (authenticated GCM) — and IsSealed stays true (the magic is not secret).
func TestWrongKeyFails(t *testing.T) {
	c1, _ := Load(KeyPath(t.TempDir()))
	c2, _ := Load(KeyPath(t.TempDir())) // another directory = another key
	sealed, _ := c1.Seal([]byte("hello"))
	if _, err := c2.Open(sealed); err == nil {
		t.Fatal("Open with a wrong key must fail")
	}
}

// TestOpenPlaintextIsBadFormat: opening a plaintext JSON (no magic) returns
// ErrBadFormat — the migration signal.
func TestOpenPlaintextIsBadFormat(t *testing.T) {
	c, _ := Load(KeyPath(t.TempDir()))
	if _, err := c.Open([]byte(`{"plaintext":true}`)); err != ErrBadFormat {
		t.Fatalf("Open(plaintext) = %v, want ErrBadFormat", err)
	}
}

// TestKeyGeneratedAndPersisted: the key is created 0600 on the first Load and
// reused afterward (same key → cross-instance round-trip).
func TestKeyGeneratedAndPersisted(t *testing.T) {
	dir := t.TempDir()
	kp := KeyPath(dir)

	c1, err := Load(kp)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	fi, err := os.Stat(kp)
	if err != nil {
		t.Fatalf("the key must be created: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key permissions = %o, want 0600", perm)
	}
	if fi.Size() != keySize {
		t.Fatalf("key size = %d, want %d", fi.Size(), keySize)
	}

	sealed, _ := c1.Seal([]byte("data"))

	// Clear the cache to force a re-read of the key from disk.
	cacheMu.Lock()
	delete(cache, kp)
	cacheMu.Unlock()

	c2, err := Load(kp)
	if err != nil {
		t.Fatalf("re-Load: %v", err)
	}
	if _, err := c2.Open(sealed); err != nil {
		t.Fatalf("the persisted key must reopen the blob: %v", err)
	}
}

// TestBadKeySize: a key file of the wrong size is refused (corruption).
func TestBadKeySize(t *testing.T) {
	dir := t.TempDir()
	kp := KeyPath(dir)
	if err := os.WriteFile(kp, []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(kp); err == nil {
		t.Fatal("a key of the wrong size must be refused")
	}
	// cache cleanup (Load failed, nothing cached, but out of caution)
	cacheMu.Lock()
	delete(cache, kp)
	cacheMu.Unlock()
	_ = filepath.Dir(kp)
}
