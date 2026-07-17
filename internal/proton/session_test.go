package proton

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jmdlab/cal-gateway/internal/atrest"
)

func sampleSession() Session {
	return Session{
		UID:           "uid-123",
		AccessToken:   "access-tok",
		RefreshToken:  "refresh-tok",
		SaltedKeyPass: []byte("salted-key-pass-bytes"),
	}
}

// TestSaveLoadRoundTripSealed: SaveSession seals, LoadSession reopens — and the
// plaintext (tokens = session handle) never appears on disk.
func TestSaveLoadRoundTripSealed(t *testing.T) {
	dir := t.TempDir()
	want := sampleSession()
	if err := SaveSession(dir, want); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, sessionFile))
	if err != nil {
		t.Fatal(err)
	}
	if !atrest.IsSealed(raw) {
		t.Fatal("session.json must be sealed at rest")
	}
	if bytes.Contains(raw, []byte("refresh-tok")) || bytes.Contains(raw, []byte("access-tok")) {
		t.Fatal("the tokens must NOT appear in plaintext on disk")
	}

	got, err := LoadSession(dir)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if got.UID != want.UID || got.RefreshToken != want.RefreshToken ||
		got.AccessToken != want.AccessToken || !bytes.Equal(got.SaltedKeyPass, want.SaltedKeyPass) {
		t.Fatalf("round-trip = %+v, want %+v", got, want)
	}
}

// TestPlaintextSessionMigration is THE critical deployment test: a LEGACY
// PLAINTEXT session.json (before encryption) must be read WITHOUT LOSS then
// re-sealed in place — the user must NEVER have to redo a TOTP login.
func TestPlaintextSessionMigration(t *testing.T) {
	dir := t.TempDir()
	want := sampleSession()

	// Write the session in PLAINTEXT, exactly like the old SaveSession.
	plain, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, sessionFile)
	if err := os.WriteFile(path, plain, 0o600); err != nil {
		t.Fatal(err)
	}

	// 1st boot: LoadSession reads the plaintext AND re-seals in place.
	got, err := LoadSession(dir)
	if err != nil {
		t.Fatalf("LoadSession on legacy plaintext: %v", err)
	}
	if got.UID != want.UID || !bytes.Equal(got.SaltedKeyPass, want.SaltedKeyPass) {
		t.Fatalf("plaintext session loaded incorrectly: %+v", got)
	}

	// The file must now be sealed (migration done), without loss.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !atrest.IsSealed(raw) {
		t.Fatal("after the 1st boot, the plaintext session.json must be re-sealed")
	}
	if bytes.Contains(raw, []byte("refresh-tok")) {
		t.Fatal("the token must no longer appear in plaintext after migration")
	}

	// 2nd boot: re-read of the sealed format, session intact.
	got2, err := LoadSession(dir)
	if err != nil {
		t.Fatalf("re-LoadSession sealed: %v", err)
	}
	if got2.RefreshToken != want.RefreshToken || got2.UID != want.UID {
		t.Fatalf("session lost on the 2nd boot: %+v", got2)
	}
}

// TestLoadNoSession: missing file → ErrNoSession (never confused with a
// corruption).
func TestLoadNoSession(t *testing.T) {
	if _, err := LoadSession(t.TempDir()); err != ErrNoSession {
		t.Fatalf("LoadSession(empty) = %v, want ErrNoSession", err)
	}
}

// TestLoadSealedWrongKey: a sealed session.json that is unreadable (wrong key)
// must NOT be treated as absent (otherwise silent loss) — clear error, and the
// file is NOT destroyed.
func TestLoadSealedWrongKey(t *testing.T) {
	dir := t.TempDir()
	if err := SaveSession(dir, sampleSession()); err != nil {
		t.Fatal(err)
	}
	// Corrupt the at-rest key and clear the cache to force a re-read.
	kp := atrest.KeyPath(dir)
	bad := make([]byte, 32)
	if err := os.WriteFile(kp, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	atrest.ResetCacheForTest()

	_, err := LoadSession(dir)
	if err == nil {
		t.Fatal("an unreadable sealed session must return an error")
	}
	if err == ErrNoSession {
		t.Fatal("must NOT be confused with ErrNoSession (silent loss)")
	}
	// The sealed file must still exist (not destroyed).
	if _, statErr := os.Stat(filepath.Join(dir, sessionFile)); statErr != nil {
		t.Fatal("session.json must not be destroyed on a decryption error")
	}
}
