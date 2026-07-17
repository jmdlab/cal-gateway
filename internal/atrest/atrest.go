// Package atrest encrypts AT REST the sensitive cal-gateway files
// (session.json = a full Proton session take; store.json = the account owner's
// DECRYPTED calendar). It closes the realistic vector flagged by the
// 2026-07-17 audit: FILE LEAKAGE (accidental copy/backup, reading an isolated
// file), both files living in the clear under /var/lib/cal-gateway.
//
// Model: AES-256-GCM with a single 32-byte key drawn at random and stored
// 0600 (`.atrest.key`) in data_dir, readable only by the `cal-gw` user. The
// daemon restarts without a human (watchdog/systemd): the key MUST therefore
// be available at boot without any input — a local key file is the only scheme
// that survives reboots with no dependency nor intervention.
//
// WHAT IT COVERS: an attacker who exfiltrates session.json/store.json WITHOUT
// the key (bare backup, file copied outside the directory, partial disk
// snapshot) gets only ciphertext. WHAT IT DOES NOT COVER: an attacker who
// already has full FS access as `cal-gw` (they also read .atrest.key) — this is
// defense in depth / anti file-leak, not a hardware secret. A TPM vault
// (systemd LoadCredentialEncrypted) would go further but adds a host-key/TPM
// dependency and a migration risk; the cost/benefit tips toward the key file
// (cf. SECURITY.md).
package atrest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// keyFileName is the name of the key file inside data_dir.
const keyFileName = ".atrest.key"

// keySize is the AES-256 key size (32 bytes).
const keySize = 32

// magic prefixes every sealed blob — lets us tell an encrypted file apart from
// a legacy plaintext JSON (migration) and acts as a format guard.
var magic = []byte("CGAR")

// formatVersion is the version of the on-disk container (magic+version+nonce+ct).
// Bumped if the envelope schema changes (future migration).
const formatVersion byte = 1

// header = magic(4) + version(1). The nonce (12) follows, then the ciphertext.
const headerLen = 5

// ErrBadFormat signals a blob that does not carry the expected magic (neither
// sealed nor recognized) — the caller decides (migrate from plaintext, or
// corruption).
var ErrBadFormat = errors.New("atrest: unknown format (no CGAR magic)")

// Cipher seals and opens blobs with a key loaded ONCE. No mutable state after
// construction: reusable concurrently.
type Cipher struct {
	aead cipher.AEAD
}

// cache memoizes a Cipher per key path: LoadSession is re-called on every
// write (token rotation), so we don't re-read/re-derive the key each time.
var (
	cacheMu sync.Mutex
	cache   = map[string]*Cipher{}
)

// KeyPath returns the key file path inside dataDir.
func KeyPath(dataDir string) string {
	return filepath.Join(dataDir, keyFileName)
}

// ResetCacheForTest clears the cipher cache — reserved for TESTS (lets a
// changed/corrupted key be simulated by forcing a disk re-read). No production
// use.
func ResetCacheForTest() {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	cache = map[string]*Cipher{}
}

// Load loads the Cipher backed by the key file keyPath, GENERATING it on the
// first call if it does not exist (32 random bytes, atomic 0600 write). The
// result is cached by path: "key loaded once". Concurrency-safe.
func Load(keyPath string) (*Cipher, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if c, ok := cache[keyPath]; ok {
		return c, nil
	}
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	c, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	cache[keyPath] = c
	return c, nil
}

// newCipher builds an AES-256-GCM Cipher from a 32-byte key.
func newCipher(key []byte) (*Cipher, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("atrest: key of %d bytes, expected %d", len(key), keySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("atrest: init AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("atrest: init GCM: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// loadOrCreateKey reads the key if the file exists (validating its size),
// otherwise draws a fresh one and writes it atomically 0600.
func loadOrCreateKey(keyPath string) ([]byte, error) {
	raw, err := os.ReadFile(keyPath)
	switch {
	case err == nil:
		if len(raw) != keySize {
			return nil, fmt.Errorf("atrest: key file %s of size %d, expected %d (corrupted?)", keyPath, len(raw), keySize)
		}
		return raw, nil
	case errors.Is(err, os.ErrNotExist):
		return generateKey(keyPath)
	default:
		return nil, fmt.Errorf("atrest: reading key %s: %w", keyPath, err)
	}
}

// generateKey draws 32 random bytes and writes them 0600 (tmp+rename), the
// directory created 0700 if needed. Best-effort against the race of two first
// boots: if the file appeared meanwhile, we re-read the existing one.
func generateKey(keyPath string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, fmt.Errorf("atrest: creating key directory: %w", err)
	}
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("atrest: drawing key: %w", err)
	}
	tmp := keyPath + ".tmp"
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		return nil, fmt.Errorf("atrest: writing tmp key: %w", err)
	}
	if err := os.Rename(tmp, keyPath); err != nil {
		_ = os.Remove(tmp)
		// Another instance may have placed the key meanwhile: re-read.
		if raw, rerr := os.ReadFile(keyPath); rerr == nil && len(raw) == keySize {
			return raw, nil
		}
		return nil, fmt.Errorf("atrest: placing key %s: %w", keyPath, err)
	}
	return key, nil
}

// IsSealed reports whether blob carries the magic of a sealed container — used
// to detect a legacy PLAINTEXT file (migration) without attempting to decrypt.
func IsSealed(blob []byte) bool {
	return len(blob) >= len(magic) && string(blob[:len(magic)]) == string(magic)
}

// Seal encrypts plain and returns the container magic+version+nonce+ciphertext.
// The nonce (12 bytes) is drawn at random on every call: two Seals of the same
// plaintext give two different blobs (hence the hash guard on the PLAINTEXT on
// the store side).
func (c *Cipher) Seal(plain []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("atrest: drawing nonce: %w", err)
	}
	out := make([]byte, 0, headerLen+len(nonce)+len(plain)+c.aead.Overhead())
	out = append(out, magic...)
	out = append(out, formatVersion)
	out = append(out, nonce...)
	out = c.aead.Seal(out, nonce, plain, nil)
	return out, nil
}

// Open decrypts a container produced by Seal. Returns ErrBadFormat if the magic
// is missing (likely legacy plaintext — the caller migrates), a generic error
// if the GCM auth fails (wrong key or corruption).
func (c *Cipher) Open(blob []byte) ([]byte, error) {
	if !IsSealed(blob) {
		return nil, ErrBadFormat
	}
	if len(blob) < headerLen+c.aead.NonceSize() {
		return nil, fmt.Errorf("atrest: truncated container (%d bytes)", len(blob))
	}
	ver := blob[len(magic)]
	if ver != formatVersion {
		return nil, fmt.Errorf("atrest: unknown format version %d (max %d)", ver, formatVersion)
	}
	nonce := blob[headerLen : headerLen+c.aead.NonceSize()]
	ct := blob[headerLen+c.aead.NonceSize():]
	plain, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("atrest: decryption/authentication: %w", err)
	}
	return plain, nil
}
