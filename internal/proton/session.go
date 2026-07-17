package proton

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/jmdlab/cal-gateway/internal/atrest"
)

// Session persistence, "bridge" model (concept verified in the official Proton
// clients and the reference study proton-cal): we NEVER store the account
// password — only the session tokens (UID, access, refresh) and the salted key
// passphrase derived once at login (mailbox password + key salt, via go-srp),
// which is enough to re-unlock the user key and address keys cold.
//
// ENCRYPTION AT REST (audit 2026-07-17): the file carries a COMPLETE Proton
// session handle (tokens + salted_key_pass = full account access). It is
// therefore SEALED via internal/atrest (AES-256-GCM, local key .atrest.key in
// 0600). Stays in 0600 in data_dir (out of the repo, gitignored) — the
// encryption is a file-leak defense layer ON TOP OF the permissions, cf.
// SECURITY.md.
//
// NON-DESTRUCTIVE MIGRATION: the session does NOT rebuild itself (it requires a
// supervised `cal-gateway login` TOTP). A LEGACY PLAINTEXT session.json
// (deployment) is therefore read as-is THEN re-sealed — NEVER discarded.

const sessionFile = "session.json"

// ErrNoSession signals the absence of a persisted session (login never done).
var ErrNoSession = errors.New("proton: no persisted session (run `cal-gateway login` first)")

// ErrSessionInvalid signals a persisted session REFUSED by the API (refresh
// token revoked/expired, 401 after a refresh attempt) or whose passphrase no
// longer unlocks the keys. Distinct from ErrNoSession (never logged in) and
// from a network outage (transient): a restart CANNOT repair it, only a
// `cal-gateway login` (supervised TOTP) recreates it. main translates this
// error into a dedicated exit code (78) so that systemd stops crash-looping
// (drop-in RestartPreventExitStatus=78).
var ErrSessionInvalid = errors.New("proton: persisted session invalid or revoked (re-run `cal-gateway login`)")

// Session is the state persisted between runs.
type Session struct {
	UID           string `json:"uid"`
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token"`
	SaltedKeyPass []byte `json:"salted_key_pass"` // base64 via encoding/json
}

// Valid reports whether the session carries the minimum to attempt a restore.
func (s Session) Valid() bool {
	return s.UID != "" && s.RefreshToken != "" && len(s.SaltedKeyPass) > 0
}

// LoadSession reads the persisted session from dataDir, decrypting it.
// MIGRATION: if the file is a legacy PLAINTEXT JSON (no atrest magic), it is
// read as-is THEN re-sealed in place on a best-effort basis — never discarded
// (the session cannot be rebuilt without a manual `login` TOTP).
func LoadSession(dataDir string) (Session, error) {
	path := filepath.Join(dataDir, sessionFile)
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, fmt.Errorf("proton: reading session: %w", err)
	}

	cipher, err := atrest.Load(atrest.KeyPath(dataDir))
	if err != nil {
		return Session{}, fmt.Errorf("proton: loading at-rest key: %w", err)
	}

	plain := raw
	sealed := atrest.IsSealed(raw)
	if sealed {
		plain, err = cipher.Open(raw)
		if err != nil {
			// Sealed blob but unreadable: wrong key or corruption. We do NOT
			// destroy it (re-login TOTP required to rebuild) — clear error, the
			// operator decides.
			return Session{}, fmt.Errorf("proton: session unreadable (at-rest key?): %w", err)
		}
	}

	var s Session
	if uerr := json.Unmarshal(plain, &s); uerr != nil {
		return Session{}, fmt.Errorf("proton: parsing session: %w", uerr)
	}
	if !s.Valid() {
		return Session{}, ErrNoSession
	}

	// Plaintext → encrypted migration: re-seal a legacy plaintext session,
	// without ever losing it. Best-effort: a write failure does not break the
	// boot (the session is already in memory, the migration will retry on the
	// next boot).
	if !sealed {
		if serr := SaveSession(dataDir, s); serr != nil {
			log.Printf("proton: session encryption migration failed (will retry on next boot): %v", serr)
		} else {
			log.Printf("proton: legacy plaintext session.json migrated to the encrypted at-rest format")
		}
	}
	return s, nil
}

// SaveSession writes the ENCRYPTED session (atrest, AES-256-GCM) in 0600,
// atomically (tmp + rename) so as to never leave a truncated session.json
// after a token refresh.
func SaveSession(dataDir string, s Session) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("proton: creating data dir: %w", err)
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("proton: encoding session: %w", err)
	}
	cipher, err := atrest.Load(atrest.KeyPath(dataDir))
	if err != nil {
		return fmt.Errorf("proton: loading at-rest key: %w", err)
	}
	sealed, err := cipher.Seal(raw)
	if err != nil {
		return fmt.Errorf("proton: sealing session: %w", err)
	}
	path := filepath.Join(dataDir, sessionFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return fmt.Errorf("proton: writing session: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("proton: replacing session: %w", err)
	}
	return nil
}
