// Package config loads cal-gateway's TOML configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// exampleAuthPassword is the placeholder [auth].password shipped in
// config.example.toml. Booting `serve` with it unchanged is refused.
const exampleAuthPassword = "change-me"

// Account describes the Proton account to bridge (secrets do NOT live here:
// the password is asked at login, the session persisted encrypted in data_dir).
type Account struct {
	Username string `toml:"username"`
}

// Auth carries the Basic auth credentials DEDICATED to the gateway (CalDAV
// client side) — never the Proton password. config.toml is gitignored.
type Auth struct {
	Username string `toml:"username"`
	Password string `toml:"password"`
}

// Invite configures the sending of OUTBOUND iMIP invitations (M5a) via the
// local Proton SMTP bridge. password is the BRIDGE password — NEVER the Proton
// password (same posture as [auth]). Missing section or enabled=false: a PUT
// with an outbound ATTENDEE is refused with 403, as before M5a.
type Invite struct {
	Enabled  bool   `toml:"enabled"`
	SMTPHost string `toml:"smtp_host"` // SMTP bridge in the clear, loopback
	SMTPPort int    `toml:"smtp_port"`
	Username string `toml:"username"`  // bridge account address (the organizer)
	Password string `toml:"password"`  // BRIDGE password
	FromName string `toml:"from_name"` // sender display name

	// WatchReplies (M6a — INBOUND RSVP, RESERVED, default false): the "has
	// accepted" badge on the organizer side. Updating the PARTSTAT on receipt
	// of an iMIP REPLY is CLIENT-SIDE on Proton (Proton Mail webmail parses the
	// email and PATCHes the attendee — never the server on its own, verified in
	// WebClients mailIntegration/invite.ts). The badge is therefore NOT free
	// for an owner living in Apple Calendar. The read-only IMAP watcher (FETCH/
	// EXAMINE STRICTLY, never STORE/DELETE) is still to be built — enabled ONLY
	// by this flag once the need is PROVEN live (FEATURE-MATRIX protocol). Today:
	// read but not wired (main.go logs a WARN).
	WatchReplies bool   `toml:"watch_replies"`
	IMAPHost     string `toml:"imap_host"`     // IMAP bridge in the clear, loopback (default 127.0.0.1)
	IMAPPort     int    `toml:"imap_port"`     // default 1143
	IMAPUsername string `toml:"imap_username"` // bridge account address
	IMAPPassword string `toml:"imap_password"` // BRIDGE password (never Proton)
}

// Config is the root configuration (see config.example.toml).
type Config struct {
	ListenAddr   string   `toml:"listen_addr"`   // e.g. "127.0.0.1:5232" (nginx TLS in front)
	DataDir      string   `toml:"data_dir"`      // sessions + SQLite shadow store
	PollInterval duration `toml:"poll_interval"` // e.g. "60s"
	Account      Account  `toml:"account"`
	Auth         Auth     `toml:"auth"`
	Invite       Invite   `toml:"invite"`
}

// Default returns a config usable without a file (for a bare `status`).
func Default() *Config {
	return &Config{
		ListenAddr:   "127.0.0.1:5232",
		DataDir:      "data",
		PollInterval: duration{60 * time.Second},
		Account:      Account{Username: "(unset)"},
		Invite:       Invite{SMTPHost: "127.0.0.1", SMTPPort: 1025},
	}
}

// Load reads and parses a config.toml.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	cfg := Default()
	if err := toml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks the fields required to run `serve`. It refuses the example
// password and empty gateway credentials so the daemon never boots with an
// insecure or half-configured [auth] section.
func (c *Config) Validate() error {
	if c.Auth.Username == "" {
		return errors.New("config: [auth].username is required (dedicated gateway credentials, not the Proton password)")
	}
	if c.Auth.Password == "" {
		return errors.New("config: [auth].password is required (dedicated gateway credentials, not the Proton password)")
	}
	if c.Auth.Password == exampleAuthPassword {
		return errors.New("config: refusing to start with the example password; set a strong [auth].password")
	}
	return nil
}

// duration wraps time.Duration to parse "60s" from the TOML.
type duration struct{ time.Duration }

func (d *duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func (d duration) String() string { return d.Duration.String() }
