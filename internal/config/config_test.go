package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeConfig writes a config.toml into a fresh TempDir and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestLoadMissingFile: an absent file is an error (Load reads from disk).
func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	if err == nil {
		t.Fatal("Load of a missing file must return an error")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Fatalf("error should mention the read failure: %v", err)
	}
}

// TestLoadMinimalValid: a minimal valid TOML parses, overrides the fields it
// sets and keeps the defaults for the rest.
func TestLoadMinimalValid(t *testing.T) {
	path := writeConfig(t, `
listen_addr = "127.0.0.1:9999"
data_dir = "/tmp/cg"
poll_interval = "30s"

[account]
username = "user@proton.me"

[auth]
username = "caldav"
password = "s3cret"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:9999" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.DataDir != "/tmp/cg" {
		t.Errorf("DataDir = %q", cfg.DataDir)
	}
	if cfg.PollInterval.Duration != 30*time.Second {
		t.Errorf("PollInterval = %s, want 30s", cfg.PollInterval)
	}
	if cfg.Account.Username != "user@proton.me" {
		t.Errorf("Account.Username = %q", cfg.Account.Username)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a valid config must pass Validate: %v", err)
	}
}

// TestLoadMalformed: a malformed TOML returns a clear parse error.
func TestLoadMalformed(t *testing.T) {
	path := writeConfig(t, "this is = not valid = toml [[[")
	_, err := Load(path)
	if err == nil {
		t.Fatal("malformed TOML must return an error")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Fatalf("error should mention the parse failure: %v", err)
	}
}

// TestDurationParsing: a valid "60s" parses; garbage is a clear error.
func TestDurationParsing(t *testing.T) {
	ok := writeConfig(t, `poll_interval = "60s"`)
	cfg, err := Load(ok)
	if err != nil {
		t.Fatalf("Load valid duration: %v", err)
	}
	if cfg.PollInterval.Duration != time.Minute {
		t.Errorf("PollInterval = %s, want 1m", cfg.PollInterval)
	}

	bad := writeConfig(t, `poll_interval = "not-a-duration"`)
	if _, err := Load(bad); err == nil {
		t.Fatal("a garbage duration must return an error")
	}
}

// TestPartialInviteKeepsSMTPDefaults: a partial [invite] section (only
// enabled) must NOT wipe the SMTP host/port defaults from Default().
func TestPartialInviteKeepsSMTPDefaults(t *testing.T) {
	path := writeConfig(t, `
[auth]
username = "caldav"
password = "s3cret"

[invite]
enabled = true
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Invite.Enabled {
		t.Fatal("Invite.Enabled should be true")
	}
	if cfg.Invite.SMTPHost != "127.0.0.1" {
		t.Errorf("Invite.SMTPHost = %q, want the 127.0.0.1 default preserved", cfg.Invite.SMTPHost)
	}
	if cfg.Invite.SMTPPort != 1025 {
		t.Errorf("Invite.SMTPPort = %d, want the 1025 default preserved", cfg.Invite.SMTPPort)
	}
}

// TestValidateRejectsExamplePassword: booting with the example password from
// config.example.toml is refused with a clear message.
func TestValidateRejectsExamplePassword(t *testing.T) {
	cfg := Default()
	cfg.Auth.Username = "caldav"
	cfg.Auth.Password = "change-me"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("the example password must be refused")
	}
	if !strings.Contains(err.Error(), "example password") {
		t.Fatalf("message should name the example password: %v", err)
	}
}

// TestValidateRejectsEmptyCredentials: empty username or password is refused.
func TestValidateRejectsEmptyCredentials(t *testing.T) {
	cases := []struct {
		name           string
		user, password string
	}{
		{"empty username", "", "s3cret"},
		{"empty password", "caldav", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Auth.Username = tc.user
			cfg.Auth.Password = tc.password
			if err := cfg.Validate(); err == nil {
				t.Fatal("empty credentials must be refused")
			}
		})
	}
}
