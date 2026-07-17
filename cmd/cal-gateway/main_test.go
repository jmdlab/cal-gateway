package main

import (
	"strings"
	"testing"
)

func TestParseConfigFlag(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"default", nil, "config.toml"},
		{"explicit", []string{"-config", "/etc/cal-gateway/config.toml"}, "/etc/cal-gateway/config.toml"},
		{"dangling flag ignored", []string{"-config"}, "config.toml"},
		{"last wins", []string{"-config", "a.toml", "-config", "b.toml"}, "b.toml"},
		{"unrelated args ignored", []string{"-v", "-config", "x.toml"}, "x.toml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseConfigFlag(tc.args); got != tc.want {
				t.Errorf("parseConfigFlag(%v) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

// TestAcquireServeLock: the instance lock refuses a second `serve` on the same
// data_dir (flock on distinct descriptors, even within a single test process)
// and releases on Close.
func TestAcquireServeLock(t *testing.T) {
	dir := t.TempDir()

	first, err := acquireServeLock(dir)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}

	if _, err := acquireServeLock(dir); err == nil {
		t.Fatal("the second lock must be refused while the first is held")
	} else if !strings.Contains(err.Error(), "already running") {
		t.Fatalf("the refusal message is unclear for an operator: %v", err)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	third, err := acquireServeLock(dir)
	if err != nil {
		t.Fatalf("after release, the lock must be re-acquirable: %v", err)
	}
	_ = third.Close()
}
