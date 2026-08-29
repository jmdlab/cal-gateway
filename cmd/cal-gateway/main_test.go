package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestRetryDelay(t *testing.T) {
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		if got := retryDelay(i + 1); got != w {
			t.Fatalf("retryDelay(%d) = %s, want %s", i+1, got, w)
		}
	}
	if got := retryDelay(0); got != 10*time.Second {
		t.Fatalf("retryDelay(0) = %s, want 10s", got)
	}
}

func TestBootstrapHandler(t *testing.T) {
	h := bootstrapHandler(func() string { return "starting: waiting for Proton (test)" })
	// /healthz from loopback: 200 + the status line (the watchdog must stay quiet).
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "127.0.0.1:4242"
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "waiting for Proton") {
		t.Fatalf("healthz loopback: code=%d body=%q", rr.Code, rr.Body.String())
	}
	// /healthz off loopback: not found (no oracle), same as the real middleware.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "10.0.0.9:4242"
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("healthz off-loopback: code=%d, want 404", rr.Code)
	}
	// Any CalDAV path: 503 + Retry-After, never connection refused.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("PROPFIND", "/anne/calendars/", nil)
	req.RemoteAddr = "127.0.0.1:4242"
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("caldav path: code=%d retry-after=%q", rr.Code, rr.Header().Get("Retry-After"))
	}
}
