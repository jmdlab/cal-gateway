package server

// Tests of the readiness gate (503 during the initial sync) and of /healthz
// (loopback, no auth, freshness of the last poller cycle). The CalDAV backend
// is never reached: the middlewares short-circuit before (503/401/404), a nil
// backend is enough.

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testHandler(ready *atomic.Bool, lastOK func() time.Time) http.Handler {
	return newHandler(Config{
		ListenAddr:   "127.0.0.1:0",
		AuthUser:     "alice",
		AuthPassword: "pw",
		Ready:        ready,
		PollerLastOK: lastOK,
	}, nil)
}

func doReq(h http.Handler, path, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestReadinessGate: while ready is false, EVERY route answers 503 +
// Retry-After (dataaccessd treats it as transient); as soon as ready flips to
// true, the normal chain resumes (here: 401, auth is reached).
func TestReadinessGate(t *testing.T) {
	ready := &atomic.Bool{}
	h := testHandler(ready, func() time.Time { return time.Now() })

	rec := doReq(h, "/alice/calendars/", "127.0.0.1:5000")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("before ready: code = %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "10" {
		t.Fatalf("Retry-After = %q, want \"10\"", got)
	}

	ready.Store(true)
	rec = doReq(h, "/alice/calendars/", "127.0.0.1:5000")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("after ready: code = %d, want 401 (the auth chain is reached)", rec.Code)
	}
}

// TestReadinessGateNil: without a gate (tests, non-serve uses), the normal
// chain is direct.
func TestReadinessGateNil(t *testing.T) {
	h := testHandler(nil, nil)
	if rec := doReq(h, "/alice/", "127.0.0.1:5000"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
}

// TestHealthzFresh: recent last poller cycle → 200, no auth.
func TestHealthzFresh(t *testing.T) {
	ready := &atomic.Bool{}
	ready.Store(true)
	h := testHandler(ready, func() time.Time { return time.Now().Add(-30 * time.Second) })

	rec := doReq(h, "/healthz", "127.0.0.1:5000")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(rec.Body.String(), "ok:") {
		t.Fatalf("body = %q, want prefix \"ok:\"", rec.Body.String())
	}
}

// TestHealthzStale: last successful cycle too old → 503 + age.
func TestHealthzStale(t *testing.T) {
	ready := &atomic.Bool{}
	ready.Store(true)
	h := testHandler(ready, func() time.Time { return time.Now().Add(-10 * time.Minute) })

	rec := doReq(h, "/healthz", "127.0.0.1:5000")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", rec.Code)
	}
	if !strings.HasPrefix(rec.Body.String(), "stale:") {
		t.Fatalf("body = %q, want prefix \"stale:\" (with the age)", rec.Body.String())
	}
}

// TestHealthzNeverSynced: ready but no cycle succeeded (initial sync failed
// outright) → 503: a watchdog restart is the right reaction.
func TestHealthzNeverSynced(t *testing.T) {
	ready := &atomic.Bool{}
	ready.Store(true)
	h := testHandler(ready, func() time.Time { return time.Time{} })

	if rec := doReq(h, "/healthz", "127.0.0.1:5000"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", rec.Code)
	}
}

// TestHealthzWarmup: during the initial sync (ready=false), /healthz answers
// 200 "starting" — a 503 would restart the HTTP watchdog in the middle of the
// startup window, exactly the original bug.
func TestHealthzWarmup(t *testing.T) {
	ready := &atomic.Bool{}
	h := testHandler(ready, func() time.Time { return time.Time{} })

	rec := doReq(h, "/healthz", "127.0.0.1:5000")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 during warmup", rec.Code)
	}
	if !strings.HasPrefix(rec.Body.String(), "starting:") {
		t.Fatalf("body = %q, want prefix \"starting:\"", rec.Body.String())
	}
}

// TestHealthzNonLoopback: off loopback, the path does not exist (404) — no
// public health oracle if the bind ever changes.
func TestHealthzNonLoopback(t *testing.T) {
	ready := &atomic.Bool{}
	ready.Store(true)
	h := testHandler(ready, func() time.Time { return time.Now() })

	if rec := doReq(h, "/healthz", "192.0.2.1:4444"); rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404 off loopback", rec.Code)
	}
	// IPv6 loopback accepted.
	if rec := doReq(h, "/healthz", "[::1]:4444"); rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 from ::1", rec.Code)
	}
}

// TestClientIPProxyHeaderTrust: the proxy headers (X-Real-IP / X-Forwarded-For)
// are honored ONLY from a loopback peer (the local nginx). A direct external
// connection could forge them to poison the fail2ban auth log — its socket
// address must win.
func TestClientIPProxyHeaderTrust(t *testing.T) {
	mk := func(remote, realIP string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if realIP != "" {
			r.Header.Set("X-Real-IP", realIP)
		}
		return r
	}
	if got := clientIP(mk("127.0.0.1:9999", "203.0.113.7")); got != "203.0.113.7" {
		t.Errorf("loopback peer: X-Real-IP must be honored, got %q", got)
	}
	if got := clientIP(mk("198.51.100.4:9999", "203.0.113.7")); got != "198.51.100.4" {
		t.Errorf("external peer: forged X-Real-IP must be IGNORED, got %q", got)
	}
	if got := clientIP(mk("198.51.100.4:9999", "")); got != "198.51.100.4" {
		t.Errorf("external peer, no headers: socket host expected, got %q", got)
	}
}

// TestMaxRequestBodyCap: a body over maxRequestBody must be cut off by the
// outermost http.MaxBytesHandler — never read fully into memory (the pre-fix
// behavior allowed an authenticated multi-GB PUT to OOM the daemon).
func TestMaxRequestBodyCap(t *testing.T) {
	seen := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = len(b)
	})
	h := http.MaxBytesHandler(inner, maxRequestBody)
	big := bytes.NewReader(make([]byte, maxRequestBody+1024))
	req := httptest.NewRequest(http.MethodPut, "/alice/calendars/cal1/evt.ics", big)
	req.Header.Set("Content-Type", "text/calendar")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen > maxRequestBody {
		t.Fatalf("handler read %d bytes — the cap (%d) did not apply", seen, maxRequestBody)
	}
}
