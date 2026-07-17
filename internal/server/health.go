package server

// /healthz — supervision endpoint for the watchdog (services-registry): an
// HTTP probe that attests the LAST POLLER CYCLE succeeded recently, where the
// historical tcp-check only proved an open port (a daemon with a dead session
// serving a frozen cache would pass the tcp-check indefinitely).

import (
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

const (
	healthzPath = "/healthz"

	// healthzMaxAge: beyond this age of the last successful cycle, the service
	// is declared stale (503) — the prod poll_interval is 60 s, so 5 minutes =
	// several consecutive failed cycles, not a blip.
	healthzMaxAge = 5 * time.Minute
)

// healthzMiddleware serves /healthz BEFORE basic auth and BEFORE the readiness
// gate (the watchdog has no credentials and must be able to probe during
// startup). Restricted to loopback: the daemon only listens on 127.0.0.1, but
// we also check RemoteAddr — if listen_addr ever changes, healthz does not
// become a public oracle (nginx does not proxy this path, and even via a proxy
// RemoteAddr would stay loopback: it is a bind guardrail, not authentication).
//
// Responses (text/plain, one line, never any event content):
//   - 200 "starting…"  : initial sync in progress (ready=false). Deliberately
//     200: a 503 here would restart the HTTP watchdog in the middle of the
//     startup window — exactly the bug we are killing.
//   - 200 "ok…"        : last full poller cycle succeeded < 5 min ago.
//   - 503 "stale…"     : no cycle succeeded, or the last success is too old
//     (age included) — a watchdog restart is then the right reaction.
func healthzMiddleware(ready *atomic.Bool, lastOK func() time.Time, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != healthzPath {
			next.ServeHTTP(w, r)
			return
		}
		if !isLoopback(r.RemoteAddr) {
			// Off loopback: the path does not exist (no oracle).
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if ready != nil && !ready.Load() {
			fmt.Fprintln(w, "starting: initial sync in progress")
			return
		}
		var last time.Time
		if lastOK != nil {
			last = lastOK()
		}
		if last.IsZero() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "stale: no poller cycle succeeded since startup")
			return
		}
		age := time.Since(last).Round(time.Second)
		if age > healthzMaxAge {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "stale: last successful poller cycle %s ago (max %s)\n", age, healthzMaxAge)
			return
		}
		fmt.Fprintf(w, "ok: last successful poller cycle %s ago\n", age)
	})
}

// isLoopback reports whether a host:port RemoteAddr comes from loopback.
func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
