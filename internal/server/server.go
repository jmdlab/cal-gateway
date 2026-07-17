// Package server hosts the http.Server that carries the CalDAV handler.
//
// Deployment model: listens on loopback only, with nginx terminating TLS in
// front. Authentication is Basic auth with credentials DEDICATED to the
// gateway (config [auth]) — never the Proton password.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	webcaldav "github.com/emersion/go-webdav/caldav"
)

// Config is the subset of configuration consumed by the server.
// (The ATTENDEE/ORGANIZER policy migrated from the middleware to the CalDAV
// backend in M5a — see putguard.go and caldav.Backend.ConfigureInvites.)
type Config struct {
	ListenAddr   string
	AuthUser     string
	AuthPassword string

	// CalendarUserAddresses: the principal's email addresses
	// (calendar-user-address-set) — THE trigger for Apple's "Add invitees" UI
	// (see principalpropfind.go). Empty = the property is not served.
	CalendarUserAddresses []string

	// Ready is the readiness gate: the port is opened IMMEDIATELY at boot (the
	// tcp watchdog passes from second 1) but every route answers 503 +
	// Retry-After until the initial sync completes (dataaccessd treats the 503
	// as transient — serving EMPTY collections, by contrast, would make events
	// "vanish" on the client). nil = no gate (tests). Set to true by main at
	// the end of the initial sync.
	Ready *atomic.Bool

	// PollerLastOK exposes the timestamp of the last fully successful poller
	// cycle (calsync.Poller.LastOK) for the /healthz endpoint. nil = /healthz
	// will answer "stale" permanently once ready.
	PollerLastOK func() time.Time
}

// Server is the CalDAV HTTP server.
type Server struct {
	httpSrv *http.Server
}

// New mounts the go-webdav CalDAV handler behind the auth middleware.
// The handler serves /.well-known/caldav itself (redirect to the principal).
func New(cfg Config, backend webcaldav.Backend) (*Server, error) {
	if cfg.ListenAddr == "" {
		return nil, errors.New("server: listen_addr is required")
	}
	if cfg.AuthUser == "" || cfg.AuthPassword == "" {
		return nil, errors.New("server: [auth] username and password are required (dedicated gateway credentials, not the Proton password)")
	}

	warnIfNotLoopback(cfg.ListenAddr)

	return &Server{
		httpSrv: &http.Server{
			Addr:              cfg.ListenAddr,
			Handler:           newHandler(cfg, backend),
			ReadHeaderTimeout: 10 * time.Second,
		},
	}, nil
}

// warnIfNotLoopback logs a clear startup WARNING when ListenAddr is not bound
// to a loopback address. The daemon carries Basic auth in clear and expects a
// TLS reverse proxy in front; binding it to a public interface would expose
// those credentials. It only WARNS — it never blocks — because an operator may
// legitimately front it with an external proxy. A non-IP host (a name we can't
// resolve here) gets a cautious warning too.
func warnIfNotLoopback(addr string) {
	const msg = "WARNING: listen_addr %q is not loopback — the daemon MUST sit behind a TLS reverse proxy; never expose Basic auth in clear on a public interface"
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No host:port split (e.g. a bare host): fall back to the whole value.
		host = addr
	}
	if host == "" {
		// Empty host = all interfaces (0.0.0.0 / [::]) — definitely public.
		log.Printf(msg, addr)
		return
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			log.Printf(msg, addr)
		}
		return
	}
	// Non-IP host (a name): we can't confirm it resolves to loopback here.
	log.Printf("WARNING: listen_addr %q host %q is not a literal loopback IP — ensure it resolves to loopback behind a TLS reverse proxy; never expose Basic auth in clear on a public interface", addr, host)
}

// newHandler assembles the full middleware chain (factored out of New for
// httptest tests). From outermost to innermost:
// healthz (loopback, no auth) → readiness gate (503 during the initial sync)
// → basic auth → CalDAV interceptors → go-webdav.
func newHandler(cfg Config, backend webcaldav.Backend) http.Handler {
	handler := &webcaldav.Handler{Backend: backend}

	// Discovery paths — SAME derivation as caldav.NewBackend (segment =
	// url.PathEscape(user)) so the root interceptor and the backend point at
	// the same principal.
	seg := url.PathEscape(cfg.AuthUser)
	principalPath := "/" + seg + "/"
	homeSetPath := principalPath + "calendars/"
	// RFC 6638 scheduling collections — at depth 2 like the home set, so NEVER
	// routed to go-webdav (fully intercepted, scheduling.go).
	inboxPath := principalPath + "inbox/"
	outboxPath := principalPath + "outbox/"

	// The inbox's schedule-default-calendar-URL: the backend's first real
	// calendar, resolved lazily and cached (nil backend = tests, the optional
	// property is simply omitted).
	var defaultCalHref func(ctx context.Context) string
	if backend != nil {
		var mu sync.Mutex
		var cached string
		defaultCalHref = func(ctx context.Context) string {
			mu.Lock()
			defer mu.Unlock()
			if cached != "" {
				return cached
			}
			cals, err := backend.ListCalendars(ctx)
			if err != nil || len(cals) == 0 {
				return ""
			}
			// Scheduling default calendar: PREFER the one whose name matches an
			// account address (the "main" calendar, alice@example.com), not the
			// first in API order (which may be a secondary "My calendar") —
			// otherwise Apple files incoming invitations into the wrong
			// calendar (duplicates observed 2026-07-17). Fallback: the first.
			pick := cals[0].Path
			for _, addr := range cfg.CalendarUserAddresses {
				for i := range cals {
					if strings.EqualFold(cals[i].Name, addr) {
						pick = cals[i].Path
					}
				}
			}
			cached = pick
			return cached
		}
	}

	var h http.Handler = handler
	h = interceptPutPrecondition(h)
	h = interceptScheduling(inboxPath, outboxPath, defaultCalHref, h)
	h = interceptPrincipalPropfind(principalPath, homeSetPath, inboxPath, outboxPath, cfg.AuthUser, cfg.CalendarUserAddresses, h)
	h = interceptRootPropfind(principalPath, homeSetPath, h)
	h = interceptProppatch(h)
	// Scheduling announcement: `calendar-auto-schedule` added to the DAV header
	// of every OPTIONS served by go-webdav (principal, home set, calendar
	// collections) — see scheduling.go.
	h = appendAutoScheduleDAV(h)
	// One-off diagnostic (see debuglog.go) — no-op if the variable is empty.
	if p := os.Getenv("CALGW_HTTPDEBUG"); p != "" {
		h = debugCapture(p, h)
	}

	root := basicAuth(cfg.AuthUser, cfg.AuthPassword, h)
	root = readinessGate(cfg.Ready, root)
	root = healthzMiddleware(cfg.Ready, cfg.PollerLastOK, root)
	return root
}

// readinessGate short-circuits EVERY route with 503 + Retry-After while ready
// is false: the port opens at second 1 (the tcp watchdog no longer kills the
// service mid initial-sync) and CalDAV clients retry — serving empty
// collections during the sync would make events "vanish" on them. ready nil =
// no gate (tests).
func readinessGate(ready *atomic.Bool, next http.Handler) http.Handler {
	if ready == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ready.Load() {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Retry-After", "10")
		http.Error(w, "cal-gateway is starting (initial sync in progress) — please retry", http.StatusServiceUnavailable)
	})
}

// Run starts listening and shuts down cleanly when ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		log.Printf("caldav server listening on %s", s.httpSrv.Addr)
		errCh <- s.httpSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.httpSrv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server: shutdown: %w", err)
		}
		<-errCh // always http.ErrServerClosed after Shutdown
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("server: %w", err)
	}
}

// basicAuth protects the whole handler. Constant-time comparison over SHA-256
// digests (lengths equalized, no size leak).
func basicAuth(user, password string, next http.Handler) http.Handler {
	wantUser := sha256.Sum256([]byte(user))
	wantPass := sha256.Sum256([]byte(password))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, ok := r.BasicAuth()
		if ok {
			u := sha256.Sum256([]byte(gotUser))
			p := sha256.Sum256([]byte(gotPass))
			if subtle.ConstantTimeCompare(u[:], wantUser[:])&subtle.ConstantTimeCompare(p[:], wantPass[:]) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}
		// Auth failure logged with the real IP (nginx passes X-Real-IP) so
		// fail2ban can ban brute-force attempts — without this log, auth
		// happening inside the Go process, no failure would be visible to a
		// bannable layer (security audit 2026-07-17). Only genuine failures
		// (credentials supplied but wrong) are logged "auth failure"; a missing
		// header (a legitimate client's first WWW-Authenticate round) is silent.
		if ok {
			log.Printf("auth failure from %s", clientIP(r))
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="cal-gateway", charset="UTF-8"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// clientIP extracts the real client IP behind nginx (X-Real-IP, else the first
// X-Forwarded-For, else RemoteAddr).
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
