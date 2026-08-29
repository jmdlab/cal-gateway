// cal-gateway — Proton↔CalDAV calendar daemon (our product).
//
// M1: READ-ONLY mirror — `serve` mounts the CalDAV server on the decrypted
// Proton calendars (a persisted session is required). See README.md for the
// architecture and the M1-M4 milestones.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"

	"golang.org/x/term"

	caldavbackend "github.com/jmdlab/cal-gateway/internal/caldav"
	"github.com/jmdlab/cal-gateway/internal/config"
	"github.com/jmdlab/cal-gateway/internal/invite"
	"github.com/jmdlab/cal-gateway/internal/proton"
	"github.com/jmdlab/cal-gateway/internal/server"
	"github.com/jmdlab/cal-gateway/internal/store"
	calsync "github.com/jmdlab/cal-gateway/internal/sync"
	"net"
	"net/http"
	"time"
)

const usage = `cal-gateway — Proton Calendar ↔ CalDAV gateway

Usage:
  cal-gateway <command> [-config <path>]

Commands:
  login    supervised Proton login (password via CALGW_LOGIN_PASSWORD or prompt, TOTP 2FA on stdin)
  serve    run the read-only CalDAV mirror (requires a persisted session)
  status   print scaffold status and exit
`

func main() {
	log.SetPrefix("cal-gateway ")
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
	case "login", "serve", "status":
		// known commands
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}

	configPath := parseConfigFlag(os.Args[2:])

	switch cmd {
	case "status":
		runStatus(configPath)
	case "login":
		if err := runLogin(configPath); err != nil {
			log.Fatalf("login: %v", err)
		}
	case "serve":
		if err := runServe(configPath); err != nil {
			if errors.Is(err, proton.ErrSessionInvalid) {
				// Dead session = a CLEAN failure, not a crash: systemd must not
				// restart in a loop a daemon that cannot authenticate (drop-in
				// RestartPreventExitStatus=78) — only a supervised TOTP re-login
				// fixes it.
				log.Printf("serve: %v", err)
				log.Printf("Proton session invalid/revoked — re-run `cal-gateway login -config %s` (exit %d, not restarted by systemd)", configPath, exitSessionInvalid)
				os.Exit(exitSessionInvalid)
			}
			log.Fatalf("serve: %v", err)
		}
	}
}

// exitSessionInvalid is the "Proton session invalid/revoked, re-login required"
// exit code (78 = EX_CONFIG from sysexits.h). The systemd drop-in
// RestartPreventExitStatus=78 prevents a crash-loop on this code.
const exitSessionInvalid = 78

// parseConfigFlag extracts the -config option from the post-command arguments,
// defaulting to "config.toml".
func parseConfigFlag(args []string) string {
	configPath := "config.toml"
	for i := 0; i < len(args); i++ {
		if args[i] == "-config" && i+1 < len(args) {
			configPath = args[i+1]
			i++
		}
	}
	return configPath
}

func runStatus(configPath string) {
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Printf("config: %v (using defaults)", err)
		cfg = config.Default()
	}
	log.Printf("listen_addr=%s data_dir=%s poll_interval=%s account=%s",
		cfg.ListenAddr, cfg.DataDir, cfg.PollInterval, cfg.Account.Username)

	if _, err := proton.LoadSession(cfg.DataDir); err != nil {
		log.Printf("session: none (%v)", err)
	} else {
		log.Printf("session: present in %s", cfg.DataDir)
	}
	log.Printf("milestones: M1 read, M2 create/delete, M3 update + shadow store/poller DONE, M4 hardening TODO")
}

// runLogin runs the supervised Proton login and persists the session.
// Designed HEADLESS: the password comes from CALGW_LOGIN_PASSWORD (fallback
// to a no-echo stdin prompt), the TOTP code is the only interactive moment
// (prompt "Code 2FA:"), the optional mailbox password from
// CALGW_MAILBOX_PASSWORD. No secret is logged or persisted — only the tokens +
// the salted key passphrase go into session.json (0600).
// The flow itself (SRP → TOTP → salts with unlock-scope 9101 → SaltForKey →
// SaveSession) lives in internal/proton/login.go.
func runLogin(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.Account.Username == "" || cfg.Account.Username == "(unset)" {
		return errors.New("account.username missing in config")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	password := os.Getenv("CALGW_LOGIN_PASSWORD")
	_ = os.Unsetenv("CALGW_LOGIN_PASSWORD")
	if password == "" {
		password, err = promptSecret("Proton password: ")
		if err != nil {
			return fmt.Errorf("reading password: %w", err)
		}
	}
	if password == "" {
		return errors.New("no password provided (set CALGW_LOGIN_PASSWORD or answer the prompt)")
	}

	prompts := proton.LoginPrompts{
		TwoFACode: func() (string, error) {
			return promptLine("Code 2FA: ")
		},
		MailboxPassword: func() ([]byte, error) {
			if mbp := os.Getenv("CALGW_MAILBOX_PASSWORD"); mbp != "" {
				_ = os.Unsetenv("CALGW_MAILBOX_PASSWORD")
				return []byte(mbp), nil
			}
			s, err := promptSecret("Mailbox password (two-password mode): ")
			return []byte(s), err
		},
	}

	err = proton.Login(ctx, cfg.DataDir, cfg.Account.Username, []byte(password), prompts)
	if errors.Is(err, proton.ErrCaptchaRequired) {
		log.Printf("CAPTCHA required, manual login needed — sign in once via an official Proton client (web/app) from this IP, then re-run `cal-gateway login`.")
		return err
	}
	if err != nil {
		return err
	}
	log.Printf("login OK, session persisted for %s (in %s)", cfg.Account.Username, cfg.DataDir)
	return nil
}

// stdinReader is shared across prompts: one bufio.Reader per prompt would
// swallow the buffer of the following inputs.
var stdinReader = bufio.NewReader(os.Stdin)

// promptLine reads a line from stdin after printing label to stderr.
func promptLine(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// promptSecret reads a secret: without echo if stdin is a TTY, otherwise a
// plain line read (supervised pipe). Never logged.
func promptSecret(label string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, label)
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(raw)), nil
	}
	return promptLine(label)
}

func runServe(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	// Refuse to boot with the example password or empty gateway credentials.
	if err := cfg.Validate(); err != nil {
		return err
	}
	// Sanity check on the poll interval: a zero/negative value is nonsensical;
	// the poller clamps it back to 60s, so warn instead of failing.
	if cfg.PollInterval.Duration <= 0 {
		log.Printf("WARN poll_interval=%s is not positive — falling back to the poller default (60s)", cfg.PollInterval)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Instance lock BEFORE RestoreAccount: two concurrent `serve` on the same
	// data_dir would be two writers of session.json (refresh-token rotation
	// race → invalidated session → manual TOTP re-login) and of store.json.
	lock, err := acquireServeLock(cfg.DataDir)
	if err != nil {
		return err
	}
	defer lock.Close() // also releases the flock

	account, err := restoreAccountWithRetry(ctx, cfg.DataDir, cfg.ListenAddr, configPath)
	if err != nil {
		return err
	}
	log.Printf("proton session restored from %s", cfg.DataDir)

	// Shadow store + poller: the CalDAV server NEVER talks to the Proton API
	// directly on a client request (root cause of the "Error 2" bug: live
	// fetch+decrypt during a PROPFIND → dataaccessd cancels). Reads are served
	// from the store, writes delegated to Proton then reflected write-through,
	// the poller reconciles.
	st, err := store.Open(filepath.Join(cfg.DataDir, "store.json"))
	if err != nil {
		return fmt.Errorf("opening shadow store: %w", err)
	}
	cached := calsync.NewCachedSource(account, st)
	poller := calsync.NewPoller(account, st, cfg.PollInterval.Duration)

	// Readiness gate: the port is opened IMMEDIATELY (the tcp watchdog passes
	// from second 1, no more SIGTERM in the middle of the initial sync window)
	// and every route answers 503 + Retry-After while ready is false. The
	// initial sync runs in a goroutine — never again BEFORE listening.
	ready := &atomic.Bool{}

	if st.Empty() {
		// Store never synced (first boot, or a previous initial sync interrupted
		// — Synced flag absent): 503 until the sync completes.
		log.Printf("store never synced — port opened immediately, 503 until the initial sync completes")
		go func() {
			if err := poller.SyncOnce(ctx); err != nil && ctx.Err() == nil {
				// Hard failure: switch into service ANYWAY — better to serve the
				// cache (possibly empty) than stay in 503 forever; the poller
				// retries every interval and /healthz stays "stale" as long as
				// no cycle succeeds.
				log.Printf("ERROR: initial sync failed: %v — switching into service anyway (cache served as-is)", err)
			}
			ready.Store(true)
			poller.Run(ctx)
		}()
	} else {
		// Store already synced at least once: serve immediately, refresh in the
		// background.
		log.Printf("store populated (%d calendars) — immediate service, background refresh", len(st.Calendars()))
		ready.Store(true)
		go func() {
			if err := poller.SyncOnce(ctx); err != nil && ctx.Err() == nil {
				log.Printf("poller: initial refresh failed: %v", err)
			}
			poller.Run(ctx)
		}()
	}

	// The Basic auth user is the principal segment (e.g. "/alice/"): go-webdav
	// v0.7.0 routes by path depth, the principal must be at depth 1 and the home
	// set at depth 2 (see internal/caldav).
	backend := caldavbackend.NewBackend(cached, cfg.Auth.Username)

	// Outbound invitation policy (M5a, backend): Proton login + ALL the
	// account addresses (aliases/custom domains included) to recognize an
	// ORGANIZER that is "ours"; the iMIP sender only exists if [invite] is
	// enabled — otherwise an outbound PUT with an ATTENDEE stays refused (403).
	var ownerAddrs []string
	if strings.Contains(cfg.Account.Username, "@") {
		ownerAddrs = append(ownerAddrs, cfg.Account.Username)
	}
	ownerAddrs = append(ownerAddrs, account.Addresses()...)
	var sender caldavbackend.InviteSender
	if cfg.Invite.Enabled {
		sender = invite.NewSender(invite.Config{
			Enabled:  true,
			Host:     cfg.Invite.SMTPHost,
			Port:     cfg.Invite.SMTPPort,
			Username: cfg.Invite.Username,
			Password: cfg.Invite.Password,
			FromName: cfg.Invite.FromName,
		})
		log.Printf("outbound invitations ENABLED (SMTP bridge %s:%d)", cfg.Invite.SMTPHost, cfg.Invite.SMTPPort)
	} else {
		log.Printf("outbound invitations disabled ([invite] absent or enabled=false) — PUT with outbound ATTENDEE → 403")
	}
	// M6a (INBOUND RSVP): the read-only IMAP watcher for the "has accepted"
	// badge is not built yet (need not proven live — see FEATURE-MATRIX §3).
	// The flag is reserved: we warn if it is enabled so nobody believes the
	// feature is running.
	if cfg.Invite.WatchReplies {
		log.Printf("WARNING [invite] watch_replies=true but the M6a IMAP watcher is NOT implemented (no-op) — see FEATURE-MATRIX §3")
	}
	backend.ConfigureInvites(ownerAddrs, cfg.Invite.FromName, sender)

	srv, err := server.New(server.Config{
		ListenAddr:            cfg.ListenAddr,
		AuthUser:              cfg.Auth.Username,
		AuthPassword:          cfg.Auth.Password,
		CalendarUserAddresses: ownerAddrs,
		Ready:                 ready,
		PollerLastOK:          poller.LastOK,
	}, backend)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}

// restoreAccountWithRetry keeps the daemon ALIVE while Proton is unreachable at
// boot. Until 2026-08-29 a 5xx from mail.proton.me on the very first request
// made `serve` exit 1: systemd restarted it every 10-60 s for the whole outage
// (83 failures logged during the Proton incident of 2026-08-26, one OnFailure
// e-mail per attempt, a "failed unit" alert for a problem on Proton's side) and
// the CalDAV clients saw connection refused instead of a clean 503.
//
// Now the FIRST failure opens a bootstrap listener on listenAddr — /healthz
// answers 200 "starting" (same contract as the readiness gate, the watchdog
// keeps quiet), everything else 503 + Retry-After — and RestoreAccount is
// retried with exponential backoff (10 s → 5 min) until Proton answers or the
// process is stopped. Errors that can NEVER self-heal (no session, session
// invalid/revoked) still return immediately: exit 78 stays the operator's
// signal.
func restoreAccountWithRetry(ctx context.Context, dataDir, listenAddr, configPath string) (*proton.Account, error) {
	var (
		boot    *http.Server
		status  atomic.Value // string shown on /healthz
		attempt int
	)
	stopBoot := func() {
		if boot == nil {
			return
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = boot.Shutdown(shutdownCtx)
		boot = nil
	}
	defer stopBoot()

	for {
		attempt++
		account, err := proton.RestoreAccount(ctx, dataDir)
		if err == nil {
			if attempt > 1 {
				log.Printf("proton reachable again after %d attempt(s) — handing the port over to the CalDAV server", attempt)
			}
			stopBoot()
			return account, nil
		}
		if errors.Is(err, proton.ErrNoSession) {
			return nil, fmt.Errorf("%w — run `cal-gateway login -config %s` first", err, configPath)
		}
		if errors.Is(err, proton.ErrSessionInvalid) || ctx.Err() != nil {
			return nil, err
		}
		delay := retryDelay(attempt)
		msg := fmt.Sprintf("starting: waiting for Proton (attempt %d failed: %v — next try in %s)", attempt, err, delay)
		status.Store(msg)
		log.Printf("proton unreachable at boot: %v — retrying in %s (attempt %d); port held with 503 meanwhile", err, delay, attempt)
		if boot == nil {
			boot = &http.Server{
				Addr:              listenAddr,
				Handler:           bootstrapHandler(func() string { s, _ := status.Load().(string); return s }),
				ReadHeaderTimeout: 10 * time.Second,
			}
			go func(srv *http.Server) {
				if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Printf("bootstrap listener on %s: %v (the CalDAV server will bind later anyway)", listenAddr, err)
				}
			}(boot)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("serve: interrupted while waiting for Proton: %w", ctx.Err())
		case <-time.After(delay):
		}
	}
}

// retryDelay is the boot backoff: 10 s, 20 s, 40 s, … capped at 5 min. A
// Proton outage lasts minutes to hours; hammering the API every 10 s for hours
// would only earn a 429 — five minutes keeps the recovery latency acceptable
// (the poller then runs every poll_interval anyway).
func retryDelay(attempt int) time.Duration {
	const base, max = 10 * time.Second, 5 * time.Minute
	if attempt < 1 {
		attempt = 1
	}
	d := base
	for i := 1; i < attempt && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	return d
}

// bootstrapHandler is what the port answers while Proton is unreachable at
// boot: /healthz (loopback only, like the real one) → 200 "starting…" so the
// watchdog does not restart a daemon that is doing the right thing; anything
// else → 503 + Retry-After, the same signal the readiness gate sends during
// the initial sync (CalDAV clients retry, they never see connection refused).
func bootstrapHandler(status func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintln(w, status())
			return
		}
		w.Header().Set("Retry-After", "30")
		http.Error(w, "cal-gateway is starting (waiting for Proton) — please retry", http.StatusServiceUnavailable)
	})
}

// acquireServeLock takes a non-blocking EXCLUSIVE flock(2) on
// <data_dir>/serve.lock — a SINGLE `serve` instance per data_dir (see the
// caller for the why). The lock is held by the descriptor: it drops
// automatically when the process dies, crash included (no stale lockfile
// possible). The returned *os.File must stay open for the whole life of the
// daemon.
func acquireServeLock(dataDir string) (*os.File, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("serve: creating data dir: %w", err)
	}
	path := filepath.Join(dataDir, "serve.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("serve: opening lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("serve: another `cal-gateway serve` instance is already running on %s (lock %s held) — stop it before restarting", dataDir, path)
	}
	// Best-effort trace of the tenant (human diagnostics only — the lock
	// semantics are carried by flock, not by the content).
	_ = f.Truncate(0)
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	return f, nil
}
