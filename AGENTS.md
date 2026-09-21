# cal-gateway

> Unofficial, MIT-licensed Go daemon that bridges Proton Calendar (end-to-end encrypted) to any standard CalDAV client, decrypting locally and re-encrypting writes.

**Status:** live · **Last verified:** 2026-09-21

This file is the entry point for any AI model or engineer taking over this project.
It is written to be publishable: no secrets, no internal topology, no personal data.
Anything marked `<LIKE_THIS>` is a deployment-specific value; it is not part of this
repository.

This repo already has a complete documentation set. **This file only routes you to it**
and lists the traps. Do not duplicate content here; fix the target document instead.

## Where to read what
| Question | Document |
|---|---|
| What it is, warnings, trade-offs, quick start, config overview | `README.md` |
| Install, systemd unit, reverse proxy, VPN-only exposure, watchdog tiers, upgrade, troubleshooting | `DEPLOYMENT.md` |
| Threat model, at-rest encryption, what the session file grants, reporting | `SECURITY.md` |
| Build, test, live-test gates, PR conventions | `CONTRIBUTING.md` |
| Which CalDAV / iCalendar / invitation features work, partially work, or are out of scope | `docs/FEATURE-MATRIX.md` |
| Every config key with comments | `config.example.toml` |
| "Up but not serving" watchdog (script + unit + timer) | `deploy/` |

## Stack
Go (version pinned in `go.mod` and `.github/workflows/ci.yml`), pure Go, no CGO. Packages under `internal/`: `proton` (API client, login, session), `caldav` + `server` (HTTP/WebDAV surface), `sync`, `store`, `atrest` (encryption at rest), `invite` (iMIP), `icaltime`, `config`. Single binary, entry point `cmd/cal-gateway/main.go`, subcommands `login`, `serve`, `status`.

## Build, test, run (from the `Makefile`)
```
make build     # CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o cal-gateway ./cmd/cal-gateway
make test      # go test ./...   (Makefile exports CGO_ENABLED=0)
make vet       # go vet ./...
make lint      # fails if gofmt -l reports anything
make fmt       # gofmt -w .
make run       # build, then ./cal-gateway serve -config config.toml
```
CI additionally runs `govulncheck`. Unit tests are mocked and need no network or credentials.

## Deploy
Follow `DEPLOYMENT.md` ("Upgrade": replace the binary, restart the unit). `login` is interactive (second factor) and must be supervised by the account holder; it cannot be automated. Verify with `cal-gateway status` and the `/healthz` endpoint described in `DEPLOYMENT.md`.

## Configuration and state
- `config.toml` (gitignored; template `config.example.toml`). The recommended exposure (local listener behind a TLS reverse proxy, private network only) is described in `DEPLOYMENT.md`; the actual port and host are deployment-specific; not part of this repository.
- The state directory (`data_dir`) must be **treated like a password**: never copy it into a repo, a ticket or a log. What it grants and how it is protected: `SECURITY.md`.
- Environment variables are test/diagnostic only, all prefixed `CALGW_`: `CALGW_LIVE`, `CALGW_LIVE_SEND`, `CALGW_DATADIR`, `CALGW_CALID`, `CALGW_UID`, `CALGW_TEST_CALID_PREFIX`, `CALGW_LOGIN_PASSWORD`, `CALGW_MAILBOX_PASSWORD`, `CALGW_SMTP_USERNAME`, `CALGW_SMTP_PASSWORD`, `CALGW_HTTPDEBUG`. See `CONTRIBUTING.md`.

## Things a new model gets wrong
1. **Bare `go test` / `go build` with CGO on.** On hosts where a stray `as` binary shadows the GNU assembler, `runtime/cgo` fails to build with a confusing assembler error. Use the `make` targets, or prefix `CGO_ENABLED=0`. The stack is pure Go; nothing needs CGO.
2. **Exiting on a transient upstream failure.** If `serve` exits non-zero while the upstream API is returning 5xx, the service manager restarts it in a tight loop and any `OnFailure=` hook fires **on every failed attempt** — an alert storm for an outage nobody on this side can fix. What must stay: `restoreAccountWithRetry` in `cmd/cal-gateway/main.go` keeps the process alive and retries with backoff. On the unit side, use a generous `RestartSec` and start-limit window, and keep any failure hook silent during an auto-restart race. General rule: any unit combining `Restart=` with `OnFailure=` must filter that race.
3. **Treating exit status 78 as a crash.** It means "session invalid, a human must re-login". The unit uses `RestartPreventExitStatus=78` on purpose; restarting cannot fix it. Never loop on it, never script the login.
4. **Turning on `CALGW_HTTPDEBUG` and leaving it.** It writes decrypted calendar content to disk in clear.
5. **Running live tests against a real calendar.** `CALGW_LIVE=1` reads and writes real events; `CALGW_LIVE_SEND=1` sends real e-mail. Disposable calendar only, both off in CI.
6. **Exposing the daemon port or weakening the proxy/VPN posture** to "make a client work". Read `SECURITY.md` first; the answer is almost always client configuration.
7. **Trusting the upstream API to be stable.** Endpoints are undocumented and reverse-engineered from the provider's open-source clients; a silent behaviour change is the first hypothesis when sync breaks. Check `docs/FEATURE-MATRIX.md` before calling something a regression.
8. **Committing local state.** `.gitignore` already covers config, session, store, keys, databases, `.eml`, logs and the built binary; keep new state files under `data/`.
9. **"go: command not found".** In a non-interactive shell the Go toolchain may be installed but absent from `PATH`; locate it rather than concluding it is missing or installing a second copy.
10. **Proxying `/healthz`.** It is a local-only endpoint by design (`DEPLOYMENT.md`); never add it to the reverse proxy.

## Known gaps
- README badges are placeholders; no tagged releases.
- The invitation quota is in-memory and resets on restart (documented in `README.md`).
- `DEPLOYMENT.md` shows the base unit only; restart back-off overrides and failure-hook filtering are deployment-specific; not part of this repository.

## How to update this file
Hand-written and deliberately short (120 lines maximum). Commands come from the `Makefile`; if a target changes, update it there first. New knowledge belongs in the five documents above, not here.
