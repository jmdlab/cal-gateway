# Contributing to cal-gateway

Thanks for your interest. This is a small project with a strict safety posture
(it holds a live, decrypted Proton session) — please read the conventions below
before opening a PR.

## Build

The whole stack is pure Go. Build with **CGO disabled** — a static binary, and
it sidesteps a toolchain gotcha where a stray `as` binary on `PATH` shadows the
GNU assembler and breaks `runtime/cgo`.

```sh
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go build -o cal-gateway ./cmd/cal-gateway
# or:
make build
```

## Test

Unit tests are **mocked and never touch the network**:

```sh
go test ./...
# or:
make test
```

They must pass with no credentials and no external services. CI runs exactly
this (plus `go vet`, `gofmt -l`, and `govulncheck`).

### Live tests (opt-in, gated by env vars)

Some tests exercise the real Proton API. They are **skipped by default** and only
run when you explicitly opt in. **Only ever run them against your own throwaway /
disposable calendar — never a real one, and never a primary account** (see the
ToS caveat in [SECURITY.md](SECURITY.md)).

Two independent gates:

- **`CALGW_LIVE=1`** — enables live tests that read/write events. Requires a
  persisted session:
  - `CALGW_DATADIR=/path/to/data` — a `data_dir` with a valid `session.json`
    (produced by `cal-gateway login`).
  - `CALGW_CALID=<calendar-id>` — the ID of a **disposable** calendar you own.
  - `CALGW_UID=<event-uid>` — where a test needs a specific event UID.
- **`CALGW_LIVE_SEND=1`** — a **second, separate gate** required before any test
  actually **sends email** (iMIP REQUEST/REPLY/CANCEL through the bridge). Leave
  it unset unless you specifically intend to send real mail from your bridge
  account.

Example (read/write, no email):

```sh
CALGW_LIVE=1 CALGW_DATADIR=./data CALGW_CALID=<your-throwaway-calendar-id> \
  go test ./internal/...
```

Because both gates default to off, CI is safe: live tests skip themselves.

## Diagnostics

`CALGW_HTTPDEBUG=<path>` dumps decrypted request/response bodies for debugging.
It writes **calendar content in clear** — use it only on a disposable account and
**never in production.** Do not commit any file it produces (`*.eml`, `*.log`,
etc. are gitignored).

## Style

- **`gofmt`** — all Go sources must be gofmt-clean. `make lint` (or `gofmt -l .`)
  must print nothing. `go vet ./...` must pass.
- **English only** — code, comments, identifiers, log messages, and docs are all
  in English.
- Keep the safety invariants intact: loopback-only defaults, no secrets in the
  repo, honest error codes over silent no-ops (see
  [docs/FEATURE-MATRIX.md](docs/FEATURE-MATRIX.md)), and the Proton Bridge IMAP
  path stays strictly read-only.

## Reporting security issues

Do **not** open a public issue for a vulnerability — see the private disclosure
process in [SECURITY.md](SECURITY.md).
