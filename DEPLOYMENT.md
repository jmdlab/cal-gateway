# Deployment

How to run cal-gateway for real. Read the [Security trade-offs](README.md#security-trade-offs)
first — this bridge decrypts your calendar on the host, so the security of the
host *is* the security of your calendar.

There are two tiers:

- **(a) Minimal / local test** — loopback only, a CalDAV client on the same
  machine. Good for trying it out. Not for daily use.
- **(b) Secure family setup** — nginx TLS + **WireGuard-only** exposure. The
  recommended target. The rest of this guide builds up to it.

---

## Prerequisites

- A Linux host you control and trust.
- **Go 1.26+** to build (build machine only; the result is a static binary).
- A domain name + TLS certificate for tier (b) (e.g. Let's Encrypt).
- A **secondary / family** Proton account (never a primary one — see the ToS
  caveat in [SECURITY.md](SECURITY.md)).
- For outgoing invitations/RSVP (optional): a running **Proton Bridge** exposing
  local SMTP (and, later, IMAP).

## Build

```sh
CGO_ENABLED=0 go build -o cal-gateway ./cmd/cal-gateway
# or: make build
# or install from source:
CGO_ENABLED=0 go install github.com/jmdlab/cal-gateway/cmd/cal-gateway@latest
```

**cgo gotcha:** build with `CGO_ENABLED=0`. The stack is pure Go, and on some
hosts a Python CLI named `as` shadows the GNU assembler on `PATH` and breaks
`runtime/cgo`. Disabling cgo sidesteps it and yields a static binary.

Install it:

```sh
sudo install -m 0755 cal-gateway /usr/local/bin/cal-gateway
```

---

## (a) Minimal / local test

For a quick trial with Thunderbird (or any CalDAV client) on the same machine.

```sh
cp config.example.toml config.toml     # edit: account.username, [auth] password
CALGW_LOGIN_PASSWORD='your-proton-password' \
  ./cal-gateway login -config config.toml   # type the TOTP code at the prompt
./cal-gateway serve -config config.toml
```

Point the client at `http://127.0.0.1:5232` with the `[auth]` credentials. This
has no TLS and no process supervision — do not use it beyond testing.

---

## (b) Secure family setup (nginx TLS + WireGuard-only)

The full picture:

```
iPhone / Mac (your devices)
   │  WireGuard tunnel  (only your devices exist on this network)
   ▼
host:  nginx :443  (TLS, allow WG subnet / deny all)
          │  reverse proxy
          ▼
       cal-gateway  127.0.0.1:5232  (loopback, Basic auth)
          │
          ▼
       Proton API
```

### 1. Service user + directories

```sh
sudo useradd --system --home-dir /var/lib/cal-gateway --shell /usr/sbin/nologin cal-gw
sudo install -d -o cal-gw -g cal-gw -m 0700 /var/lib/cal-gateway
sudo install -d -o root  -g cal-gw -m 0750 /etc/cal-gateway
```

Write `/etc/cal-gateway/config.toml` (see [config.example.toml](config.example.toml))
with `0640 root:cal-gw`. Set `listen_addr = "127.0.0.1:5232"` and `data_dir =
"/var/lib/cal-gateway"`.

### 2. Log in (CLI, supervised)

The session is created interactively — the daemon cannot do this unattended
because of TOTP:

```sh
sudo -u cal-gw CALGW_LOGIN_PASSWORD='your-proton-password' \
  /usr/local/bin/cal-gateway login -config /etc/cal-gateway/config.toml
# → prompts "Code 2FA:" — type the current TOTP code.
# → writes session.json (0600, sealed at rest) into /var/lib/cal-gateway.
# Two-password mode: also provide CALGW_MAILBOX_PASSWORD.
```

**CAPTCHA fallback:** if login reports `CAPTCHA required`, sign in once from an
official Proton client (web/app) **from this host's IP**, then re-run the login.

The password is passed via env (never logged) and is the only cleartext moment;
only tokens + the salted key passphrase are persisted (see [SECURITY.md](SECURITY.md)).

### 3. systemd unit (hardened)

`/etc/systemd/system/cal-gateway.service`:

```ini
[Unit]
Description=cal-gateway — Proton Calendar to CalDAV bridge
Documentation=https://github.com/jmdlab/cal-gateway
After=network-online.target
Wants=network-online.target
# Do not start until a session exists (created by `cal-gateway login`).
ConditionPathExists=/var/lib/cal-gateway/session.json

[Service]
Type=simple
User=cal-gw
Group=cal-gw
ExecStart=/usr/local/bin/cal-gateway serve -config /etc/cal-gateway/config.toml
Restart=on-failure
RestartSec=10
# A dead Proton session exits 78 (EX_CONFIG) and must NOT crash-loop — it needs
# a manual `cal-gateway login`. Keep this so systemd stops cleanly on exit 78.
RestartPreventExitStatus=78

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077

# Only writable path: the data_dir (session.json + shadow store).
StateDirectory=cal-gateway
StateDirectoryMode=0700
ReadWritePaths=/var/lib/cal-gateway

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now cal-gateway
systemctl status cal-gateway
```

### 4. nginx reverse proxy (TLS)

Terminate TLS at nginx and proxy to the loopback daemon. WebDAV methods
(OPTIONS/PROPFIND/REPORT/PUT/DELETE) and headers must pass through untouched.

`/etc/nginx/sites-available/cal.example.com`:

```nginx
# 80: ACME challenges + redirect. 443: TLS terminated here, proxy to 127.0.0.1:5232.
server {
    listen 80;
    listen [::]:80;
    server_name cal.example.com;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 301 https://$host$request_uri; }
}

# Rate-limit zone (put this in http{} / a conf.d snippet if not already present):
# limit_req_zone $binary_remote_addr zone=caldav:10m rate=2r/s;

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name cal.example.com;

    ssl_certificate     /etc/letsencrypt/live/cal.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cal.example.com/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    client_max_body_size 16m;

    location / {
        # dataaccessd syncs arrive in bursts (~40 requests in a few seconds):
        # a generous burst + nodelay, with the sustained rate capped by the zone.
        # The real ban comes from fail2ban (jail on auth failures) below.
        limit_req zone=caldav burst=50 nodelay;

        proxy_pass http://127.0.0.1:5232;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        # WebDAV headers relayed explicitly.
        proxy_set_header Destination $http_destination;
        proxy_set_header Depth $http_depth;
        proxy_set_header Brief $http_brief;
        proxy_read_timeout 120s;
        proxy_buffering off;
    }
}
```

> `/healthz` is served on loopback without auth and is deliberately **not**
> proxied — do not add a `location /healthz` here. It stays a local-only oracle
> for the watchdog.

Enable + reload:

```sh
sudo ln -s /etc/nginx/sites-available/cal.example.com /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 5. fail2ban jail (brute-force on 401)

cal-gateway logs auth failures with the real client IP (from `X-Real-IP`) to the
journal, so failures are bannable.

`/etc/fail2ban/filter.d/cal-gateway-auth.conf`:

```ini
[Definition]
failregex = cal-gateway auth failure from <HOST>$
ignoreregex =
```

`/etc/fail2ban/jail.d/cal-gateway-auth.conf`:

```ini
[cal-gateway-auth]
enabled      = true
backend      = systemd
journalmatch = _SYSTEMD_UNIT=cal-gateway.service
filter       = cal-gateway-auth
maxretry     = 6
findtime     = 600
bantime      = 3600
# Ban at the nginx edge: the attacker hits :443 (and :80).
port         = 443,80
action       = %(action_)s
```

```sh
sudo systemctl restart fail2ban
sudo fail2ban-client status cal-gateway-auth
```

### 6. WireGuard-only lockdown (the recommended step)

This is what turns "a stranger who finds your URL can guess your password" into
"the service does not exist for anyone outside your own devices." Restrict the
CalDAV vhost to a WireGuard subnet; your iPhone/Mac reach it only through the
tunnel.

**Server `wg0`** (`/etc/wireguard/wg0.conf`), subnet `10.10.0.0/24`, server
`10.10.0.1`:

```ini
[Interface]
Address = 10.10.0.1/24
ListenPort = 51820
PrivateKey = <server-private-key>

# iPhone
[Peer]
PublicKey = <iphone-public-key>
AllowedIPs = 10.10.0.2/32

# Mac
[Peer]
PublicKey = <mac-public-key>
AllowedIPs = 10.10.0.3/32
```

```sh
sudo systemctl enable --now wg-quick@wg0
```

Open **only** the WireGuard UDP port to the internet (e.g. `51820/udp`) in your
firewall/security group. Keep **80/tcp** open for ACME renewals; do **not**
expose 443 publicly.

**Lock the vhost to the WG subnet.** In the `server { listen 443 … }` block,
restrict access — keep ACME on port 80 public so certs can renew:

```nginx
    # inside the 443 server block
    location / {
        allow 10.10.0.0/24;   # WireGuard peers only
        deny  all;            # everyone else: 403
        # ... the proxy_pass block from step 4 ...
    }
```

**Apply / rollback pattern** (so a mistake never locks you out permanently):

```sh
sudo nginx -t && sudo systemctl reload nginx          # apply
# verify from a WG-connected device that CalDAV works, and from a non-WG
# network that :443 now returns 403.
# rollback if needed: revert the allow/deny lines, then:
sudo nginx -t && sudo systemctl reload nginx
```

Because your devices connect over the tunnel, point them at the tunnel-facing
name/IP (e.g. `https://cal.example.com` resolving to `10.10.0.1`, or the WG IP
directly with a matching certificate/SAN).

### 7. Add the account on iPhone / Mac

Connect the device to WireGuard first (WireGuard app / Settings → VPN), then:

- **iOS:** Settings → Calendar → Accounts → Add Account → Other → **Add CalDAV
  Account**. Server: `cal.example.com` (or the WG IP). Username/Password: the
  `[auth]` credentials from `config.toml` (**not** the Proton password).
- **macOS:** Calendar → Settings → Accounts → **+** → Other CalDAV Account →
  Manual. Same server + `[auth]` credentials.

Use HTTPS. If the client offers "Advanced", the account/principal path is served
under the auth username (e.g. `/<auth-username>/`).

### 8. Keeping it running (watchdog)

Two independent tiers of resilience — install both:

- **Tier 1 — systemd itself.** The unit uses `Restart=on-failure` +
  `RestartSec`, so a *crashed* process is restarted automatically. And
  `RestartPreventExitStatus=78` means a **dead Proton session** (exit 78) does
  **not** crash-loop: the daemon stops cleanly and waits for a manual
  `cal-gateway login`. This is by design — a revoked refresh token or unlockable
  keys can only be fixed by a supervised TOTP re-login, not by restarting.
- **Tier 2 — the `/healthz` watchdog** (`deploy/`). systemd only knows whether
  the *process* is alive, not whether it is actually *serving correctly*. The
  daemon can be "up" (port open) yet unhealthy — e.g. the Proton API has been
  unreachable for > 5 min, so `/healthz` returns `503 stale`. The watchdog
  probes `/healthz` every 2 minutes and restarts on any non-2xx, catching that
  "up but not working" class.

Install the watchdog:

```sh
sudo install -m 0755 deploy/cal-gateway-watchdog.sh /usr/local/bin/
sudo cp deploy/cal-gateway-watchdog.service deploy/cal-gateway-watchdog.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cal-gateway-watchdog.timer
# cron alternative (non-systemd): */2 * * * * /usr/local/bin/cal-gateway-watchdog.sh
```

**Honest limitation:** a restart will **not** fix a genuinely dead session (that
needs a re-login). For that case, wire up the `# notify hook` in the watchdog
script (mail/webhook) so a human is alerted when restarts don't make it healthy
again — that is the exit-78 signal.

---

## Upgrades

Replace the binary and restart:

```sh
sudo install -m 0755 cal-gateway /usr/local/bin/cal-gateway
sudo systemctl restart cal-gateway
```

The at-rest migration (cleartext → sealed `session.json`/`store.json`) is
**automatic and non-destructive** on the first boot of a newer binary — the
session is never discarded, the store re-syncs if unreadable (see
[SECURITY.md](SECURITY.md)).

## Troubleshooting

- **Service stopped with exit 78** — the Proton session is invalid/revoked.
  Re-run `cal-gateway login` (supervised, with TOTP). Not a crash-loop; expected.
- **`CAPTCHA required` at login** — sign in once via an official Proton client
  from this host's IP, then re-run the login.
- **A write returns 403** — this is usually gatekeeping, not a bug. Check
  [docs/FEATURE-MATRIX.md](docs/FEATURE-MATRIX.md) for the specific policy
  (e.g. THISANDFUTURE edits, floating-time events, VTODO/VJOURNAL, per-occurrence
  RSVP on invited series).
- **Client shows nothing on first connect / 503s** — the initial sync is still
  running. The daemon opens the port immediately and returns `503 + Retry-After`
  until the first full sync finishes; clients retry automatically.
- **Health check** — `curl -s http://127.0.0.1:5232/healthz` on the host: `ok`
  (recent successful poll), `starting` (warming up), or `stale: …` (last
  successful poll too old → the watchdog will restart).
