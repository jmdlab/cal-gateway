# Security — cal-gateway

## Reporting a vulnerability

Please report security issues **privately**, not in public issues or pull
requests.

- **Preferred:** open a private
  [GitHub Security Advisory](https://github.com/jmdlab/cal-gateway/security/advisories/new)
  on this repository (Security → Advisories → *Report a vulnerability*).
- Include a description, affected version/commit, reproduction steps, and impact.

**Response target (best-effort, no guarantee):** acknowledgement within ~7 days,
an initial assessment within ~30 days. This is a small community project — please
allow reasonable time for a coordinated fix before any public disclosure. We will
credit reporters who want to be credited.

## Caveat — undocumented API and Proton's Terms of Service

This is a **security-relevant caveat**, not just a functional one. cal-gateway
talks to **undocumented, private Proton API endpoints** reverse-engineered from
Proton's open-source clients. Two consequences:

- **They can change without notice**, and a change can break the bridge
  *silently* — including in ways that affect data integrity (e.g. a write path
  that stops round-tripping correctly). Do not treat this bridge as a system of
  record.
- **Using it may violate Proton's Terms of Service**, which can result in
  warnings, rate-limiting, CAPTCHA challenges, or **account suspension**. Use a
  **secondary / family account**, never a primary one. This is a risk you accept
  by running the software; there is no warranty (see [LICENSE](LICENSE)).

## Network posture — the primary mitigation

The most effective control is **not exposing the daemon.**

- **Bind loopback only** (`listen_addr = 127.0.0.1:…`) and terminate TLS in a
  reverse proxy. Never bind the daemon to a public interface.
- **Use a strong, dedicated `[auth]` password** — a separate app password, never
  your Proton password.
- **Prefer WireGuard/VPN-only exposure.** With a public HTTPS endpoint, a single
  leaked or guessed Basic-auth password yields full calendar read/write and — if
  `[invite]` is enabled — the ability to send email as you. Restricting the
  vhost to a WireGuard subnet puts a second, key-based, no-public-auth-surface
  layer in front of that password: an attacker must breach WireGuard before they
  can even reach the auth. This directly mitigates the **leaked-credentials**
  vector that the at-rest encryption below does *not* cover. See the two-tier
  guide in [DEPLOYMENT.md](DEPLOYMENT.md).
- Defense-in-depth for a public endpoint: a **fail2ban** jail on auth failures
  and **nginx rate-limiting** (both shown in DEPLOYMENT.md) slow brute-force but
  do not remove the exposure.
- **`CALGW_HTTPDEBUG` writes decrypted calendar content in clear** to disk. It is
  a diagnostic switch only — never enable it in production.

Compromising the host means compromising the calendar (and mail, if invitations
are enabled): the gateway holds a live, decrypted session. **Do not run this on a
host you do not trust.**

## Encryption at rest for sensitive files (audit 2026-07-17)

Two files in `data_dir` carry sensitive data and are **sealed at rest** via
`internal/atrest`:

| File           | Sensitive contents                                                          | Reconstructible? |
|----------------|-----------------------------------------------------------------------------|------------------|
| `session.json` | Proton tokens (UID/access/refresh) + `salted_key_pass` — **a full session grant** | No — supervised TOTP re-login required |
| `store.json`   | The **decrypted** calendar (titles, attendees, dates)                       | Yes — pure cache; a resync repopulates it |

### Cryptographic scheme

- **AES-256-GCM**, 96-bit nonce drawn at random on each seal.
- **Container format:** `magic("CGAR") ‖ version(1) ‖ nonce(12) ‖ ciphertext+tag`.
  The magic distinguishes a sealed file from a legacy cleartext JSON (migration)
  and acts as a format guard; the version byte allows a future envelope
  migration.
- **Key:** 32 random bytes in `<data_dir>/.atrest.key`, **0600**, generated on
  **first boot** if absent. Loaded **once** per process (cached by path) —
  `LoadSession` is called on every token rotation.
- **One key** for both files (session + store), local to the service.

### Design decision: local key file (option A)

The daemon runs as `cal-gw` (non-root) and **restarts without a human**
(watchdog/systemd). The key must therefore be available **at boot without any
prompt.**

- **Chosen — 0600 key file (A):** simple, survives reboots, zero dependencies,
  safe production migration.
- **Rejected — systemd `LoadCredentialEncrypted=` / TPM (B):** stronger (key
  sealed by the host key/TPM, never in clear on the FS) but adds a host-key/TPM
  dependency and a migration risk; marginal benefit here since the key file is
  already 0600 `cal-gw` and the realistic vector is a **leaked file**, not full
  root access. Reconsider if the threat model hardens.
- **Rejected — deriving from an external secret store (C):** couples two services
  and is fragile in operation.

### Threat model

**What it COVERS** (the realistic vector the audit flagged):

- **A leaked file / bare backup:** `session.json` or `store.json` copied out of
  the directory, bundled into an archive, or read in isolation → **useless**
  without `.atrest.key`.
- A partial disk snapshot that misses the key file.

**What it does NOT cover** (honesty):

- An attacker who **already has full filesystem access as `cal-gw`** (or root):
  they read `.atrest.key` too and decrypt. This is **defense-in-depth /
  anti-file-leak**, *not* a hardware secret. The remaining protections are the
  0600 permissions, the systemd hardening of the unit, and keeping `data_dir`
  out of backups.
- **This is not Proton's zero-access encryption.** With Proton's own apps, the
  server cannot read your calendar; here, the gateway can and must. If the host
  is compromised, so is the calendar. See the "Security trade-offs" section of
  the [README](README.md).

### Cleartext → sealed migration (deployment)

**Non-destructive and automatic** on the new binary's first boot:

- A **cleartext** `session.json` (legacy) is read as-is and **re-sealed in place**
  (best-effort; a write failure does not break boot and is retried on the next
  boot). **Never discarded:** the session cannot be rebuilt without a supervised
  TOTP re-login. Proven by `TestPlaintextSessionMigration`.
- A **cleartext** `store.json` (legacy) is read as-is (`Synced` preserved, no 503
  window) and re-sealed on the first persist. A **sealed but unreadable** blob
  (wrong key/corruption) is treated as absent → resync (the cache is
  reconstructible). Proven by `TestPlaintextMigration`.

### Interaction with the store's conditional-persist guard

The store skips the disk rewrite when state is unchanged (an anti-churn perf
guard). The comparison hash is over the **cleartext** (the JSON before sealing):
the GCM nonce changes on every `Seal`, so hashing the ciphertext would make every
blob look "different" and defeat the skip.
