#!/bin/sh
# cal-gateway-watchdog — restart cal-gateway when it is "up but not serving".
#
# systemd already restarts a *crashed* process. This catches the other class of
# failure: the process is alive and the port is open, but the daemon is not
# actually healthy (e.g. the Proton API has been unreachable for > ~5 min, so
# the last successful poll is stale). The daemon exposes a loopback, no-auth
# /healthz endpoint for exactly this:
#   200 "ok" / "starting"  -> healthy
#   503 "stale: ..."       -> unhealthy (last successful Proton poll too old)
# Anything that is not HTTP 2xx (503, timeout, connection refused) is UNHEALTHY.
#
# Run it every ~2 min from the provided systemd timer (preferred) or from cron.
set -eu

# ---- config -----------------------------------------------------------------
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:5232/healthz}"
SERVICE="${SERVICE:-cal-gateway}"
RESTART_CMD="${RESTART_CMD:-systemctl restart ${SERVICE}}"
LOG="${LOG:-/var/log/cal-gateway-watchdog.log}"
# -----------------------------------------------------------------------------

log() {
	# timestamped line to both the log file (best-effort) and stdout (journal).
	line="$(date '+%Y-%m-%dT%H:%M:%S%z') cal-gateway-watchdog: $*"
	echo "$line"
	echo "$line" >>"$LOG" 2>/dev/null || true
}

# curl -f makes non-2xx a non-zero exit; --max-time bounds a hung daemon.
if curl -sf --max-time 8 "$HEALTH_URL" >/dev/null 2>&1; then
	# healthy — nothing to do.
	exit 0
fi

log "UNHEALTHY ($HEALTH_URL did not return 2xx) — restarting via: $RESTART_CMD"
if sh -c "$RESTART_CMD"; then
	log "restart command issued"
else
	log "ERROR: restart command failed"
fi

# notify hook (optional): a restart does NOT fix a genuinely dead Proton session
# (exit 78 needs a manual `cal-gateway login` with TOTP). Wire up mail/webhook
# here so a human is alerted when restarts don't stick.
# printf '%s\n' "cal-gateway unhealthy on $(hostname)" | mail -s "cal-gateway watchdog" you@example.com
