#!/usr/bin/env bash
# deploy.sh – Stops everything, runs MailProbe v2 directly via docker run.
set -euo pipefail

IMAGE="ghcr.io/brightcolor/mailprobev2:latest"
HTTP_PORT="${HTTP_PORT:-8080}"
DATA_VOL="mailprobe_data"

BOLD='\033[1m'
BLUE='\033[1;34m'
GREEN='\033[1;32m'
RED='\033[1;31m'
RESET='\033[0m'

log() { printf "${BLUE}[deploy]${RESET} %s\n" "$*"; }
ok()  { printf "${GREEN}[deploy]${RESET} %s\n" "$*"; }
err() { printf "${RED}[deploy] ERROR:${RESET} %s\n" "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || err "Linux only."
command -v docker >/dev/null 2>&1 || {
  log "Docker not found – installing..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
}

# ── 1. Stop + remove ALL running containers ───────────────────────────────────
log "Stopping all running containers..."
RUNNING=$(docker ps -q 2>/dev/null || true)
if [[ -n "$RUNNING" ]]; then
  docker stop $RUNNING
  docker rm   $RUNNING
  ok "Containers stopped."
else
  ok "No containers were running."
fi

# ── 2. Force-remove container named 'mailprobe' if leftover ──────────────────
docker rm -f mailprobe 2>/dev/null && log "Removed leftover 'mailprobe' container." || true

# ── 3. Pull latest v2 image ───────────────────────────────────────────────────
log "Pulling $IMAGE ..."
docker pull "$IMAGE"
ok "Image ready."

# ── 4. Create data volume if needed ──────────────────────────────────────────
docker volume create "$DATA_VOL" >/dev/null
ok "Data volume '$DATA_VOL' ready."

# ── 5. Start MailProbe v2 ─────────────────────────────────────────────────────
IP=$(hostname -I 2>/dev/null | awk '{print $1}')

log "Starting MailProbe v2..."
docker run -d \
  --name mailprobe \
  --restart unless-stopped \
  -p "${HTTP_PORT}:8080" \
  -p "25:2525" \
  -v "${DATA_VOL}:/data" \
  -e APP_NAME=MailProbe \
  -e HTTP_LISTEN_ADDR=:8080 \
  -e SMTP_LISTEN_ADDR=:2525 \
  -e PUBLIC_BASE_URL="http://${IP}:${HTTP_PORT}" \
  -e DATA_DIR=/data \
  -e DB_PATH=/data/mailprobe.db \
  -e MAILBOX_TTL=24h \
  -e DATA_RETENTION_TTL=168h \
  -e CLEANUP_INTERVAL=30m \
  -e MAX_MESSAGE_BYTES=2097152 \
  -e MAX_ACTIVE_MAILBOXES_PER_IP=20 \
  -e MAX_ACTIVE_MAILBOXES_GLOBAL=2000 \
  -e WEB_RATE_LIMIT_PER_MIN=60 \
  -e WEB_BURST_PER_10_SEC=20 \
  -e SMTP_RATE_LIMIT_PER_HOUR=200 \
  -e SMTP_BURST_PER_MIN=40 \
  -e ENABLE_RBL_CHECKS=false \
  -e ENABLE_SPAMASSASSIN=false \
  -e ENABLE_RSPAMD=false \
  -e ENABLE_REDIS=false \
  --memory=512m \
  --cpus=0.50 \
  "$IMAGE"

# ── 6. Health check ───────────────────────────────────────────────────────────
log "Waiting for health check..."
for i in $(seq 1 12); do
  if wget -qO- "http://127.0.0.1:${HTTP_PORT}/healthz" >/dev/null 2>&1; then
    ok "Health check passed."
    break
  fi
  [[ $i -eq 12 ]] && { log "Timed out – check logs: docker logs mailprobe"; break; }
  sleep 5
done

printf "\n${BOLD}══════════════════════════════════════════${RESET}\n"
printf "${GREEN}  MailProbe v2 läuft!${RESET}\n\n"
printf "  Image: %s\n"    "$IMAGE"
printf "  Web:   http://%s:%s\n" "$IP" "$HTTP_PORT"
printf "  SMTP:  %s:25\n" "$IP"
printf "  Logs:  docker logs -f mailprobe\n"
printf "${BOLD}══════════════════════════════════════════${RESET}\n\n"
