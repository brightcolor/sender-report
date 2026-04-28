#!/usr/bin/env bash
# deploy.sh – Removes any v1/old Docker setup, deploys MailProbe v2 fresh.
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/mailprobe}"
HTTP_PORT="${HTTP_PORT:-8080}"
SMTP_PORT="${SMTP_PORT:-2525}"
MAILPROBE_IMAGE="ghcr.io/brightcolor/mailprobe:latest"
REPO_URL="https://github.com/brightcolor/mailprobev2.git"

BOLD='\033[1m'
BLUE='\033[1;34m'
GREEN='\033[1;32m'
RED='\033[1;31m'
RESET='\033[0m'

log()  { printf "${BLUE}[deploy]${RESET} %s\n" "$*"; }
ok()   { printf "${GREEN}[deploy]${RESET} %s\n" "$*"; }
err()  { printf "${RED}[deploy] ERROR:${RESET} %s\n" "$*" >&2; exit 1; }

# ── Checks ────────────────────────────────────────────────────────────────────
[[ "$(uname -s)" == "Linux" ]] || err "Linux only."
command -v docker >/dev/null 2>&1 || {
  log "Docker not found – installing..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
}
docker compose version >/dev/null 2>&1 || {
  log "Docker Compose plugin not found – installing..."
  apt-get update -y -qq
  apt-get install -y -qq docker-compose-plugin
}

# ── 1. Stop + remove ALL running containers ───────────────────────────────────
log "Stopping all running containers..."
RUNNING=$(docker ps -q 2>/dev/null || true)
[[ -n "$RUNNING" ]] && docker stop $RUNNING && docker rm $RUNNING || true
ok "All containers stopped and removed."

# ── 2. Remove old v1 containers by known names (if any remain) ───────────────
for name in mailprobe mailprobe-v1 mailprobev1 mp_mailprobe; do
  docker rm -f "$name" 2>/dev/null && log "Removed old container: $name" || true
done

# ── 3. Remove old installation if it belongs to a different repo ──────────────
if [[ -d "$INSTALL_DIR/.git" ]]; then
  REMOTE=$(git -C "$INSTALL_DIR" remote get-url origin 2>/dev/null || echo "")
  if [[ "$REMOTE" != *"mailprobev2"* ]]; then
    log "Old repo detected at $INSTALL_DIR ($REMOTE) – removing..."
    # Bring down any compose stack that might still reference this dir
    docker compose -f "$INSTALL_DIR/docker-compose.yml" down -v 2>/dev/null || true
    rm -rf "$INSTALL_DIR"
    ok "Old installation removed."
  fi
fi

# ── 4. Clone or update v2 repo ────────────────────────────────────────────────
if [[ -d "$INSTALL_DIR/.git" ]]; then
  log "Updating MailProbe v2 in $INSTALL_DIR..."
  git -C "$INSTALL_DIR" fetch origin main
  git -C "$INSTALL_DIR" checkout main
  git -C "$INSTALL_DIR" pull --ff-only origin main
else
  log "Cloning MailProbe v2 to $INSTALL_DIR..."
  mkdir -p "$(dirname "$INSTALL_DIR")"
  git clone --branch main "$REPO_URL" "$INSTALL_DIR"
fi
ok "Repository ready."

# ── 5. Write .env ─────────────────────────────────────────────────────────────
cd "$INSTALL_DIR"
cp .env.example .env

IP=$(hostname -I 2>/dev/null | awk '{print $1}')

set_env() {
  local k="$1" v="$2"
  sed -i "s|^${k}=.*|${k}=${v}|" .env
}

set_env APP_NAME              "MailProbe"
set_env HTTP_PORT             "$HTTP_PORT"
set_env SMTP_PORT             "$SMTP_PORT"
set_env MAILPROBE_IMAGE       "$MAILPROBE_IMAGE"
set_env PUBLIC_BASE_URL       "http://${IP}:${HTTP_PORT}"
set_env MAILBOX_TTL           "24h"
set_env DATA_RETENTION_TTL    "168h"
set_env CLEANUP_INTERVAL      "30m"
set_env MAX_MESSAGE_BYTES     "2097152"
set_env ENABLE_RBL_CHECKS     "false"
set_env ENABLE_SPAMASSASSIN   "false"
set_env ENABLE_RSPAMD         "false"
set_env ENABLE_REDIS          "false"
ok ".env written."

# ── 6. Pull image + start ─────────────────────────────────────────────────────
log "Pulling MailProbe v2 image..."
docker compose pull

log "Starting MailProbe v2..."
docker compose up -d

# ── 7. Health check ───────────────────────────────────────────────────────────
log "Waiting for health check..."
for i in $(seq 1 12); do
  if wget -qO- "http://127.0.0.1:${HTTP_PORT}/healthz" >/dev/null 2>&1; then
    ok "Health check passed."
    break
  fi
  [[ $i -eq 12 ]] && { log "Health check timed out – check: docker logs mailprobe"; break; }
  sleep 5
done

printf "\n${BOLD}══════════════════════════════════════════${RESET}\n"
printf "${GREEN}  MailProbe v2 läuft!${RESET}\n\n"
printf "  Web:   http://${IP}:${HTTP_PORT}\n"
printf "  SMTP:  ${IP}:${SMTP_PORT}\n"
printf "  Logs:  docker logs -f mailprobe\n"
printf "${BOLD}══════════════════════════════════════════${RESET}\n\n"
