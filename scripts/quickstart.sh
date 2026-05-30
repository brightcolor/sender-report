#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/brightcolor/sender-report.git}"
BRANCH="${BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/sender-report}"
HTTP_PORT="${HTTP_PORT:-9090}"
SMTP_PORT="${SMTP_PORT:-25}"   # External mail servers connect on port 25
SENDER_REPORT_IMAGE="${SENDER_REPORT_IMAGE:-ghcr.io/brightcolor/sender-report:latest}"
SMTP_DOMAIN="${SMTP_DOMAIN:-}"
PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-}"
ENABLE_TLS="${ENABLE_TLS:-false}"
TLS_CERT_FILE="${TLS_CERT_FILE:-}"
TLS_KEY_FILE="${TLS_KEY_FILE:-}"
FORCE_HTTPS="${FORCE_HTTPS:-false}"
HEALTHCHECK_URL="${HEALTHCHECK_URL:-http://127.0.0.1:${HTTP_PORT}/healthz}"
ENABLE_RSPAMD="${ENABLE_RSPAMD:-}"
ENABLE_REDIS="${ENABLE_REDIS:-}"
DISPLAY_WEB_URL=""

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

log() {
  printf '[quickstart] %s\n' "$*"
}

prompt_yes_no() {
  local question="$1"
  local default_value="${2:-n}"
  local answer

  if [[ ! -t 0 ]]; then
    if [[ "$default_value" == "y" ]]; then
      echo "true"
    else
      echo "false"
    fi
    return
  fi

  while true; do
    read -r -p "$question [$default_value]: " answer
    answer="${answer:-$default_value}"
    case "${answer,,}" in
      y|yes) echo "true"; return ;;
      n|no)  echo "false"; return ;;
      *)     echo "Please answer y or n." ;;
    esac
  done
}

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This quickstart script supports Linux only." >&2
  exit 1
fi

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
else
  if ! have_cmd sudo; then
    echo "sudo is required when running as non-root." >&2
    exit 1
  fi
  SUDO="sudo"
fi

install_base_packages() {
  if have_cmd apt-get; then
    log "Installing base packages (curl, ca-certificates, git)"
    $SUDO apt-get update -y
    $SUDO apt-get install -y curl ca-certificates git
  else
    echo "Unsupported distro: apt-get not found. Install Docker + Docker Compose manually." >&2
    exit 1
  fi
}

install_docker_if_needed() {
  if have_cmd docker; then
    log "Docker already installed"
    return
  fi

  log "Installing Docker"
  curl -fsSL https://get.docker.com | $SUDO sh
}

install_compose_if_needed() {
  if docker compose version >/dev/null 2>&1; then
    log "Docker Compose plugin already available"
    return
  fi

  log "Installing Docker Compose plugin"
  if have_cmd apt-get; then
    $SUDO apt-get update -y
    $SUDO apt-get install -y docker-compose-plugin
  fi

  if ! docker compose version >/dev/null 2>&1; then
    echo "Docker Compose plugin installation failed." >&2
    exit 1
  fi
}

prepare_docker_service() {
  if have_cmd systemctl; then
    $SUDO systemctl enable --now docker || true
  fi
}

ensure_repo() {
  local parent
  parent="$(dirname "$INSTALL_DIR")"
  $SUDO mkdir -p "$parent"

  if [[ ! -d "$INSTALL_DIR/.git" ]]; then
    log "Cloning repository into $INSTALL_DIR"
    $SUDO git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
  else
    log "Updating existing repository in $INSTALL_DIR"
    $SUDO git -C "$INSTALL_DIR" fetch origin
    $SUDO git -C "$INSTALL_DIR" checkout "$BRANCH"
    $SUDO git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH"
  fi

  if [[ -n "${SUDO_USER:-}" ]]; then
    $SUDO chown -R "$SUDO_USER":"$SUDO_USER" "$INSTALL_DIR"
  fi
}

infer_display_web_url() {
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [[ -z "$ip" ]]; then
    ip="127.0.0.1"
  fi
  DISPLAY_WEB_URL="${PUBLIC_BASE_URL:-http://${ip}:${HTTP_PORT}}"
}

set_env_key() {
  local key="$1"
  local value="$2"

  if grep -qE "^${key}=" .env; then
    sed -i "s|^${key}=.*|${key}=${value}|" .env
  else
    printf '%s=%s\n' "$key" "$value" >> .env
  fi
}

setup_env_file() {
  cd "$INSTALL_DIR"

  if [[ ! -f .env ]]; then
    cp .env.example .env
  fi

  infer_display_web_url

  set_env_key "HTTP_PORT"       "$HTTP_PORT"
  set_env_key "SMTP_PORT"       "$SMTP_PORT"
  set_env_key "SMTP_DOMAIN"     "$SMTP_DOMAIN"
  set_env_key "PUBLIC_BASE_URL" "$PUBLIC_BASE_URL"
  set_env_key "ENABLE_TLS"      "$ENABLE_TLS"
  set_env_key "TLS_CERT_FILE"   "$TLS_CERT_FILE"
  set_env_key "TLS_KEY_FILE"    "$TLS_KEY_FILE"
  set_env_key "FORCE_HTTPS"     "$FORCE_HTTPS"
  set_env_key "HEALTHCHECK_URL" "$HEALTHCHECK_URL"
  set_env_key "SENDER_REPORT_IMAGE" "$SENDER_REPORT_IMAGE"
  set_env_key "ENABLE_RSPAMD"   "$ENABLE_RSPAMD"
  set_env_key "ENABLE_REDIS"    "$ENABLE_REDIS"
  set_env_key "REDIS_ADDR"      "redis:6379"

  # Ensure data directory exists for the bind mount
  mkdir -p "$INSTALL_DIR/data"
}

setup_optional_services_override() {
  cd "$INSTALL_DIR"
  local override_file="docker-compose.override.yml"

  if [[ "$ENABLE_RSPAMD" != "true" && "$ENABLE_REDIS" != "true" ]]; then
    rm -f "$override_file"
    return
  fi

  cat > "$override_file" <<'YAML'
services:
YAML

  if [[ "$ENABLE_RSPAMD" == "true" ]]; then
    cat >> "$override_file" <<'YAML'
  rspamd:
    image: rspamd/rspamd:latest
    container_name: sender-report-rspamd
    restart: unless-stopped
    expose:
      - "11334"
    volumes:
      - ./rspamd/local.d:/etc/rspamd/local.d:ro
    mem_limit: 256m
YAML
  fi

  if [[ "$ENABLE_REDIS" == "true" ]]; then
    cat >> "$override_file" <<'YAML'
  redis:
    image: redis:7-alpine
    container_name: sender-report-redis
    restart: unless-stopped
    command: ["redis-server", "--appendonly", "yes", "--save", "60", "1000"]
    expose:
      - "6379"
    volumes:
      - ./data/redis:/data
    mem_limit: 128m
YAML
  fi
}

docker_cmd() {
  if docker info >/dev/null 2>&1; then
    docker "$@"
  else
    $SUDO docker "$@"
  fi
}

start_stack() {
  cd "$INSTALL_DIR"
  log "Pulling container image"
  docker_cmd compose pull

  log "Starting Sender-Report stack"
  docker_cmd compose up -d
}

main() {
  if [[ -z "$ENABLE_RSPAMD" ]]; then
    ENABLE_RSPAMD="$(prompt_yes_no "Enable optional Rspamd service?" "n")"
  fi
  if [[ -z "$ENABLE_REDIS" ]]; then
    ENABLE_REDIS="$(prompt_yes_no "Enable optional Redis service?" "n")"
  fi

  install_base_packages
  install_docker_if_needed
  prepare_docker_service
  install_compose_if_needed
  ensure_repo
  setup_env_file
  setup_optional_services_override
  start_stack

  cat <<EOF

══════════════════════════════════════════════
  Sender-Report setup complete
══════════════════════════════════════════════

  Install path : $INSTALL_DIR
  Data dir     : $INSTALL_DIR/data
  Web UI       : $DISPLAY_WEB_URL
  SMTP port    : $SMTP_PORT (host)
  SMTP address : ${SMTP_DOMAIN:+<token>@$SMTP_DOMAIN}${SMTP_DOMAIN:-<token>@<web-host>}
  Rspamd       : $ENABLE_RSPAMD
  Redis        : $ENABLE_REDIS

══════════════════════════════════════════════

Next steps:
  1. Point your DNS A + MX records to this server's IP.
  2. Make sure port $SMTP_PORT is open in your firewall.
     External mail servers (Gmail, etc.) connect on port 25 —
     if you changed SMTP_PORT away from 25, route :25 -> :$SMTP_PORT.
  3. If another MTA (postfix/exim) is running, stop it first:
       sudo systemctl stop postfix && sudo systemctl disable postfix
  4. Open $DISPLAY_WEB_URL and generate a test mailbox.

EOF

  if [[ "$ENABLE_REDIS" == "true" ]]; then
    echo "Note: Redis is optional and not used by the core Sender-Report code path."
    echo ""
  fi
}

main "$@"
