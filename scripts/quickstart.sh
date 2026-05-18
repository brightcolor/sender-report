#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/brightcolor/mailprobev2.git}"
BRANCH="${BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/mailprobe}"
HTTP_PORT="${HTTP_PORT:-8080}"
SMTP_PORT="${SMTP_PORT:-2525}"
MAILPROBE_IMAGE="${MAILPROBE_IMAGE:-ghcr.io/brightcolor/mailprobe:latest}"
SMTP_DOMAIN="${SMTP_DOMAIN:-}"
PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-}"
ENABLE_TLS="${ENABLE_TLS:-false}"
TLS_CERT_FILE="${TLS_CERT_FILE:-}"
TLS_KEY_FILE="${TLS_KEY_FILE:-}"
FORCE_HTTPS="${FORCE_HTTPS:-false}"
HEALTHCHECK_URL="${HEALTHCHECK_URL:-}"
ENABLE_RSPAMD="${ENABLE_RSPAMD:-}"
ENABLE_REDIS="${ENABLE_REDIS:-}"
DISPLAY_WEB_URL=""

# Original requested ports (preserved for change-detection in summary)
_HTTP_PORT_REQUESTED="$HTTP_PORT"
_SMTP_PORT_REQUESTED="$SMTP_PORT"

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# ── Port utilities ─────────────────────────────────────────────────────────────

# Returns 0 (true) if something is already listening/allocated on $1
port_in_use() {
  local port="$1"

  # 1. Ask the kernel via ss (covers host processes and docker-proxy)
  if have_cmd ss; then
    ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE "(^|:)${port}$" && return 0
  fi

  # 2. Also check netstat as a fallback (older distros without ss)
  if have_cmd netstat; then
    netstat -tlnp 2>/dev/null | awk '{print $4}' | grep -qE "(^|:)${port}$" && return 0
  fi

  # 3. Query Docker directly – catches running containers whose docker-proxy
  #    may not appear in ss until it has fully started.
  if have_cmd docker && docker info >/dev/null 2>&1; then
    docker ps --format '{{.Ports}}' 2>/dev/null \
      | grep -qE "(0\.0\.0\.0|::|\*):${port}->" && return 0
  fi

  # 4. /dev/tcp connect attempt (bash builtin, no external deps)
  if ( timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null ); then
    return 0
  fi

  return 1
}

# Prints a free port: $1 if available, otherwise a random port in [10000,49999]
# that does not collide with $2 (optional second port to avoid)
find_free_port() {
  local preferred="$1"
  local avoid="${2:-0}"

  if ! port_in_use "$preferred"; then
    echo "$preferred"
    return
  fi

  # Try up to 30 random candidates in the ephemeral-safe range
  local attempt
  for attempt in $(seq 1 30); do
    # RANDOM is 0-32767; shift into [10000,49999]
    local candidate=$(( 10000 + (RANDOM * 2) % 40000 ))
    [[ "$candidate" -eq "$avoid" ]] && continue
    if ! port_in_use "$candidate"; then
      echo "$candidate"
      return
    fi
  done

  # Last resort: ask the kernel for a free port via Python3 (always present in
  # Docker-capable environments) then close it immediately.
  if have_cmd python3; then
    python3 - "$avoid" <<'PY'
import socket, sys
avoid = int(sys.argv[1]) if len(sys.argv) > 1 else 0
for _ in range(10):
    s = socket.socket()
    s.bind(('', 0))
    p = s.getsockname()[1]
    s.close()
    if p != avoid:
        print(p)
        break
PY
    return
  fi

  # Give up – return the preferred port and let Docker complain if it's busy
  echo "$preferred"
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
      n|no) echo "false"; return ;;
      *) echo "Please answer y or n." ;;
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

resolve_ports() {
  log "Checking port availability..."

  # If a previous MailProbe stack is running from this install dir, bring it
  # down first so its ports don't block our own re-deployment.
  if [[ -d "$INSTALL_DIR" ]] && have_cmd docker && docker info >/dev/null 2>&1; then
    if docker_cmd compose -f "$INSTALL_DIR/docker-compose.yml" ps -q 2>/dev/null | grep -q .; then
      log "Stopping existing MailProbe stack before port check..."
      docker_cmd compose -f "$INSTALL_DIR/docker-compose.yml" down 2>/dev/null || true
    fi
  fi

  local new_http
  new_http="$(find_free_port "$HTTP_PORT" "$SMTP_PORT")"
  if [[ "$new_http" != "$HTTP_PORT" ]]; then
    log "Port $HTTP_PORT (HTTP) is already in use – using $new_http instead"
    HTTP_PORT="$new_http"
  fi

  local new_smtp
  new_smtp="$(find_free_port "$SMTP_PORT" "$HTTP_PORT")"
  if [[ "$new_smtp" != "$SMTP_PORT" ]]; then
    log "Port $SMTP_PORT (SMTP) is already in use – using $new_smtp instead"
    SMTP_PORT="$new_smtp"
  fi

  # Keep the healthcheck URL in sync with the final HTTP port
  if [[ -z "$HEALTHCHECK_URL" ]]; then
    HEALTHCHECK_URL="http://127.0.0.1:${HTTP_PORT}/healthz"
  fi
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

  set_env_key "HTTP_PORT" "$HTTP_PORT"
  set_env_key "SMTP_PORT" "$SMTP_PORT"
  set_env_key "SMTP_DOMAIN" "$SMTP_DOMAIN"
  set_env_key "PUBLIC_BASE_URL" "$PUBLIC_BASE_URL"
  set_env_key "ENABLE_TLS" "$ENABLE_TLS"
  set_env_key "TLS_CERT_FILE" "$TLS_CERT_FILE"
  set_env_key "TLS_KEY_FILE" "$TLS_KEY_FILE"
  set_env_key "FORCE_HTTPS" "$FORCE_HTTPS"
  set_env_key "HEALTHCHECK_URL" "$HEALTHCHECK_URL"
  set_env_key "MAILPROBE_IMAGE" "$MAILPROBE_IMAGE"
  set_env_key "ENABLE_RSPAMD" "$ENABLE_RSPAMD"
  set_env_key "ENABLE_REDIS" "$ENABLE_REDIS"
  set_env_key "REDIS_ADDR" "redis:6379"
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
    container_name: mailprobe-rspamd
    restart: unless-stopped
    expose:
      - "11334"
    mem_limit: 256m
YAML
  fi

  if [[ "$ENABLE_REDIS" == "true" ]]; then
    cat >> "$override_file" <<'YAML'
  redis:
    image: redis:7-alpine
    container_name: mailprobe-redis
    restart: unless-stopped
    command: ["redis-server", "--appendonly", "yes", "--save", "60", "1000"]
    expose:
      - "6379"
    volumes:
      - mailprobe_redis_data:/data
    mem_limit: 128m
YAML
  fi

  if [[ "$ENABLE_REDIS" == "true" ]]; then
    cat >> "$override_file" <<'YAML'

volumes:
  mailprobe_redis_data:
    driver: local
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

  log "Starting MailProbe stack"
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
  resolve_ports
  setup_env_file
  setup_optional_services_override
  start_stack

  # Build port-change notices for the summary
  local http_note="" smtp_note=""
  if [[ "$HTTP_PORT" != "$_HTTP_PORT_REQUESTED" ]]; then
    http_note="  ⚠  Port $_HTTP_PORT_REQUESTED was busy – using $HTTP_PORT instead"
  fi
  if [[ "$SMTP_PORT" != "$_SMTP_PORT_REQUESTED" ]]; then
    smtp_note="  ⚠  Port $_SMTP_PORT_REQUESTED was busy – using $SMTP_PORT instead"
  fi

  cat <<EOF

══════════════════════════════════════════════
  MailProbe setup complete
══════════════════════════════════════════════

  Install path : $INSTALL_DIR
  Web UI       : $DISPLAY_WEB_URL${http_note:+
$http_note}
  SMTP port    : $SMTP_PORT (host)${smtp_note:+
$smtp_note}
  SMTP address : ${SMTP_DOMAIN:+<token>@$SMTP_DOMAIN}${SMTP_DOMAIN:-<token>@<web-host>}
  Rspamd       : $ENABLE_RSPAMD
  Redis        : $ENABLE_REDIS

══════════════════════════════════════════════

Next steps:
  1. Point your DNS A + MX records to this server.
  2. Route inbound SMTP to host port $SMTP_PORT
     (or forward host :25 → container :2525).
  3. Open $DISPLAY_WEB_URL and generate a test mailbox.

EOF

  if [[ "$ENABLE_REDIS" == "true" ]]; then
    echo "Note: Redis is optional and not used by the core MailProbe code path."
    echo ""
  fi
}

main "$@"
