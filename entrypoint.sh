#!/bin/sh
set -e

# When ./data is bind-mounted from the Docker host the directory may be
# owned by root. Fix ownership so the unprivileged app user can write the
# SQLite database and other runtime files.
chown -R app:app /data 2>/dev/null || true

exec su-exec app /app/mailprobe "$@"
