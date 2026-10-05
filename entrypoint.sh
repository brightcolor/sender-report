#!/bin/sh
set -e

# The image runs as the unprivileged user "app" (USER in the Dockerfile), and
# the server checks at startup that it can write DATA_DIR.
#
# A container started as root (docker run --user root, user: root in
# compose) first hands DATA_DIR to "app" and then runs the server as "app".
if [ "$(id -u)" = "0" ]; then
	data_dir="${DATA_DIR:-/data}"
	mkdir -p "$data_dir"
	chown -R app:app "$data_dir" || true
	exec su-exec app /app/sender-report "$@"
fi

exec /app/sender-report "$@"
