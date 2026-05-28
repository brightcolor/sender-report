# Allow unauthenticated access from Docker-internal networks.
# The mailprobe container connects via the compose bridge (172.16–31.x.x).
# Do NOT expose the Rspamd controller port (11334) to the public internet.
secure_ip = ["127.0.0.1", "::1", "172.16.0.0/12", "10.0.0.0/8", "192.168.0.0/16"];
