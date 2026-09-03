# DNS resolver for Rspamd.
#
# The compose file routes this container's DNS to the bundled unbound resolver
# (172.28.0.53) via its `dns:` setting, so no nameserver is pinned here.
#
# Why not public resolvers: this container's most valuable lookups are the
# blocklists (DNSBL, URIBL, SURBL), and Spamhaus and friends refuse queries that
# arrive through 8.8.8.8, 1.1.1.1 or any other shared resolver. They answer with
# an error code in 127.255.255.0/24, which is not a listing and not an all-clear
# either — the reputation half of the check simply stops working, quietly.
#
# Why not the Docker resolver: 127.0.0.11 is a forwarder that rate-limits under
# the query volume Rspamd produces and cannot serve DNSKEY or TLSA records.
#
# Override only if you operate your own recursive resolver elsewhere. Do not put
# a public resolver here.
dns {
    timeout = 1s;
    sockets = 16;
    retransmits = 5;
}
