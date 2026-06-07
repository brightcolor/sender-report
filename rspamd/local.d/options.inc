# DNS resolver for Rspamd.
#
# Inside Docker, Rspamd would otherwise use the container's /etc/resolv.conf
# (Docker's embedded resolver at 127.0.0.11), which frequently fails or rate-limits
# the many DNS lookups Rspamd needs (DNSBL/URIBL/SPF/DKIM). Pin public resolvers so
# name resolution works reliably.
dns {
    nameserver = ["8.8.8.8:53", "1.1.1.1:53"];
    timeout = 1s;
    sockets = 16;
    retransmits = 5;
}
