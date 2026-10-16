// Package dnsfallback fragt bei einer TXT-Abfrage zusätzlich externe Resolver,
// wenn der lokale Resolver keinen Record liefert.
//
// Der lokale Resolver (in Docker meist 127.0.0.11) antwortet gelegentlich mit
// „no such host“ für einen Record, den es gibt, etwa aus einem Zwischenspeicher
// mit Negativ-Antwort. Ein DKIM-, SPF- oder DMARC-Befund „Record fehlt“ wäre dann
// falsch. Die externen Resolver sind nur für TXT-Records gedacht. Blocklisten
// (DNSBL) antworten über öffentliche Resolver mit Fehlercodes und bleiben beim
// lokalen Resolver.
package dnsfallback

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultResolvers ist die Vorgabe für DNS_FALLBACK_RESOLVERS.
	DefaultResolvers = "1.1.1.1,8.8.8.8,9.9.9.9"
	// Off schaltet den Fallback in DNS_FALLBACK_RESOLVERS ab.
	Off = "none"

	DefaultTimeout = 2 * time.Second
	MinTimeout     = 500 * time.Millisecond
	MaxTimeout     = 10 * time.Second
	MaxResolvers   = 5
)

type resolver struct {
	addr string
	r    *net.Resolver
}

var (
	mu        sync.RWMutex
	resolvers []resolver
	timeout   = DefaultTimeout

	// localLookup ist der lokale Resolver; Tests ersetzen ihn.
	localLookup = func(ctx context.Context, name string) ([]string, error) {
		return net.DefaultResolver.LookupTXT(ctx, name)
	}
)

// ParseResolvers prüft die Liste aus DNS_FALLBACK_RESOLVERS und gibt die
// Adressen in der Form host:port zurück. Leer oder „none“ ergibt eine leere Liste.
func ParseResolvers(list string) ([]string, error) {
	list = strings.TrimSpace(list)
	if list == "" || strings.EqualFold(list, Off) {
		return nil, nil
	}
	var out []string
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		addr, err := normalizeAddr(part)
		if err != nil {
			return nil, err
		}
		out = append(out, addr)
	}
	if len(out) > MaxResolvers {
		return nil, fmt.Errorf("DNS_FALLBACK_RESOLVERS lists %d resolvers; at most %d are asked, so shorten the list", len(out), MaxResolvers)
	}
	return out, nil
}

func normalizeAddr(s string) (string, error) {
	host, port := s, "53"
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	} else {
		host = strings.Trim(s, "[]")
	}
	if net.ParseIP(host) == nil {
		return "", fmt.Errorf("DNS_FALLBACK_RESOLVERS contains %q, which is not an IP address; list addresses such as 1.1.1.1 or 8.8.8.8:53 separated by commas, or set it to %s to turn the fallback off", s, Off)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("DNS_FALLBACK_RESOLVERS contains %q with the port %q; use a port from 1 to 65535 or leave the port out to use 53", s, port)
	}
	return net.JoinHostPort(host, port), nil
}

// Configure setzt die externen Resolver und die Wartezeit je Resolver. Eine leere
// Liste schaltet den Fallback ab.
func Configure(addrs []string, perResolverTimeout time.Duration) {
	list := make([]resolver, 0, len(addrs))
	for _, a := range addrs {
		addr := a
		list = append(list, resolver{addr: addr, r: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: perResolverTimeout}
				return d.DialContext(ctx, network, addr)
			},
		}})
	}
	mu.Lock()
	resolvers = list
	if perResolverTimeout > 0 {
		timeout = perResolverTimeout
	}
	mu.Unlock()
}

// Resolvers nennt die Adressen der externen Resolver in der Reihenfolge der Abfrage.
func Resolvers() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, len(resolvers))
	for i, r := range resolvers {
		out[i] = r.addr
	}
	return out
}

// Hosts nennt die Resolver ohne Port, für Meldungen an Menschen.
func Hosts() []string {
	addrs := Resolvers()
	for i, a := range addrs {
		if h, _, err := net.SplitHostPort(a); err == nil {
			addrs[i] = h
		}
	}
	return addrs
}

// LookupTXT fragt zuerst den lokalen Resolver. Liefert er keine Records oder
// einen Fehler, fragen die externen Resolver der Reihe nach. Den Fehler des
// lokalen Resolvers bekommt der Aufrufer, wenn auch die externen nichts finden.
func LookupTXT(ctx context.Context, name string) ([]string, error) {
	recs, _, err := LookupTXTSource(ctx, name)
	return recs, err
}

// LookupTXTSource wie LookupTXT, zusätzlich mit der Adresse des Resolvers, der
// geantwortet hat. Bei einer Antwort des lokalen Resolvers ist sie leer.
func LookupTXTSource(ctx context.Context, name string) (recs []string, source string, err error) {
	recs, err = localLookup(ctx, name)
	if err == nil && len(recs) > 0 {
		return recs, "", nil
	}
	mu.RLock()
	list, wait := resolvers, timeout
	mu.RUnlock()
	for _, r := range list {
		if ctx.Err() != nil {
			break
		}
		qctx, cancel := context.WithTimeout(ctx, wait)
		got, ferr := r.r.LookupTXT(qctx, name)
		cancel()
		if ferr == nil && len(got) > 0 {
			return got, r.addr, nil
		}
	}
	return recs, "", err
}
