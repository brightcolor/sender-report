package dnsfallback

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeDNS startet einen UDP-DNS-Server auf 127.0.0.1, der für bekannte Namen ein
// TXT-Record liefert und sonst NXDOMAIN. Er zählt die Anfragen. Die Tests fragen
// absolute Namen (mit Punkt am Ende), damit die Suchdomänen des Systems keine
// zusätzlichen Anfragen auslösen.
func fakeDNS(t *testing.T, records map[string]string) (addr string, queries *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	queries = new(atomic.Int32)
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		queries.Add(1)
		m := new(dns.Msg)
		m.SetReply(req)
		if txt, ok := records[strings.TrimSuffix(req.Question[0].Name, ".")]; ok {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{txt}})
		} else {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), queries
}

func withLocal(t *testing.T, f func(ctx context.Context, name string) ([]string, error)) {
	t.Helper()
	old := localLookup
	localLookup = f
	t.Cleanup(func() { localLookup = old; Configure(nil, DefaultTimeout) })
}

func notFound(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

func TestFallbackFindetRecordDenDerLokaleResolverNichtKennt(t *testing.T) {
	ext, _ := fakeDNS(t, map[string]string{"dkim._domainkey.hopux.de": "v=DKIM1; k=rsa; p=ABC"})
	withLocal(t, notFound)
	Configure([]string{ext}, time.Second)

	recs, via, err := LookupTXTSource(context.Background(), "dkim._domainkey.hopux.de.")
	if err != nil || len(recs) != 1 || !strings.HasPrefix(recs[0], "v=DKIM1") {
		t.Fatalf("recs=%v err=%v", recs, err)
	}
	if via != ext {
		t.Errorf("Quelle = %q, erwartet %q", via, ext)
	}
}

func TestLokalerTrefferFragtKeinenExternenResolver(t *testing.T) {
	ext, queries := fakeDNS(t, map[string]string{"a.example": "extern"})
	withLocal(t, func(context.Context, string) ([]string, error) { return []string{"lokal"}, nil })
	Configure([]string{ext}, time.Second)

	recs, via, err := LookupTXTSource(context.Background(), "a.example.")
	if err != nil || recs[0] != "lokal" || via != "" {
		t.Fatalf("recs=%v via=%q err=%v", recs, via, err)
	}
	if n := queries.Load(); n != 0 {
		t.Errorf("externer Resolver wurde %d-mal gefragt, obwohl lokal ein Treffer vorlag", n)
	}
}

func TestBeideKennenDenNamenNichtGibtDenLokalenFehlerZurueck(t *testing.T) {
	ext, queries := fakeDNS(t, nil)
	withLocal(t, notFound)
	Configure([]string{ext}, time.Second)

	_, via, err := LookupTXTSource(context.Background(), "gibt-es-nicht.example.")
	var de *net.DNSError
	if !errors.As(err, &de) || !de.IsNotFound || via != "" {
		t.Fatalf("err=%v via=%q, erwartet den lokalen NXDOMAIN-Fehler", err, via)
	}
	if n := queries.Load(); n != 1 {
		t.Errorf("externer Resolver wurde %d-mal gefragt, erwartet 1", n)
	}
}

func TestAbgeschalteterFallbackFragtNiemandenExtern(t *testing.T) {
	_, queries := fakeDNS(t, map[string]string{"a.example": "extern"})
	withLocal(t, notFound)
	Configure(nil, time.Second)
	if _, _, err := LookupTXTSource(context.Background(), "a.example."); err == nil {
		t.Fatal("ohne Fallback bleibt der lokale Fehler")
	}
	if n := queries.Load(); n != 0 {
		t.Errorf("%d externe Anfragen trotz abgeschaltetem Fallback", n)
	}
}

func TestZweiterResolverSpringtEin(t *testing.T) {
	first, q1 := fakeDNS(t, nil)
	second, q2 := fakeDNS(t, map[string]string{"x.example": "v=spf1 -all"})
	withLocal(t, notFound)
	Configure([]string{first, second}, time.Second)

	recs, via, err := LookupTXTSource(context.Background(), "x.example.")
	if err != nil || via != second || recs[0] != "v=spf1 -all" {
		t.Fatalf("recs=%v via=%q err=%v", recs, via, err)
	}
	if q1.Load() != 1 || q2.Load() != 1 {
		t.Errorf("Anfragen: erster=%d zweiter=%d, erwartet je 1", q1.Load(), q2.Load())
	}
}

func TestParseResolvers(t *testing.T) {
	ok := map[string][]string{
		"1.1.1.1,8.8.8.8":           {"1.1.1.1:53", "8.8.8.8:53"},
		" 9.9.9.9:5353 ":            {"9.9.9.9:5353"},
		"2606:4700:4700::1111":      {"[2606:4700:4700::1111]:53"},
		"[2001:4860:4860::8888]:53": {"[2001:4860:4860::8888]:53"},
		"none":                      nil,
		"":                          nil,
	}
	for in, want := range ok {
		got, err := ParseResolvers(in)
		if err != nil || strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("ParseResolvers(%q) = %v, %v; erwartet %v", in, got, err, want)
		}
	}
	for _, in := range []string{"dns.google", "1.1.1.1:0", "1.1.1.1:abc", "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5,6.6.6.6"} {
		if _, err := ParseResolvers(in); err == nil {
			t.Errorf("ParseResolvers(%q) sollte einen Fehler liefern", in)
		}
	}
}
