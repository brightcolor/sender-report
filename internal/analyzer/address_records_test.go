package analyzer

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// fakeZone startet einen DNS-Server auf 127.0.0.1, setzt ihn als Resolver und
// beantwortet nur, was in zone steht: Name → Typ → Antworten (Textform).
// Alles andere ist NODATA (NOERROR ohne Antwort).
func fakeZone(t *testing.T, zone map[string]map[uint16][]string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true // ohne Antwort und ohne dieses Kennzeichen wertet Go die Antwort als fehlerhafte Weiterleitung
		q := req.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		for _, rr := range zone[name][q.Qtype] {
			if parsed, err := dns.NewRR(q.Name + " 60 IN " + dns.TypeToString[q.Qtype] + " " + rr); err == nil {
				m.Answer = append(m.Answer, parsed)
			}
		}
		_ = w.WriteMsg(m)
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started

	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", pc.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = old; _ = srv.Shutdown() })
}

// Eine Hauptdomain, die nur MX-Records trägt, ist ein üblicher Aufbau. Der Befund
// „hat keine A/AAAA-Records“ gab dafür früher einen Abzug und die Anleitung, einen
// A-Record für den HELO-Namen zu setzen, der längst existierte.
func TestAddressRecordsAcceptsAMailDomainWithOnlyMX(t *testing.T) {
	fakeZone(t, map[string]map[uint16][]string{
		"mailonly.test":  {dns.TypeMX: {"10 mail.mailonly.test."}},
		"host.test":      {dns.TypeA: {"203.0.113.7"}},
		"mail.host.test": {dns.TypeAAAA: {"2001:db8::1"}},
	})
	ctx := context.Background()

	res := addressRecordCheck(ctx, "mailonly.test")
	if res.Status != "info" || res.ScoreDelta != 0 {
		t.Errorf("nur MX: Status %q, Abzug %v, erwartet info ohne Abzug (%s)", res.Status, res.ScoreDelta, res.Summary)
	}
	if !strings.Contains(res.Summary, "MX-Records (1)") || res.TechnicalDetails["mx_hosts"] != "mail.mailonly.test" {
		t.Errorf("Befund nennt die MX-Records nicht: %q %v", res.Summary, res.TechnicalDetails)
	}

	if res := addressRecordCheck(ctx, "host.test"); res.Status != "pass" {
		t.Errorf("A-Record vorhanden: Status %q (%s)", res.Status, res.Summary)
	}
	if res := addressRecordCheck(ctx, "mail.host.test"); res.Status != "pass" {
		t.Errorf("nur AAAA vorhanden: Status %q (%s)", res.Status, res.Summary)
	}

	res = addressRecordCheck(ctx, "nothing.test")
	if res.Status != "warn" || !strings.Contains(res.Summary, "weder A/AAAA- noch MX-Records") {
		t.Errorf("weder A noch MX: Status %q (%s)", res.Status, res.Summary)
	}
	if res.TechnicalDetails["domain"] != "nothing.test" {
		t.Errorf("Befund nennt die geprüfte Domain nicht: %v", res.TechnicalDetails)
	}
}

// Die Anleitung bezieht sich auf die Domain des Befunds und nicht auf den HELO-Namen.
func TestAddressRecordsAdviceNamesTheCheckedDomain(t *testing.T) {
	fakeZone(t, nil)
	res := addressRecordCheck(context.Background(), "nothing.test")
	ctx := checkContext{}
	ctx.Message.HELO = "mail.hopux.test"
	ctx.Message.RemoteIP = "203.0.113.7"
	got := enrichCheckResult(res, ctx)
	for _, want := range []string{"nothing.test", "dig MX nothing.test +short"} {
		if !strings.Contains(got.Recommendation, want) {
			t.Errorf("Anleitung sollte %q enthalten:\n%s", want, got.Recommendation)
		}
	}
	if strings.Contains(got.Recommendation, "mail.hopux.test") || strings.Contains(got.Recommendation, "203.0.113.7") {
		t.Errorf("Anleitung nennt HELO-Name oder IP statt der geprüften Domain:\n%s", got.Recommendation)
	}
}
