package analyzer

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brightcolor/sender-report/internal/model"
)

// TestRspamdBekommtUmschlagUndVollenQuelltext: Rspamd meldete bei einer
// vollständigen Mail fehlende From-, Date- und Message-ID-Header sowie „kein
// DMARC“. Die Anfrage trug weder IP noch Umschlagdaten, und der Quelltext
// kam mit CR CR LF im Kopf an. Der Test hält fest, was bei Rspamd ankommt.
func TestRspamdBekommtUmschlagUndVollenQuelltext(t *testing.T) {
	var gotHeaders http.Header
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"score":0.5,"required_score":15,"action":"no action","symbols":{}}`))
	}))
	defer srv.Close()

	raw := "From: a@example.org\r\nDate: Fri, 16 Oct 2026 16:41:03 +0200\r\nMessage-ID: <x@example.org>\r\nSubject: Test\r\n\r\nHallo\r\n"
	msg := model.Message{
		RawSource: raw,
		RemoteIP:  "209.85.214.171",
		HELO:      "mail-pl1-f171.google.com",
		SMTPFrom:  "info@example.org",
		RCPTTo:    "token@mx.example.net",
	}
	res := rspamdHeuristic(context.Background(), srv.URL, "", msg)
	if res.Status != "pass" {
		t.Fatalf("Status = %q, erwartet pass (%s)", res.Status, res.Summary)
	}
	for k, want := range map[string]string{
		"Ip": "209.85.214.171", "Helo": "mail-pl1-f171.google.com",
		"From": "info@example.org", "Rcpt": "token@mx.example.net",
	} {
		if got := gotHeaders.Get(k); got != want {
			t.Errorf("Anfrage-Header %s = %q, erwartet %q", k, got, want)
		}
	}
	if gotBody != raw {
		t.Errorf("Quelltext verändert:\n%q", gotBody)
	}
}

func TestRspamdUmschlagslosesNachrichtLaesstFelderWeg(t *testing.T) {
	got := rspamdEnvelopeHeaders(model.Message{RemoteIP: "kein-ip", HELO: "  "})
	if len(got) != 0 {
		t.Errorf("leere oder ungültige Werte dürfen nicht gesendet werden: %v", got)
	}
	if v := rspamdEnvelopeHeaders(model.Message{RemoteIP: "2001:db8::1"})["IP"]; !strings.HasPrefix(v, "2001") {
		t.Errorf("IPv6 muss durchgereicht werden, war %q", v)
	}
}
