package analyzer

import (
	"strings"
	"testing"
	"time"
)

// Rohmeldung des Prüfers, wie sie im Bericht stand und nichts über Selector,
// Domain oder Ursache verriet.
const verifierNoKey = "hopux.de=dkim: no key for signature: lookup dkim._domainkey.hopux.de on 127.0.0.11:53: no such host"

func TestMissingKeyFindingNamesSelectorDomainAndRecord(t *testing.T) {
	cases := []struct {
		name       string
		diag       dkimKeyDiag
		wantStatus string
		wantDE     []string
		wantSugg   []string
	}{
		{
			name:       "Record fehlt",
			diag:       dkimKeyDiag{Selector: "dkim", Domain: "hopux.de", DNSName: "dkim._domainkey.hopux.de", State: dkimKeyAbsent},
			wantStatus: "fail",
			wantDE:     []string{"Selector „dkim“", "hopux.de", "dkim._domainkey.hopux.de", "keinen TXT-Record", "no such host"},
			wantSugg:   []string{"TXT-Record dkim._domainkey.hopux.de anlegen", "dig +short TXT dkim._domainkey.hopux.de"},
		},
		{
			name:       "anderer Selector",
			diag:       dkimKeyDiag{Selector: "mail2026", Domain: "example.org", DNSName: "mail2026._domainkey.example.org", State: dkimKeyAbsent},
			wantStatus: "fail",
			wantDE:     []string{"Selector „mail2026“", "mail2026._domainkey.example.org"},
			wantSugg:   []string{"mail2026._domainkey.example.org", "s= der Signatur"},
		},
		{
			name:       "DNS antwortet nicht",
			diag:       dkimKeyDiag{Selector: "dkim", Domain: "hopux.de", DNSName: "dkim._domainkey.hopux.de", State: dkimKeyUnavailable},
			wantStatus: "warn",
			wantDE:     []string{"nicht beantwortet", "offen"},
			wantSugg:   []string{"dig NS hopux.de"},
		},
		{
			name: "Record fehlerhaft",
			diag: dkimKeyDiag{Selector: "dkim", Domain: "hopux.de", DNSName: "dkim._domainkey.hopux.de", State: dkimKeyUnusable,
				ProblemDE: "p= ist leer, der Schlüssel gilt damit als widerrufen", ProblemEN: "p= is empty"},
			wantStatus: "fail",
			wantDE:     []string{"vorhanden, aber unbrauchbar", "p= ist leer"},
			wantSugg:   []string{"korrigieren", "ohne Zeilenumbrüche"},
		},
		{
			name:       "Record inzwischen da",
			diag:       dkimKeyDiag{Selector: "dkim", Domain: "hopux.de", DNSName: "dkim._domainkey.hopux.de", State: dkimKeyUsable, KeyInfo: "RSA, 2048 Bit"},
			wantStatus: "warn",
			wantDE:     []string{"Inzwischen ist der Record abrufbar", "RSA, 2048 Bit", "Negativ-Antwort"},
			wantSugg:   []string{"Testmail erneut senden"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := classifyDKIMFailure("permerror", verifierNoKey, time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC), tc.diag)
			if f.status != tc.wantStatus {
				t.Errorf("status = %q, erwartet %q", f.status, tc.wantStatus)
			}
			for _, w := range tc.wantDE {
				if !strings.Contains(f.summaryDE, w) {
					t.Errorf("Befund sollte %q enthalten:\n%s", w, f.summaryDE)
				}
			}
			for _, w := range tc.wantSugg {
				if !strings.Contains(f.suggestDE, w) {
					t.Errorf("Empfehlung sollte %q enthalten:\n%s", w, f.suggestDE)
				}
			}
			if strings.Contains(f.suggestDE, "<selector>") {
				t.Errorf("Empfehlung darf keinen Platzhalter <selector> mehr enthalten:\n%s", f.suggestDE)
			}
			if !strings.Contains(f.summaryEN, tc.diag.DNSName) {
				t.Errorf("englischer Befund nennt den DNS-Namen nicht: %s", f.summaryEN)
			}
		})
	}
}

func TestMissingKeyFindingWithoutSignatureKeepsGenericText(t *testing.T) {
	f := classifyDKIMFailure("permerror", verifierNoKey, time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC), dkimKeyDiag{})
	if !strings.Contains(f.summaryDE, "Selector-DNS-Record fehlt") {
		t.Errorf("ohne Diagnose bleibt der bisherige Text: %s", f.summaryDE)
	}
}

func TestInspectDKIMKeyRecords(t *testing.T) {
	const goodKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0+LyS9O1ePv+6M+ItVIio12lokcFIaWfm9F7n0yyT5ow8AT3Gxl8jlbbHnMohB4KtkGhiZyF17BrKXELH9NwG0w3PCSbUbcoKEsspLRaXjytfZ0RUshuIMgx+nOp3MpvZr1OI0CltMerTW1hxCRlqGE9sskUwKPtTicwn3cD8AbKPU8S2pdFkJJlsRLcJ/yw3lliaRbN/ST2bQJMP4fif1G6Mfo6/FeyiN/Vv9wHr8edPR310yamyh0p/RYbOKNpRV4G5lihMqMi1+W1D9qI/odpxICj6+6nYxUCZOe0ZDe1gWY5bIOM37vJ/l9I9AkVRn4bqFkdGquKbImMNcxDIwIDAQAB"
	cases := []struct {
		name    string
		records []string
		wantOK  string
		wantErr string
	}{
		{"gültig, mit Leerzeichen", []string{"v=DKIM1; k=rsa; p=" + goodKey}, "RSA, 2048 Bit", ""},
		{"gültig, ohne v=, mit s=email und t=s", []string{"k=rsa;t=s;s=email;p=" + goodKey}, "RSA, 2048 Bit", ""},
		{"zwei Records", []string{"v=DKIM1; p=" + goodKey, "v=DKIM1; p=" + goodKey}, "", "2 TXT-Records"},
		{"p fehlt", []string{"google-site-verification=abc"}, "", "fehlt das Tag p="},
		{"widerrufen", []string{"v=DKIM1; k=rsa; p="}, "", "widerrufen"},
		{"falsche Version", []string{"v=DKIM2; p=" + goodKey}, "", "v=DKIM1"},
		{"Dienst ohne email", []string{"v=DKIM1; s=sms; p=" + goodKey}, "", "s=sms"},
		{"kein Base64", []string{"v=DKIM1; p=\"abc\"-%%"}, "", "Base64"},
		{"kein Schlüssel", []string{"v=DKIM1; p=YWJjZA=="}, "", "lesbaren"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, problem, problemEN := inspectDKIMKeyRecords(tc.records)
			if tc.wantErr == "" {
				if problem != "" || info != tc.wantOK {
					t.Fatalf("info=%q problem=%q, erwartet info=%q", info, problem, tc.wantOK)
				}
				return
			}
			if !strings.Contains(problem, tc.wantErr) {
				t.Errorf("Problem %q sollte %q enthalten", problem, tc.wantErr)
			}
			if problemEN == "" {
				t.Error("englische Beschreibung fehlt")
			}
		})
	}
}

func TestDKIMDetailIsKeyProblem(t *testing.T) {
	for d, want := range map[string]bool{
		verifierNoKey: true, "x=dkim: key syntax error": true, "x=dkim: key revoked": true,
		"x=dkim: body hash did not verify": false, "": false,
	} {
		if got := dkimDetailIsKeyProblem(d); got != want {
			t.Errorf("dkimDetailIsKeyProblem(%q) = %v, erwartet %v", d, got, want)
		}
	}
}
