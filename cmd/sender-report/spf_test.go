package main

import (
	"context"
	"net/mail"
	"strings"
	"testing"

	"github.com/brightcolor/sender-report/internal/config"
	"github.com/brightcolor/sender-report/internal/smtp"
)

// TestPTRNameUnderDomain guards the SPF ptr mechanism against the two ways its
// suffix comparison used to be wrong.
//
// With an empty domain — which is what `ptr` without a value produced, since
// RFC 7208 §5.5 says it defaults to the current domain and that default was
// missing — strings.HasSuffix(host, "") is true for every name. A record
// ending in `ptr -all` therefore authorised every IP on the internet, the exact
// opposite of what it states. Without the label boundary, an attacker's
// "notexample.org" passed for "example.org".
func TestPTRNameUnderDomain(t *testing.T) {
	cases := []struct {
		host, domain string
		want         bool
	}{
		{"mail.example.org", "example.org", true},
		{"example.org", "example.org", true},
		{"MAIL.EXAMPLE.ORG", "example.org", true},
		{"mail.example.org.", "example.org", true},
		{"a.b.example.org", "example.org", true},

		{"notexample.org", "example.org", false},
		{"evil-example.org", "example.org", false},
		{"example.org.attacker.net", "example.org", false},
		{"mail.example.com", "example.org", false},

		// The empty-domain case: every one of these must be false.
		{"mail.example.org", "", false},
		{"anything.at.all", "", false},
		{"", "example.org", false},
		{"", "", false},
	}

	for _, tc := range cases {
		if got := ptrNameUnderDomain(tc.host, tc.domain); got != tc.want {
			t.Errorf("ptrNameUnderDomain(%q, %q) = %v, want %v", tc.host, tc.domain, got, tc.want)
		}
	}
}

// TestSPFLookupBudgetIsAConstant documents why the limit is not the recursion
// depth: RFC 7208 §4.6.4 counts DNS-querying mechanisms across the whole
// evaluation, so twenty includes side by side must fail even though none of
// them nests.
func TestSPFLookupBudgetIsAConstant(t *testing.T) {
	if spfLookupBudget != 10 {
		t.Errorf("spfLookupBudget = %d, want 10 (RFC 7208 §4.6.4)", spfLookupBudget)
	}
}

// TestReceivedHeaderIsWritten covers the duty RFC 5321 §4.4 places on the
// receiving server — which for a test message is this one.
//
// Without it, a message delivered straight here (swaks, a smtplib script, any
// MTA going directly to the MX) legitimately arrived with no Received header at
// all, and the report failed the sender for it with "the transport path must
// contain Received headers". Nothing the sender could have done.
func TestReceivedHeaderIsWritten(t *testing.T) {
	rm := smtp.ReceivedMail{
		RemoteIP: "203.0.113.5",
		HELO:     "mail.example.org",
		MailFrom: "sender@example.org",
		RcptTo:   "abc123@mx-test.example.net",
		TLS:      true,
	}

	got := buildReceivedHeader("sender.report", rm)

	for _, want := range []string{"Received: from mail.example.org", "([203.0.113.5])", "by sender.report", "ESMTPS", "abc123@mx-test.example.net"} {
		if !strings.Contains(got, want) {
			t.Errorf("header missing %q:\n%s", want, got)
		}
	}

	t.Run("plain delivery is marked ESMTP, not ESMTPS", func(t *testing.T) {
		plain := buildReceivedHeader("sender.report", smtp.ReceivedMail{RemoteIP: "203.0.113.5", HELO: "h"})
		if strings.Contains(plain, "ESMTPS") {
			t.Errorf("unencrypted delivery claims TLS:\n%s", plain)
		}
		if !strings.Contains(plain, "ESMTP") {
			t.Errorf("protocol missing:\n%s", plain)
		}
	})

	t.Run("continuation lines are folded with a tab", func(t *testing.T) {
		// A header spanning lines must continue with whitespace, or every parser
		// downstream reads the rest as separate headers.
		for _, line := range strings.Split(strings.ReplaceAll(got, "\r\n", "\n"), "\n")[1:] {
			if line == "" {
				continue
			}
			if !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " ") {
				t.Errorf("continuation line is not folded: %q", line)
			}
		}
	})

	t.Run("every line ends in CRLF, never CR CR LF", func(t *testing.T) {
		// Rspamd (and other strict parsers) read a stray CR in front of CRLF as the
		// end of the header block. Everything after it then counts as body: the
		// report claimed From, Date, Message-ID, Subject and DMARC were missing on a
		// message that carried all of them.
		raw := "From: a@example.org\r\nDate: Fri, 16 Oct 2026 16:41:03 +0200\r\nSubject: Test\r\n\r\nHallo\r\n"
		enriched := prependHeaders(raw, []string{got, "X-Test: eins"})
		if strings.Contains(enriched, "\r\r") {
			t.Errorf("doppeltes CR im Quelltext: %q", enriched)
		}
		if strings.Contains(strings.ReplaceAll(enriched, "\r\n", ""), "\n") {
			t.Errorf("einzelnes LF im Quelltext: %q", enriched)
		}
		head, _, ok := strings.Cut(enriched, "\r\n\r\n")
		if !ok {
			t.Fatalf("Kopf und Text sind nicht durch eine Leerzeile getrennt: %q", enriched)
		}
		for _, h := range []string{"From: a@example.org", "Date: ", "Subject: Test", "X-Test: eins", "Received: from"} {
			if !strings.Contains(head, h) {
				t.Errorf("Kopfzeile %q liegt nicht im Kopfblock: %q", h, head)
			}
		}
	})

	t.Run("the message parses with the header prepended", func(t *testing.T) {
		raw := "From: a@example.org\r\nSubject: Test\r\n\r\nHallo\r\n"
		enriched := prependHeaders(raw, []string{got})
		msg, err := mail.ReadMessage(strings.NewReader(enriched))
		if err != nil {
			t.Fatalf("enriched message no longer parses: %v", err)
		}
		if msg.Header.Get("Received") == "" {
			t.Error("Received header did not survive prependHeaders")
		}
		if msg.Header.Get("From") != "a@example.org" {
			t.Errorf("original headers damaged: From = %q", msg.Header.Get("From"))
		}
	})
}

// Die Neuprüfung nimmt die Kopfzeilen, die dieser Server beim Empfang vorangestellt
// hat, vollständig wieder ab und lässt alles andere stehen, auch fremde
// Authentication-Results-Zeilen.
func TestStripReceiverHeadersRestoresTheOriginal(t *testing.T) {
	const host = "mx.sender.test"
	original := "Authentication-Results: mx.google.com; dkim=pass header.i=@example.org\r\n" +
		"Received: by 2002:a05:6512 with SMTP id abc; Fri, 16 Oct 2026 16:41:00 +0200\r\n" +
		"From: a@example.org\r\nSubject: Test\r\nContent-Type: text/plain\r\n\r\nHallo\r\n\r\nzweiter Absatz\r\n"
	rm := smtp.ReceivedMail{RemoteIP: "209.85.214.171", HELO: "mail.google.com", MailFrom: "a@example.org", RcptTo: "x@mx.sender.test", TLS: true}
	enriched := prependHeaders(original, []string{
		buildReceivedHeader(host, rm),
		buildAuthenticationResultsHeader(host, authResults{SPFResult: "pass", DKIMResult: "none", DMARCResult: "none"}),
		buildReceivedSPFHeader(host, rm, "pass"),
		"X-Sender-Report-SPF-Detail: domain=example.org",
		"X-Sender-Report-DKIM-Detail: none",
		"X-Sender-Report-DMARC-Detail: none",
	})
	if !strings.Contains(enriched, "X-Sender-Report-SPF-Detail") {
		t.Fatal("Testaufbau: die Kopfzeilen fehlen")
	}

	clean, tls := stripReceiverHeaders(enriched, host)
	if !tls {
		t.Error("die entfernte Received-Zeile nannte ESMTPS, tls muss wahr sein")
	}
	if clean != original {
		t.Errorf("nach dem Entfernen steht nicht der Originaltext da:\n%q\nerwartet\n%q", clean, original)
	}
	if again, _ := stripReceiverHeaders(clean, host); again != clean {
		t.Error("das Entfernen ist nicht idempotent")
	}
}

func TestStripReceiverHeadersIgnoresOtherHosts(t *testing.T) {
	raw := "Authentication-Results: mx.other.test; spf=pass\r\nReceived: from a by mx.other.test with ESMTP; x\r\nFrom: a@example.org\r\n\r\nHallo"
	clean, tls := stripReceiverHeaders(raw, "mx.sender.test")
	if clean != raw || tls {
		t.Errorf("Kopfzeilen anderer Server bleiben stehen:\n%q", clean)
	}
}

// Die Neuprüfung ersetzt die alten Ergebnisse, sie hängt keine zweite Serie an.
func TestReverifyReplacesTheReceiverHeaders(t *testing.T) {
	cfg := config.Config{SMTPDomain: "mx.sender.test"}
	rm := smtp.ReceivedMail{RemoteIP: "203.0.113.5", HELO: "mail.example.org", MailFrom: "a@example.org", RcptTo: "x@mx.sender.test"}
	raw := "From: a@example.org\r\nSubject: Test\r\n\r\nHallo\r\n"
	first := reverifyReceiverAuth(context.Background(), cfg, rm, raw)
	second := reverifyReceiverAuth(context.Background(), cfg, rm, first)
	for _, name := range []string{"Received:", "Authentication-Results:", "Received-SPF:", "X-Sender-Report-DKIM-Detail:"} {
		if n := strings.Count(second, "\r\n"+name) + strings.Count(second[:len(name)], name); n != 1 {
			t.Errorf("%s steht %d-mal im Kopf, erwartet einmal", name, n)
		}
	}
	if _, err := mail.ReadMessage(strings.NewReader(second)); err != nil {
		t.Errorf("die Nachricht lässt sich nicht mehr lesen: %v", err)
	}
}
