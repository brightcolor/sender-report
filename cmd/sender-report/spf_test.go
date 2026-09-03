package main

import (
	"net/mail"
	"strings"
	"testing"

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
