package analyzer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"golang.org/x/net/idna"

	"github.com/brightcolor/sender-report/internal/model"
)

// TestClassifyDNSErrorSeparatesAbsentFromUnavailable is the guard for the whole
// third-state mechanism. Before it existed, every one of these errors produced
// the same empty result and the same "record is missing" verdict.
//
// Revert classifyDNSError to the old behaviour — treating any error as an
// absent record — and the SERVFAIL, timeout, refused and generic cases below
// turn red.
func TestClassifyDNSErrorSeparatesAbsentFromUnavailable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want dnsStatus
	}{
		{"no error", nil, dnsOK},
		{
			"NXDOMAIN is authoritative and negative",
			&net.DNSError{Err: "no such host", Name: "absent.example", IsNotFound: true},
			dnsAbsent,
		},
		{
			"SERVFAIL says nothing about the domain",
			&net.DNSError{Err: "server misbehaving", Name: "example.org", IsTemporary: true},
			dnsUnavailable,
		},
		{
			"timeout says nothing about the domain",
			&net.DNSError{Err: "i/o timeout", Name: "example.org", IsTimeout: true},
			dnsUnavailable,
		},
		{
			"refused without any flag must not be read as absent",
			&net.DNSError{Err: "connection refused", Name: "example.org"},
			dnsUnavailable,
		},
		{
			"wrapped resolver failure is still a failure",
			fmt.Errorf("looking up MX: %w", &net.DNSError{Err: "i/o timeout", IsTimeout: true}),
			dnsUnavailable,
		},
		{
			"a non-DNS error must never claim the record is missing",
			errors.New("resolver socket closed"),
			dnsUnavailable,
		},
		{"context deadline", context.DeadlineExceeded, dnsUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyDNSError(tc.err); got != tc.want {
				t.Fatalf("classifyDNSError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestDNSLookupFailedMatchesClassification pins the exported helper used by the
// SMTP-side SPF evaluation, where the difference decides between temperror and
// a hard fail.
func TestDNSLookupFailedMatchesClassification(t *testing.T) {
	if DNSLookupFailed(&net.DNSError{IsNotFound: true}) {
		t.Error("NXDOMAIN must not count as a failed lookup — it is a valid negative answer")
	}
	if !DNSLookupFailed(&net.DNSError{IsTimeout: true}) {
		t.Error("a timeout must count as a failed lookup, otherwise -all produces a hard fail")
	}
	if DNSLookupFailed(nil) {
		t.Error("nil error must not count as a failed lookup")
	}
}

// TestAsciiDomainPreservesUnderscoreLabels guards the conversion against the
// two ways it could break DNS names the checks rely on: underscore labels used
// by DMARC/DKIM/MTA-STS, and internationalised domains that Go's resolver would
// otherwise reject as "not found".
func TestAsciiDomainPreservesUnderscoreLabels(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"example.org", "example.org"},
		{"_dmarc.example.org", "_dmarc.example.org"},
		{"selector1._domainkey.example.org", "selector1._domainkey.example.org"},
		{"_mta-sts.example.org", "_mta-sts.example.org"},
		{"_smtp._tls.example.org", "_smtp._tls.example.org"},
		{"EXAMPLE.org.", "EXAMPLE.org"},
		// bücher.de is the textbook A-label example and is checked verbatim.
		{"bücher.de", "xn--bcher-kva.de"},
	}

	for _, tc := range cases {
		got, err := asciiDomain(tc.in)
		if err != nil {
			t.Errorf("asciiDomain(%q) returned error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("asciiDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	if _, err := asciiDomain("   "); err == nil {
		t.Error("an empty domain must be rejected, not looked up")
	}

	// For the remaining internationalised names, checking a hand-written
	// A-label would only test the author's punycode knowledge. Converting back
	// tests the property that matters: the name that goes on the wire is still
	// the name the user typed, with underscore labels intact.
	roundTrip := []string{"bäcker.de", "_dmarc.bäcker.de", "münchen.example", "faß.de"}
	for _, in := range roundTrip {
		ascii, err := asciiDomain(in)
		if err != nil {
			t.Errorf("asciiDomain(%q) returned error: %v", in, err)
			continue
		}
		if !isASCII(ascii) {
			t.Errorf("asciiDomain(%q) = %q, which is still not ASCII — the resolver would reject it as not found", in, ascii)
		}
		back, err := idna.ToUnicode(ascii)
		if err != nil {
			t.Errorf("idna.ToUnicode(%q) returned error: %v", ascii, err)
			continue
		}
		if want := strings.ToLower(in); back != want {
			t.Errorf("round trip of %q produced %q via %q, want %q", in, back, ascii, want)
		}
	}
}

// TestUnresolvedNeverMovesScore fixes the rule that a resolver outage is not
// the sender's fault. A non-zero delta here would mean this server's own DNS
// trouble costs a stranger points.
func TestUnresolvedNeverMovesScore(t *testing.T) {
	c := unresolved("dmarc", "DMARC", "Der DMARC-Eintrag")

	if c.ScoreDelta != 0 {
		t.Errorf("ScoreDelta = %v, want 0 — a failed lookup must not be charged to the sender", c.ScoreDelta)
	}
	if c.Status != "info" {
		t.Errorf("Status = %q, want \"info\" — neither pass nor fail may be claimed", c.Status)
	}
	if c.ID != "dmarc" {
		t.Errorf("ID = %q, want \"dmarc\" — the check must keep its identity for filtering and recheck", c.ID)
	}
	if _, ok := c.TechnicalDetails[unresolvedDetailKey]; !ok {
		t.Errorf("missing %q detail — countUnresolved cannot see this check", unresolvedDetailKey)
	}
	// The wording must not leave the reader believing the record is absent.
	if strings.Contains(c.Summary, "nicht gefunden") || strings.Contains(c.Summary, "Kein ") {
		t.Errorf("summary claims absence: %q", c.Summary)
	}
	if !strings.Contains(c.Summary, "kann durchaus vorhanden sein") {
		t.Errorf("summary must say the record may well exist, got: %q", c.Summary)
	}
}

// TestCountUnresolvedAndWarning checks that an incomplete report announces
// itself instead of passing its score off as a finished verdict.
func TestCountUnresolvedAndWarning(t *testing.T) {
	checks := []model.CheckResult{
		pass("spf", "SPF", 0.4, "ok", ""),
		unresolved("dmarc", "DMARC", "Der DMARC-Eintrag"),
		fail("ptr", "PTR/rDNS", -1.0, "kein PTR", ""),
		unresolved("mx_records", "MX-Records", "Die MX-Einträge"),
	}

	if got := countUnresolved(checks); got != 2 {
		t.Fatalf("countUnresolved = %d, want 2", got)
	}
	if got := countUnresolved(nil); got != 0 {
		t.Errorf("countUnresolved(nil) = %d, want 0", got)
	}

	if w := unresolvedWarning(1); !strings.HasPrefix(w, "Eine Prüfung") {
		t.Errorf("singular wording wrong: %q", w)
	}
	if w := unresolvedWarning(3); !strings.Contains(w, "3 Prüfungen") {
		t.Errorf("plural wording wrong: %q", w)
	}
	if w := unresolvedWarning(2); !strings.Contains(w, "unvollständig") {
		t.Errorf("warning must call the result incomplete, got: %q", w)
	}
}
