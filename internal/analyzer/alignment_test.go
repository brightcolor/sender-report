package analyzer

import (
	"net/mail"
	"testing"
)

// TestRelaxedAlignment covers both directions in which the old HasSuffix pair
// was wrong: it missed sibling subdomains under one organisation, and it
// accepted a domain that merely ends in the other one.
func TestRelaxedAlignment(t *testing.T) {
	cases := []struct {
		auth, from string
		want       bool
		why        string
	}{
		{"example.org", "example.org", true, "identical"},
		{"bounce.example.org", "example.org", true, "subdomain of the From domain"},
		{"example.org", "mail.example.org", true, "From on a subdomain of the auth domain"},
		{"bounce.example.org", "mail.example.org", true, "siblings — the case the old test missed"},
		{"a.b.c.example.co.uk", "example.co.uk", true, "multi-label public suffix"},

		{"notexample.org", "example.org", false, "ends in the other name but is a different organisation"},
		{"example.org.attacker.net", "example.org", false, "the other name as a prefix"},
		{"example.com", "example.org", false, "different organisation"},
		{"", "example.org", false, "no auth domain"},
		{"example.org", "", false, "no From domain"},
	}

	for _, tc := range cases {
		if got := relaxedAligned(tc.auth, tc.from); got != tc.want {
			t.Errorf("relaxedAligned(%q, %q) = %v, want %v (%s)", tc.auth, tc.from, got, tc.want, tc.why)
		}
	}
}

// TestDKIMSigningDomainsReadsEverySignature covers the standard ESP setup: the
// platform signs and so does the customer's own domain. Reading only the first
// header made the report contradict itself — "DMARC: pass" next to "no DKIM
// alignment" — depending on which signature happened to come first.
func TestDKIMSigningDomainsReadsEverySignature(t *testing.T) {
	headers := mail.Header{
		"Dkim-Signature": []string{
			"v=1; a=rsa-sha256; d=mailprovider.net; s=k1; h=from:to; b=AAAA",
			"v=1; a=rsa-sha256; d=meine-firma.de; s=sel; h=from:to; b=BBBB",
		},
	}

	got := dkimSigningDomains(headers)
	if len(got) != 2 {
		t.Fatalf("got %d signing domains (%v), want 2", len(got), got)
	}
	if got[0] != "mailprovider.net" || got[1] != "meine-firma.de" {
		t.Errorf("signing domains = %v, want [mailprovider.net meine-firma.de]", got)
	}

	// The point of reading all of them: alignment must be found on the second.
	aligned := false
	for _, d := range got {
		if relaxedAligned(d, "meine-firma.de") {
			aligned = true
		}
	}
	if !aligned {
		t.Error("no aligned signature found — the customer's own signature was ignored")
	}

	t.Run("duplicates collapse and empty headers are skipped", func(t *testing.T) {
		h := mail.Header{"Dkim-Signature": []string{
			"v=1; d=example.org; b=A",
			"v=1; d=example.org; b=B",
			"",
		}}
		if got := dkimSigningDomains(h); len(got) != 1 {
			t.Errorf("got %v, want one unique domain", got)
		}
	})

	t.Run("no signature yields nothing", func(t *testing.T) {
		if got := dkimSigningDomains(mail.Header{}); len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})
}
