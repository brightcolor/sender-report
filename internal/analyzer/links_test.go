package analyzer

import (
	"strings"
	"testing"
)

// TestLooksLikeDomainRejectsOrdinaryLinkText covers the false-positive engine
// behind the most expensive wrong accusation in the report.
//
// The old rule was "contains a dot and no space", and publicsuffix happily
// turns an unknown final label into a suffix of its own — so a download link
// labelled Rechnung_2025_11.pdf became a "classic phishing pattern" at -2.6.
func TestLooksLikeDomainRejectsOrdinaryLinkText(t *testing.T) {
	notDomains := []string{
		"Rechnung_2025_11.pdf",
		"Angebot_final.docx",
		"Weiterlesen.",
		"AGB.",
		"Mehr.",
		"Version 2.1",
		"2.1.4",
		"Az. 12.345.678",
		"Angebot.zip",
		"Clip.mov",
		"",
		"   ",
		"de",
		".de",
		"kein-punkt-hier",
	}
	for _, s := range notDomains {
		if looksLikeDomain(s) {
			t.Errorf("looksLikeDomain(%q) = true — ordinary link text would be reported as a disguised link", s)
		}
	}

	domains := []string{
		"example.org",
		"www.meine-firma.de",
		"shop.example.co.uk",
		"EXAMPLE.ORG",
		"sub.domain.example.com",
	}
	for _, s := range domains {
		if !looksLikeDomain(s) {
			t.Errorf("looksLikeDomain(%q) = false — a genuine mismatch would go unnoticed", s)
		}
	}
}

// TestLinkMismatchSeparatesTrackingFromPhishing pins the distinction the check
// exists for. Both shapes look identical structurally; only one is a deception.
func TestLinkMismatchSeparatesTrackingFromPhishing(t *testing.T) {
	t.Run("ESP click tracking is normal and costs nothing", func(t *testing.T) {
		// What Mailchimp, CleverReach and Brevo produce by default: the visible
		// text is the sender's own domain, the href is the provider's counter.
		body := `<html><body><a href="https://click.mailprovider.net/c/abc">www.meine-firma.de</a></body></html>`
		c := linkDomainMismatchCheck(body, "meine-firma.de")

		if c.Status == "fail" {
			t.Errorf("standard click tracking reported as failure: %q", c.Summary)
		}
		if c.ScoreDelta < 0 {
			t.Errorf("ScoreDelta = %v — the sender cannot change this and it is not a deception", c.ScoreDelta)
		}
		if !strings.Contains(c.Summary, "Normalfall") {
			t.Errorf("the reader should learn that this is normal, got: %q", c.Summary)
		}
	})

	t.Run("a foreign domain in the text stays a failure", func(t *testing.T) {
		body := `<html><body><a href="https://evil.example.net/login">www.sparkasse.de</a></body></html>`
		c := linkDomainMismatchCheck(body, "meine-firma.de")

		if c.Status != "fail" {
			t.Errorf("status = %q, want fail — this is the actual phishing pattern", c.Status)
		}
		if !strings.Contains(c.TechnicalDetails["betroffene_links"], "sparkasse.de") {
			t.Errorf("the report must name the offending link, details: %v", c.TechnicalDetails)
		}
	})

	t.Run("a file name in the link text is not a domain", func(t *testing.T) {
		body := `<html><body><a href="https://kunde.example.com/dl/8123">Rechnung_2025_11.pdf</a></body></html>`
		c := linkDomainMismatchCheck(body, "example.com")

		if c.Status != "pass" {
			t.Errorf("status = %q, want pass — a download link is not a phishing pattern (%q)", c.Status, c.Summary)
		}
	})

	t.Run("a sentence ending in a period is not a domain", func(t *testing.T) {
		body := `<html><body><a href="https://shop.example.de/blog/1">Weiterlesen.</a></body></html>`
		c := linkDomainMismatchCheck(body, "example.de")

		if c.Status != "pass" {
			t.Errorf("status = %q, want pass (%q)", c.Status, c.Summary)
		}
	})

	t.Run("matching text and target pass", func(t *testing.T) {
		body := `<html><body><a href="https://www.example.org/x">www.example.org</a></body></html>`
		c := linkDomainMismatchCheck(body, "example.org")

		if c.Status != "pass" {
			t.Errorf("status = %q, want pass", c.Status)
		}
	})

	t.Run("a foreign domain outweighs tracking in the same mail", func(t *testing.T) {
		body := `<html><body>` +
			`<a href="https://click.mailprovider.net/c/abc">www.meine-firma.de</a>` +
			`<a href="https://evil.example.net/login">paypal.de</a>` +
			`</body></html>`
		c := linkDomainMismatchCheck(body, "meine-firma.de")

		if c.Status != "fail" {
			t.Errorf("status = %q, want fail — the genuine mismatch must not be masked by the harmless one", c.Status)
		}
	})
}
