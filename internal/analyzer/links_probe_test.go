package analyzer

import (
	"net/http"
	"strings"
	"testing"
)

// TestActionLinksAreNeverOpened is the guard against the one place where this
// tool could damage the thing it is inspecting.
//
// The link check fetched every URL in the message with a GET, and a newsletter
// footer carries the unsubscribe link. Outside RFC 8058 one-click, those act on
// a plain GET — so checking the mail unsubscribed the address under test, and
// then reported the link as working.
func TestActionLinksAreNeverOpened(t *testing.T) {
	mustSkip := []string{
		"https://example.org/unsubscribe/abc123",
		"https://example.org/newsletter/abmelden?id=7",
		"https://example.org/abbestellen",
		"https://example.org/opt-out/xyz",
		"https://example.org/optout",
		"https://list.example.org/u/unsub?c=1",
		"https://example.org/confirm/token",
		"https://example.org/bestaetigen?t=9",
		"https://example.org/bestätigung",
		"https://example.org/double-opt-in/1",
		"https://example.org/verify/email",
		"https://example.org/aktivieren/konto",
		"https://example.org/austragen",
	}
	for _, u := range mustSkip {
		if !isActionLink(u) {
			t.Errorf("isActionLink(%q) = false — this link would be opened, and opening it acts on the recipient", u)
		}
	}

	mustCheck := []string{
		"https://example.org/",
		"https://shop.example.org/produkt/123",
		"https://example.org/blog/2026/newsletter-tipps",
		"https://example.org/impressum",
		"https://example.org/agb",
	}
	for _, u := range mustCheck {
		if isActionLink(u) {
			t.Errorf("isActionLink(%q) = true — an ordinary link would go unchecked", u)
		}
	}
}

// TestStatusNoteSeparatesRefusalFromBreakage covers the second half of the same
// finding: a WAF answering 403 to an unknown user agent is not a broken link,
// and a timeout from this server says nothing about the sender's links either.
func TestStatusNoteSeparatesRefusalFromBreakage(t *testing.T) {
	cases := map[int]string{
		0:                              "keine Antwort",
		http.StatusForbidden:           "nicht defekt",
		http.StatusUnauthorized:        "nicht defekt",
		http.StatusTooManyRequests:     "Zugriffsgrenze",
		http.StatusNotFound:            "HTTP 404",
		http.StatusInternalServerError: "HTTP 500",
	}
	for status, want := range cases {
		if got := statusNote(status); !strings.Contains(got, want) {
			t.Errorf("statusNote(%d) = %q, want it to contain %q", status, got, want)
		}
	}
}
