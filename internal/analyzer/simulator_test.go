package analyzer

import (
	"net/mail"
	"strings"
	"testing"

	"github.com/brightcolor/sender-report/internal/model"
)

// TestSimulatorPlaceholdersAreReadable guards two things the simulator used to
// get wrong: sixteen checks appeared under their raw identifier, and every
// placeholder promised a recheck button — including for checks that cannot be
// rechecked at all, because they need the IP of a real connection.
func TestSimulatorPlaceholdersAreReadable(t *testing.T) {
	for _, id := range []string{"dane_tlsa", "ptr_pattern", "mta_sts", "rbl", "envelope_mx"} {
		if name := checkNameDE(id); name == id {
			t.Errorf("checkNameDE(%q) returns the raw identifier — that is what the reader would see", id)
		}
	}

	t.Run("checks needing a real delivery do not promise a button", func(t *testing.T) {
		for _, id := range []string{"rbl", "ptr", "ptr_pattern"} {
			text := simPlaceholderText(id)
			if strings.Contains(text, "↻") {
				t.Errorf("%s: placeholder points at a recheck button; Recheckable(%q)=%v", id, id, Recheckable(id))
			}
			if !strings.Contains(text, "Testmail") {
				t.Errorf("%s: should tell the reader how to get this checked, got: %q", id, text)
			}
		}
	})

	t.Run("recheckable checks keep the hint", func(t *testing.T) {
		if !strings.Contains(simPlaceholderText("mta_sts"), "↻") {
			t.Error("mta_sts is recheckable and should say so")
		}
	})
}

// TestSimulatedAuthResultsAreLabelled pins the honesty rule for the simulator:
// SPF, DKIM and DMARC are copied out of the pasted Authentication-Results
// header, not measured. Presenting them like a verified result would let anyone
// paste "spf=pass" and be told their SPF passes.
func TestSimulatedAuthResultsAreLabelled(t *testing.T) {
	checks := []model.CheckResult{
		pass("spf", "SPF", 0.4, "SPF laut Authentication-Results bestanden.", ""),
		pass("dkim", "DKIM", 0.4, "DKIM bestanden.", ""),
		warn("mx_records", "MX-Records", -0.3, "kein MX.", ""),
	}
	markSimulatedAuthResults(checks)

	for _, c := range checks[:2] {
		if !strings.Contains(c.Summary, "nicht selbst nachgeprüft") {
			t.Errorf("%s: result is not marked as taken over unverified: %q", c.ID, c.Summary)
		}
		if c.TechnicalDetails["herkunft"] == "" {
			t.Errorf("%s: missing provenance detail", c.ID)
		}
	}
	if strings.Contains(checks[2].Summary, "nicht selbst nachgeprüft") {
		t.Error("mx_records is a real check in the simulator path and must not be labelled")
	}
}

// TestAdviceKeepsSeverityOrder covers the sidebar: the reader should meet the
// finding that costs them delivery first, not the one that sorts first
// alphabetically.
func TestAdviceKeepsSeverityOrder(t *testing.T) {
	in := []string{
		"Zebra: kritischer Punkt",
		"Alpha: Kleinigkeit",
		"Zebra: kritischer Punkt", // duplicate
		"",
		"Beta: mittel",
	}
	got := dedupeKeepOrder(in)

	want := []string{"Zebra: kritischer Punkt", "Alpha: Kleinigkeit", "Beta: mittel"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d: got %q, want %q — order was not preserved", i, got[i], want[i])
		}
	}

	if len(dedupeKeepOrder(nil)) != 0 {
		t.Error("nil input should yield an empty result")
	}
}

// TestDMARCPolicyHonoursPctAndSp covers the two tags that decide whether a
// policy actually applies. "p=reject; pct=1" was reported as the strongest
// possible protection while covering one message in a hundred, and a weaker
// sp= left every subdomain unprotected without a word in the report.
func TestDMARCPolicyHonoursPctAndSp(t *testing.T) {
	cases := []struct {
		name       string
		record     string
		policy     string
		wantStatus string
		wantInText string
	}{
		{"full reject passes", "v=DMARC1; p=reject; rua=mailto:a@example.org", "reject", "pass", "stärkster Schutz"},
		{"pct=1 is not full protection", "v=DMARC1; p=reject; pct=1", "reject", "warn", "pct=1"},
		{"pct=50 is not full protection", "v=DMARC1; p=quarantine; pct=50", "quarantine", "warn", "50 %"},
		{"sp=none exposes subdomains", "v=DMARC1; p=reject; sp=none", "reject", "warn", "Subdomains ungeschützt"},
		{"pct=100 is the normal case", "v=DMARC1; p=reject; pct=100", "reject", "pass", "stärkster Schutz"},
	}

	for _, tc := range cases {
		got := dmarcPolicyCheck([]string{tc.record}, tc.policy)
		if got.Status != tc.wantStatus {
			t.Errorf("%s: status = %q, want %q (%q)", tc.name, got.Status, tc.wantStatus, got.Summary)
		}
		if !strings.Contains(got.Summary, tc.wantInText) {
			t.Errorf("%s: summary should mention %q, got: %q", tc.name, tc.wantInText, got.Summary)
		}
	}
}

// TestBulkContentBreaksTheCircularClassification covers the loop the mail-type
// detection used to be caught in: the only bulk signals were the List-* headers,
// so a newsletter missing them was classified as personal — and the
// List-Unsubscribe check was then skipped as "not applicable" for exactly the
// mail that had the problem.
func TestBulkContentBreaksTheCircularClassification(t *testing.T) {
	newsletterHTML := `<html><body>` +
		`<a href="https://example.org/1">Eins</a><a href="https://example.org/2">Zwei</a>` +
		`<a href="https://example.org/3">Drei</a><a href="https://example.org/4">Vier</a>` +
		`<a href="https://example.org/5">Fünf</a>` +
		`<p>Wenn Sie keine weiteren E-Mails wünschen, können Sie sich hier abmelden.</p>` +
		`</body></html>`

	t.Run("a newsletter without list headers is recognised", func(t *testing.T) {
		body := parsedBody{HTML: newsletterHTML, AllText: newsletterHTML, HasHTMLPart: true}
		if !looksLikeBulkContent(mail.Header{}, body) {
			t.Error("a mailing with five links and an unsubscribe line was not recognised as bulk")
		}
	})

	t.Run("a personal reply mentioning unsubscribing is not bulk", func(t *testing.T) {
		body := parsedBody{HTML: newsletterHTML, AllText: newsletterHTML, HasHTMLPart: true}
		h := mail.Header{"In-Reply-To": []string{"<abc@example.org>"}}
		if looksLikeBulkContent(h, body) {
			t.Error("a reply in a running conversation must not be reclassified as a mailing")
		}
	})

	t.Run("a short plain-text note is not bulk", func(t *testing.T) {
		body := parsedBody{AllText: "Hallo, bitte vom Verteiler abmelden. Gruß", HasHTMLPart: false}
		if looksLikeBulkContent(mail.Header{}, body) {
			t.Error("a plain-text message must not be reclassified as a mailing")
		}
	})

	t.Run("HTML without an unsubscribe phrase is not bulk", func(t *testing.T) {
		h := `<html><body><a href="a">1</a><a href="b">2</a><a href="c">3</a><a href="d">4</a><a href="e">5</a></body></html>`
		body := parsedBody{HTML: h, AllText: h, HasHTMLPart: true}
		if looksLikeBulkContent(mail.Header{}, body) {
			t.Error("a link-heavy personal mail without an unsubscribe line must stay personal")
		}
	})
}
