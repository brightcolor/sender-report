package analyzer

import (
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/brightcolor/sender-report/internal/model"
)

// TestDetailedRecommendationReachesTheReader guards the advice the report is
// supposed to give.
//
// defaultRecommendation used to open with "if c.Suggestion != "" { return it }",
// and every check sets a suggestion — pass, warn, fail and info all take one as
// an argument. The worked-out texts below that line, the ones that fill in the
// reader's own domain, IP and selector, were therefore unreachable for around
// two dozen checks. Restore that early return and this test turns red.
func TestDetailedRecommendationReachesTheReader(t *testing.T) {
	ctx := checkContext{
		FromDomain:     "meine-firma.de",
		EnvelopeDomain: "bounce.versand.example",
	}

	cases := []string{"spf_alignment", "dkim_alignment", "from_alignment", "return_path"}
	for _, id := range cases {
		c := model.CheckResult{ID: id, Suggestion: "Kurzfassung ohne Details."}
		got := defaultRecommendation(c, ctx)

		if got == c.Suggestion {
			t.Errorf("%s: the one-line suggestion won — the worked-out text is unreachable", id)
			continue
		}
		if !strings.Contains(got, "meine-firma.de") {
			t.Errorf("%s: advice should name the reader's own domain, got: %q", id, got)
		}
	}

	t.Run("an unlisted check still falls back to its own suggestion", func(t *testing.T) {
		c := model.CheckResult{ID: "an_id_with_no_case", Suggestion: "Eigener Hinweis."}
		if got := defaultRecommendation(c, ctx); got != "Eigener Hinweis." {
			t.Errorf("fallback lost: got %q", got)
		}
	})

	t.Run("no suggestion and no case still yields something usable", func(t *testing.T) {
		c := model.CheckResult{ID: "an_id_with_no_case"}
		if got := defaultRecommendation(c, ctx); strings.TrimSpace(got) == "" {
			t.Error("a check must never end up with an empty recommendation")
		}
	})
}

// TestUserFacingTextIsConsistentlyFormal is a completeness guard over the whole
// file rather than a spot check: the report addressed its reader as "du" in
// some places and "Sie" in others, sometimes within one screen.
//
// It reads the source because that is where the strings live — there is no
// runtime path that enumerates every user-facing sentence.
func TestUserFacingTextIsConsistentlyFormal(t *testing.T) {
	// Both files carry text the reader sees. Limiting the guard to analyzer.go
	// let the five section headings in the web layer keep addressing the reader
	// informally right above checks that addressed them formally.
	files := []string{"analyzer.go", filepath.Join("..", "web", "server.go")}

	// Only inside double-quoted strings, and only whole words: "du" also occurs
	// inside identifiers and English comments.
	informal := regexp.MustCompile(`"[^"]*\b(du|dir|dein|deine|deiner|deinem|deinen)\b[^"]*"`)

	total := 0
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("cannot read %s: %v", f, err)
		}
		for _, m := range informal.FindAllString(string(src), -1) {
			if len(m) > 120 {
				m = m[:120] + "…"
			}
			t.Errorf("%s: informal address in user-facing text: %s", f, m)
			total++
		}
	}
	if total > 0 {
		t.Errorf("%d string(s) address the reader informally; the report uses \"Sie\" throughout", total)
	}
}

// TestCoreExplanationsAreSelfContained checks that the three explanations every
// reader sees do not lean on jargon they never define. The target reader runs a
// small business and sends a newsletter: clever, but has never heard of a TXT
// record.
func TestCoreExplanationsAreSelfContained(t *testing.T) {
	cases := map[string]struct {
		mustContain []string
		reason      string
	}{
		"SPF":   {[]string{"Sender Policy Framework"}, "the abbreviation is spelled out once"},
		"DKIM":  {[]string{"DomainKeys Identified Mail"}, "the abbreviation is spelled out once"},
		"DMARC": {[]string{"Alignment"}, "alignment is the concept that decides the result"},
	}

	ctx := checkContext{FromDomain: "meine-firma.de"}
	for _, id := range []string{"spf", "dkim", "dmarc"} {
		c := enrichCheckResult(pass(id, id, 0, "ok", ""), ctx)
		want := cases[strings.ToUpper(id)]
		for _, phrase := range want.mustContain {
			if !strings.Contains(c.Explanation, phrase) {
				t.Errorf("%s explanation is missing %q (%s):\n%s", id, phrase, want.reason, c.Explanation)
			}
		}
		if len(c.Explanation) < 200 {
			t.Errorf("%s explanation looks too thin to teach anything: %q", id, c.Explanation)
		}
	}
}

// TestOneClickUnsubscribeNeedsBothHalves covers RFC 8058's two requirements.
// Checking only the Post header let a mailto:-only mailing count as fully
// conformant — while Gmail and Yahoo, the entire reason to implement RFC 8058,
// find nothing they can POST to and treat the sender as if it were missing.
func TestOneClickUnsubscribeNeedsBothHalves(t *testing.T) {
	cases := []struct {
		name       string
		unsub      string
		post       string
		wantStatus string
	}{
		{
			"both halves present",
			"<https://example.org/u/abc>, <mailto:unsub@example.org>",
			"List-Unsubscribe=One-Click",
			"pass",
		},
		{
			"post header but only mailto",
			"<mailto:unsub@example.org>",
			"List-Unsubscribe=One-Click",
			"warn",
		},
		{
			"https but no post header",
			"<https://example.org/u/abc>",
			"",
			"warn",
		},
	}

	for _, tc := range cases {
		h := mail.Header{
			"List-Unsubscribe":      []string{tc.unsub},
			"List-Unsubscribe-Post": []string{tc.post},
			"List-Id":               []string{"<news.example.org>"},
		}
		found := false
		for _, c := range newsletterHeuristics(h, parsedBody{}, "bulk") {
			if c.ID != "one_click_unsub" {
				continue
			}
			found = true
			if c.Status != tc.wantStatus {
				t.Errorf("%s: status = %q, want %q (%q)", tc.name, c.Status, tc.wantStatus, c.Summary)
			}
		}
		if !found {
			t.Errorf("%s: one_click_unsub check did not run", tc.name)
		}
	}
}
