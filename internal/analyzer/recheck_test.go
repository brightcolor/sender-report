package analyzer

import (
	"strings"
	"testing"
)

// TestRecheckKeepsPenaltyThroughEnrichment is the guard that matters, because
// the bug it protects against is invisible in the recheck function alone.
//
// enrichCheckResult re-derives ScoreDelta from (importance × status) for almost
// every check, and "info" scores 0. A recheck that reported the SPF record as
// present therefore cleared the -2.6 penalty even though nothing had verified
// that the sending IP is authorised — and the same for DMARC alignment, 5.2
// points for one click. Remove the recheckPendingDetailKey case from that switch
// and this test turns red; testing recheckUnconfirmed on its own would not.
func TestRecheckKeepsPenaltyThroughEnrichment(t *testing.T) {
	in := RecheckInput{FromDomain: "example.org", PrevStatus: "fail", PrevDelta: -2.6}

	for _, id := range []string{"spf", "dmarc"} {
		c := recheckUnconfirmed(id, "Test", in, "Record vorhanden.")
		enriched := enrichCheckResult(c, checkContext{FromDomain: "example.org"})

		if enriched.ScoreDelta != -2.6 {
			t.Errorf("%s: ScoreDelta = %v after enrichment, want -2.6 — the original penalty was cleared by a recheck that verified nothing",
				id, enriched.ScoreDelta)
		}
		if enriched.Status == "pass" {
			t.Errorf("%s: status = pass — a DNS lookup cannot establish that the check passes", id)
		}
	}
}

// TestRecheckNeverReportsPass pins the rule at the level of the score gate:
// essentialsAllPass only looks at the status, so a "pass" from a recheck also
// lifted the 9.5 cap for essential checks.
func TestRecheckNeverReportsPass(t *testing.T) {
	in := RecheckInput{PrevStatus: "fail", PrevDelta: -2.6}
	c := recheckUnconfirmed("spf", "SPF", in, "Record vorhanden.")

	if c.Status == "pass" {
		t.Fatal("recheck result must not be pass")
	}
	if !strings.Contains(c.Suggestion, "Testmail") {
		t.Errorf("the result must tell the reader how to get it confirmed, got: %q", c.Suggestion)
	}
}

// TestPendingDeltaFallback covers the case where the client does not send the
// previous finding (older report pages). Falling back to zero would reopen the
// exact loophole for every client that has not reloaded.
func TestPendingDeltaFallback(t *testing.T) {
	cases := []struct {
		name string
		in   RecheckInput
		id   string
		want float64
	}{
		{"previous fail is carried over", RecheckInput{PrevStatus: "fail", PrevDelta: -2.6}, "spf", -2.6},
		{"previous warn is carried over", RecheckInput{PrevStatus: "warn", PrevDelta: -1.3}, "spf", -1.3},
		{"previously clean stays clean", RecheckInput{PrevStatus: "pass", PrevDelta: 0}, "spf", 0},
		{"unknown previous state is not treated as clean", RecheckInput{}, "spf", -1.3},
		{"unknown previous state, dmarc", RecheckInput{}, "dmarc", -1.3},
	}

	for _, tc := range cases {
		if got := tc.in.pendingDelta(tc.id); got != tc.want {
			t.Errorf("%s: pendingDelta(%q) = %v, want %v", tc.name, tc.id, got, tc.want)
		}
	}
}

// TestSPFRecheckMissingRecordKeepsWeight covers the mirror case: reporting a
// still-missing SPF record as "info" handed back 1.3 points to a domain that had
// no SPF record at all.
func TestSPFRecheckMissingRecordKeepsWeight(t *testing.T) {
	c := warn("spf", "SPF", 0, "Kein SPF-Record (v=spf1) für example.org gefunden.", "")
	enriched := enrichCheckResult(c, checkContext{EnvelopeDomain: "example.org"})

	if enriched.ScoreDelta >= 0 {
		t.Errorf("a missing SPF record must keep a penalty, got ScoreDelta %v", enriched.ScoreDelta)
	}
	if enriched.Status == "info" {
		t.Error("a missing record is a finding, not a notice")
	}
}
