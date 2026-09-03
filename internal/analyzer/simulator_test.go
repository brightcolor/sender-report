package analyzer

import (
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
