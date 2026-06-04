package analyzer

import (
	"context"
	"encoding/json"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/brightcolor/sender-report/internal/model"
)

func TestParseAuthResult(t *testing.T) {
	input := "mx.example; spf=pass smtp.mailfrom=example.org; dkim=fail header.d=example.org; dmarc=pass"

	if got := parseAuthResult(input, "spf"); got != "pass" {
		t.Fatalf("spf expected pass, got %q", got)
	}
	if got := parseAuthResult(input, "dkim"); got != "fail" {
		t.Fatalf("dkim expected fail, got %q", got)
	}
	if got := parseAuthResult(input, "dmarc"); got != "pass" {
		t.Fatalf("dmarc expected pass, got %q", got)
	}
	if got := parseAuthResult(input, "arc"); got != "" {
		t.Fatalf("arc expected empty, got %q", got)
	}
}

func TestHeaderValues(t *testing.T) {
	h := mail.Header{}
	h["Received"] = []string{"hop1", "hop2"}

	vals := headerValues(h, "Received")
	if len(vals) != 2 {
		t.Fatalf("expected 2 values, got %d", len(vals))
	}
	if vals[0] != "hop1" || vals[1] != "hop2" {
		t.Fatalf("unexpected values: %#v", vals)
	}

	vals[0] = "mutated"
	orig := h["Received"][0]
	if orig != "hop1" {
		t.Fatalf("headerValues should return copy, original mutated: %q", orig)
	}
}

func TestNewsletterHeuristicsListUnsubscribe(t *testing.T) {
	headers := mail.Header{}
	headers["Precedence"] = []string{"bulk"}
	body := parsedBody{AllText: "hello subscribers"}

	checks := newsletterHeuristics(headers, body)
	if len(checks) == 0 {
		t.Fatal("expected newsletter checks")
	}
	if checks[0].ID != "list_unsub" || checks[0].Status != "warn" {
		t.Fatalf("expected list_unsub warn, got id=%s status=%s", checks[0].ID, checks[0].Status)
	}

	headers["List-Unsubscribe"] = []string{"<mailto:unsubscribe@example.org>"}
	checks = newsletterHeuristics(headers, body)
	if len(checks) == 0 {
		t.Fatal("expected newsletter checks with list-unsubscribe")
	}
	if checks[0].ID != "list_unsub" || checks[0].Status != "pass" {
		t.Fatalf("expected list_unsub pass, got id=%s status=%s", checks[0].ID, checks[0].Status)
	}
}

func TestTopRspamdSymbols(t *testing.T) {
	raw := map[string]json.RawMessage{
		"R_DKIM_REJECT": json.RawMessage(`{"score": 4.2, "description":"DKIM validation failed"}`),
		"R_SPF_FAIL":    json.RawMessage(`{"score": 3.1, "description":"SPF failed"}`),
		"NEUTRAL":       json.RawMessage(`{"score": 0.0, "description":"neutral"}`),
	}

	top := topRspamdSymbols(raw, 2)
	if len(top) != 2 {
		t.Fatalf("expected 2 top symbols, got %d", len(top))
	}
	if top[0].Name != "R_DKIM_REJECT" || top[1].Name != "R_SPF_FAIL" {
		t.Fatalf("unexpected order: %#v", top)
	}
}

func TestRspamdSuggestionFor(t *testing.T) {
	symbols := []rspamdSymbol{
		{Name: "R_DKIM_REJECT", Score: 4.1},
		{Name: "R_SPF_FAIL", Score: 2.9},
		{Name: "URL_PHISHING", Score: 2.4},
	}

	s := rspamdSuggestionFor(symbols, "reject")
	if s == "" {
		t.Fatal("expected non-empty suggestion")
	}
	if !(strings.Contains(s, "DKIM") || strings.Contains(s, "SPF") || strings.Contains(strings.ToLower(s), "links")) {
		t.Fatalf("expected practical recommendation, got: %q", s)
	}
}

func TestAnalyzeAddsStructuredCheckDetails(t *testing.T) {
	raw := strings.Join([]string{
		"From: Sender <sender@example.org>",
		"To: test@example.test",
		"Subject: Test",
		"Message-ID: <abc@example.org>",
		"Date: Tue, 23 Apr 2024 12:00:00 +0000",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		"Hello world",
	}, "\r\n")
	engine := New(Options{})
	report := engine.Analyze(context.Background(), Input{
		Message: model.Message{
			ID:         1,
			SMTPFrom:   "bounce@example.org",
			RCPTTo:     "token@example.test",
			RemoteIP:   "203.0.113.10",
			HELO:       "mail.example.org",
			RawSource:  raw,
			SizeBytes:  int64(len(raw)),
			ReceivedAt: mailDate(t, "Tue, 23 Apr 2024 12:00:00 +0000"),
		},
		SMTPDomain: "example.test",
	})

	if len(report.Checks) == 0 {
		t.Fatal("expected checks")
	}
	var spf *model.CheckResult
	for i := range report.Checks {
		if report.Checks[i].ID == "spf" {
			spf = &report.Checks[i]
			break
		}
	}
	if spf == nil {
		t.Fatal("expected SPF check")
	}
	if spf.TechnicalDetails["remote_ip"] != "203.0.113.10" {
		t.Fatalf("expected remote_ip detail, got %#v", spf.TechnicalDetails)
	}
	if spf.Explanation == "" || spf.Recommendation == "" || spf.Category == "" || spf.Severity == "" {
		t.Fatalf("expected structured detail fields, got %+v", *spf)
	}

	var subject *model.CheckResult
	for i := range report.Checks {
		if report.Checks[i].ID == "subject" {
			subject = &report.Checks[i]
			break
		}
	}
	if subject == nil {
		t.Fatal("expected subject check")
	}
	if _, ok := subject.TechnicalDetails["remote_ip"]; ok {
		t.Fatalf("subject check should not contain generic remote_ip detail: %#v", subject.TechnicalDetails)
	}
	if subject.TechnicalDetails["subject"] != "Test" {
		t.Fatalf("expected only subject-specific details, got %#v", subject.TechnicalDetails)
	}
}

func TestRBLProviderMetaIncludesConcreteDelisting(t *testing.T) {
	cases := []struct {
		provider string
		wantURL  string
		wantText string
	}{
		{"zen.spamhaus.org", "https://check.spamhaus.org/", "ISP"},
		{"bl.spamcop.net", "https://www.spamcop.net/bl.shtml", "automatisch"},
		{"b.barracudacentral.org", "https://www.barracudacentral.org/rbl/removal-request", "Removal Request"},
		{"psbl.surriel.com", "https://www.psbl.org/remove", "self-service"},
		{"dnsbl.dronebl.org", "https://www.dronebl.org/lookup", "Lookup"},
		{"bl.blocklist.de", "https://www.blocklist.de/en/delist.html?ip=203.0.113.10", "Delist-Seite"},
	}
	for _, tc := range cases {
		meta := rblProviderMeta(tc.provider, "203.0.113.10")
		if meta.DelistURL != tc.wantURL {
			t.Fatalf("%s delist url mismatch: got %q want %q", tc.provider, meta.DelistURL, tc.wantURL)
		}
		if !strings.Contains(meta.Delisting, tc.wantText) {
			t.Fatalf("%s delisting text should contain %q, got %q", tc.provider, tc.wantText, meta.Delisting)
		}
	}
}

func TestAnalyzeExtractsHTMLHrefLinks(t *testing.T) {
	raw := strings.Join([]string{
		"From: Sender <sender@example.org>",
		"To: test@example.test",
		"Subject: HTML link",
		"Message-ID: <html-link@example.org>",
		"Date: Tue, 23 Apr 2024 12:00:00 +0000",
		"Content-Type: text/html; charset=UTF-8",
		"",
		`<html><body><a href="https://example.org/path?utm_source=test">Open</a></body></html>`,
	}, "\r\n")
	engine := New(Options{})
	report := engine.Analyze(context.Background(), Input{
		Message: model.Message{
			ID:         2,
			SMTPFrom:   "bounce@example.org",
			RCPTTo:     "token@example.test",
			RemoteIP:   "203.0.113.10",
			HELO:       "mail.example.org",
			RawSource:  raw,
			SizeBytes:  int64(len(raw)),
			ReceivedAt: mailDate(t, "Tue, 23 Apr 2024 12:00:00 +0000"),
		},
		SMTPDomain: "example.test",
	})

	if len(report.Links) != 1 || report.Links[0] != "https://example.org/path?utm_source=test" {
		t.Fatalf("expected href link extraction, got %#v", report.Links)
	}
}

func mailDate(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := mail.ParseDate(value)
	if err != nil {
		t.Fatalf("parse date: %v", err)
	}
	return parsed
}

func TestRunChecksConcurrentlyOrderAndPanicIsolation(t *testing.T) {
	tasks := []checkTask{
		{"a", func(context.Context) []model.CheckResult { return one(pass("a", "A", 0, "ok", "")) }},
		{"boom", func(context.Context) []model.CheckResult { panic("kaboom") }},
		{"b", func(context.Context) []model.CheckResult { return one(pass("b", "B", 0, "ok", "")) }},
	}
	got := runChecksConcurrently(context.Background(), tasks, 4)
	if len(got) != 3 {
		t.Fatalf("expected 3 results, got %d", len(got))
	}
	// Deterministic task order preserved despite concurrency.
	if got[0].ID != "a" || got[1].ID != "boom" || got[2].ID != "b" {
		t.Fatalf("unexpected order: %s, %s, %s", got[0].ID, got[1].ID, got[2].ID)
	}
	// The panicking task degrades to a non-penalising info check.
	if got[1].Status != "info" || got[1].ScoreDelta != 0 {
		t.Fatalf("panicked task should be info/0, got %s/%v", got[1].Status, got[1].ScoreDelta)
	}
}

func TestCheckImportanceLevels(t *testing.T) {
	cases := map[string]string{
		"spf":            "Kritisch",
		"dkim":           "Kritisch",
		"rbl":            "Kritisch",
		"dkim_keylength": "Wichtig",
		"mx_records":     "Wichtig",
		"dnssec":         "Optional",
		"bimi":           "Optional",
		"date_skew":      "Empfohlen", // falls through to default
	}
	for id, want := range cases {
		if got := checkImportance(id); got != want {
			t.Errorf("checkImportance(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"mail.example.com":  "example.com",
		"a.b.example.co.uk": "example.co.uk",
		"example.org":       "example.org",
		"":                  "",
	}
	for in, want := range cases {
		if got := registrableDomain(in); got != want {
			t.Errorf("registrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAnalyzeNoPanicOnGarbageInput(t *testing.T) {
	engine := New(Options{}) // no network checks enabled
	// Already-cancelled context → the internal timeout context is immediately done,
	// so DNS-dependent checks return fast and the test stays quick + deterministic.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, raw := range []string{"", "not a real email", "From: \x00\x01 broken", "Subject: x\r\n\r\nbody"} {
		report := engine.Analyze(ctx, Input{Message: model.Message{RawSource: raw}})
		if len(report.Checks) == 0 {
			t.Fatalf("expected some checks even for garbage input %q", raw)
		}
		if report.Score < 0 || report.Score > 10 {
			t.Fatalf("score out of range for %q: %v", raw, report.Score)
		}
	}
}
