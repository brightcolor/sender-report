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

func TestClassifyDKIMFailure(t *testing.T) {
	cases := []struct {
		name        string
		result      string
		detail      string
		wantStatus  string
		wantMsgSub  string // substring the German summary must contain
		wantMsgENub string // substring the English summary must contain
		wantSuggest string // substring the German suggestion must contain
	}{
		{
			name:        "rsa-sha1 deprecated is a warning, not a fail",
			result:      "permerror",
			detail:      "example.com=dkim: hash algorithm too weak: sha1",
			wantStatus:  "warn",
			wantMsgSub:  "rsa-sha1",
			wantMsgENub: "rsa-sha1",
			wantSuggest: "rsa-sha256",
		},
		{
			name:       "insecure body length tag is a warning",
			result:     "fail",
			detail:     "example.com=dkim: message contains an insecure body length tag",
			wantStatus: "warn",
			wantMsgSub: "l=-Tag",
		},
		{
			name:       "body hash mismatch stays a hard fail",
			result:     "fail",
			detail:     "example.com=dkim: body hash did not verify",
			wantStatus: "fail",
			wantMsgSub: "nach dem Signieren verändert",
		},
		{
			name:       "key too short stays a hard fail",
			result:     "permerror",
			detail:     "example.com=dkim: key is too short: want 1024 bits, has 768 bits",
			wantStatus: "fail",
			wantMsgSub: "zu kurz",
		},
		{
			name:       "unknown reason still surfaces raw detail",
			result:     "fail",
			detail:     "example.com=dkim: something entirely new",
			wantStatus: "fail",
			wantMsgSub: "something entirely new",
		},
		{
			name:       "no detail falls back to generic",
			result:     "permerror",
			detail:     "",
			wantStatus: "fail",
			wantMsgSub: "DKIM meldet permerror",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := classifyDKIMFailure(tc.result, tc.detail)
			if f.status != tc.wantStatus {
				t.Fatalf("status: got %q, want %q", f.status, tc.wantStatus)
			}
			if !strings.Contains(f.summaryDE, tc.wantMsgSub) {
				t.Fatalf("summaryDE %q does not contain %q", f.summaryDE, tc.wantMsgSub)
			}
			if tc.wantMsgENub != "" && !strings.Contains(f.summaryEN, tc.wantMsgENub) {
				t.Fatalf("summaryEN %q does not contain %q", f.summaryEN, tc.wantMsgENub)
			}
			if tc.wantSuggest != "" && !strings.Contains(f.suggestDE, tc.wantSuggest) {
				t.Fatalf("suggestDE %q does not contain %q", f.suggestDE, tc.wantSuggest)
			}
		})
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

	checks := newsletterHeuristics(headers, body, "bulk")
	if len(checks) == 0 {
		t.Fatal("expected newsletter checks")
	}
	if checks[0].ID != "list_unsub" || checks[0].Status != "warn" {
		t.Fatalf("expected list_unsub warn, got id=%s status=%s", checks[0].ID, checks[0].Status)
	}

	headers["List-Unsubscribe"] = []string{"<mailto:unsubscribe@example.org>"}
	checks = newsletterHeuristics(headers, body, "bulk")
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

func TestScoreForWeighting(t *testing.T) {
	// Passes/infos never change the score (no inflation).
	for _, imp := range []string{"Kritisch", "Wichtig", "Empfohlen", "Optional"} {
		if got := scoreFor(imp, "pass"); got != 0 {
			t.Errorf("pass/%s should be 0, got %v", imp, got)
		}
		if got := scoreFor(imp, "info"); got != 0 {
			t.Errorf("info/%s should be 0, got %v", imp, got)
		}
	}
	// A critical failure must hurt far more than a recommended/cosmetic one.
	if scoreFor("Kritisch", "fail") >= scoreFor("Wichtig", "fail") {
		t.Fatal("critical fail should be more negative than important fail")
	}
	if scoreFor("Wichtig", "fail") >= scoreFor("Empfohlen", "fail") {
		t.Fatal("important fail should be more negative than recommended fail")
	}
	// Optional checks never penalise.
	if scoreFor("Optional", "fail") != 0 || scoreFor("Optional", "warn") != 0 {
		t.Fatal("optional checks must never penalise the score")
	}
	// One critical failure should outweigh several cosmetic warnings.
	crit := scoreFor("Kritisch", "fail")
	cosmetic := 4 * scoreFor("Empfohlen", "warn")
	if crit >= cosmetic {
		t.Fatalf("one critical fail (%v) should outweigh 4 cosmetic warns (%v)", crit, cosmetic)
	}
}

func TestEssentialsAllPassGate(t *testing.T) {
	pass := []model.CheckResult{
		{ID: "spf", Status: "pass"}, {ID: "dkim", Status: "pass"},
		{ID: "dmarc", Status: "pass"}, {ID: "ptr", Status: "pass"},
	}
	if !essentialsAllPass(pass) {
		t.Fatal("all essentials pass should return true")
	}
	// An unconfirmed/neutral essential (info) must block the perfect score.
	infoSPF := append([]model.CheckResult{{ID: "spf", Status: "info"}}, pass[1:]...)
	if essentialsAllPass(infoSPF) {
		t.Fatal("an essential that is only 'info' must not count as all-pass")
	}
	failPTR := append([]model.CheckResult{}, pass...)
	failPTR[3] = model.CheckResult{ID: "ptr", Status: "warn"}
	if essentialsAllPass(failPTR) {
		t.Fatal("a warning on an essential must not count as all-pass")
	}
}

func TestComputeScore(t *testing.T) {
	// All essentials pass, no deductions → perfect 10 / Excellent.
	clean := []model.CheckResult{
		{ID: "spf", Status: "pass"}, {ID: "dkim", Status: "pass"},
		{ID: "dmarc", Status: "pass"}, {ID: "ptr", Status: "pass"},
	}
	if s, l := ComputeScore(clean); s != 10 || l != "Excellent" {
		t.Fatalf("clean → got %v/%q, want 10/Excellent", s, l)
	}
	// An essential only "info" caps the score below 10 even with no deductions.
	capped := append([]model.CheckResult{{ID: "spf", Status: "info"}}, clean[1:]...)
	if s, _ := ComputeScore(capped); s != 9.5 {
		t.Fatalf("unconfirmed essential → got %v, want 9.5", s)
	}
	// Heavy deductions clamp at 0.
	bad := []model.CheckResult{
		{ID: "spf", Status: "fail", ScoreDelta: -2.6}, {ID: "dkim", Status: "fail", ScoreDelta: -2.6},
		{ID: "dmarc", Status: "fail", ScoreDelta: -2.6}, {ID: "ptr", Status: "fail", ScoreDelta: -2.6},
	}
	if s, l := ComputeScore(bad); s != 0 || l != "High Risk" {
		t.Fatalf("bad → got %v/%q, want 0/High Risk", s, l)
	}
}
