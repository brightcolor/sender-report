package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brightcolor/sender-report/internal/config"
	"github.com/brightcolor/sender-report/internal/model"
)

func TestRandomTokenHexLength(t *testing.T) {
	tok, err := randomToken(6)
	if err != nil {
		t.Fatalf("randomToken returned error: %v", err)
	}
	if len(tok) != 12 {
		t.Fatalf("expected hex token length 12, got %d (%q)", len(tok), tok)
	}
}

func TestSortChecksSeverityOrder(t *testing.T) {
	checks := []model.CheckResult{
		{Name: "C", Status: "pass"},
		{Name: "B", Status: "warn"},
		{Name: "D", Status: "info"},
		{Name: "A", Status: "fail"},
	}

	sortChecks(checks)

	wantOrder := []string{"fail", "warn", "pass", "info"}
	for i, want := range wantOrder {
		if checks[i].Status != want {
			t.Fatalf("at %d expected %q, got %q", i, want, checks[i].Status)
		}
	}
}

func TestMessageBodyViewsMultipartAlternative(t *testing.T) {
	raw := strings.Join([]string{
		"From: sender@example.org",
		"To: test@example.test",
		"Subject: Multipart",
		"MIME-Version: 1.0",
		"Content-Type: multipart/alternative; boundary=abc123",
		"",
		"--abc123",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		"Hello plain text world",
		"--abc123",
		"Content-Type: text/html; charset=UTF-8",
		"",
		"<html><body><p>Hello <b>HTML</b> world</p></body></html>",
		"--abc123--",
		"",
	}, "\r\n")

	plain, html := messageBodyViews(raw)
	if !strings.Contains(plain, "Hello plain text world") {
		t.Fatalf("expected plaintext body, got %q", plain)
	}
	if !strings.Contains(html, "<b>HTML</b>") {
		t.Fatalf("expected html body, got %q", html)
	}
}

func TestMessageBodyViewsHTMLOnlyBase64(t *testing.T) {
	raw := strings.Join([]string{
		"From: sender@example.org",
		"To: test@example.test",
		"Subject: HTML",
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=UTF-8",
		"Content-Transfer-Encoding: base64",
		"",
		"PGh0bWw+PGJvZHk+PHA+SGVsbG8gPGI+SFRNTDwvYj48L3A+PC9ib2R5PjwvaHRtbD4=",
	}, "\r\n")

	plain, html := messageBodyViews(raw)
	if !strings.Contains(html, "<b>HTML</b>") {
		t.Fatalf("expected decoded html body, got %q", html)
	}
	if !strings.Contains(plain, "Hello HTML") {
		t.Fatalf("expected stripped plaintext fallback, got %q", plain)
	}
}

func TestMessageBodyViewsDecodesNonUTF8Charset(t *testing.T) {
	raw := strings.Join([]string{
		"From: sender@example.org",
		"To: test@example.test",
		"Subject: Charset",
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=iso-8859-1",
		"Content-Transfer-Encoding: quoted-printable",
		"",
		"<p>Gr=FC=DFe</p>",
	}, "\r\n")

	plain, html := messageBodyViews(raw)
	if !strings.Contains(html, "Grüße") {
		t.Fatalf("expected charset-decoded html, got %q", html)
	}
	if !strings.Contains(plain, "Grüße") {
		t.Fatalf("expected charset-decoded plaintext fallback, got %q", plain)
	}
}

func TestClientIPIgnoresForwardedForWithoutTrustedProxy(t *testing.T) {
	srv := &Server{}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")

	if got := srv.clientIP(req); got != "198.51.100.10" {
		t.Fatalf("expected remote address without trusted proxy, got %q", got)
	}
}

func TestClientIPUsesForwardedForFromTrustedProxy(t *testing.T) {
	trustedProxy, err := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parse trusted proxy cidr: %v", err)
	}
	srv := &Server{trustedProxy: trustedProxy}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.99, 10.1.2.3")

	if got := srv.clientIP(req); got != "203.0.113.99" {
		t.Fatalf("expected forwarded client ip, got %q", got)
	}
}

func TestRequestDerivedPublicURLAndSMTPDomain(t *testing.T) {
	srv := &Server{}
	req := httptest.NewRequest("GET", "http://probe.example.test:8080/", nil)
	req.Host = "probe.example.test:8080"

	if got := srv.publicBaseURL(req); got != "http://probe.example.test:8080" {
		t.Fatalf("expected request-derived public URL, got %q", got)
	}
	if got := srv.requestSMTPDomain(req); got != "probe.example.test" {
		t.Fatalf("expected request-derived smtp domain without port, got %q", got)
	}
}

func TestRequestURLUsesTrustedForwardedHeaders(t *testing.T) {
	trustedProxy, err := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parse trusted proxy cidr: %v", err)
	}
	srv := &Server{trustedProxy: trustedProxy}
	req := httptest.NewRequest("GET", "http://internal:8080/", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "sender-report.example.test")

	if got := srv.publicBaseURL(req); got != "https://sender-report.example.test" {
		t.Fatalf("expected forwarded public URL, got %q", got)
	}
	if got := srv.requestSMTPDomain(req); got != "sender-report.example.test" {
		t.Fatalf("expected forwarded smtp domain, got %q", got)
	}
}

func TestConfiguredPublicURLAndSMTPDomainOverrideRequest(t *testing.T) {
	srv := &Server{cfg: config.Config{PublicBaseURL: "https://configured.example", SMTPDomain: "mx.example"}}
	req := httptest.NewRequest("GET", "http://request.example/", nil)

	if got := srv.publicBaseURL(req); got != "https://configured.example" {
		t.Fatalf("expected configured public URL, got %q", got)
	}
	if got := srv.requestSMTPDomain(req); got != "mx.example" {
		t.Fatalf("expected configured smtp domain, got %q", got)
	}
}

func TestGroupReportChecksCategoryOrdering(t *testing.T) {
	checks := []model.CheckResult{
		{ID: "ptr", Name: "PTR", Status: "pass", Category: "DNS und Infrastruktur"},
		{ID: "spf", Name: "SPF", Status: "fail", Category: "Authentifizierung"},
		{ID: "date", Name: "Date", Status: "info", Category: ""},
		{ID: "mime", Name: "MIME", Status: "warn", Category: "Format und Inhalt"},
	}

	groups := groupReportChecks(checks)

	if len(groups) == 0 {
		t.Fatal("expected at least one check group")
	}
	if groups[0].Name != "Authentifizierung" {
		t.Fatalf("expected Authentifizierung first, got %q", groups[0].Name)
	}
	// Empty category should fall back to "Header und Rohdaten"
	last := groups[len(groups)-1]
	if last.Name != "Header und Rohdaten" {
		t.Fatalf("expected Header und Rohdaten last (fallback for empty category), got %q", last.Name)
	}
}

func TestGroupLinksByDomainCombinesAndSorts(t *testing.T) {
	links := []string{
		"https://example.org/a",
		"https://example.org/b",
		"https://www.other.com/x",
		"https://other.com/y",
		"not-a-url",
	}

	groups := groupLinksByDomain(links)

	if len(groups) == 0 {
		t.Fatal("expected link groups")
	}
	// www.other.com and other.com should both map to "other.com"
	var otherGroup *ReportLinkGroup
	for i := range groups {
		if groups[i].Domain == "other.com" {
			otherGroup = &groups[i]
		}
	}
	if otherGroup == nil {
		t.Fatal("expected other.com group (www. stripped)")
	}
	if otherGroup.Count != 2 {
		t.Fatalf("expected 2 links for other.com, got %d", otherGroup.Count)
	}
}

func TestReportHeroTitleThresholds(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{9.5, "Wow"},
		{7.5, "Solide"},
		{5.5, "braucht"},
		{3.0, "Hohes"},
	}
	for _, tc := range cases {
		got := reportHeroTitle(tc.score)
		if !strings.Contains(got, tc.want) {
			t.Errorf("score %.1f: title %q should contain %q", tc.score, got, tc.want)
		}
	}
}

func TestReportHeroSubtitleThresholds(t *testing.T) {
	if reportHeroSubtitle(9.5) == "" {
		t.Fatal("expected non-empty subtitle for score 9.5")
	}
	if reportHeroSubtitle(0.0) == "" {
		t.Fatal("expected non-empty subtitle for score 0.0")
	}
}

func TestScorePercentBounds(t *testing.T) {
	if got := scorePercent(-5); got != 0 {
		t.Fatalf("expected 0 for negative score, got %v", got)
	}
	if got := scorePercent(10); got != 100 {
		t.Fatalf("expected 100 for score 10, got %v", got)
	}
	if got := scorePercent(15); got != 100 {
		t.Fatalf("expected 100 for score >10, got %v", got)
	}
	if got := scorePercent(5); got != 50 {
		t.Fatalf("expected 50 for score 5, got %v", got)
	}
}

func TestDetailsTextFormatting(t *testing.T) {
	details := map[string]string{
		"b_key": "value2",
		"a_key": "value1",
		"empty": "",
	}
	got := detailsText(details)
	if !strings.Contains(got, "a_key: value1") {
		t.Errorf("expected a_key line, got %q", got)
	}
	if !strings.Contains(got, "b_key: value2") {
		t.Errorf("expected b_key line, got %q", got)
	}
	if strings.Contains(got, "empty") {
		t.Errorf("empty value should be omitted, got %q", got)
	}
	// keys should be sorted
	posA := strings.Index(got, "a_key")
	posB := strings.Index(got, "b_key")
	if posA > posB {
		t.Errorf("expected a_key before b_key (sorted), got %q", got)
	}
}

func TestSafeIDOutputIsURLSafe(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Authentifizierung", "authentifizierung"},
		{"DNS und Infrastruktur", "dns-und-infrastruktur"},
		{"---", "item"},
	}
	for _, tc := range cases {
		if got := safeID(tc.in); got != tc.want {
			t.Errorf("safeID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestForceHTTPSRedirect(t *testing.T) {
	srv := &Server{cfg: config.Config{ForceHTTPS: true}}
	handler := srv.withHTTPSRedirect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "http://probe.example.test/report/abc", nil)
	req.Host = "probe.example.test"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusPermanentRedirect {
		t.Fatalf("expected 308 redirect, got %d", rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "https://probe.example.test/report/abc" {
		t.Fatalf("unexpected redirect location %q", got)
	}
}
