package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

	wantOrder := []string{"fail", "warn", "info", "pass"}
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

	groups := groupReportChecks(checks, "de")

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
		got := reportHeroTitle(tc.score, "de")
		if !strings.Contains(got, tc.want) {
			t.Errorf("score %.1f: title %q should contain %q", tc.score, got, tc.want)
		}
	}
}

func TestReportHeroSubtitleThresholds(t *testing.T) {
	if reportHeroSubtitle(9.5, "de") == "" {
		t.Fatal("expected non-empty subtitle for score 9.5")
	}
	if reportHeroSubtitle(0.0, "de") == "" {
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

// TestReportRendersInTheSelectedLanguage covers the point of storing an English
// variant of every check alongside the German one: nothing read them, so the
// server-rendered report was German whatever the visitor selected. Only the
// client-side decrypted path ever used them.
func TestReportRendersInTheSelectedLanguage(t *testing.T) {
	c := model.CheckResult{
		Name: "SPF für example.org", NameEN: "SPF for example.org",
		Summary: "SPF bestanden.", SummaryEN: "SPF passed.",
		Explanation: "Deutsche Erklärung.", ExplanationEN: "English explanation.",
		Recommendation: "Deutsche Empfehlung.", RecommendationEN: "English advice.",
	}

	if got := pickLang("en", c.Explanation, c.ExplanationEN); got != "English explanation." {
		t.Errorf("English report showed %q", got)
	}
	if got := pickLang("de", c.Explanation, c.ExplanationEN); got != "Deutsche Erklärung." {
		t.Errorf("German report showed %q", got)
	}

	t.Run("stored reports without an English variant keep the German text", func(t *testing.T) {
		// Everything analysed before the EN fields existed has them empty.
		// An empty explanation would be worse than a German one.
		if got := pickLang("en", "Nur deutsch vorhanden.", ""); got != "Nur deutsch vorhanden." {
			t.Errorf("legacy report lost its text: %q", got)
		}
		if got := pickLang("en", "Nur deutsch.", "   "); got != "Nur deutsch." {
			t.Errorf("whitespace-only English variant must not win: %q", got)
		}
	})
}

// TestGroupHeadingsFollowTheLanguage pins the five section headings, which were
// hard-coded German in the server while the checks underneath them translated.
func TestGroupHeadingsFollowTheLanguage(t *testing.T) {
	checks := []model.CheckResult{
		{ID: "spf", Name: "SPF", Status: "fail", Category: "Authentifizierung"},
	}

	de := groupReportChecks(checks, "de")
	en := groupReportChecks(checks, "en")

	if len(de) == 0 || len(en) == 0 {
		t.Fatal("expected a group in both languages")
	}
	if de[0].Name != "Authentifizierung" {
		t.Errorf("German heading = %q", de[0].Name)
	}
	if en[0].Name != "Authentication" {
		t.Errorf("English heading = %q, want Authentication", en[0].Name)
	}
	if de[0].Hint == en[0].Hint {
		t.Error("the section hint is identical in both languages — it was not translated")
	}
	if strings.Contains(en[0].Hint, "Ihre") || strings.Contains(en[0].Hint, "Nachricht") {
		t.Errorf("English hint still contains German: %q", en[0].Hint)
	}
}

// TestTechLabelsFollowTheLanguage covers the raw-data table, which was German
// only: the English report showed English check names and explanations above a
// table captioned "Sendende IP" and "Schlüssellänge (Bit)".
func TestTechLabelsFollowTheLanguage(t *testing.T) {
	cases := []struct{ key, de, en string }{
		{"remote_ip", "Sendende IP", "Sending IP"},
		{"key_bits", "Schlüssellänge (Bit)", "Key length (bits)"},
		{"checked_providers", "Geprüfte Listen", "Lists checked"},
		{"image_text_ratio", "Bild/Text-Verhältnis", "Image-to-text ratio"},
	}
	for _, tc := range cases {
		if got := techLabel("de", tc.key); got != tc.de {
			t.Errorf("techLabel(de, %q) = %q, want %q", tc.key, got, tc.de)
		}
		if got := techLabel("en", tc.key); got != tc.en {
			t.Errorf("techLabel(en, %q) = %q, want %q", tc.key, got, tc.en)
		}
	}

	t.Run("protocol names stay identical in both languages", func(t *testing.T) {
		for _, k := range []string{"helo", "return_path", "list_id", "message_id"} {
			if techLabel("de", k) != techLabel("en", k) {
				t.Errorf("%q differs between languages although it is a protocol name", k)
			}
		}
	})

	t.Run("unknown keys still get a readable caption", func(t *testing.T) {
		if got := techLabel("en", "some_new_key"); got != "Some new key" {
			t.Errorf("fallback = %q", got)
		}
	})

	t.Run("the client-side table carries the same language", func(t *testing.T) {
		en, err := techLabelsJSON("en")
		if err != nil {
			t.Fatalf("techLabelsJSON: %v", err)
		}
		if !strings.Contains(string(en), "Sending IP") {
			t.Error("English table is missing its English captions")
		}
		if strings.Contains(string(en), "Sendende IP") {
			t.Error("English table still carries the German caption")
		}
		de, _ := techLabelsJSON("de")
		if !strings.Contains(string(de), "Sendende IP") {
			t.Error("German table lost its captions")
		}
	})
}

// TestThemeMenuRendersConfiguredDefault renders a page with a UI_DEFAULT_THEME
// other than the default: the server hands the value to the pre-paint script
// through <html data-default-theme>, and the navbar menu offers all display
// options in the page language.
func TestThemeMenuRendersConfiguredDefault(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	cases := []struct {
		theme, lang string
		labels      []string
	}{
		{"werkbank", "de", []string{"System", "Hell", "Dunkel", "Werkbank"}},
		{"dark", "en", []string{"System", "Light", "Dark", "Workbench"}},
	}
	for _, tc := range cases {
		t.Run(tc.theme+"/"+tc.lang, func(t *testing.T) {
			srv := newPageTestServer(t, tc.theme)
			body := renderPage(t, srv.aboutPage, "/about", tc.lang)
			if !strings.Contains(body, `data-default-theme="`+tc.theme+`"`) {
				t.Errorf("page does not carry the configured default %q", tc.theme)
			}
			for _, choice := range config.UIThemes {
				if !strings.Contains(body, `data-theme-choice="`+choice+`"`) {
					t.Errorf("menu lacks the option %q", choice)
				}
			}
			for _, label := range tc.labels {
				if !strings.Contains(body, ">"+label+"</button>") {
					t.Errorf("menu lacks the %s label %q", tc.lang, label)
				}
			}
			if strings.Index(body, "/static/werkbank.css") < strings.Index(body, "/static/app.css") {
				t.Error("werkbank.css must load after app.css, otherwise app.css wins")
			}
		})
	}
}

// TestStaticPagesRenderCompletely renders the pages that need no mailbox. The
// about page stopped halfway with "template error" from v1.22.0 on, because
// its data lacked a field the template asks for; the status stayed 200, so
// only the cut-off body showed it.
func TestStaticPagesRenderCompletely(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	srv := newPageTestServer(t, "auto")
	pages := []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/about", srv.aboutPage},
		{"/privacy", srv.privacyPage},
	}
	for _, p := range pages {
		for _, lang := range []string{"de", "en"} {
			renderPage(t, p.handler, p.path, lang)
		}
	}
}

// newPageTestServer builds a server without a store; enough for the pages
// that render from configuration alone. The caller must run from the repo
// root, where New finds the templates.
func newPageTestServer(t *testing.T, theme string) *Server {
	t.Helper()
	srv, err := New(config.Config{UIDefaultTheme: theme, WebRateLimitPerMin: 60, WebBurstPer10Sec: 20}, nil, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// renderPage calls a page handler and fails unless the page rendered to the
// end: a template error after the first byte still answers 200.
func renderPage(t *testing.T, handler http.HandlerFunc, path, lang string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Accept-Language", lang)
	rec := httptest.NewRecorder()
	handler(rec, req)
	body := strings.TrimSpace(rec.Body.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("%s (%s) answered %d", path, lang, rec.Code)
	}
	if strings.Contains(body, "template error") || !strings.HasSuffix(body, "</html>") {
		tail := body
		if len(tail) > 120 {
			tail = tail[len(tail)-120:]
		}
		t.Fatalf("%s (%s) did not render completely, it ends with %q", path, lang, tail)
	}
	return body
}

// TestEveryPageOffersTheDisplayOptions keeps every page on the shared theme
// partials: operator default, pre-paint script, stylesheet and navbar menu.
// A page without them would ignore the visitor's choice.
func TestEveryPageOffersTheDisplayOptions(t *testing.T) {
	want := []string{"about.html", "home.html", "mailbox.html", "privacy.html", "report.html", "simulate.html"}
	pages, err := filepath.Glob(filepath.Join("templates", "*.html"))
	if err != nil {
		t.Fatalf("glob templates: %v", err)
	}
	seen := map[string]bool{}
	for _, page := range pages {
		name := filepath.Base(page)
		if name == "_partials.html" {
			continue
		}
		seen[name] = true
		raw, err := os.ReadFile(page)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(raw)
		for _, part := range []string{
			`data-default-theme="{{defaultTheme}}"`,
			`{{template "theme-boot" .}}`,
			`{{template "theme-menu" .}}`,
			`/static/werkbank.css?v={{appVersion}}`,
		} {
			if !strings.Contains(src, part) {
				t.Errorf("%s lacks %s", name, part)
			}
		}
		if strings.Index(src, "/static/werkbank.css") < strings.Index(src, "/static/app.css") {
			t.Errorf("%s loads werkbank.css before app.css", name)
		}
	}
	for _, name := range want {
		if !seen[name] {
			t.Errorf("expected page %s among the templates", name)
		}
	}
}
