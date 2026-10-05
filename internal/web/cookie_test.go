package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/brightcolor/sender-report/internal/config"
)

// cookieTestConfig uses cookie settings other than the defaults (sr_lang,
// sr_mailbox, 365 days).
func cookieTestConfig(mode string) config.Config {
	return config.Config{
		CookieSecure:      mode,
		LangCookieName:    "ui_language",
		LangCookieDays:    30,
		MailboxCookieName: "box_token",
	}
}

func TestSecureCookiesFollowsTheSetting(t *testing.T) {
	proxy, err := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parse trusted proxy cidr: %v", err)
	}
	plain := func() *http.Request { return httptest.NewRequest(http.MethodPost, "http://sender.example/lang", nil) }
	viaTLSProxy := func() *http.Request {
		r := plain()
		r.RemoteAddr = "10.1.2.3:4567"
		r.Header.Set("X-Forwarded-Proto", "https")
		return r
	}
	cases := []struct {
		name, mode, publicURL string
		req                   func() *http.Request
		want                  bool
	}{
		{"auto, plain HTTP", "auto", "", plain, false},
		{"auto, HTTPS through a trusted proxy", "auto", "", viaTLSProxy, true},
		{"auto, public URL with https", "auto", "https://sender.example", plain, true},
		{"auto, public URL with http", "auto", "http://sender.example", plain, false},
		{"always", "always", "", plain, true},
		{"never, HTTPS through a trusted proxy", "never", "https://sender.example", viaTLSProxy, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cookieTestConfig(tc.mode)
			cfg.PublicBaseURL = tc.publicURL
			srv := &Server{cfg: cfg, trustedProxy: proxy}
			if got := srv.secureCookies(tc.req()); got != tc.want {
				t.Fatalf("secureCookies = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSetLangStoresTheChoiceInTheConfiguredCookie(t *testing.T) {
	srv := &Server{cfg: cookieTestConfig("always")}
	req := httptest.NewRequest(http.MethodPost, "/lang", strings.NewReader("l=de"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://sender.example/about?x=1")
	rr := httptest.NewRecorder()

	srv.setLang(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "/about?x=1" {
		t.Errorf("Location = %q, want /about?x=1", got)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != "ui_language" || c.Value != "de" {
		t.Errorf("cookie = %s=%s, want ui_language=de", c.Name, c.Value)
	}
	if c.MaxAge != 30*24*60*60 {
		t.Errorf("MaxAge = %d, want 30 days", c.MaxAge)
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Errorf("attributes HttpOnly=%v Secure=%v SameSite=%v Path=%q, want HttpOnly, Secure, Lax, /", c.HttpOnly, c.Secure, c.SameSite, c.Path)
	}
}

func TestSetLangAnswersOtherMethodsWithTheWayForward(t *testing.T) {
	srv := &Server{cfg: cookieTestConfig("auto")}
	for _, tc := range []struct{ lang, want string }{
		{"de", "Umschalter oben auf der Seite"},
		{"en", "switcher at the top of the page"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/lang", nil)
		req.Header.Set("Accept-Language", tc.lang)
		rr := httptest.NewRecorder()
		srv.setLang(rr, req)
		if rr.Code != http.StatusMethodNotAllowed || rr.Header().Get("Allow") != http.MethodPost {
			t.Fatalf("%s: status %d, Allow %q", tc.lang, rr.Code, rr.Header().Get("Allow"))
		}
		if !strings.Contains(rr.Body.String(), tc.want) {
			t.Errorf("%s: body %q lacks %q", tc.lang, rr.Body.String(), tc.want)
		}
		if len(rr.Result().Cookies()) != 0 {
			t.Errorf("%s: a GET request set a cookie", tc.lang)
		}
	}
}

func TestLocalReturnPathStaysOnThisInstance(t *testing.T) {
	cases := []struct{ name, referer, want string }{
		{"page with query", "https://sender.example/report/abc?msg=1", "/report/abc?msg=1"},
		{"page of another host keeps its path", "https://other.example/about", "/about"},
		{"no referrer", "", "/"},
		{"relative referrer", "about", "/"},
		{"double slash at the start", "https://sender.example//a/b", "/"},
		{"backslash stays encoded", `https://sender.example/\a`, "/%5Ca"},
		{"unparsable referrer", "%zz", "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := localReturnPath(tc.referer); got != tc.want {
				t.Fatalf("localReturnPath(%q) = %q, want %q", tc.referer, got, tc.want)
			}
		})
	}
}

func TestLanguageFollowsTheConfiguredCookie(t *testing.T) {
	srv := &Server{cfg: cookieTestConfig("auto")}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "en")
	req.AddCookie(&http.Cookie{Name: "ui_language", Value: "de"})
	if got := srv.lang(req); got != "de" {
		t.Errorf("lang = %q, want de from the configured cookie", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "en")
	req.AddCookie(&http.Cookie{Name: "sr_lang", Value: "de"})
	if got := srv.lang(req); got != "en" {
		t.Errorf("lang = %q, want en: only the configured cookie name counts", got)
	}
}

func TestForceHTTPSRedirectUsesThePublicHost(t *testing.T) {
	srv := &Server{cfg: config.Config{ForceHTTPS: true, PublicBaseURL: "https://sender.example:8443"}}
	handler := srv.withHTTPSRedirect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "http://10.0.0.5:9090/report/abc?msg=1", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want 308", rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "https://sender.example:8443/report/abc?msg=1" {
		t.Errorf("Location = %q", got)
	}
}

func TestForceHTTPSRedirectNeedsAHostName(t *testing.T) {
	proxy, err := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parse trusted proxy cidr: %v", err)
	}
	srv := &Server{cfg: config.Config{ForceHTTPS: true}, trustedProxy: proxy}
	handler := srv.withHTTPSRedirect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	for _, tc := range []struct {
		host, wantLocation string
		wantCode           int
	}{
		{"sender.example", "https://sender.example/about", http.StatusPermanentRedirect},
		{"[2001:db8::1]:8080", "https://[2001:db8::1]:8080/about", http.StatusPermanentRedirect},
		{"sender example", "", http.StatusBadRequest},
	} {
		req := httptest.NewRequest(http.MethodGet, "http://internal:8080/about", nil)
		req.RemoteAddr = "10.1.2.3:4567"
		req.Header.Set("X-Forwarded-Host", tc.host)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != tc.wantCode || rr.Header().Get("Location") != tc.wantLocation {
			t.Errorf("host %q: status %d Location %q, want %d %q", tc.host, rr.Code, rr.Header().Get("Location"), tc.wantCode, tc.wantLocation)
		}
		if tc.wantCode == http.StatusBadRequest && !strings.Contains(rr.Body.String(), "public address") {
			t.Errorf("host %q: body %q does not say what to do", tc.host, rr.Body.String())
		}
	}
}

func TestPrivacyPageListsTheConfiguredCookies(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	for _, tc := range []struct{ mode, note string }{
		{"always", "SameSite=Lax, Secure</small>"},
		{"auto", "SameSite=Lax, Secure bei HTTPS</small>"},
		{"never", "SameSite=Lax</small>"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			cfg := cookieTestConfig(tc.mode)
			cfg.UIDefaultTheme = "auto"
			srv, err := New(cfg, nil, nil, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			body := renderPage(t, srv.privacyPage, "/privacy", "de")
			for _, want := range []string{
				"<code>box_token</code>",
				"<code>ui_language</code>",
				"<td>" + strconv.Itoa(cfg.LangCookieDays) + " Tage</td>",
				tc.note,
			} {
				if !strings.Contains(body, want) {
					t.Errorf("privacy page lacks %q", want)
				}
			}
			if strings.Contains(body, "sr_mailbox") || strings.Contains(body, "sr_lang") {
				t.Error("privacy page still names a default cookie")
			}
		})
	}
}

// The redirect target keeps the escaped form of the request path.
func TestForceHTTPSRedirectKeepsTheEscapedPath(t *testing.T) {
	srv := &Server{cfg: config.Config{ForceHTTPS: true}}
	handler := srv.withHTTPSRedirect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "http://sender.example/raw/a%2Fb/c?q=%C3%A4", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location %q: %v", rr.Header().Get("Location"), err)
	}
	if loc.Host != "sender.example" || loc.EscapedPath() != "/raw/a%2Fb/c" || loc.RawQuery != "q=%C3%A4" {
		t.Errorf("Location = %q", rr.Header().Get("Location"))
	}
}
