//go:build cgo
// +build cgo

package web

import (
	"encoding/json"
	"encoding/xml"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brightcolor/sender-report/internal/i18n"
)

func TestSplitLangPrefix(t *testing.T) {
	for _, tc := range []struct {
		in   string
		lang i18n.Lang
		rest string
		ok   bool
	}{
		{"/de", i18n.DE, "/", true},
		{"/de/", i18n.DE, "/", true},
		{"/en/about", i18n.EN, "/about", true},
		{"/de/guides", i18n.DE, "/guides", true},
		{"/en/guides/spf", i18n.EN, "/guides/spf", true},
		{"/en/api/stats", "", "", false}, // nur öffentliche Seiten tragen ein Präfix
		{"/de/report/abc", "", "", false},
		{"/deutsch", "", "", false},
		{"/about", "", "", false},
	} {
		lang, rest, ok := splitLangPrefix(tc.in)
		if ok != tc.ok || lang != tc.lang || rest != tc.rest {
			t.Errorf("splitLangPrefix(%q) = %q, %q, %v; erwartet %q, %q, %v", tc.in, lang, rest, ok, tc.lang, tc.rest, tc.ok)
		}
	}
}

func TestLangPathAndSwap(t *testing.T) {
	if got := langPath("de", "/"); got != "/de/" {
		t.Errorf("langPath start = %q", got)
	}
	if got := langPath("en", "/guides/spf"); got != "/en/guides/spf" {
		t.Errorf("langPath guide = %q", got)
	}
	if got := langPath("fr", "/about"); got != "/en/about" {
		t.Errorf("unbekannte Sprache fällt auf Englisch zurück: %q", got)
	}
	for in, want := range map[string]string{
		"/de/about":          "/en/about",
		"/de/guides/spf?x=1": "/en/guides/spf?x=1",
		"/de":                "/en/",
		"/about":             "/about",
		"/report/abc":        "/report/abc",
	} {
		if got := swapLangPrefix(in, i18n.EN); got != want {
			t.Errorf("swapLangPrefix(%q) = %q, erwartet %q", in, got, want)
		}
	}
}

func TestSEOHeadNamesCanonicalAndAlternates(t *testing.T) {
	got := string(seoHead("de", "https://sender.report/", "/guides/spf"))
	for _, want := range []string{
		`<link rel="canonical" href="https://sender.report/de/guides/spf" />`,
		`hreflang="de" href="https://sender.report/de/guides/spf"`,
		`hreflang="en" href="https://sender.report/en/guides/spf"`,
		`hreflang="x-default" href="https://sender.report/guides/spf"`,
		`<meta property="og:url" content="https://sender.report/de/guides/spf" />`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("seoHead lacks %s\n%s", want, got)
		}
	}
	if home := string(seoHead("en", "https://sender.report", "/")); !strings.Contains(home, `href="https://sender.report/en/"`) || !strings.Contains(home, `hreflang="x-default" href="https://sender.report/"`) {
		t.Errorf("Startseite: %s", home)
	}
}

func publicServer(t *testing.T) *Server {
	t.Helper()
	restoreWD := chdirToRepoRoot(t)
	t.Cleanup(restoreWD)
	srv, _, _, _, _ := prepareWebTestFixture(t)
	srv.cfg.PublicBaseURL = "https://sender.test"
	return srv
}

func getPage(srv *Server, path, acceptLanguage string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if acceptLanguage != "" {
		req.Header.Set("Accept-Language", acceptLanguage)
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	return rr
}

// Das Sprachpräfix bestimmt die Sprache, auch gegen Cookie und Accept-Language.
func TestLanguagePrefixOverridesNegotiation(t *testing.T) {
	srv := publicServer(t)
	for _, tc := range []struct{ path, accept, htmlLang, canonical string }{
		{"/de/about", "en", `<html lang="de"`, `href="https://sender.test/de/about"`},
		{"/en/about", "de", `<html lang="en"`, `href="https://sender.test/en/about"`},
		{"/de/", "en", `<html lang="de"`, `href="https://sender.test/de/"`},
		{"/en/privacy", "de", `<html lang="en"`, `href="https://sender.test/en/privacy"`},
		{"/about", "de", `<html lang="de"`, `href="https://sender.test/de/about"`}, // ohne Präfix wählt der Header, canonical zeigt auf die Sprachadresse
	} {
		rr := getPage(srv, tc.path, tc.accept)
		if rr.Code != http.StatusOK {
			t.Errorf("%s: Status %d", tc.path, rr.Code)
			continue
		}
		body := rr.Body.String()
		if !strings.Contains(body, tc.htmlLang) {
			t.Errorf("%s (Accept-Language %s): Sprache falsch, erwartet %s", tc.path, tc.accept, tc.htmlLang)
		}
		if !strings.Contains(body, `<link rel="canonical" `+tc.canonical) {
			t.Errorf("%s: canonical fehlt oder falsch, erwartet %s", tc.path, tc.canonical)
		}
		if !strings.Contains(body, `hreflang="x-default"`) {
			t.Errorf("%s: x-default fehlt", tc.path)
		}
	}
	if vary := getPage(srv, "/about", "de").Header().Get("Vary"); !strings.Contains(vary, "Accept-Language") {
		t.Errorf("Adresse ohne Präfix wählt per Accept-Language, Vary lautet %q", vary)
	}
	if vary := getPage(srv, "/de/about", "de").Header().Get("Vary"); strings.Contains(vary, "Accept-Language") {
		t.Errorf("Adresse mit Präfix ist sprachfest, Vary lautet %q", vary)
	}
	// Seiten außerhalb der öffentlichen Liste kennen kein Präfix.
	if rr := getPage(srv, "/de/api/stats", ""); rr.Code != http.StatusNotFound {
		t.Errorf("/de/api/stats: Status %d, erwartet 404", rr.Code)
	}
}

func TestEveryGuideRendersInBothLanguages(t *testing.T) {
	srv := publicServer(t)
	for _, lang := range []string{"de", "en"} {
		index := getPage(srv, "/"+lang+"/guides", "")
		if index.Code != http.StatusOK {
			t.Fatalf("/%s/guides: Status %d", lang, index.Code)
		}
		for _, g := range guideList {
			if !strings.Contains(index.Body.String(), "/"+lang+"/guides/"+g.Slug) {
				t.Errorf("Übersicht %s verlinkt %s nicht", lang, g.Slug)
			}
			rr := getPage(srv, "/"+lang+"/guides/"+g.Slug, "")
			if rr.Code != http.StatusOK {
				t.Errorf("/%s/guides/%s: Status %d", lang, g.Slug, rr.Code)
				continue
			}
			body := rr.Body.String()
			txt := g.text(lang)
			for _, want := range []string{"<title>" + template.HTMLEscapeString(txt.Title), "<h1 ", template.HTMLEscapeString(txt.H1), `rel="canonical" href="https://sender.test/` + lang + `/guides/` + g.Slug + `"`, `application/ld+json`, `/static/og-image.png`} {
				if !strings.Contains(body, want) {
					t.Errorf("%s/%s lacks %q", lang, g.Slug, want)
				}
			}
			// JSON-LD ist gültiges JSON und enthält Article, Breadcrumbs und FAQ.
			marker := `<script type="application/ld+json">`
			start := strings.Index(body, marker) + len(marker)
			end := strings.Index(body[start:], "</script>")
			var doc struct {
				Graph []map[string]any `json:"@graph"`
			}
			if err := json.Unmarshal([]byte(body[start:start+end]), &doc); err != nil {
				t.Errorf("%s/%s: JSON-LD ungültig: %v", lang, g.Slug, err)
				continue
			}
			types := map[string]bool{}
			for _, n := range doc.Graph {
				types[n["@type"].(string)] = true
			}
			for _, want := range []string{"Article", "BreadcrumbList", "FAQPage"} {
				if !types[want] {
					t.Errorf("%s/%s: JSON-LD ohne %s", lang, g.Slug, want)
				}
			}
			// Jeder Ratgeber führt zum Test und zu verwandten Ratgebern.
			if !strings.Contains(body, `href="/`+lang+`/"`) {
				t.Errorf("%s/%s verlinkt den Test nicht", lang, g.Slug)
			}
			for _, rel := range g.Related {
				if _, ok := findGuide(rel); !ok {
					t.Errorf("%s verweist auf unbekannten Ratgeber %s", g.Slug, rel)
				} else if !strings.Contains(body, "/"+lang+"/guides/"+rel) {
					t.Errorf("%s/%s verlinkt %s nicht", lang, g.Slug, rel)
				}
			}
		}
	}
	if rr := getPage(srv, "/de/guides/gibt-es-nicht", ""); rr.Code != http.StatusNotFound {
		t.Errorf("unbekannter Ratgeber: Status %d, erwartet 404", rr.Code)
	}
}

func TestGuideContentIsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, g := range guideList {
		if seen[g.Slug] {
			t.Errorf("Slug %s doppelt", g.Slug)
		}
		seen[g.Slug] = true
		if lastModified(g.Updated) == "" {
			t.Errorf("%s: Updated %q ist kein Datum", g.Slug, g.Updated)
		}
		for lang, txt := range map[string]guideText{"de": g.DE, "en": g.EN} {
			if txt.Title == "" || txt.H1 == "" || txt.Lead == "" || len(txt.Sections) == 0 || len(txt.FAQ) == 0 {
				t.Errorf("%s/%s unvollständig", g.Slug, lang)
			}
			if n := len([]rune(txt.Title)); n > 90 {
				t.Errorf("%s/%s: Titel hat %d Zeichen, mehr als 90 verlieren in der Suche den Schluss", g.Slug, lang, n)
			}
			if n := len([]rune(txt.Description)); n < 70 || n > 200 {
				t.Errorf("%s/%s: Beschreibung hat %d Zeichen, erwartet 70 bis 200", g.Slug, lang, n)
			}
		}
	}
}

func TestSitemapListsBothLanguagesWithAlternates(t *testing.T) {
	srv := publicServer(t)
	rr := getPage(srv, "/sitemap.xml", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("Status %d", rr.Code)
	}
	var doc struct {
		URLs []struct {
			Loc   string `xml:"loc"`
			Links []struct {
				Hreflang string `xml:"hreflang,attr"`
				Href     string `xml:"href,attr"`
			} `xml:"http://www.w3.org/1999/xhtml link"`
			Lastmod string `xml:"lastmod"`
		} `xml:"url"`
	}
	if err := xml.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("Sitemap ist kein gültiges XML: %v", err)
	}
	locs := map[string]bool{}
	for _, u := range doc.URLs {
		locs[u.Loc] = true
		if len(u.Links) != 3 {
			t.Errorf("%s: %d Alternativen, erwartet 3 (de, en, x-default)", u.Loc, len(u.Links))
		}
	}
	for _, want := range []string{"https://sender.test/de/", "https://sender.test/en/", "https://sender.test/de/guides", "https://sender.test/en/guides/spf", "https://sender.test/de/about"} {
		if !locs[want] {
			t.Errorf("Sitemap lacks %s", want)
		}
	}
	for _, u := range doc.URLs {
		if strings.Contains(u.Loc, "/guides/") && u.Lastmod == "" {
			t.Errorf("%s ohne lastmod", u.Loc)
		}
		if strings.Contains(u.Loc, "/report/") || strings.Contains(u.Loc, "/mailbox/") {
			t.Errorf("private Seite in der Sitemap: %s", u.Loc)
		}
	}
	robots := getPage(srv, "/robots.txt", "").Body.String()
	for _, want := range []string{"Sitemap: https://sender.test/sitemap.xml", "Disallow: /report/", "Allow: /guides", "Allow: /de/"} {
		if !strings.Contains(robots, want) {
			t.Errorf("robots.txt lacks %q", want)
		}
	}
}
