package web

import (
	"context"
	"fmt"
	"html"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/brightcolor/sender-report/internal/i18n"
)

// Öffentliche Seiten gibt es unter eigenen Adressen je Sprache: /de/… und /en/….
// Suchmaschinen rufen Seiten ohne Sprachkopf auf und sähen sonst nur eine
// Sprache unter einer Adresse. Die Adresse ohne Präfix bleibt erreichbar und
// wählt die Sprache wie bisher (Cookie, Accept-Language).

type langOverrideKey struct{}

// langPrefixedPages sind die Seiten, die es mit Sprachpräfix gibt.
func langPrefixedPage(rest string) bool {
	switch rest {
	case "/", "/about", "/privacy", "/simulate", "/guides":
		return true
	}
	return strings.HasPrefix(rest, "/guides/") && len(rest) > len("/guides/")
}

// splitLangPrefix trennt /de oder /en vom Pfad. ok ist nur wahr, wenn der Rest
// eine öffentliche Seite ist.
func splitLangPrefix(path string) (lang i18n.Lang, rest string, ok bool) {
	for _, l := range []i18n.Lang{i18n.DE, i18n.EN} {
		p := "/" + string(l)
		if path == p {
			return l, "/", true
		}
		if strings.HasPrefix(path, p+"/") {
			rest = strings.TrimPrefix(path, p)
			if langPrefixedPage(rest) {
				return l, rest, true
			}
		}
	}
	return "", "", false
}

// withLangPrefix bedient /de/… und /en/… mit denselben Seiten wie die Adressen
// ohne Präfix, in der Sprache des Präfixes.
func (s *Server) withLangPrefix(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if l, rest, ok := splitLangPrefix(r.URL.Path); ok {
			r2 := r.Clone(context.WithValue(r.Context(), langOverrideKey{}, l))
			r2.URL.Path = rest
			r2.URL.RawPath = ""
			next.ServeHTTP(w, r2)
			return
		}
		// Ohne Präfix wählt die Anfrage die Sprache; Caches müssen das wissen.
		if langPrefixedPage(r.URL.Path) {
			w.Header().Add("Vary", "Accept-Language, Cookie")
		}
		next.ServeHTTP(w, r)
	})
}

// swapLangPrefix setzt in einem Rückkehrpfad das Sprachpräfix auf lang. Pfade
// ohne Präfix bleiben unverändert.
func swapLangPrefix(target string, lang i18n.Lang) string {
	path, query, hasQuery := strings.Cut(target, "?")
	if _, rest, ok := splitLangPrefix(path); ok {
		path = langPath(string(lang), rest)
	}
	if hasQuery {
		return path + "?" + query
	}
	return path
}

// langPath ist die Adresse einer öffentlichen Seite in der Sprache lang.
func langPath(lang, path string) string {
	if lang != string(i18n.DE) && lang != string(i18n.EN) {
		lang = string(i18n.EN)
	}
	if path == "" || path == "/" {
		return "/" + lang + "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "/" + lang + path
}

// seoHead schreibt canonical, hreflang und og:url für eine öffentliche Seite.
// path ist die Adresse ohne Sprachpräfix, etwa "/about".
func seoHead(lang, publicURL, path string) template.HTML {
	base := strings.TrimRight(publicURL, "/")
	if path == "" {
		path = "/"
	}
	canonical := base + langPath(lang, path)
	var b strings.Builder
	line := func(format string, args ...string) {
		esc := make([]any, len(args))
		for i, a := range args {
			esc[i] = html.EscapeString(a)
		}
		b.WriteString("  ")
		b.WriteString(fmt.Sprintf(format, esc...))
		b.WriteString("\n")
	}
	line(`<link rel="canonical" href="%s" />`, canonical)
	line(`<link rel="alternate" hreflang="de" href="%s" />`, base+langPath("de", path))
	line(`<link rel="alternate" hreflang="en" href="%s" />`, base+langPath("en", path))
	line(`<link rel="alternate" hreflang="x-default" href="%s" />`, base+path)
	line(`<meta property="og:url" content="%s" />`, canonical)
	return template.HTML(b.String())
}

// lastModified prüft das Datum im Sitemap-Eintrag eines Ratgebers (JJJJ-MM-TT).
func lastModified(date string) string {
	if _, err := time.Parse("2006-01-02", date); err != nil {
		return ""
	}
	return date
}

// robotsTxt erlaubt das Crawlen der öffentlichen Seiten, sperrt die Seiten mit
// Token und nennt die Sitemap.
func (s *Server) robotsTxt(w http.ResponseWriter, r *http.Request) {
	base := s.publicBaseURL(r)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = io.WriteString(w, strings.Join([]string{
		"User-agent: *",
		"Allow: /$",
		"Allow: /de/",
		"Allow: /en/",
		"Allow: /about",
		"Allow: /guides",
		"Allow: /privacy",
		"Disallow: /mailbox/",
		"Disallow: /report/",
		"Disallow: /raw/",
		"Disallow: /api/",
		"Sitemap: " + base + "/sitemap.xml",
		"",
	}, "\n"))
}

// sitemapPage ist ein Eintrag der Sitemap.
type sitemapPage struct {
	Path     string // ohne Sprachpräfix
	Priority string
	Changes  string
	Updated  string // JJJJ-MM-TT oder leer
}

// sitemapPages sind die öffentlichen Seiten, jede in beiden Sprachen.
func sitemapPages() []sitemapPage {
	pages := []sitemapPage{
		{Path: "/", Priority: "1.0", Changes: "weekly"},
		{Path: "/guides", Priority: "0.9", Changes: "weekly"},
		{Path: "/about", Priority: "0.8", Changes: "monthly"},
		{Path: "/privacy", Priority: "0.3", Changes: "yearly"},
	}
	for _, g := range guideList {
		pages = append(pages, sitemapPage{Path: "/guides/" + g.Slug, Priority: "0.8", Changes: "monthly", Updated: g.Updated})
	}
	return pages
}

// sitemapXML listet die öffentlichen Seiten in beiden Sprachen mit
// hreflang-Verweisen aufeinander.
func (s *Server) sitemapXML(w http.ResponseWriter, r *http.Request) {
	base := s.publicBaseURL(r)
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">` + "\n")
	esc := html.EscapeString
	for _, p := range sitemapPages() {
		for _, l := range []string{"de", "en"} {
			b.WriteString("  <url>\n    <loc>" + esc(base+langPath(l, p.Path)) + "</loc>\n")
			for _, alt := range []string{"de", "en"} {
				b.WriteString(`    <xhtml:link rel="alternate" hreflang="` + alt + `" href="` + esc(base+langPath(alt, p.Path)) + `"/>` + "\n")
			}
			b.WriteString(`    <xhtml:link rel="alternate" hreflang="x-default" href="` + esc(base+p.Path) + `"/>` + "\n")
			if d := lastModified(p.Updated); d != "" {
				b.WriteString("    <lastmod>" + d + "</lastmod>\n")
			}
			b.WriteString("    <changefreq>" + p.Changes + "</changefreq>\n    <priority>" + p.Priority + "</priority>\n  </url>\n")
		}
	}
	b.WriteString("</urlset>\n")
	_, _ = io.WriteString(w, b.String())
}
