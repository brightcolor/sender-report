package web

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strings"

	"github.com/brightcolor/sender-report/internal/i18n"
)

// Ratgeber: öffentliche Seiten zu den Fragen, mit denen Menschen vor einem
// Zustellbarkeitsproblem suchen. Sie führen zum Test und liefern Suchmaschinen
// Inhalt zu SPF, DKIM, DMARC, Spam-Score, Blacklists und Reverse-DNS.

type guideSection struct {
	Heading    string
	Paragraphs []string
	Items      []string
	Code       string
}

type guideFAQ struct{ Q, A string }

type guideText struct {
	Title, Description, H1, Lead string
	Sections                     []guideSection
	FAQ                          []guideFAQ
}

type guide struct {
	Slug    string
	Updated string // JJJJ-MM-TT
	Icon    string // Bootstrap-Icons-Klasse
	Related []string
	DE, EN  guideText
}

func (g guide) text(lang string) guideText {
	if i18n.Lang(lang) == i18n.DE {
		return g.DE
	}
	return g.EN
}

// guideLink ist ein Verweis auf einen Ratgeber in Listen.
type guideLink struct {
	Slug, Title, Description, Icon, Heading string
}

// GuidePageData sind die Daten der Seiten unter /guides.
type GuidePageData struct {
	AppName     string
	Domain      string
	PublicURL   string
	Lang        string
	Slug        string // leer auf der Übersicht
	SEOPath     string // Adresse ohne Sprachpräfix für canonical und hreflang
	PageTitle   string
	H1          string
	Lead        string
	Description string
	Guide       guideText
	Icon        string
	Updated     string
	Related     []guideLink
	Guides      []guideLink
	JSONLD      template.JS
}

func findGuide(slug string) (guide, bool) {
	for _, g := range guideList {
		if g.Slug == slug {
			return g, true
		}
	}
	return guide{}, false
}

func guideLinks(lang string, slugs []string) []guideLink {
	var out []guideLink
	for _, g := range guideList {
		if slugs != nil && !contains(slugs, g.Slug) {
			continue
		}
		t := g.text(lang)
		out = append(out, guideLink{Slug: g.Slug, Title: t.H1, Description: t.Description, Icon: g.Icon})
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// guidesIndex serves /guides.
func (s *Server) guidesIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	lang := string(s.lang(r))
	base := s.publicBaseURL(r)
	title, lead, desc := guidesIntro(lang)
	s.render(w, "guides", GuidePageData{
		AppName:     s.cfg.AppName,
		Domain:      s.requestSMTPDomain(r),
		PublicURL:   base,
		Lang:        lang,
		SEOPath:     "/guides",
		PageTitle:   title + " – " + s.cfg.AppName,
		H1:          title,
		Lead:        lead,
		Description: desc,
		Guides:      guideLinks(lang, nil),
		JSONLD:      guidesIndexJSONLD(lang, base, s.cfg.AppName),
	})
}

// guidePage serves /guides/{slug}.
func (s *Server) guidePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	slug := strings.Trim(strings.TrimPrefix(r.URL.Path, "/guides/"), "/")
	g, ok := findGuide(slug)
	if !ok {
		http.NotFound(w, r)
		return
	}
	lang := string(s.lang(r))
	base := s.publicBaseURL(r)
	s.render(w, "guides", GuidePageData{
		AppName:     s.cfg.AppName,
		Domain:      s.requestSMTPDomain(r),
		PublicURL:   base,
		Lang:        lang,
		Slug:        g.Slug,
		SEOPath:     "/guides/" + g.Slug,
		PageTitle:   g.text(lang).Title,
		H1:          g.text(lang).H1,
		Lead:        g.text(lang).Lead,
		Description: g.text(lang).Description,
		Guide:       g.text(lang),
		Icon:        g.Icon,
		Updated:     g.Updated,
		Related:     guideLinks(lang, g.Related),
		JSONLD:      guideJSONLD(g, lang, base, s.cfg.AppName),
	})
}

func jsonLD(v any) template.JS {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return template.JS(b)
}

func guideJSONLD(g guide, lang, base, app string) template.JS {
	t := g.text(lang)
	pageURL := base + langPath(lang, "/guides/"+g.Slug)
	faq := make([]map[string]any, 0, len(t.FAQ))
	for _, f := range t.FAQ {
		faq = append(faq, map[string]any{
			"@type": "Question", "name": f.Q,
			"acceptedAnswer": map[string]any{"@type": "Answer", "text": f.A},
		})
	}
	org := map[string]any{"@type": "Organization", "name": app, "url": base + "/"}
	graph := []any{
		map[string]any{
			"@type": "Article", "headline": t.H1, "description": t.Description, "inLanguage": lang,
			"datePublished": g.Updated, "dateModified": g.Updated,
			"mainEntityOfPage": pageURL, "author": org, "publisher": org,
		},
		map[string]any{
			"@type": "BreadcrumbList",
			"itemListElement": []any{
				map[string]any{"@type": "ListItem", "position": 1, "name": app, "item": base + langPath(lang, "/")},
				map[string]any{"@type": "ListItem", "position": 2, "name": guidesName(lang), "item": base + langPath(lang, "/guides")},
				map[string]any{"@type": "ListItem", "position": 3, "name": t.H1, "item": pageURL},
			},
		},
	}
	if len(faq) > 0 {
		graph = append(graph, map[string]any{"@type": "FAQPage", "mainEntity": faq})
	}
	return jsonLD(map[string]any{"@context": "https://schema.org", "@graph": graph})
}

func guidesIndexJSONLD(lang, base, app string) template.JS {
	var items []any
	for i, g := range guideList {
		items = append(items, map[string]any{
			"@type": "ListItem", "position": i + 1,
			"url": base + langPath(lang, "/guides/"+g.Slug), "name": g.text(lang).H1,
		})
	}
	return jsonLD(map[string]any{
		"@context": "https://schema.org",
		"@graph": []any{
			map[string]any{"@type": "CollectionPage", "name": guidesName(lang) + " – " + app, "inLanguage": lang,
				"url": base + langPath(lang, "/guides")},
			map[string]any{"@type": "ItemList", "itemListElement": items},
		},
	})
}

func guidesName(lang string) string {
	if i18n.Lang(lang) == i18n.DE {
		return "Ratgeber"
	}
	return "Guides"
}

// guidesIntro ist der Einleitungstext der Übersicht.
func guidesIntro(lang string) (title, lead, description string) {
	if i18n.Lang(lang) == i18n.DE {
		return "Ratgeber zur E-Mail-Zustellbarkeit",
			"Verständliche Anleitungen zu SPF, DKIM, DMARC, Spam-Score, Blacklists und Reverse-DNS. Jeder Ratgeber erklärt das Verfahren, nennt typische Fehler und führt zum kostenlosen Test.",
			"Ratgeber zu SPF, DKIM, DMARC, Spam-Score, Blacklists und Reverse-DNS: so verbesserst du die Zustellbarkeit deiner E-Mails. Mit kostenlosem Test."
	}
	return "Email deliverability guides",
		"Clear guides to SPF, DKIM, DMARC, spam score, blacklists and reverse DNS. Each guide explains the standard, names typical mistakes and leads to the free test.",
		"Guides to SPF, DKIM, DMARC, spam score, blacklists and reverse DNS: how to improve the deliverability of your email. With a free test."
}
