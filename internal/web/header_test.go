package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// Bootstrap 5 breakpoints, narrowest first; "xs" stands for everything below sm.
var headerBreakpoints = []string{"xs", "sm", "md", "lg", "xl", "xxl"}

var (
	headerNavBlock         = regexp.MustCompile(`(?s)<nav class="app-header.*?</nav>`)
	headerTemplateAction   = regexp.MustCompile(`(?s)\{\{.*?\}\}`)
	headerTemplateControls = regexp.MustCompile(`^\{\{-?\s*(if|else|end|range|with|define|block|template|/\*)`)
)

// TestHeaderActionsStayReachableOnPhones checks the navbar of every page at
// each Bootstrap breakpoint, using the display utilities in the markup. Below
// sm the header row holds only the menus and the language switch, and the menu
// buttons show an icon; up to md at most two further buttons fit next to them.
// Every action the desktop header offers must stay reachable at every width,
// directly or from a menu. On phones the report header used to run far past
// the screen edge and the overflow was clipped, so "Mail simulieren", "PDF"
// and "Neuer Test" could not be tapped.
func TestHeaderActionsStayReachableOnPhones(t *testing.T) {
	partials, err := os.ReadFile(filepath.Join("templates", "_partials.html"))
	if err != nil {
		t.Fatalf("read partials: %v", err)
	}
	themeMenu := definedBlock(t, string(partials), "theme-menu")

	pages, err := filepath.Glob(filepath.Join("templates", "*.html"))
	if err != nil {
		t.Fatalf("glob templates: %v", err)
	}
	checked := 0
	for _, page := range pages {
		name := filepath.Base(page)
		if name == "_partials.html" {
			continue
		}
		raw, err := os.ReadFile(page)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		block := headerNavBlock.FindString(string(raw))
		if block == "" {
			t.Errorf("%s has no app-header navbar", name)
			continue
		}
		checked++
		t.Run(strings.TrimSuffix(name, ".html"), func(t *testing.T) {
			nav := parseHeader(t, strings.ReplaceAll(block, `{{template "theme-menu" .}}`, themeMenu))
			desktop := reachableActions(nav, len(headerBreakpoints)-1)
			if len(desktop) == 0 {
				t.Fatal("found no header actions at desktop width")
			}
			for bp, bpName := range headerBreakpoints {
				reach := reachableActions(nav, bp)
				for key := range desktop {
					if !reach[key] {
						t.Errorf("at %s the %s cannot be reached", bpName, key)
					}
				}
			}

			var extra []string
			for _, c := range rowControls(nav, 0) {
				switch {
				case isLanguageSwitch(c):
				case nodeAttr(c, "data-bs-toggle") == "dropdown":
					if text := visibleText(c, 0); text != "" {
						t.Errorf("at xs the menu button shows the text %q; below sm it shows its icon only", text)
					}
				default:
					extra = append(extra, actionKey(c))
				}
			}
			if len(extra) > 0 {
				t.Errorf("at xs the header row also holds %s; below sm these belong in the menu", strings.Join(extra, ", "))
			}

			extra = extra[:0]
			for _, c := range rowControls(nav, 1) {
				if !isLanguageSwitch(c) && nodeAttr(c, "data-bs-toggle") != "dropdown" {
					extra = append(extra, actionKey(c))
				}
			}
			if len(extra) > 2 {
				t.Errorf("at sm the header row holds %d buttons besides the menus (%s); two fit", len(extra), strings.Join(extra, ", "))
			}
		})
	}
	if checked != 6 {
		t.Errorf("checked %d page headers, expected 6", checked)
	}
}

// TestHiddenAtFollowsBootstrapDisplayUtilities pins the breakpoint logic the
// header test relies on.
func TestHiddenAtFollowsBootstrapDisplayUtilities(t *testing.T) {
	cases := []struct {
		class  string
		hidden []bool // xs, sm, md, lg, xl, xxl
	}{
		{"nav-item", []bool{false, false, false, false, false, false}},
		{"d-none", []bool{true, true, true, true, true, true}},
		{"nav-item d-none d-sm-block", []bool{true, false, false, false, false, false}},
		{"d-none d-md-inline-block", []bool{true, true, false, false, false, false}},
		{"d-md-none", []bool{false, false, true, true, true, true}},
		{"d-sm-none d-lg-flex", []bool{false, true, true, false, false, false}},
		{"d-inline-block d-print-none", []bool{false, false, false, false, false, false}},
	}
	for _, tc := range cases {
		for bp, want := range tc.hidden {
			if got := hiddenAt(tc.class, bp); got != want {
				t.Errorf("hiddenAt(%q, %s) = %v, want %v", tc.class, headerBreakpoints[bp], got, want)
			}
		}
	}
}

// definedBlock returns the body of {{define "name"}} … {{end}} from a partials file.
func definedBlock(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, `{{define "`+name+`"}}`)
	if start < 0 {
		t.Fatalf("partial %q not found", name)
	}
	body := src[start+len(`{{define "`+name+`"}}`):]
	if next := strings.Index(body, "{{define "); next >= 0 {
		body = body[:next]
	}
	end := strings.LastIndex(body, "{{end}}")
	if end < 0 {
		t.Fatalf("partial %q has no {{end}}", name)
	}
	return body[:end]
}

// parseHeader turns the navbar source into a node tree. Both branches of
// {{if}}/{{else}} stay in, so optional buttons count as present; actions that
// print a value stay as text without their quotes, so labels and links keep a
// readable text and attribute values stay intact.
func parseHeader(t *testing.T, src string) *html.Node {
	t.Helper()
	src = headerTemplateAction.ReplaceAllStringFunc(src, func(action string) string {
		if headerTemplateControls.MatchString(action) {
			return ""
		}
		return strings.ReplaceAll(action, `"`, "")
	})
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	return doc
}

// reachableActions collects the actions a visitor can reach at breakpoint bp:
// buttons in the header row plus the entries of menus whose button is shown.
func reachableActions(nav *html.Node, bp int) map[string]bool {
	reach := map[string]bool{}
	for _, c := range rowControls(nav, bp) {
		if nodeAttr(c, "data-bs-toggle") != "dropdown" {
			reach[actionKey(c)] = true
			continue
		}
		menu := menuOf(c)
		if menu == nil {
			continue
		}
		walkNodes(menu, func(n *html.Node) {
			if isHeaderControl(n) && !hiddenUpTo(n, menu.Parent, bp) {
				reach[actionKey(n)] = true
			}
		})
	}
	return reach
}

// rowControls lists the buttons and links shown in the header row at bp,
// without the brand and without menu entries.
func rowControls(nav *html.Node, bp int) []*html.Node {
	var out []*html.Node
	walkNodes(nav, func(n *html.Node) {
		if !isHeaderControl(n) || nodeHasClass(n, "navbar-brand") || nodeInsideClass(n, "dropdown-menu") {
			return
		}
		if !hiddenUpTo(n, nil, bp) {
			out = append(out, n)
		}
	})
	return out
}

// menuOf finds the dropdown menu a toggle button opens.
func menuOf(toggle *html.Node) *html.Node {
	for p := toggle.Parent; p != nil; p = p.Parent {
		var menu *html.Node
		walkNodes(p, func(n *html.Node) {
			if menu == nil && nodeHasClass(n, "dropdown-menu") {
				menu = n
			}
		})
		if menu != nil {
			return menu
		}
	}
	return nil
}

// actionKey names what a control does, so the same action matches in the
// header row and in a menu.
func actionKey(n *html.Node) string {
	switch {
	case nodeAttr(n, "data-theme-choice") != "":
		return "display option " + nodeAttr(n, "data-theme-choice")
	case isLanguageSwitch(n):
		return "language switch"
	case nodeAttr(n, "href") != "":
		return "link " + nodeAttr(n, "href")
	case nodeAttr(n, "data-bs-target") != "":
		return "dialog " + nodeAttr(n, "data-bs-target")
	case nodeHasAttr(n, "data-simulate"):
		return "mail simulator"
	}
	return "button " + strings.Join(strings.Fields(visibleText(n, len(headerBreakpoints)-1)), " ")
}

// hiddenAt reports whether the Bootstrap display utilities in class hide an
// element at breakpoint bp. They apply mobile first: d-none from xs up,
// d-md-block from md up; the widest one that applies wins.
func hiddenAt(class string, bp int) bool {
	hidden, from := false, -1
	for _, c := range strings.Fields(class) {
		rest, ok := strings.CutPrefix(c, "d-")
		if !ok {
			continue
		}
		at := 0
		if infix, value, found := strings.Cut(rest, "-"); found {
			if infix == "print" {
				continue
			}
			for i, name := range headerBreakpoints {
				if i > 0 && name == infix {
					at, rest = i, value
				}
			}
		}
		if at <= bp && at >= from {
			from, hidden = at, rest == "none"
		}
	}
	return hidden
}

// hiddenUpTo reports whether n or one of its ancestors below stop is hidden at bp.
func hiddenUpTo(n, stop *html.Node, bp int) bool {
	for p := n; p != nil && p != stop; p = p.Parent {
		if p.Type == html.ElementNode && hiddenAt(nodeAttr(p, "class"), bp) {
			return true
		}
	}
	return false
}

// visibleText is the text of n that is not hidden at bp.
func visibleText(n *html.Node, bp int) string {
	var b strings.Builder
	walkNodes(n, func(c *html.Node) {
		if c.Type == html.TextNode && !hiddenUpTo(c.Parent, n.Parent, bp) {
			b.WriteString(c.Data)
		}
	})
	return strings.TrimSpace(b.String())
}

func isHeaderControl(n *html.Node) bool {
	return n.Type == html.ElementNode && (n.Data == "button" || (n.Data == "a" && nodeHasAttr(n, "href")))
}

func isLanguageSwitch(n *html.Node) bool {
	return n.Data == "button" && nodeAttr(n, "name") == "l"
}

func nodeInsideClass(n *html.Node, class string) bool {
	for p := n.Parent; p != nil; p = p.Parent {
		if nodeHasClass(p, class) {
			return true
		}
	}
	return false
}

func nodeHasClass(n *html.Node, class string) bool {
	for _, c := range strings.Fields(nodeAttr(n, "class")) {
		if c == class {
			return true
		}
	}
	return false
}

func nodeHasAttr(n *html.Node, key string) bool {
	for _, a := range n.Attr {
		if a.Key == key {
			return true
		}
	}
	return false
}

func nodeAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func walkNodes(n *html.Node, visit func(*html.Node)) {
	visit(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walkNodes(c, visit)
	}
}
