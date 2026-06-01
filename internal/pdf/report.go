// Package pdf generates a branded PDF deliverability report.
package pdf

import (
	"bytes"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-pdf/fpdf"

	"github.com/brightcolor/sender-report/internal/model"
)

// ── Public types ──────────────────────────────────────────────────────────────

type Options struct {
	IncludePass    bool
	IncludeWarn    bool
	IncludeFail    bool
	IncludeInfo    bool
	IncludeHero    bool
	IncludeMeta    bool
	IncludeDetails bool
}

type CheckGroup struct {
	Name   string
	Hint   string
	Checks []model.CheckResult
}

type ReportData struct {
	AppName     string
	PublicURL   string
	Mailbox     model.Mailbox
	Message     model.Message
	Report      model.AnalysisReport
	Groups      []CheckGroup
	GeneratedAt time.Time
}

// ── Colour palette ────────────────────────────────────────────────────────────

type rgb struct{ r, g, b int }

var (
	colPrimary = rgb{13, 110, 253}
	colSuccess = rgb{25, 135, 84}
	colWarning = rgb{253, 126, 20}
	colDanger  = rgb{220, 53, 69}
	colCyan    = rgb{13, 202, 240}
	colGray    = rgb{108, 117, 125}
	colLight   = rgb{248, 249, 250}
	colBorder  = rgb{222, 226, 230}
	colWhite   = rgb{255, 255, 255}
	colDark    = rgb{33, 37, 41}
	colSubtext = rgb{73, 80, 87}

	colGrpBg = rgb{235, 242, 255}
	colGrpFg = rgb{10, 66, 180}

	colExplFg = rgb{40, 50, 110}
	colRecoFg = rgb{102, 68, 3}
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func statusColor(status string) rgb {
	switch status {
	case "pass":
		return colSuccess
	case "warn":
		return colWarning
	case "fail":
		return colDanger
	case "info":
		return colCyan
	default:
		return colGray
	}
}

func statusLabel(status string) string {
	switch status {
	case "pass":
		return "OK"
	case "warn":
		return "WARNUNG"
	case "fail":
		return "FEHLER"
	case "info":
		return "INFO"
	default:
		return strings.ToUpper(status)
	}
}

func scoreColor(score float64) rgb {
	switch {
	case score >= 7.5:
		return colSuccess
	case score >= 5.5:
		return colWarning
	default:
		return colDanger
	}
}

func scoreLabel(score float64) string {
	switch {
	case score >= 9:
		return "Ausgezeichnet"
	case score >= 7.5:
		return "Sehr gut"
	case score >= 5.5:
		return "Verbesserungsbedarf"
	default:
		return "Kritisch"
	}
}

func lighten(c rgb, t float64) rgb {
	l := func(a int) int { return a + int(float64(255-a)*t) }
	return rgb{l(c.r), l(c.g), l(c.b)}
}

// latin1 converts UTF-8 text to fpdf-safe Latin-1 approximation.
func latin1(s string) string {
	var b strings.Builder
	rep := map[rune]string{
		'ä': "ae", 'ö': "oe", 'ü': "ue",
		'Ä': "Ae", 'Ö': "Oe", 'Ü': "Ue",
		'ß': "ss",
		0x2013: "-", 0x2014: "-", // en-dash, em-dash
		0x2018: "'", 0x2019: "'", // curly single quotes
		0x201C: "\"", 0x201D: "\"", // curly double quotes
		0x2026: "...",              // ellipsis
		0x2192: "->", 0x2190: "<-", // arrows
		0x2713: "+", 0x2717: "x", 0x2714: "+", // check marks
		0x26A0: "!", 0x2022: "*", // warning, bullet
	}
	for _, r := range s {
		if r < 128 {
			b.WriteRune(r)
			continue
		}
		if sub, ok := rep[r]; ok {
			b.WriteString(sub)
			continue
		}
		if utf8.RuneLen(r) <= 2 && r <= 0xFF {
			b.WriteRune(r)
		}
		// skip other non-Latin-1 characters silently
	}
	return b.String()
}

// Drawing shorthands
func sf(f *fpdf.Fpdf, style string, pt float64) { f.SetFont("Helvetica", style, pt) }
func fc(f *fpdf.Fpdf, c rgb)                    { f.SetFillColor(c.r, c.g, c.b) }
func tc(f *fpdf.Fpdf, c rgb)                    { f.SetTextColor(c.r, c.g, c.b) }
func dc(f *fpdf.Fpdf, c rgb)                    { f.SetDrawColor(c.r, c.g, c.b) }

// wrapText splits s into lines that fit within maxW at the current font.
func wrapText(f *fpdf.Fpdf, s string, maxW float64) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	raw := f.SplitLines([]byte(s), maxW)
	out := make([]string, 0, len(raw))
	for _, b := range raw {
		if t := strings.TrimSpace(string(b)); t != "" {
			out = append(out, string(b))
		}
	}
	return out
}

// checkCounts returns pass/warn/fail/info counts for a slice of checks.
func checkCounts(checks []model.CheckResult) (pass, warn, fail, info int) {
	for _, c := range checks {
		switch c.Status {
		case "pass":
			pass++
		case "warn":
			warn++
		case "fail":
			fail++
		case "info":
			info++
		}
	}
	return
}

// ── Entry point ───────────────────────────────────────────────────────────────

func Generate(data ReportData, opts Options) ([]byte, error) {
	f := fpdf.New("P", "mm", "A4", "")
	f.SetMargins(14, 14, 14)
	f.SetAutoPageBreak(true, 16)
	f.AddPage()

	pageW, _ := f.GetPageSize()
	cw := pageW - 28 // 182 mm

	// Footer on every page — use plain ASCII dashes to avoid encoding issues
	appL := latin1(data.AppName)
	f.SetFooterFunc(func() {
		f.SetY(-12)
		dc(f, colBorder)
		f.SetLineWidth(0.2)
		f.Line(14, f.GetY(), pageW-14, f.GetY())
		f.Ln(1.5)
		sf(f, "", 6.5)
		tc(f, colGray)
		f.CellFormat(0, 4,
			fmt.Sprintf("%s  -  Deliverability Report  -  Seite %d", appL, f.PageNo()),
			"", 0, "C", false, 0, "")
	})

	drawHeader(f, data, pageW)

	// E2E notice (shown when plaintext fields are replaced server-side)
	if data.Message.Subject == "[encrypted]" {
		drawE2ENotice(f, cw)
		f.Ln(4)
	}

	if opts.IncludeHero {
		drawHero(f, data, cw)
		f.Ln(5)
	}

	// Category overview table (always shown, gives quick orientation)
	drawCategoryTable(f, data, opts, cw)
	f.Ln(5)

	if opts.IncludeMeta {
		drawMeta(f, data, cw)
		f.Ln(5)
	}

	for _, grp := range data.Groups {
		filtered := filterChecks(grp.Checks, opts)
		if len(filtered) == 0 {
			continue
		}
		if f.GetY() > 250 {
			f.AddPage()
		}
		drawGroupHeader(f, grp, filtered, cw)
		for _, chk := range filtered {
			drawCheckCard(f, chk, cw, opts.IncludeDetails, grp.Name)
		}
		f.Ln(4)
	}

	var buf bytes.Buffer
	if err := f.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ── Page sections ─────────────────────────────────────────────────────────────

func drawHeader(f *fpdf.Fpdf, data ReportData, pageW float64) {
	const barH, stripH = 22.0, 9.0

	// Blue top bar
	fc(f, colPrimary)
	f.Rect(0, 0, pageW, barH, "F")

	// Logo: white rounded square
	fc(f, colWhite)
	f.RoundedRect(10, 5, 12, 12, 1.5, "1234", "F")
	fc(f, colPrimary)
	f.Rect(11.5, 7, 9, 6, "F")
	dc(f, colWhite)
	f.SetLineWidth(0.55)
	f.Line(11.5, 7.5, 16, 11)
	f.Line(16, 11, 20.5, 7.5)
	fc(f, colSuccess)
	f.Circle(21, 16, 3, "F")
	tc(f, colWhite)
	sf(f, "B", 5.5)
	f.SetXY(19.2, 14.2)
	f.CellFormat(3.6, 3.6, "+", "", 0, "C", false, 0, "")

	tc(f, colWhite)
	sf(f, "B", 12)
	f.SetXY(25, 7)
	f.CellFormat(90, 8, latin1(data.AppName), "", 0, "L", false, 0, "")
	sf(f, "", 8)
	f.SetXY(0, 7)
	f.CellFormat(pageW-13, 8, "DELIVERABILITY REPORT", "", 0, "R", false, 0, "")

	// Info strip
	fc(f, colLight)
	f.Rect(0, barH, pageW, stripH, "F")
	dc(f, colBorder)
	f.SetLineWidth(0.2)
	f.Line(0, barH+stripH, pageW, barH+stripH)

	sf(f, "", 7.5)
	tc(f, colSubtext)
	f.SetXY(14, barH+2)
	f.CellFormat(75, 5, latin1("Mailbox: "+data.Mailbox.Address), "", 0, "L", false, 0, "")
	f.CellFormat(40, 5, fmt.Sprintf("Score: %.1f / 10", data.Report.Score), "", 0, "C", false, 0, "")
	f.CellFormat(0, 5, latin1("Erstellt: "+data.GeneratedAt.Format("02.01.2006  15:04")), "", 0, "R", false, 0, "")

	f.SetY(barH + stripH + 5)
}

// cleanMeta returns a display-friendly value for E2E-encrypted fields.
// Fields stored as "[encrypted]" by the server are replaced with a clear notice.
func cleanMeta(s, label string) string {
	if s == "[encrypted]" || s == "" {
		return "(E2E-verschluesselt - nur im Browser lesbar)"
	}
	return s
}

// drawE2ENotice renders a compact info banner when the message is E2E encrypted.
func drawE2ENotice(f *fpdf.Fpdf, w float64) {
	const x, h = 14.0, 9.0
	y := f.GetY()

	// Amber background
	fc(f, rgb{255, 248, 230})
	dc(f, rgb{253, 200, 100})
	f.SetLineWidth(0.2)
	f.RoundedRect(x, y, w, h, 1.5, "1234", "FD")

	// Left amber accent
	fc(f, rgb{253, 126, 20})
	f.Rect(x, y, 3, h, "F")
	f.RoundedRect(x, y, 3, h, 1.5, "14", "F")

	sf(f, "B", 7.5)
	tc(f, rgb{102, 68, 3})
	f.SetXY(x+6, y+1.5)
	f.CellFormat(w-10, 5, "E2E-verschluesselt: Betreff, Absender und IP sind nur im Browser mit deinem Schlussel lesbar.", "", 0, "L", false, 0, "")

	sf(f, "", 6.5)
	f.SetXY(x+6, y+5.5)
	f.CellFormat(w-10, 3.5, "Der Score und alle Pruefergebnisse sind serverseitig verfuegbar und werden vollstaendig angezeigt.", "", 0, "L", false, 0, "")

	f.SetY(y + h)
}

// drawHero: coloured sidebar (46 mm) with large score + white right panel.
func drawHero(f *fpdf.Fpdf, data ReportData, w float64) {
	const (
		x     = 14.0
		cardH = 42.0
		sideW = 46.0
		pad   = 4.0
	)
	y := f.GetY()
	col := scoreColor(data.Report.Score)
	label := scoreLabel(data.Report.Score)

	// Card background
	fc(f, colWhite)
	dc(f, colBorder)
	f.SetLineWidth(0.2)
	f.RoundedRect(x, y, w, cardH, 2, "1234", "F")

	// Coloured left panel
	fc(f, col)
	f.Rect(x, y, sideW, cardH, "F")
	f.RoundedRect(x, y, sideW, cardH, 2, "14", "F")

	// Card border on top
	dc(f, colBorder)
	f.RoundedRect(x, y, w, cardH, 2, "1234", "D")
	f.SetLineWidth(0.12)
	f.Line(x+sideW, y+2, x+sideW, y+cardH-2)

	// Score number centred in sidebar
	sf(f, "B", 26)
	tc(f, colWhite)
	scoreStr := fmt.Sprintf("%.1f", data.Report.Score)
	sw := f.GetStringWidth(scoreStr)
	f.SetXY(x+(sideW-sw)/2, y+7)
	f.CellFormat(sw, 16, scoreStr, "", 0, "L", false, 0, "")

	sf(f, "", 8.5)
	tenW := f.GetStringWidth("/ 10")
	f.SetXY(x+(sideW-tenW)/2, y+24)
	f.CellFormat(tenW, 6, "/ 10", "", 0, "L", false, 0, "")

	sf(f, "B", 6)
	lUp := strings.ToUpper(label)
	lw := f.GetStringWidth(lUp)
	tc(f, lighten(col, 0.55))
	f.SetXY(x+(sideW-lw)/2, y+33)
	f.CellFormat(lw, 5, lUp, "", 0, "L", false, 0, "")

	// Right panel
	rx := x + sideW + pad
	rw := w - sideW - pad - 3

	sf(f, "", 6.5)
	tc(f, colGray)
	f.SetXY(rx, y+5)
	f.CellFormat(rw, 4.5, "GESAMTSCORE", "", 0, "L", false, 0, "")

	sf(f, "B", 15)
	tc(f, colDark)
	f.SetXY(rx, y+10)
	f.CellFormat(rw, 10, latin1(label), "", 0, "L", false, 0, "")

	// Count pills
	counts := map[string]int{"pass": 0, "warn": 0, "fail": 0, "info": 0}
	for _, c := range data.Report.Checks {
		counts[c.Status]++
	}
	type pill struct{ status, label string }
	pills := []pill{{"pass", "bestanden"}, {"warn", "Warnungen"}, {"fail", "Fehler"}, {"info", "Infos"}}
	px, py := rx, y+23
	sf(f, "B", 6.5)
	for _, p := range pills {
		pc := statusColor(p.status)
		txt := fmt.Sprintf("%d %s", counts[p.status], p.label)
		tw := f.GetStringWidth(txt)
		pw := tw + 6
		if px+pw > x+w-3 {
			px = rx
			py += 8
		}
		fc(f, lighten(pc, 0.82))
		f.RoundedRect(px, py, pw, 6, 1, "1234", "F")
		tc(f, pc)
		f.SetXY(px, py)
		f.CellFormat(pw, 6, txt, "", 0, "C", false, 0, "")
		px += pw + 3
	}

	f.SetY(y + cardH)
}

// drawCategoryTable shows a compact overview of all groups with check counts.
func drawCategoryTable(f *fpdf.Fpdf, data ReportData, opts Options, w float64) {
	const x = 14.0

	// Section header
	sf(f, "B", 7.5)
	tc(f, colSubtext)
	f.SetXY(x, f.GetY())
	f.CellFormat(w, 5, "PRUEFKATEGORIEN - UEBERSICHT", "", 1, "L", false, 0, "")
	f.Ln(1)

	y := f.GetY()

	// Table header row
	const rowH = 7.5
	colWs := [5]float64{70, 28, 28, 28, 28} // name, pass, warn, fail, info

	fc(f, colPrimary)
	f.Rect(x, y, w, rowH, "F")
	sf(f, "B", 7)
	tc(f, colWhite)

	headers := [5]string{"Kategorie", "OK", "Warnungen", "Fehler", "Infos"}
	aligns := [5]string{"L", "C", "C", "C", "C"}
	cx := x + 3
	for i, h := range headers {
		f.SetXY(cx, y+1.5)
		f.CellFormat(colWs[i], rowH-2, h, "", 0, aligns[i], false, 0, "")
		cx += colWs[i]
	}
	y += rowH

	// Data rows
	dc(f, colBorder)
	f.SetLineWidth(0.12)

	even := false
	for _, grp := range data.Groups {
		if len(grp.Checks) == 0 {
			continue
		}
		pass, warn, fail, info := checkCounts(grp.Checks)

		if even {
			fc(f, rgb{245, 247, 252})
		} else {
			fc(f, colWhite)
		}
		f.Rect(x, y, w, rowH, "F")
		f.Line(x, y+rowH, x+w, y+rowH)
		even = !even

		sf(f, "B", 7)
		tc(f, colDark)
		f.SetXY(x+3, y+1.5)
		f.CellFormat(colWs[0], rowH-2, latin1(grp.Name), "", 0, "L", false, 0, "")

		// Count cells with colour coding
		type countCell struct {
			n   int
			col rgb
		}
		cells := []countCell{{pass, colSuccess}, {warn, colWarning}, {fail, colDanger}, {info, colCyan}}
		cx = x + 3 + colWs[0]
		for i, cell := range cells {
			if cell.n > 0 {
				tc(f, cell.col)
				sf(f, "B", 7)
			} else {
				tc(f, rgb{180, 185, 190})
				sf(f, "", 7)
			}
			f.SetXY(cx, y+1.5)
			f.CellFormat(colWs[i+1], rowH-2, fmt.Sprintf("%d", cell.n), "", 0, "C", false, 0, "")
			cx += colWs[i+1]
		}
		y += rowH
	}

	// Outer border
	dc(f, colBorder)
	f.SetLineWidth(0.2)
	f.Rect(x, f.GetY()-float64(countGroups(data.Groups))*rowH-rowH, w,
		float64(countGroups(data.Groups))*rowH+rowH, "D")

	f.SetY(y)
}

func countGroups(groups []CheckGroup) int {
	n := 0
	for _, g := range groups {
		if len(g.Checks) > 0 {
			n++
		}
	}
	return n
}

func drawMeta(f *fpdf.Fpdf, data ReportData, w float64) {
	const x, cellH, gap = 14.0, 14.0, 4.0
	y := f.GetY()
	cw := (w - gap) / 2

	subject := cleanMeta(data.Message.Subject, "Betreff")
	received := "(E2E-verschluesselt)"
	if !data.Message.ReceivedAt.IsZero() {
		received = data.Message.ReceivedAt.Format("02.01.2006  15:04:05")
	}
	smtpFrom := cleanMeta(data.Message.SMTPFrom, "Envelope-From")
	source := data.Message.RemoteIP
	if source == "[encrypted]" || source == "" {
		source = cleanMeta("[encrypted]", "Quelle")
	} else if data.Message.HELO != "" && data.Message.HELO != "[encrypted]" {
		source += " / " + data.Message.HELO
	}

	items := [4]struct{ label, value string }{
		{"Betreff", subject},
		{"Empfangen", received},
		{"Envelope-From", smtpFrom},
		{"Quelle (IP / HELO)", source},
	}

	dc(f, colBorder)
	f.SetLineWidth(0.2)
	for i, item := range items {
		col := i % 2
		row := i / 2
		ix := x + float64(col)*(cw+gap)
		iy := y + float64(row)*(cellH+2)

		fc(f, colWhite)
		f.RoundedRect(ix, iy, cw, cellH, 1.5, "1234", "FD")
		fc(f, colPrimary)
		f.Rect(ix+1.5, iy, cw-3, 2, "F")

		sf(f, "", 6.5)
		tc(f, colGray)
		f.SetXY(ix+4, iy+4)
		f.CellFormat(cw-6, 4, latin1(item.label), "", 0, "L", false, 0, "")

		sf(f, "B", 8)
		tc(f, colDark)
		val := latin1(item.value)
		for len(val) > 3 && f.GetStringWidth(val) > cw-8 {
			val = val[:len(val)-4] + "..."
		}
		f.SetXY(ix+4, iy+8.5)
		f.CellFormat(cw-6, 5, val, "", 0, "L", false, 0, "")
	}
	f.SetY(y + 2*(cellH+2))
}

// drawGroupHeader shows group name + count pills in a light-blue bar.
func drawGroupHeader(f *fpdf.Fpdf, grp CheckGroup, filtered []model.CheckResult, w float64) {
	const x, h = 14.0, 9.0
	y := f.GetY()

	fc(f, colGrpBg)
	f.Rect(x, y, w, h, "F")
	fc(f, colPrimary)
	f.Rect(x, y, 3, h, "F")
	dc(f, colBorder)
	f.SetLineWidth(0.15)
	f.Line(x, y+h, x+w, y+h)

	sf(f, "B", 8)
	tc(f, colGrpFg)
	f.SetXY(x+5, y+2)
	f.CellFormat(100, 5, latin1(grp.Name), "", 0, "L", false, 0, "")

	// Compact count pills right-aligned
	pass, warn, fail, info := checkCounts(filtered)
	type cpill struct {
		n   int
		col rgb
		lbl string
	}
	cpills := []cpill{{pass, colSuccess, "OK"}, {warn, colWarning, "W"}, {fail, colDanger, "F"}, {info, colCyan, "I"}}
	px := x + w - 2
	sf(f, "B", 5.5)
	for i := len(cpills) - 1; i >= 0; i-- {
		p := cpills[i]
		if p.n == 0 {
			continue
		}
		txt := fmt.Sprintf("%d %s", p.n, p.lbl)
		tw := f.GetStringWidth(txt)
		pw := tw + 4
		px -= pw
		fc(f, lighten(p.col, 0.75))
		f.RoundedRect(px, y+2.5, pw, 4.5, 0.7, "1234", "F")
		tc(f, p.col)
		f.SetXY(px, y+2.5)
		f.CellFormat(pw, 4.5, txt, "", 0, "C", false, 0, "")
		px -= 2
	}

	f.Ln(h + 1)
}

// drawCheckCard renders one check as a self-contained card.
// Card height is calculated from actual content so nothing is clipped.
func drawCheckCard(f *fpdf.Fpdf, chk model.CheckResult, w float64, details bool, grpName string) {
	const (
		x      = 14.0
		accent = 4.0
		padL   = 5.0
		padR   = 4.0
		padTop = 3.5
		padBot = 3.5
		nameH  = 5.5
		lineH  = 4.5
		smallH = 4.0
	)

	col := statusColor(chk.Status)
	txX := x + accent + padL
	txW := w - accent - padL - padR

	// ── Pre-measure all content ───────────────────────────────────────

	// Badge and delta widths (needed for nameW)
	sf(f, "B", 5.5)
	badgeLabel := statusLabel(chk.Status)
	badgeW := f.GetStringWidth(badgeLabel) + 5

	sf(f, "B", 7)
	delta := fmt.Sprintf("%+.1f", chk.ScoreDelta)
	deltaW := f.GetStringWidth(delta) + 3

	nameW := txW - badgeW - deltaW - 2

	// Summary
	sf(f, "", 7.5)
	summary := latin1(chk.Summary)
	if strings.TrimSpace(summary) == "" {
		summary = "(Details im Web-Report verfuegbar - Inhalt moeglicherweise E2E-verschluesselt)"
	}
	summLines := wrapText(f, summary, txW)
	summH := float64(len(summLines)) * lineH

	// Explanation
	var explLines []string
	explH := 0.0
	if details && chk.Explanation != "" {
		sf(f, "", 7)
		explLines = wrapText(f, latin1(chk.Explanation), txW-2)
		if len(explLines) > 0 {
			explH = 5.5 + float64(len(explLines))*smallH + 2
		}
	}

	// Recommendation (warn/fail only)
	var recoLines []string
	recoH := 0.0
	if details && chk.Recommendation != "" && (chk.Status == "warn" || chk.Status == "fail") {
		sf(f, "", 7)
		recoLines = wrapText(f, latin1(chk.Recommendation), txW-2)
		if len(recoLines) > 0 {
			recoH = 5.5 + float64(len(recoLines))*smallH + 2
		}
	}

	sepH := 0.0
	if explH+recoH > 0 {
		sepH = 3.0
	}

	cardH := padTop + nameH + 1.5 + summH + sepH + explH + recoH + padBot

	// ── Page break ────────────────────────────────────────────────────
	if f.GetY()+cardH > 276 {
		f.AddPage()
		if grpName != "" {
			drawGroupHeader(f, CheckGroup{Name: latin1(grpName) + " (Forts.)"}, nil, w)
		}
	}

	y := f.GetY()

	// ── Draw card ─────────────────────────────────────────────────────
	fc(f, colWhite)
	dc(f, colBorder)
	f.SetLineWidth(0.15)
	f.Rect(x, y, w, cardH, "FD")
	fc(f, col)
	f.Rect(x, y, accent, cardH, "F")

	// Name line
	curY := y + padTop

	// Status badge (right)
	sf(f, "B", 5.5)
	badgeX := x + w - badgeW - padR
	fc(f, col)
	f.RoundedRect(badgeX, curY+0.5, badgeW, 4.5, 0.7, "1234", "F")
	tc(f, colWhite)
	f.SetXY(badgeX, curY+0.5)
	f.CellFormat(badgeW, 4.5, badgeLabel, "", 0, "C", false, 0, "")

	// Score delta
	sf(f, "B", 7)
	tc(f, col)
	f.SetXY(badgeX-deltaW-1, curY+0.5)
	f.CellFormat(deltaW, 4.5, delta, "", 0, "R", false, 0, "")

	// Check name
	sf(f, "B", 8.5)
	tc(f, colDark)
	f.SetXY(txX, curY)
	f.CellFormat(nameW, nameH, latin1(chk.Name), "", 0, "L", false, 0, "")
	curY += nameH + 1.5

	// Summary (all wrapped lines)
	sf(f, "", 7.5)
	tc(f, colSubtext)
	for _, line := range summLines {
		f.SetXY(txX, curY)
		f.CellFormat(txW, lineH, line, "", 0, "L", false, 0, "")
		curY += lineH
	}

	// Detail blocks
	if sepH > 0 {
		curY += 1.5
		dc(f, colBorder)
		f.SetLineWidth(0.12)
		f.Line(x+accent, curY, x+w-0.5, curY)
		curY += 1.5
	}

	if len(explLines) > 0 {
		sf(f, "B", 6.5)
		tc(f, colExplFg)
		f.SetXY(txX, curY)
		f.CellFormat(txW, 5, "Erklaerung", "", 0, "L", false, 0, "")
		curY += 5.5

		sf(f, "", 7)
		for _, line := range explLines {
			f.SetXY(txX+1, curY)
			f.CellFormat(txW-1, smallH, line, "", 0, "L", false, 0, "")
			curY += smallH
		}
		curY += 2

		if len(recoLines) > 0 {
			dc(f, colBorder)
			f.SetLineWidth(0.1)
			f.Line(x+accent, curY, x+w-0.5, curY)
			curY += 1.5
		}
	}

	if len(recoLines) > 0 {
		sf(f, "B", 6.5)
		tc(f, colRecoFg)
		f.SetXY(txX, curY)
		f.CellFormat(txW, 5, "Empfehlung", "", 0, "L", false, 0, "")
		curY += 5.5

		sf(f, "", 7)
		tc(f, colRecoFg)
		for _, line := range recoLines {
			f.SetXY(txX+1, curY)
			f.CellFormat(txW-1, smallH, line, "", 0, "L", false, 0, "")
			curY += smallH
		}
	}

	f.SetY(y + cardH + 1.5)
}

func filterChecks(checks []model.CheckResult, opts Options) []model.CheckResult {
	out := make([]model.CheckResult, 0, len(checks))
	for _, c := range checks {
		switch c.Status {
		case "pass":
			if opts.IncludePass {
				out = append(out, c)
			}
		case "warn":
			if opts.IncludeWarn {
				out = append(out, c)
			}
		case "fail":
			if opts.IncludeFail {
				out = append(out, c)
			}
		case "info":
			if opts.IncludeInfo {
				out = append(out, c)
			}
		}
	}
	return out
}
