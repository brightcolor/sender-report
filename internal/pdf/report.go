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

// Options controls which sections appear in the generated PDF.
type Options struct {
	IncludePass    bool
	IncludeWarn    bool
	IncludeFail    bool
	IncludeInfo    bool
	IncludeHero    bool
	IncludeMeta    bool
	IncludeDetails bool
}

// CheckGroup is a named group of checks.
type CheckGroup struct {
	Name   string
	Hint   string
	Checks []model.CheckResult
}

// ReportData holds everything the PDF generator needs.
type ReportData struct {
	AppName     string
	PublicURL   string
	Mailbox     model.Mailbox
	Message     model.Message
	Report      model.AnalysisReport
	Groups      []CheckGroup
	GeneratedAt time.Time
}

// ── Colour palette (Bootstrap 5 / AdminLTE light) ─────────────────────────────

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

	colExplFg = rgb{50, 60, 120}   // explanation label / text
	colRecoFg = rgb{102, 68, 3}    // recommendation label / text
)

// ── Status helpers ────────────────────────────────────────────────────────────

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

// ── Latin-1 helper ────────────────────────────────────────────────────────────

func latin1(s string) string {
	var b strings.Builder
	rep := map[rune]string{
		'ä': "ae", 'ö': "oe", 'ü': "ue",
		'Ä': "Ae", 'Ö': "Oe", 'Ü': "Ue",
		'ß': "ss",
		'–': "-", '—': "-",      // en dash, em dash
		'‘': "'", '’': "'",      // curly single quotes
		'“': "\"", '”': "\"",    // curly double quotes
		'…': "...",                   // ellipsis
		'→': "->", '←': "<-",   // arrows
		'✓': "+", '✗': "x", '✔': "+", // check marks
		'⚠': "!", '•': "*",      // warning, bullet
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
	}
	return b.String()
}

// ── Drawing primitives ────────────────────────────────────────────────────────

func sf(f *fpdf.Fpdf, style string, pt float64) { f.SetFont("Helvetica", style, pt) }
func fc(f *fpdf.Fpdf, c rgb)                    { f.SetFillColor(c.r, c.g, c.b) }
func tc(f *fpdf.Fpdf, c rgb)                    { f.SetTextColor(c.r, c.g, c.b) }
func dc(f *fpdf.Fpdf, c rgb)                    { f.SetDrawColor(c.r, c.g, c.b) }

// wrapLines splits text into lines that fit within maxW at the current font.
func wrapLines(f *fpdf.Fpdf, text string, maxW float64) []string {
	raw := f.SplitLines([]byte(text), maxW)
	out := make([]string, len(raw))
	for i, b := range raw {
		out[i] = string(b)
	}
	return out
}

// ── Main entry point ──────────────────────────────────────────────────────────

// Generate creates a PDF and returns the raw bytes.
func Generate(data ReportData, opts Options) ([]byte, error) {
	f := fpdf.New("P", "mm", "A4", "")
	f.SetMargins(14, 14, 14)
	f.SetAutoPageBreak(true, 16)
	f.AddPage()

	pageW, _ := f.GetPageSize()
	cw := pageW - 28 // 182 mm content width

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
			fmt.Sprintf("%s  –  Deliverability Report  –  Seite %d", appL, f.PageNo()),
			"", 0, "C", false, 0, "")
	})

	drawHeader(f, data, pageW)

	if opts.IncludeHero {
		drawHero(f, data, cw)
		f.Ln(5)
	}
	if opts.IncludeMeta {
		drawMeta(f, data, cw)
		f.Ln(5)
	}

	for _, grp := range data.Groups {
		checks := filterChecks(grp.Checks, opts)
		if len(checks) == 0 {
			continue
		}
		if f.GetY() > 250 {
			f.AddPage()
		}
		drawGroupHeader(f, grp, cw)
		for _, chk := range checks {
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

// ── Section renderers ─────────────────────────────────────────────────────────

func drawHeader(f *fpdf.Fpdf, data ReportData, pageW float64) {
	const barH, stripH = 22.0, 9.0

	// Blue bar
	fc(f, colPrimary)
	f.Rect(0, 0, pageW, barH, "F")

	// Logo mark: white rounded square
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

	// App name
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

// drawHero uses a coloured sidebar panel with a large score number –
// no circles that look rough in PDF renderers.
func drawHero(f *fpdf.Fpdf, data ReportData, w float64) {
	const (
		x       = 14.0
		cardH   = 42.0
		sideW   = 46.0 // coloured left panel
		padSide = 4.0  // inner padding of right panel
	)
	y := f.GetY()
	col := scoreColor(data.Report.Score)
	label := scoreLabel(data.Report.Score)

	// Card shell: white fill + border
	fc(f, colWhite)
	dc(f, colBorder)
	f.SetLineWidth(0.2)
	f.RoundedRect(x, y, w, cardH, 2, "1234", "F")

	// Coloured left panel (left corners rounded)
	fc(f, col)
	f.Rect(x, y, sideW, cardH, "F")
	f.RoundedRect(x, y, sideW, cardH, 2, "14", "F")

	// Border on top
	dc(f, colBorder)
	f.RoundedRect(x, y, w, cardH, 2, "1234", "D")

	// Subtle vertical divider
	f.SetLineWidth(0.12)
	f.Line(x+sideW, y+2, x+sideW, y+cardH-2)

	// ── Score number (centred in left panel) ─────────────────────────
	scoreStr := fmt.Sprintf("%.1f", data.Report.Score)
	sf(f, "B", 26)
	tc(f, colWhite)
	sw := f.GetStringWidth(scoreStr)
	f.SetXY(x+(sideW-sw)/2, y+8)
	f.CellFormat(sw, 16, scoreStr, "", 0, "L", false, 0, "")

	sf(f, "", 8.5)
	tenStr := "/ 10"
	tw := f.GetStringWidth(tenStr)
	f.SetXY(x+(sideW-tw)/2, y+25)
	f.CellFormat(tw, 6, tenStr, "", 0, "L", false, 0, "")

	// Status label under score (e.g. "SEHR GUT")
	sf(f, "B", 6)
	labelUp := strings.ToUpper(label)
	lw := f.GetStringWidth(labelUp)
	tc(f, lighten(col, 0.6))
	f.SetXY(x+(sideW-lw)/2, y+32)
	f.CellFormat(lw, 5, labelUp, "", 0, "L", false, 0, "")

	// ── Right panel ───────────────────────────────────────────────────
	rx := x + sideW + padSide
	rw := w - sideW - padSide - 3

	sf(f, "", 6.5)
	tc(f, colGray)
	f.SetXY(rx, y+5)
	f.CellFormat(rw, 4, "GESAMTSCORE", "", 0, "L", false, 0, "")

	sf(f, "B", 14)
	tc(f, colDark)
	f.SetXY(rx, y+10)
	f.CellFormat(rw, 9, latin1(label), "", 0, "L", false, 0, "")

	// Count pills
	counts := map[string]int{"pass": 0, "warn": 0, "fail": 0, "info": 0}
	for _, c := range data.Report.Checks {
		counts[c.Status]++
	}
	pills := []struct{ status, suffix string }{
		{"pass", "bestanden"},
		{"warn", "Warnungen"},
		{"fail", "Fehler"},
		{"info", "Infos"},
	}
	pillX, pillY := rx, y+22
	sf(f, "B", 6.5)
	for _, p := range pills {
		pc := statusColor(p.status)
		txt := fmt.Sprintf("%d %s", counts[p.status], p.suffix)
		tw2 := f.GetStringWidth(txt)
		pw := tw2 + 6
		if pillX+pw > x+w-3 {
			pillX = rx
			pillY += 8
		}
		fc(f, lighten(pc, 0.82))
		f.RoundedRect(pillX, pillY, pw, 6, 1, "1234", "F")
		tc(f, pc)
		f.SetXY(pillX, pillY)
		f.CellFormat(pw, 6, txt, "", 0, "C", false, 0, "")
		pillX += pw + 3
	}

	f.SetY(y + cardH)
}

func drawMeta(f *fpdf.Fpdf, data ReportData, w float64) {
	const (
		x     = 14.0
		cellH = 14.0
		gap   = 4.0
	)
	y := f.GetY()
	cellW := (w - gap) / 2

	subject := data.Message.Subject
	if subject == "" {
		subject = "(kein Betreff)"
	}
	received := "(verschluesselt)"
	if !data.Message.ReceivedAt.IsZero() {
		received = data.Message.ReceivedAt.Format("02.01.2006  15:04:05")
	}
	smtpFrom := data.Message.SMTPFrom
	if smtpFrom == "" {
		smtpFrom = "(leer)"
	}
	source := data.Message.RemoteIP
	if data.Message.HELO != "" {
		source += " / " + data.Message.HELO
	}

	items := [4]struct{ label, value string }{
		{"Betreff", subject},
		{"Empfangen", received},
		{"Envelope-From", smtpFrom},
		{"Quelle", source},
	}

	dc(f, colBorder)
	f.SetLineWidth(0.2)

	for i, item := range items {
		col := i % 2
		row := i / 2
		ix := x + float64(col)*(cellW+gap)
		iy := y + float64(row)*(cellH+2)

		fc(f, colWhite)
		f.RoundedRect(ix, iy, cellW, cellH, 1.5, "1234", "FD")

		// Coloured top line (thin, primary)
		fc(f, colPrimary)
		f.Rect(ix+1.5, iy, cellW-3, 2, "F")

		sf(f, "", 6.5)
		tc(f, colGray)
		f.SetXY(ix+4, iy+4)
		f.CellFormat(cellW-6, 4, latin1(item.label), "", 0, "L", false, 0, "")

		sf(f, "B", 8)
		tc(f, colDark)
		val := item.value
		sf(f, "B", 8)
		// Truncate if too wide
		for len(val) > 3 && f.GetStringWidth(latin1(val)) > cellW-8 {
			val = val[:len(val)-4] + "..."
		}
		f.SetXY(ix+4, iy+8.5)
		f.CellFormat(cellW-6, 5, latin1(val), "", 0, "L", false, 0, "")
	}

	f.SetY(y + 2*(cellH+2))
}

func drawGroupHeader(f *fpdf.Fpdf, grp CheckGroup, w float64) {
	const x, h = 14.0, 8.0
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
	f.SetXY(x+5, y+1.5)
	f.CellFormat(w-8, 5, latin1(grp.Name), "", 1, "L", false, 0, "")
	f.Ln(1)
}

// drawCheckCard renders a self-contained card for one check.
// Card height is calculated from the actual text content, so nothing is clipped.
func drawCheckCard(f *fpdf.Fpdf, chk model.CheckResult, w float64, details bool, grpName string) {
	const (
		x      = 14.0
		accent = 4.0 // left coloured stripe
		padL   = 5.0 // padding left of text
		padR   = 4.0 // padding right
		padTop = 3.5
		padBot = 3.5
		nameH  = 5.5  // name line height
		lineH  = 4.5  // body text line height
		smallH = 4.0  // detail text line height
	)

	col := statusColor(chk.Status)
	txX := x + accent + padL   // text content starts here
	txW := w - accent - padL - padR

	// ── Pre-measure all content ───────────────────────────────────────
	// Name (badge width we need first)
	sf(f, "B", 5.5)
	badgeLabel := statusLabel(chk.Status)
	badgeW := f.GetStringWidth(badgeLabel) + 5
	sf(f, "B", 7)
	delta := fmt.Sprintf("%+.1f", chk.ScoreDelta)
	deltaW := f.GetStringWidth(delta) + 3

	nameW := txW - badgeW - deltaW - 2

	// Summary lines
	sf(f, "", 7.5)
	summLines := wrapLines(f, latin1(chk.Summary), txW)
	summH := float64(len(summLines)) * lineH

	// Explanation
	var explLines []string
	explH := 0.0
	if details && chk.Explanation != "" {
		sf(f, "", 7)
		explLines = wrapLines(f, latin1(chk.Explanation), txW-2)
		explH = 5.0 + float64(len(explLines))*smallH + 2
	}

	// Recommendation (warn/fail only)
	var recoLines []string
	recoH := 0.0
	if details && chk.Recommendation != "" && (chk.Status == "warn" || chk.Status == "fail") {
		sf(f, "", 7)
		recoLines = wrapLines(f, latin1(chk.Recommendation), txW-2)
		recoH = 5.0 + float64(len(recoLines))*smallH + 2
	}

	sepH := 0.0
	if explH+recoH > 0 {
		sepH = 2.0 // gap + separator before detail blocks
	}

	cardH := padTop + nameH + 1.5 + summH + sepH + explH + recoH + padBot

	// ── Page break ────────────────────────────────────────────────────
	if f.GetY()+cardH > 276 {
		f.AddPage()
		if grpName != "" {
			drawGroupHeader(f, CheckGroup{Name: latin1(grpName) + " (Fortsetzung)"}, w)
		}
	}

	y := f.GetY()

	// ── Card background + left accent ─────────────────────────────────
	fc(f, colWhite)
	dc(f, colBorder)
	f.SetLineWidth(0.15)
	f.Rect(x, y, w, cardH, "FD")
	fc(f, col)
	f.Rect(x, y, accent, cardH, "F")

	// ── Name line ─────────────────────────────────────────────────────
	curY := y + padTop

	// Status badge (right-aligned)
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

	// ── Summary (all wrapped lines) ───────────────────────────────────
	sf(f, "", 7.5)
	tc(f, colSubtext)
	for _, line := range summLines {
		f.SetXY(txX, curY)
		f.CellFormat(txW, lineH, line, "", 0, "L", false, 0, "")
		curY += lineH
	}

	// ── Detail blocks ─────────────────────────────────────────────────
	if sepH > 0 {
		curY += 1.5
		dc(f, colBorder)
		f.SetLineWidth(0.12)
		f.Line(x+accent, curY, x+w-0.5, curY)
		curY += 1
	}

	// Explanation
	if len(explLines) > 0 {
		sf(f, "B", 6.5)
		tc(f, colExplFg)
		f.SetXY(txX, curY)
		f.CellFormat(txW, 5, "Erklaerung", "", 0, "L", false, 0, "")
		curY += 5

		sf(f, "", 7)
		tc(f, colExplFg)
		for _, line := range explLines {
			f.SetXY(txX+1, curY)
			f.CellFormat(txW-1, smallH, line, "", 0, "L", false, 0, "")
			curY += smallH
		}
		curY += 2

		// Separator between expl and reco
		if len(recoLines) > 0 {
			dc(f, colBorder)
			f.SetLineWidth(0.1)
			f.Line(x+accent, curY, x+w-0.5, curY)
			curY += 1.5
		}
	}

	// Recommendation
	if len(recoLines) > 0 {
		sf(f, "B", 6.5)
		tc(f, colRecoFg)
		f.SetXY(txX, curY)
		f.CellFormat(txW, 5, "Empfehlung", "", 0, "L", false, 0, "")
		curY += 5

		sf(f, "", 7)
		tc(f, colRecoFg)
		for _, line := range recoLines {
			f.SetXY(txX+1, curY)
			f.CellFormat(txW-1, smallH, line, "", 0, "L", false, 0, "")
			curY += smallH
		}
	}

	f.SetY(y + cardH + 1.5) // gap between cards
}

// filterChecks returns only the checks matching the given options.
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
