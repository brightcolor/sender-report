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

// CheckGroup is a named group of checks (mirrors web.ReportCheckGroup).
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

// ── Color palette (Bootstrap 5 / AdminLTE light mode) ────────────────────────

type rgb struct{ r, g, b int }

var (
	colPrimary = rgb{13, 110, 253}  // bs-primary
	colSuccess = rgb{25, 135, 84}   // bs-success
	colWarning = rgb{253, 126, 20}  // bs-warning (orange)
	colDanger  = rgb{220, 53, 69}   // bs-danger
	colCyan    = rgb{13, 202, 240}  // bs-info
	colGray    = rgb{108, 117, 125} // bs-secondary
	colLight   = rgb{248, 249, 250} // bs-light  (#f8f9fa)
	colALTEBg  = rgb{244, 246, 249} // AdminLTE body background
	colBorder  = rgb{222, 226, 230} // bs-border (#dee2e6)
	colWhite   = rgb{255, 255, 255}
	colDark    = rgb{33, 37, 41}    // bs-dark (#212529)
	colSubtext = rgb{73, 80, 87}    // slightly lighter than dark

	// Group header: AdminLTE light blue
	colGrpBg = rgb{235, 242, 255}
	colGrpFg = rgb{10, 66, 180}

	// Detail block tints
	colExplBg = rgb{241, 243, 255} // light indigo — explanation
	colExplFg = rgb{73, 80, 87}
	colRecoBg = rgb{255, 248, 230} // light amber — recommendation
	colRecoFg = rgb{102, 68, 3}
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

func statusSymbol(status string) string {
	switch status {
	case "pass":
		return "+"
	case "warn":
		return "!"
	case "fail":
		return "x"
	case "info":
		return "i"
	default:
		return "-"
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

// lighten blends c toward white by factor (0 = original, 1 = white).
func lighten(c rgb, factor float64) rgb {
	lerp := func(a int) int { return a + int(float64(255-a)*factor) }
	return rgb{lerp(c.r), lerp(c.g), lerp(c.b)}
}

// ── Latin-1 conversion ────────────────────────────────────────────────────────

// latin1 converts UTF-8 to fpdf-compatible Latin-1 approximation.
func latin1(s string) string {
	var b strings.Builder
	rep := map[rune]string{
		'ä': "ae", 'ö': "oe", 'ü': "ue",
		'Ä': "Ae", 'Ö': "Oe", 'Ü': "Ue",
		'ß': "ss", '–': "-", '—': "-",
		'‘': "'", '’': "'", '“': "\"", '”': "\"",
		'…': "...", '→': "->", '←': "<-",
		'✓': "+", '✗': "x", '✔': "+",
		'⚠': "!", '•': "*",
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

func setFont(f *fpdf.Fpdf, style string, size float64) { f.SetFont("Helvetica", style, size) }
func setFill(f *fpdf.Fpdf, c rgb)                      { f.SetFillColor(c.r, c.g, c.b) }
func setTextColor(f *fpdf.Fpdf, c rgb)                 { f.SetTextColor(c.r, c.g, c.b) }
func setDraw(f *fpdf.Fpdf, c rgb)                      { f.SetDrawColor(c.r, c.g, c.b) }

// ── Main entry point ──────────────────────────────────────────────────────────

// Generate creates a PDF report and returns the raw bytes.
func Generate(data ReportData, opts Options) ([]byte, error) {
	f := fpdf.New("P", "mm", "A4", "")
	f.SetMargins(14, 14, 14)
	f.SetAutoPageBreak(true, 16)
	f.AddPage()

	pageW, _ := f.GetPageSize()
	cw := pageW - 28 // content width (182mm for A4)

	// Register footer (called automatically on every page by fpdf)
	appNameL1 := latin1(data.AppName)
	f.SetFooterFunc(func() {
		f.SetY(-13)
		setDraw(f, colBorder)
		f.SetLineWidth(0.2)
		f.Line(14, f.GetY(), pageW-14, f.GetY())
		f.Ln(1)
		setFont(f, "", 6.5)
		setTextColor(f, colGray)
		f.CellFormat(0, 4,
			fmt.Sprintf("%s  –  Deliverability Report  –  Seite %d", appNameL1, f.PageNo()),
			"", 0, "C", false, 0, "")
	})

	drawHeader(f, data, pageW)

	if opts.IncludeHero {
		drawHero(f, data, cw)
		f.Ln(4)
	}
	if opts.IncludeMeta {
		drawMeta(f, data, cw)
		f.Ln(4)
	}

	for _, grp := range data.Groups {
		checks := filterChecks(grp.Checks, opts)
		if len(checks) == 0 {
			continue
		}
		if f.GetY() > 248 {
			f.AddPage()
		}
		drawGroupHeader(f, grp, cw)
		for _, chk := range checks {
			drawCheck(f, chk, cw, opts.IncludeDetails)
		}
		f.Ln(3)
	}

	var buf bytes.Buffer
	if err := f.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ── Section renderers ─────────────────────────────────────────────────────────

// drawHeader renders the blue top bar + the light info strip below it.
func drawHeader(f *fpdf.Fpdf, data ReportData, pageW float64) {
	const barH, stripH = 22.0, 9.0

	// ── Blue bar ──────────────────────────────────────────────────────
	setFill(f, colPrimary)
	f.Rect(0, 0, pageW, barH, "F")

	// Logo: white rounded square
	setFill(f, colWhite)
	f.RoundedRect(10, 5, 12, 12, 1.5, "1234", "F")
	// Envelope body (primary blue on white)
	setFill(f, colPrimary)
	f.Rect(11.5, 7, 9, 6, "F")
	// Envelope V-flap (white lines)
	setDraw(f, colWhite)
	f.SetLineWidth(0.55)
	f.Line(11.5, 7.5, 16, 11)
	f.Line(16, 11, 20.5, 7.5)
	// Green check badge (bottom-right of logo)
	setFill(f, colSuccess)
	f.Circle(21, 16, 3, "F")
	setTextColor(f, colWhite)
	setFont(f, "B", 5.5)
	f.SetXY(19.2, 14.2)
	f.CellFormat(3.6, 3.6, "+", "", 0, "C", false, 0, "")

	// App name (left)
	setTextColor(f, colWhite)
	setFont(f, "B", 12)
	f.SetXY(25, 7)
	f.CellFormat(90, 8, latin1(data.AppName), "", 0, "L", false, 0, "")

	// "DELIVERABILITY REPORT" (right-aligned)
	setFont(f, "", 8)
	f.SetXY(0, 7)
	f.CellFormat(pageW-13, 8, "DELIVERABILITY REPORT", "", 0, "R", false, 0, "")

	// ── Info strip ────────────────────────────────────────────────────
	setFill(f, colLight)
	f.Rect(0, barH, pageW, stripH, "F")
	setDraw(f, colBorder)
	f.SetLineWidth(0.2)
	f.Line(0, barH+stripH, pageW, barH+stripH)

	setFont(f, "", 7.5)
	setTextColor(f, colSubtext)
	f.SetXY(14, barH+2)
	f.CellFormat(75, 5, latin1("Mailbox: "+data.Mailbox.Address), "", 0, "L", false, 0, "")
	f.CellFormat(40, 5, fmt.Sprintf("Score: %.1f / 10", data.Report.Score), "", 0, "C", false, 0, "")
	f.CellFormat(0, 5, latin1("Erstellt: "+data.GeneratedAt.Format("02.01.2006  15:04")), "", 0, "R", false, 0, "")

	f.SetY(barH + stripH + 5)
}

// drawHero renders the score card with donut ring, label and count pills.
func drawHero(f *fpdf.Fpdf, data ReportData, w float64) {
	const (
		x      = 14.0
		cardH  = 38.0
		accentW = 4.0
		ringR  = 14.0  // outer ring radius
		innerR = 9.5   // white inner radius (donut)
	)
	y := f.GetY()
	score := data.Report.Score
	col := scoreColor(score)
	label := scoreLabel(score)

	// ── Card shell ────────────────────────────────────────────────────
	// 1. White fill
	setFill(f, colWhite)
	f.RoundedRect(x, y, w, cardH, 2, "1234", "F")
	// 2. Colored left accent (only left corners rounded)
	setFill(f, col)
	f.Rect(x, y, accentW, cardH, "F")
	f.RoundedRect(x, y, accentW, cardH, 2, "14", "F")
	// 3. Border on top (drawn last so it overlays the accent)
	setDraw(f, colBorder)
	f.SetLineWidth(0.2)
	f.RoundedRect(x, y, w, cardH, 2, "1234", "D")

	// ── Score donut ring ──────────────────────────────────────────────
	cx := x + accentW + 24
	cy := y + cardH/2

	// Gray track
	setFill(f, colALTEBg)
	setDraw(f, colBorder)
	f.SetLineWidth(0.25)
	f.Circle(cx, cy, ringR, "FD")

	// Colored fill (masked by white inner → donut effect)
	setFill(f, col)
	f.Circle(cx, cy, ringR-0.5, "F")

	// White inner circle
	setFill(f, colWhite)
	f.Circle(cx, cy, innerR, "F")

	// Score number
	setFont(f, "B", 13)
	setTextColor(f, col)
	f.SetXY(cx-8, cy-5.5)
	f.CellFormat(16, 7, fmt.Sprintf("%.1f", score), "", 0, "C", false, 0, "")
	// "/10" label
	setFont(f, "", 6)
	setTextColor(f, colGray)
	f.SetXY(cx-8, cy+1.8)
	f.CellFormat(16, 4, "/10", "", 0, "C", false, 0, "")

	// ── Right panel ───────────────────────────────────────────────────
	rx := cx + ringR + 4
	rw := x + w - rx - 4
	ry := y + 5.5

	// "GESAMTSCORE" micro label
	setFont(f, "", 6.5)
	setTextColor(f, colGray)
	f.SetXY(rx, ry)
	f.CellFormat(rw, 4.5, "GESAMTSCORE", "", 1, "L", false, 0, "")

	// Hero label
	setFont(f, "B", 13)
	setTextColor(f, colDark)
	f.SetXY(rx, ry+5)
	f.CellFormat(rw, 9, latin1(label), "", 1, "L", false, 0, "")

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
	pillX := rx
	pillY := ry + 17
	setFont(f, "B", 6)
	for _, p := range pills {
		pCol := statusColor(p.status)
		txt := fmt.Sprintf("%d %s", counts[p.status], p.suffix)
		tw := f.GetStringWidth(txt)
		pillW := tw + 6
		setFill(f, lighten(pCol, 0.82))
		f.RoundedRect(pillX, pillY, pillW, 5.5, 1, "1234", "F")
		setTextColor(f, pCol)
		f.SetXY(pillX, pillY)
		f.CellFormat(pillW, 5.5, txt, "", 0, "C", false, 0, "")
		pillX += pillW + 2.5
	}

	f.SetY(y + cardH)
}

// drawMeta renders the 2×2 metadata info-box grid.
func drawMeta(f *fpdf.Fpdf, data ReportData, w float64) {
	const (
		x      = 14.0
		cellH  = 13.0
		gap    = 4.0
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

	setDraw(f, colBorder)
	f.SetLineWidth(0.2)

	for i, item := range items {
		col := i % 2
		row := i / 2
		ix := x + float64(col)*(cellW+gap)
		iy := y + float64(row)*(cellH+2)

		// Card: white fill + border
		setFill(f, colWhite)
		f.RoundedRect(ix, iy, cellW, cellH, 1.5, "1234", "FD")

		// Left gray accent
		setFill(f, colGray)
		f.Rect(ix, iy, 3, cellH, "F")
		f.RoundedRect(ix, iy, 3, cellH, 1.5, "14", "F")

		// Label (small, muted)
		setFont(f, "", 6.5)
		setTextColor(f, colGray)
		f.SetXY(ix+5, iy+1.5)
		f.CellFormat(cellW-7, 4, latin1(item.label), "", 0, "L", false, 0, "")

		// Value (bold, dark)
		setFont(f, "B", 7.5)
		setTextColor(f, colDark)
		val := item.value
		if len(val) > 44 {
			val = val[:41] + "..."
		}
		f.SetXY(ix+5, iy+6.5)
		f.CellFormat(cellW-7, 5, latin1(val), "", 0, "L", false, 0, "")
	}

	f.SetY(y + 2*(cellH+2))
}

// drawGroupHeader renders a light-blue AdminLTE-style section divider.
func drawGroupHeader(f *fpdf.Fpdf, grp CheckGroup, w float64) {
	const x = 14.0
	const h = 8.5
	y := f.GetY()

	// Light blue background
	setFill(f, colGrpBg)
	f.Rect(x, y, w, h, "F")

	// Primary left accent
	setFill(f, colPrimary)
	f.Rect(x, y, 3, h, "F")

	// Bottom border
	setDraw(f, colBorder)
	f.SetLineWidth(0.15)
	f.Line(x, y+h, x+w, y+h)

	// Group name
	setFont(f, "B", 8)
	setTextColor(f, colGrpFg)
	f.SetXY(x+5, y+2)
	f.CellFormat(w-8, 5, latin1(grp.Name), "", 1, "L", false, 0, "")

	f.Ln(0.5)
}

// drawCheck renders one check row plus optional detail blocks.
func drawCheck(f *fpdf.Fpdf, chk model.CheckResult, w float64, details bool) {
	const (
		x     = 14.0
		rowH  = 11.5
		iconR = 3.5
	)

	// Estimate total height (row + detail blocks) for page-break check
	extraH := 0.0
	if details {
		if chk.Explanation != "" {
			setFont(f, "", 6.5)
			lines := f.SplitLines([]byte(latin1(chk.Explanation)), w-10)
			extraH += float64(len(lines))*4 + 5
		}
		if chk.Recommendation != "" && (chk.Status == "warn" || chk.Status == "fail") {
			setFont(f, "", 6.5)
			lines := f.SplitLines([]byte(latin1(chk.Recommendation)), w-10)
			extraH += float64(len(lines))*4 + 11
		}
	}
	if f.GetY()+rowH+extraH > 275 {
		f.AddPage()
		drawGroupHeader(f, CheckGroup{Name: "(Fortsetzung)"}, w)
	}

	col := statusColor(chk.Status)
	y := f.GetY()

	// ── Row background ────────────────────────────────────────────────
	setFill(f, colWhite)
	f.Rect(x, y, w, rowH, "F")
	// Bottom separator line
	setDraw(f, colBorder)
	f.SetLineWidth(0.12)
	f.Line(x, y+rowH, x+w, y+rowH)

	// Left status stripe (3mm)
	setFill(f, col)
	f.Rect(x, y, 3, rowH, "F")

	// ── Status icon circle ────────────────────────────────────────────
	iconCx := x + 3 + 5.5
	iconCy := y + rowH/2
	setFill(f, col)
	f.Circle(iconCx, iconCy, iconR, "F")
	setTextColor(f, colWhite)
	setFont(f, "B", 7)
	f.SetXY(iconCx-iconR, iconCy-iconR)
	f.CellFormat(iconR*2, iconR*2, statusSymbol(chk.Status), "", 0, "C", false, 0, "")

	// ── Status badge (top-right) ──────────────────────────────────────
	setFont(f, "B", 5.5)
	badgeLabel := statusLabel(chk.Status)
	badgeW := f.GetStringWidth(badgeLabel) + 4
	badgeX := x + w - badgeW - 1.5
	setFill(f, col)
	f.RoundedRect(badgeX, y+3, badgeW, 5, 0.8, "1234", "F")
	setTextColor(f, colWhite)
	f.SetXY(badgeX, y+3)
	f.CellFormat(badgeW, 5, badgeLabel, "", 0, "C", false, 0, "")

	// ── Score delta ───────────────────────────────────────────────────
	setFont(f, "B", 6.5)
	delta := fmt.Sprintf("%+.1f", chk.ScoreDelta)
	deltaW := f.GetStringWidth(delta) + 2
	setTextColor(f, col)
	f.SetXY(badgeX-deltaW-1, y+3)
	f.CellFormat(deltaW, 5, delta, "", 0, "R", false, 0, "")

	// ── Check name ────────────────────────────────────────────────────
	nameX := iconCx + iconR + 2.5
	nameW := badgeX - deltaW - nameX - 2
	setFont(f, "B", 7.5)
	setTextColor(f, colDark)
	f.SetXY(nameX, y+1.5)
	f.CellFormat(nameW, 5, latin1(chk.Name), "", 0, "L", false, 0, "")

	// ── Summary (first wrapped line) ──────────────────────────────────
	setFont(f, "", 6.5)
	setTextColor(f, colGray)
	summLines := f.SplitLines([]byte(latin1(chk.Summary)), nameW)
	if len(summLines) > 0 {
		f.SetXY(nameX, y+6.5)
		f.CellFormat(nameW, 4, string(summLines[0]), "", 0, "L", false, 0, "")
	}

	f.SetY(y + rowH)

	if !details {
		return
	}

	// ── Detail blocks ─────────────────────────────────────────────────
	if chk.Explanation != "" {
		drawDetailBox(f, latin1(chk.Explanation), w, colExplBg, colExplFg, "Erklaerung")
	}
	if chk.Recommendation != "" && (chk.Status == "warn" || chk.Status == "fail") {
		drawDetailBox(f, latin1(chk.Recommendation), w, colRecoBg, colRecoFg, "Empfehlung")
	}
}

// drawDetailBox renders a tinted labeled text block below a check row.
func drawDetailBox(f *fpdf.Fpdf, text string, w float64, bg, fg rgb, headerLabel string) {
	const x = 14.0

	// Header label row
	const hdrH = 5.5
	yy := f.GetY()
	if yy+hdrH > 278 {
		f.AddPage()
		yy = f.GetY()
	}
	setFill(f, bg)
	f.Rect(x, yy, w, hdrH, "F")
	setFont(f, "B", 6.5)
	setTextColor(f, fg)
	f.SetXY(x+4, yy+1)
	f.CellFormat(w-8, hdrH-1, headerLabel, "", 1, "L", false, 0, "")

	// Text body
	setFont(f, "", 6.5)
	lines := f.SplitLines([]byte(text), w-10)
	bodyH := float64(len(lines))*4 + 4

	yy = f.GetY()
	if yy+bodyH > 278 {
		f.AddPage()
		yy = f.GetY()
	}
	// Slightly lighter bg for body
	setFill(f, lighten(bg, 0.3))
	f.Rect(x, yy, w, bodyH, "F")
	setTextColor(f, fg)
	f.SetXY(x+4, yy+2)
	for _, line := range lines {
		f.SetX(x + 4)
		f.CellFormat(w-8, 4, string(line), "", 1, "L", false, 0, "")
	}
	f.Ln(1)
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
