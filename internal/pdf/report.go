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

// colour constants (R,G,B)
type rgb struct{ r, g, b int }

var (
	colBlue    = rgb{13, 110, 253}
	colGreen   = rgb{25, 135, 84}
	colOrange  = rgb{253, 126, 20}
	colRed     = rgb{220, 53, 69}
	colCyan    = rgb{13, 202, 240}
	colGray    = rgb{108, 117, 125}
	colLightBg = rgb{248, 249, 250}
	colBorder  = rgb{222, 226, 230}
	colWhite   = rgb{255, 255, 255}
	colBlack   = rgb{33, 37, 41}
	colDkGray  = rgb{73, 80, 87}
)

func statusColor(status string) rgb {
	switch status {
	case "pass":
		return colGreen
	case "warn":
		return colOrange
	case "fail":
		return colRed
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

// latin1 converts a UTF-8 string to fpdf-compatible Latin-1 approximation.
// Characters outside Latin-1 are replaced by a safe ASCII approximation.
func latin1(s string) string {
	var b strings.Builder
	replacements := map[rune]string{
		'ä': "ae", 'ö': "oe", 'ü': "ue", 'Ä': "Ae", 'Ö': "Oe", 'Ü': "Ue",
		'ß': "ss", '–': "-", '—': "-", '‘': "'", '’': "'",
		'“': "\"", '”': "\"", '…': "...", '→': "->", '←': "<-",
		'✓': "+", '✗': "x", '✔': "+", '⚠': "!", '•': "*",
	}
	for _, r := range s {
		if r < 128 {
			b.WriteRune(r)
			continue
		}
		if sub, ok := replacements[r]; ok {
			b.WriteString(sub)
			continue
		}
		if utf8.RuneLen(r) <= 2 && r <= 0xFF {
			// Latin-1 supplement — fpdf handles these natively
			b.WriteRune(r)
		}
		// else: skip unknown characters
	}
	return b.String()
}

// Generate creates a PDF report and returns the raw bytes.
func Generate(data ReportData, opts Options) ([]byte, error) {
	f := fpdf.New("P", "mm", "A4", "")
	f.SetMargins(14, 14, 14)
	f.SetAutoPageBreak(true, 14)
	f.AddPage()

	pageW, _ := f.GetPageSize()
	contentW := pageW - 28 // left + right margin

	// ── Header bar ────────────────────────────────────────────────────────
	drawHeader(f, data, pageW)
	f.Ln(6)

	// ── Score Hero ────────────────────────────────────────────────────────
	if opts.IncludeHero {
		drawHero(f, data, contentW)
		f.Ln(4)
	}

	// ── Metadaten ─────────────────────────────────────────────────────────
	if opts.IncludeMeta {
		drawMeta(f, data, contentW)
		f.Ln(4)
	}

	// ── Check-Gruppen ─────────────────────────────────────────────────────
	for _, grp := range data.Groups {
		checks := filterChecks(grp.Checks, opts)
		if len(checks) == 0 {
			continue
		}
		drawGroupHeader(f, grp, contentW)
		for _, chk := range checks {
			drawCheck(f, chk, contentW, opts.IncludeDetails)
		}
		f.Ln(3)
	}

	// ── Footer auf jeder Seite ─────────────────────────────────────────────
	f.SetFooterFunc(func() {
		f.SetY(-12)
		setFont(f, "", 7)
		setTextColor(f, colGray)
		f.CellFormat(0, 4,
			fmt.Sprintf("%s  –  Deliverability Report  –  Seite %d", data.AppName, f.PageNo()),
			"", 0, "C", false, 0, "")
	})

	var buf bytes.Buffer
	if err := f.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ── Drawing helpers ────────────────────────────────────────────────────────

func setFont(f *fpdf.Fpdf, style string, size float64) {
	f.SetFont("Helvetica", style, size)
}

func setFillColor(f *fpdf.Fpdf, c rgb) {
	f.SetFillColor(c.r, c.g, c.b)
}

func setTextColor(f *fpdf.Fpdf, c rgb) {
	f.SetTextColor(c.r, c.g, c.b)
}

func setDrawColor(f *fpdf.Fpdf, c rgb) {
	f.SetDrawColor(c.r, c.g, c.b)
}

func drawHeader(f *fpdf.Fpdf, data ReportData, pageW float64) {
	// Blue background bar
	setFillColor(f, colBlue)
	f.Rect(0, 0, pageW, 22, "F")

	// Logo mark (small filled square + green dot)
	setFillColor(f, colWhite)
	f.RoundedRect(10, 5, 12, 12, 1.5, "1234", "F")

	// Envelope body (blue on white)
	setFillColor(f, colBlue)
	f.Rect(11.5, 7, 9, 6, "F")
	// Envelope flap (V-shape approximation via lines)
	setDrawColor(f, colBlue)
	f.SetLineWidth(0.5)
	f.Line(11.5, 7.5, 16, 11)
	f.Line(16, 11, 20.5, 7.5)

	// Green check badge (tiny filled circle bottom-right of logo)
	setFillColor(f, colGreen)
	f.Circle(21, 16, 3, "F")
	setTextColor(f, colWhite)
	setFont(f, "B", 5)
	f.SetXY(19.2, 14.2)
	f.CellFormat(3.6, 3.6, "+", "", 0, "C", false, 0, "")

	// App name
	setTextColor(f, colWhite)
	setFont(f, "B", 13)
	f.SetXY(25, 6.5)
	f.CellFormat(80, 8, latin1(data.AppName), "", 0, "L", false, 0, "")

	// Document type (right-aligned)
	setFont(f, "", 8)
	f.SetXY(0, 6.5)
	f.CellFormat(pageW-12, 8, "DELIVERABILITY REPORT", "", 0, "R", false, 0, "")

	// Sub-line: mailbox | score | date
	setFillColor(f, colLightBg)
	f.Rect(0, 22, pageW, 10, "F")
	setDrawColor(f, colBorder)
	f.SetLineWidth(0.2)
	f.Line(0, 32, pageW, 32)

	setTextColor(f, colDkGray)
	setFont(f, "", 8)
	f.SetXY(14, 24.5)
	scoreStr := fmt.Sprintf("%.1f/10", data.Report.Score)
	dateStr := data.GeneratedAt.Format("02.01.2006  15:04")
	f.CellFormat(70, 5, latin1("Mailbox: "+data.Mailbox.Address), "", 0, "L", false, 0, "")
	f.CellFormat(35, 5, "Score: "+scoreStr, "", 0, "C", false, 0, "")
	f.CellFormat(0, 5, latin1("Erstellt: "+dateStr), "", 0, "R", false, 0, "")

	f.SetY(36)
}

func drawHero(f *fpdf.Fpdf, data ReportData, w float64) {
	x := f.GetX()
	y := f.GetY()
	score := data.Report.Score

	// Determine hero color
	heroColor := colGreen
	heroLabel := "Sehr gut"
	switch {
	case score >= 9:
		heroColor = colGreen
		heroLabel = "Ausgezeichnet"
	case score >= 7.5:
		heroColor = colGreen
		heroLabel = "Sehr gut"
	case score >= 5.5:
		heroColor = colOrange
		heroLabel = "Verbesserungsbedarf"
	default:
		heroColor = colRed
		heroLabel = "Kritisch"
	}

	// Card background
	setFillColor(f, colLightBg)
	setDrawColor(f, colBorder)
	f.SetLineWidth(0.2)
	f.RoundedRect(x, y, w, 32, 2, "1234", "FD")

	// Left accent stripe (colored)
	setFillColor(f, heroColor)
	f.RoundedRect(x, y, 3, 32, 2, "1234", "F")
	f.Rect(x+1.5, y, 1.5, 32, "F")

	// Score circle
	cx := x + 22
	cy := y + 16
	setFillColor(f, heroColor)
	f.Circle(cx, cy, 12, "F")
	setTextColor(f, colWhite)
	setFont(f, "B", 14)
	scoreText := fmt.Sprintf("%.1f", score)
	f.SetXY(cx-9, cy-6)
	f.CellFormat(18, 8, scoreText, "", 0, "C", false, 0, "")
	setFont(f, "", 6)
	f.SetXY(cx-9, cy+2)
	f.CellFormat(18, 4, "/10", "", 0, "C", false, 0, "")

	// Hero label + subtitle
	setTextColor(f, colBlack)
	setFont(f, "B", 13)
	f.SetXY(x+38, y+5)
	f.CellFormat(w-42, 8, latin1(heroLabel), "", 0, "L", false, 0, "")

	// Count pills
	counts := map[string]int{"pass": 0, "warn": 0, "fail": 0, "info": 0}
	for _, c := range data.Report.Checks {
		counts[c.Status]++
	}
	pillX := x + 38
	pillY := y + 16
	for _, pair := range []struct {
		status string
		label  string
	}{
		{"pass", "bestanden"}, {"warn", "Warnungen"}, {"fail", "Fehler"}, {"info", "Infos"},
	} {
		col := statusColor(pair.status)
		n := counts[pair.status]
		label := fmt.Sprintf("%d %s", n, pair.label)
		setFillColor(f, col)
		setTextColor(f, colWhite)
		setFont(f, "B", 7)
		lw := float64(len(label))*1.9 + 6
		f.RoundedRect(pillX, pillY, lw, 6, 1, "1234", "F")
		f.SetXY(pillX, pillY)
		f.CellFormat(lw, 6, latin1(label), "", 0, "C", false, 0, "")
		pillX += lw + 3
	}

	f.SetY(y + 36)
}

func drawMeta(f *fpdf.Fpdf, data ReportData, w float64) {
	y := f.GetY()
	x := f.GetX()
	cellW := (w - 4) / 2
	h := 12.0

	type metaItem struct{ label, value string }
	subject := data.Message.Subject
	if subject == "" {
		subject = "(kein Betreff)"
	}
	received := ""
	if !data.Message.ReceivedAt.IsZero() {
		received = data.Message.ReceivedAt.Format("02.01.2006 15:04:05")
	} else {
		received = "(verschluesselt)"
	}
	smtpFrom := data.Message.SMTPFrom
	if smtpFrom == "" {
		smtpFrom = "(leer)"
	}
	source := data.Message.RemoteIP
	if data.Message.HELO != "" {
		source += " / " + data.Message.HELO
	}

	items := []metaItem{
		{"Betreff", subject},
		{"Empfangen", received},
		{"Envelope-From", smtpFrom},
		{"Quelle", source},
	}

	setDrawColor(f, colBorder)
	f.SetLineWidth(0.2)
	for i, item := range items {
		col := i % 2
		row := i / 2
		ix := x + float64(col)*(cellW+4)
		iy := y + float64(row)*(h+2)

		setFillColor(f, colLightBg)
		f.RoundedRect(ix, iy, cellW, h, 1.5, "1234", "FD")

		setTextColor(f, colGray)
		setFont(f, "", 7)
		f.SetXY(ix+3, iy+1.5)
		f.CellFormat(cellW-6, 4, latin1(item.label), "", 0, "L", false, 0, "")

		setTextColor(f, colBlack)
		setFont(f, "B", 8)
		f.SetXY(ix+3, iy+5.5)
		// Truncate long values
		val := item.value
		if len(val) > 45 {
			val = val[:42] + "..."
		}
		f.CellFormat(cellW-6, 5, latin1(val), "", 0, "L", false, 0, "")
	}

	f.SetY(y + float64(len(items)/2)*(h+2) + 2)
}

func drawGroupHeader(f *fpdf.Fpdf, grp CheckGroup, w float64) {
	f.SetX(14)
	y := f.GetY()
	if y > 260 {
		f.AddPage()
	}

	setFillColor(f, colBlue)
	setTextColor(f, colWhite)
	f.SetLineWidth(0)
	f.RoundedRect(14, f.GetY(), w, 8, 1.5, "1234", "F")
	setFont(f, "B", 9)
	f.SetXY(17, f.GetY()+1.5)
	f.CellFormat(w-6, 5, latin1(grp.Name), "", 1, "L", false, 0, "")
	f.Ln(1)
}

func drawCheck(f *fpdf.Fpdf, chk model.CheckResult, w float64, details bool) {
	f.SetX(14)
	y := f.GetY()

	// Estimate needed height
	detailH := 0.0
	if details && chk.Explanation != "" {
		lines := f.SplitLines([]byte(latin1(chk.Explanation)), w-28)
		detailH = float64(len(lines))*4 + 2
	}
	neededH := 10 + detailH
	if y+neededH > 275 {
		f.AddPage()
		drawGroupHeader(f, CheckGroup{Name: "(Fortsetzung)"}, w)
	}

	col := statusColor(chk.Status)
	y = f.GetY()

	// Status bar (left colored stripe)
	setFillColor(f, col)
	f.Rect(14, y, 2, 9, "F")

	// Row background (alternating)
	setFillColor(f, colWhite)
	setDrawColor(f, colBorder)
	f.SetLineWidth(0.15)
	f.Rect(16, y, w-2, 9, "FD")

	// Status badge
	setFillColor(f, col)
	setTextColor(f, colWhite)
	setFont(f, "B", 6)
	badgeLabel := statusLabel(chk.Status)
	badgeW := float64(len(badgeLabel))*1.6 + 4
	f.RoundedRect(w-badgeW, y+1.5, badgeW, 5, 0.8, "1234", "F")
	f.SetXY(w-badgeW, y+1.5)
	f.CellFormat(badgeW, 5, badgeLabel, "", 0, "C", false, 0, "")

	// Score delta
	delta := fmt.Sprintf("%+.1f", chk.ScoreDelta)
	setTextColor(f, col)
	setFont(f, "B", 7)
	f.SetXY(w-badgeW-12, y+2.5)
	f.CellFormat(10, 4, delta, "", 0, "R", false, 0, "")

	// Symbol
	setFillColor(f, col)
	setTextColor(f, colWhite)
	setFont(f, "B", 7)
	f.RoundedRect(17.5, y+2, 5, 5, 0.8, "1234", "F")
	f.SetXY(17.5, y+2)
	f.CellFormat(5, 5, statusSymbol(chk.Status), "", 0, "C", false, 0, "")

	// Check name
	setTextColor(f, colBlack)
	setFont(f, "B", 8)
	f.SetXY(24, y+1.5)
	f.CellFormat(w-60, 4.5, latin1(chk.Name), "", 0, "L", false, 0, "")

	// Summary
	setTextColor(f, colDkGray)
	setFont(f, "", 7)
	f.SetXY(24, y+5.5)
	summary := chk.Summary
	if len(summary) > 80 {
		summary = summary[:77] + "..."
	}
	f.CellFormat(w-60, 3.5, latin1(summary), "", 0, "L", false, 0, "")

	f.SetY(y + 9)

	// Details (explanation)
	if details && chk.Explanation != "" {
		f.SetX(16)
		setFillColor(f, rgb{238, 242, 250})
		setTextColor(f, colDkGray)
		setFont(f, "", 7)

		lines := f.SplitLines([]byte(latin1(chk.Explanation)), w-28)
		blockH := float64(len(lines))*4 + 3
		yy := f.GetY()
		f.Rect(16, yy, w-2, blockH, "F")
		f.SetXY(19, yy+1.5)
		for _, line := range lines {
			f.SetX(19)
			f.CellFormat(w-10, 4, string(line), "", 1, "L", false, 0, "")
		}
		f.Ln(1)
	}
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
