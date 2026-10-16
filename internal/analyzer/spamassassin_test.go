package analyzer

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
)

// Antwort von spamd auf REPORT, wie sie das Standard-Berichtsmuster liefert.
const spamdReport = "SPAMD/1.1 0 EX_OK\r\nContent-length: 600\r\nSpam: False ; 3.5 / 5.0\r\n\r\n" +
	"Spam detection software, running on the system \"mx\",\r\nhas NOT identified this incoming email as spam.\r\n\r\n" +
	"Content analysis details:   (3.5 points, 5.0 required)\r\n\r\n" +
	" pts rule name              description\r\n" +
	"---- ---------------------- --------------------------------------------------\r\n" +
	" 2.0 MISSING_SUBJECT        Missing Subject: header\r\n" +
	" 1.5 URIBL_BLOCKED          ADMINISTRATOR NOTICE: The query to URIBL was blocked.\r\n" +
	"                            See\r\n" +
	"                            http://wiki.apache.org/spamassassin/DnsBlocklists\r\n" +
	"                             for more information.\r\n" +
	"-0.0 SPF_PASS               SPF: sender matches SPF record\r\n" +
	" 0.0 HTML_MESSAGE           BODY: HTML included in message\r\n"

func TestParseSpamAssassinReport(t *testing.T) {
	rules := parseSpamAssassinReport(spamdReport)
	if len(rules) != 4 {
		t.Fatalf("%d Regeln gelesen, erwartet 4: %+v", len(rules), rules)
	}
	if rules[0].Name != "MISSING_SUBJECT" || rules[0].Score != 2.0 || rules[1].Name != "URIBL_BLOCKED" {
		t.Errorf("Reihenfolge nach Gewicht falsch: %+v", rules)
	}
	if !strings.Contains(rules[1].Description, "was blocked. See http://wiki.apache.org") || !strings.HasSuffix(rules[1].Description, "for more information.") {
		t.Errorf("mehrzeilige Beschreibung nicht zusammengefügt: %q", rules[1].Description)
	}
	if got := parseSpamAssassinReport("SPAMD/1.1 0 EX_OK\r\nSpam: False ; 1.0 / 5.0\r\n\r\nkein Bericht"); len(got) != 0 {
		t.Errorf("ohne Tabelle keine Regeln, war %+v", got)
	}
}

func TestSpamAssassinAdviceNamesTheBiggestRules(t *testing.T) {
	got := spamAssassinAdvice(parseSpamAssassinReport(spamdReport))
	for _, w := range []string{"MISSING_SUBJECT (+2.0)", "URIBL_BLOCKED (+1.5)", "tests_3_4_x.html"} {
		if !strings.Contains(got, w) {
			t.Errorf("Empfehlung sollte %q enthalten: %s", w, got)
		}
	}
	if strings.Contains(got, "SPF_PASS") || strings.Contains(got, "HTML_MESSAGE") {
		t.Errorf("Regeln unter 0,5 Punkten gehören nicht in die Empfehlung: %s", got)
	}
	if got := spamAssassinAdvice(nil); !strings.Contains(got, "Die Regeln stehen in der Tabelle") {
		t.Errorf("ohne Regeln bleibt der allgemeine Hinweis: %s", got)
	}
}

// Ein Fake-spamd: er verlangt REPORT und liefert die Tabelle. Der Befund nennt
// danach die Regeln in den Details und in der Empfehlung.
func TestSpamAssassinCheckListsTheRules(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	gotCmd := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		gotCmd <- strings.TrimSpace(line)
		_, _ = io.WriteString(c, spamdReport)
	}()

	res := spamAssassinHeuristic(context.Background(), ln.Addr().String(), "Subject: x\r\n\r\nHallo\r\n", 0.6)
	if cmd := <-gotCmd; !strings.HasPrefix(cmd, "REPORT ") {
		t.Errorf("Anfrage an spamd = %q, erwartet REPORT", cmd)
	}
	if res.Status != "warn" {
		t.Fatalf("Status = %q, erwartet warn (3,5 von 5,0): %s", res.Status, res.Summary)
	}
	for _, k := range []string{"sym:MISSING_SUBJECT", "sym:URIBL_BLOCKED", "sym:SPF_PASS"} {
		if res.TechnicalDetails[k] == "" {
			t.Errorf("Details ohne %s: %v", k, res.TechnicalDetails)
		}
	}
	if !strings.HasPrefix(res.TechnicalDetails["sym:MISSING_SUBJECT"], "+2.00|Missing Subject") {
		t.Errorf("Detail im Format Wert|Beschreibung|Erklärung erwartet: %q", res.TechnicalDetails["sym:MISSING_SUBJECT"])
	}
	if !strings.Contains(res.Suggestion, "MISSING_SUBJECT (+2.0)") {
		t.Errorf("Empfehlung nennt die Regel nicht: %s", res.Suggestion)
	}
}

func fakeSpamd(t *testing.T, resp string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = bufio.NewReader(c).ReadString('\n')
			_, _ = io.WriteString(c, resp)
			c.Close()
		}
	}()
	return ln.Addr().String()
}

// SPAMASSASSIN_WARN_RATIO bestimmt, ab welchem Anteil des Limits der Befund gelb wird.
func TestSpamAssassinWarnsOnlyNearTheLimit(t *testing.T) {
	for _, tc := range []struct {
		score, ratio float64
		want         string
	}{
		{3.5, 0.9, "pass"},
		{4.4, 0.9, "pass"},
		{4.5, 0.9, "warn"},
		{4.9, 0.9, "warn"},
		{3.5, 0.6, "warn"},
		{2.9, 0.6, "pass"},
		{4.9, 1.0, "pass"},
		{5.0, 1.0, "warn"},
		{3.5, 0, "pass"}, // ohne Angabe gilt die Vorgabe 0,9
	} {
		resp := "SPAMD/1.1 0 EX_OK\r\nSpam: False ; " + strconv.FormatFloat(tc.score, 'f', 1, 64) + " / 5.0\r\n\r\n"
		res := spamAssassinHeuristic(context.Background(), fakeSpamd(t, resp), "Subject: x\r\n\r\nHallo", tc.ratio)
		if res.Status != tc.want {
			t.Errorf("Wert %.1f bei Anteil %v: Status %q, erwartet %q", tc.score, tc.ratio, res.Status, tc.want)
		}
	}
}
