package web

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The about and privacy pages name the receiving window (MAILBOX_TTL) and the
// retention (DATA_RETENTION_TTL) the operator configured, not the defaults.
func TestAboutAndPrivacyNameTheConfiguredLifetimes(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	cfg := cookieTestConfig("auto")
	cfg.UIDefaultTheme = "auto"
	cfg.MailboxTTL = 6 * time.Hour
	cfg.RetentionTTL = 14 * 24 * time.Hour
	srv, err := New(cfg, nil, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pages := []struct {
		name, path, lang string
		handler          http.HandlerFunc
		want             []string
	}{
		{"about de", "/about", "de", srv.aboutPage, []string{
			"Aufbewahrungsfrist von 14 Tagen",
			"Die Adresse nimmt 6 Stunden lang Mails an.",
			"Er ist noch 14 Tage nach Eingang",
		}},
		{"about en", "/about", "en", srv.aboutPage, []string{
			"The address accepts mail for 6 hours.",
			"for 14 days after",
		}},
		{"privacy de", "/privacy", "de", srv.privacyPage, []string{
			"<strong>Mailbox-TTL</strong> (6 Stunden)",
			"<strong>Datenaufbewahrung</strong> (14 Tage)",
			"Empfangsfenster der Mailbox ab (6 Stunden)",
		}},
	}
	for _, p := range pages {
		body := renderPage(t, p.handler, p.path, p.lang)
		for _, want := range p.want {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %q", p.name, want)
			}
		}
		for _, stale := range []string{"von 30 Tagen", "(Standard: 30 Tage)", "(Standard: 24 Stunden)", "standardmäßig 24 Stunden", "24 hours by default"} {
			if strings.Contains(body, stale) {
				t.Errorf("%s still names %q instead of the configured value", p.name, stale)
			}
		}
	}
}
