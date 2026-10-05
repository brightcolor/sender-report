package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadParsesConfiguredValues(t *testing.T) {
	t.Setenv("APP_NAME", "ProbeX")
	t.Setenv("HTTP_LISTEN_ADDR", ":18080")
	t.Setenv("ENABLE_TLS", "true")
	t.Setenv("TLS_CERT_FILE", "/certs/fullchain.pem")
	t.Setenv("TLS_KEY_FILE", "/certs/privkey.pem")
	t.Setenv("FORCE_HTTPS", "true")
	t.Setenv("SMTP_LISTEN_ADDR", ":12525")
	t.Setenv("PUBLIC_BASE_URL", "https://example.test/")
	t.Setenv("SMTP_DOMAIN", "Mail.Example.Test")
	t.Setenv("DB_PATH", "/tmp/test.db")
	t.Setenv("DATA_DIR", "/tmp/data")
	t.Setenv("MAILBOX_TTL", "2h")
	t.Setenv("DATA_RETENTION_TTL", "48h")
	t.Setenv("CLEANUP_INTERVAL", "15m")
	t.Setenv("MAX_MESSAGE_BYTES", "1048576")
	t.Setenv("MAX_ACTIVE_MAILBOXES_PER_IP", "12")
	t.Setenv("MAX_ACTIVE_MAILBOXES_GLOBAL", "1200")
	t.Setenv("WEB_RATE_LIMIT_PER_MIN", "90")
	t.Setenv("WEB_BURST_PER_10_SEC", "30")
	t.Setenv("SMTP_RATE_LIMIT_PER_HOUR", "220")
	t.Setenv("SMTP_BURST_PER_MIN", "45")
	t.Setenv("ENABLE_RBL_CHECKS", "true")
	t.Setenv("RBL_PROVIDERS", "zen.spamhaus.org, bl.spamcop.net")
	t.Setenv("ENABLE_SPAMASSASSIN", "true")
	t.Setenv("SPAMASSASSIN_HOSTPORT", "spamd:783")
	t.Setenv("ENABLE_RSPAMD", "true")
	t.Setenv("RSPAMD_URL", "http://rspamd:11334/checkv2")
	t.Setenv("RSPAMD_PASSWORD", "secret")
	t.Setenv("ALERT_WEBHOOK_URL", "https://alerts.example.test/hook")
	t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 127.0.0.1/32")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.AppName != "ProbeX" || cfg.PublicBaseURL != "https://example.test" {
		t.Fatalf("unexpected basic config values: %+v", cfg)
	}
	if cfg.SMTPDomain != "mail.example.test" {
		t.Fatalf("expected lowercased smtp domain, got %q", cfg.SMTPDomain)
	}
	if !cfg.EnableTLS || cfg.TLSCertFile != "/certs/fullchain.pem" || cfg.TLSKeyFile != "/certs/privkey.pem" || !cfg.ForceHTTPS {
		t.Fatalf("unexpected tls config values: %+v", cfg)
	}
	if cfg.MailboxTTL != 2*time.Hour || cfg.RetentionTTL != 48*time.Hour || cfg.CleanupInterval != 15*time.Minute {
		t.Fatalf("unexpected duration values: mailbox=%s retention=%s cleanup=%s", cfg.MailboxTTL, cfg.RetentionTTL, cfg.CleanupInterval)
	}
	if cfg.MaxActiveGlobal != 1200 || cfg.WebBurstPer10Sec != 30 || cfg.SMTPBurstPerMin != 45 {
		t.Fatalf("unexpected burst/global limits: %+v", cfg)
	}
	if cfg.AlertWebhookURL != "https://alerts.example.test/hook" {
		t.Fatalf("expected alert webhook URL to be set, got %q", cfg.AlertWebhookURL)
	}
	if !cfg.EnableRBLChecks || !cfg.EnableSpamAssassin || !cfg.EnableRspamd {
		t.Fatalf("expected optional checks to be enabled: %+v", cfg)
	}
	if len(cfg.RBLProviders) != 2 || len(cfg.TrustedProxyCIDRs) != 2 {
		t.Fatalf("unexpected csv parsing: rbl=%v proxy=%v", cfg.RBLProviders, cfg.TrustedProxyCIDRs)
	}
}

func TestLoadRejectsInvalidLimits(t *testing.T) {
	t.Setenv("SMTP_DOMAIN", "example.test")
	t.Setenv("MAX_MESSAGE_BYTES", "1024")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for too low MAX_MESSAGE_BYTES")
	}
}

func TestLoadRejectsZeroBurstLimit(t *testing.T) {
	t.Setenv("SMTP_DOMAIN", "example.test")
	t.Setenv("WEB_BURST_PER_10_SEC", "0")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for zero WEB_BURST_PER_10_SEC")
	}
}

func TestLoadAllowsEmptyPublicURLAndSMTPDomain(t *testing.T) {
	t.Setenv("PUBLIC_BASE_URL", "")
	t.Setenv("SMTP_DOMAIN", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.PublicBaseURL != "" {
		t.Fatalf("expected empty PUBLIC_BASE_URL default for request-derived URL, got %q", cfg.PublicBaseURL)
	}
	if cfg.SMTPDomain != "" {
		t.Fatalf("expected empty SMTP_DOMAIN default for request-derived mailbox domain, got %q", cfg.SMTPDomain)
	}
}

func TestLoadRejectsTLSWithoutCertificatePaths(t *testing.T) {
	t.Setenv("ENABLE_TLS", "true")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error when ENABLE_TLS is true without TLS cert/key paths")
	}
}

func TestLoadDefaultsUIThemeToAuto(t *testing.T) {
	t.Setenv("UI_DEFAULT_THEME", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.UIDefaultTheme != "auto" {
		t.Fatalf("expected UI_DEFAULT_THEME default auto, got %q", cfg.UIDefaultTheme)
	}
}

func TestLoadAcceptsEveryUITheme(t *testing.T) {
	for _, raw := range []string{"auto", "light", "dark", "werkbank", " Werkbank ", "DARK"} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("UI_DEFAULT_THEME", raw)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load returned error for %q: %v", raw, err)
			}
			want := strings.ToLower(strings.TrimSpace(raw))
			if cfg.UIDefaultTheme != want {
				t.Fatalf("expected UI_DEFAULT_THEME %q, got %q", want, cfg.UIDefaultTheme)
			}
		})
	}
}

func TestLoadRejectsUnknownUITheme(t *testing.T) {
	t.Setenv("UI_DEFAULT_THEME", "sepia")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for unknown UI_DEFAULT_THEME")
	}
	msg := err.Error()
	for _, part := range []string{"UI_DEFAULT_THEME", `"sepia"`, "auto, light, dark, werkbank"} {
		if !strings.Contains(msg, part) {
			t.Fatalf("error message %q should mention %q", msg, part)
		}
	}
}

func TestLoadDefaultsCookieSettings(t *testing.T) {
	for _, key := range []string{"COOKIE_SECURE", "LANG_COOKIE_NAME", "LANG_COOKIE_DAYS", "MAILBOX_COOKIE_NAME"} {
		t.Setenv(key, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.CookieSecure != "auto" || cfg.LangCookieName != "sr_lang" || cfg.LangCookieDays != 365 || cfg.MailboxCookieName != "sr_mailbox" {
		t.Fatalf("unexpected cookie defaults: secure=%q lang=%q days=%d mailbox=%q", cfg.CookieSecure, cfg.LangCookieName, cfg.LangCookieDays, cfg.MailboxCookieName)
	}
}

func TestLoadParsesCookieSettings(t *testing.T) {
	t.Setenv("COOKIE_SECURE", " Always ")
	t.Setenv("LANG_COOKIE_NAME", "ui_language")
	t.Setenv("LANG_COOKIE_DAYS", "30")
	t.Setenv("MAILBOX_COOKIE_NAME", "box.token")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.CookieSecure != "always" || cfg.LangCookieName != "ui_language" || cfg.LangCookieDays != 30 || cfg.MailboxCookieName != "box.token" {
		t.Fatalf("unexpected cookie settings: secure=%q lang=%q days=%d mailbox=%q", cfg.CookieSecure, cfg.LangCookieName, cfg.LangCookieDays, cfg.MailboxCookieName)
	}
	for _, days := range []string{"1", "400"} {
		t.Setenv("LANG_COOKIE_DAYS", days)
		if _, err := Load(); err != nil {
			t.Errorf("LANG_COOKIE_DAYS=%s rejected: %v", days, err)
		}
	}
}

func TestLoadRejectsInvalidCookieSettings(t *testing.T) {
	cases := []struct {
		name  string
		env   map[string]string
		parts []string
	}{
		{"unknown mode", map[string]string{"COOKIE_SECURE": "sometimes"}, []string{"COOKIE_SECURE", `"sometimes"`, "auto, always, never"}},
		{"space in the name", map[string]string{"LANG_COOKIE_NAME": "ui language"}, []string{"LANG_COOKIE_NAME", `"ui language"`, "letters, digits"}},
		{"semicolon in the name", map[string]string{"MAILBOX_COOKIE_NAME": "box;token"}, []string{"MAILBOX_COOKIE_NAME", `"box;token"`}},
		{"same name twice", map[string]string{"LANG_COOKIE_NAME": "sr_state", "MAILBOX_COOKIE_NAME": "sr_state"}, []string{"LANG_COOKIE_NAME and MAILBOX_COOKIE_NAME", `"sr_state"`, "different names"}},
		{"zero days", map[string]string{"LANG_COOKIE_DAYS": "0"}, []string{"LANG_COOKIE_DAYS=0", "1 to 400"}},
		{"more than browsers keep", map[string]string{"LANG_COOKIE_DAYS": "401"}, []string{"LANG_COOKIE_DAYS=401", "400 days"}},
		{"days as a word", map[string]string{"LANG_COOKIE_DAYS": "one year"}, []string{"LANG_COOKIE_DAYS", `"one year"`, "whole number", "365"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			_, err := Load()
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, part := range tc.parts {
				if !strings.Contains(err.Error(), part) {
					t.Errorf("error message %q should mention %q", err.Error(), part)
				}
			}
		})
	}
}

func TestSplitCSV(t *testing.T) {
	got := splitCSV(" a, ,b ,, c ")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("unexpected splitCSV output: %#v", got)
	}
}
