package config

import (
	"strconv"
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

func TestLoadDefaultsRequestLimits(t *testing.T) {
	t.Setenv("PAYLOAD_RATE_LIMIT_PER_MIN", "")
	t.Setenv("IPT_RATE_LIMIT_PER_HOUR", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.PayloadRateLimitPerMin != 30 || cfg.IPTRateLimitPerHour != 3 {
		t.Fatalf("unexpected request limit defaults: payload=%d ipt=%d", cfg.PayloadRateLimitPerMin, cfg.IPTRateLimitPerHour)
	}
}

func TestLoadParsesRequestLimits(t *testing.T) {
	t.Setenv("PAYLOAD_RATE_LIMIT_PER_MIN", " 45 ")
	t.Setenv("IPT_RATE_LIMIT_PER_HOUR", "7")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.PayloadRateLimitPerMin != 45 || cfg.IPTRateLimitPerHour != 7 {
		t.Fatalf("unexpected request limits: payload=%d ipt=%d", cfg.PayloadRateLimitPerMin, cfg.IPTRateLimitPerHour)
	}
	for _, tc := range []struct{ key, value string }{
		{"PAYLOAD_RATE_LIMIT_PER_MIN", "1"},
		{"PAYLOAD_RATE_LIMIT_PER_MIN", "600"},
		{"IPT_RATE_LIMIT_PER_HOUR", "1"},
		{"IPT_RATE_LIMIT_PER_HOUR", "60"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			if _, err := Load(); err != nil {
				t.Errorf("%s=%s rejected: %v", tc.key, tc.value, err)
			}
		})
	}
}

func TestLoadRejectsInvalidRequestLimits(t *testing.T) {
	cases := []struct {
		key, value string
		parts      []string
	}{
		{"PAYLOAD_RATE_LIMIT_PER_MIN", "0", []string{"PAYLOAD_RATE_LIMIT_PER_MIN=0", "1 to 600", "encrypted reports", "use 30"}},
		{"PAYLOAD_RATE_LIMIT_PER_MIN", "601", []string{"PAYLOAD_RATE_LIMIT_PER_MIN=601", "1 to 600"}},
		{"PAYLOAD_RATE_LIMIT_PER_MIN", "thirty", []string{"PAYLOAD_RATE_LIMIT_PER_MIN", `"thirty"`, "whole number", "30"}},
		{"IPT_RATE_LIMIT_PER_HOUR", "0", []string{"IPT_RATE_LIMIT_PER_HOUR=0", "1 to 60", "placement tests", "use 3"}},
		{"IPT_RATE_LIMIT_PER_HOUR", "61", []string{"IPT_RATE_LIMIT_PER_HOUR=61", "1 to 60"}},
		{"IPT_RATE_LIMIT_PER_HOUR", "3.5", []string{"IPT_RATE_LIMIT_PER_HOUR", `"3.5"`, "whole number"}},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
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

func TestLoadNamesTheSettingOutsideItsBounds(t *testing.T) {
	cases := []struct {
		key, value, want string
	}{
		{"WEB_BURST_PER_10_SEC", "0", "WEB_BURST_PER_10_SEC=0 is below 1"},
		{"MAX_ACTIVE_MAILBOXES_GLOBAL", "-5", "MAX_ACTIVE_MAILBOXES_GLOBAL=-5 is below 1"},
		{"SMTP_BURST_PER_MIN", "0", "SMTP_BURST_PER_MIN=0 is below 1"},
		{"MAILBOX_TTL", "-1h", "MAILBOX_TTL=-1h0m0s is not a positive duration"},
		{"CLEANUP_INTERVAL", "0s", "CLEANUP_INTERVAL=0s is not a positive duration"},
		{"MAX_MESSAGE_BYTES", "1024", "MAX_MESSAGE_BYTES=1024 is below 524288"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestLoadDefaultsIPTTokenLengthTo128Bits(t *testing.T) {
	t.Setenv("IPT_TOKEN_LENGTH", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.IPTTokenLength != 32 {
		t.Fatalf("IPT_TOKEN_LENGTH default = %d, want 32", cfg.IPTTokenLength)
	}
}

func TestLoadParsesIPTTokenLength(t *testing.T) {
	for _, n := range []int{16, 41, 64} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			t.Setenv("IPT_TOKEN_LENGTH", strconv.Itoa(n))
			cfg, err := Load()
			if err != nil {
				t.Fatalf("IPT_TOKEN_LENGTH=%d rejected: %v", n, err)
			}
			if cfg.IPTTokenLength != n {
				t.Fatalf("IPT_TOKEN_LENGTH = %d, want %d", cfg.IPTTokenLength, n)
			}
		})
	}
}

func TestLoadRejectsIPTTokenLengthOutsideItsBounds(t *testing.T) {
	cases := []struct {
		value string
		parts []string
	}{
		{"6", []string{"IPT_TOKEN_LENGTH=6", "16 to 64", "at least 16 hexadecimal characters (64 random bits)", "use 32"}},
		{"15", []string{"IPT_TOKEN_LENGTH=15", "16 to 64"}},
		{"65", []string{"IPT_TOKEN_LENGTH=65", "16 to 64"}},
		{"long", []string{"IPT_TOKEN_LENGTH", `"long"`, "whole number", "32"}},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("IPT_TOKEN_LENGTH", tc.value)
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

func TestLoadDefaultsHTTPSExemptPathsToTheHealthChecks(t *testing.T) {
	t.Setenv("FORCE_HTTPS_EXEMPT_PATHS", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if strings.Join(cfg.ForceHTTPSExemptPaths, ",") != "/healthz,/readyz" {
		t.Fatalf("FORCE_HTTPS_EXEMPT_PATHS default = %q, want /healthz and /readyz", cfg.ForceHTTPSExemptPaths)
	}
}

func TestLoadParsesHTTPSExemptPaths(t *testing.T) {
	cases := []struct{ raw, want string }{
		{" /livez , /probe/ ", "/livez|/probe/"},
		{"/healthz", "/healthz"},
		{"/status/v1.json,/k8s/live", "/status/v1.json|/k8s/live"},
		{"none", ""},
		{" NONE ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			t.Setenv("FORCE_HTTPS_EXEMPT_PATHS", tc.raw)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load returned error: %v", err)
			}
			if got := strings.Join(cfg.ForceHTTPSExemptPaths, "|"); got != tc.want {
				t.Fatalf("FORCE_HTTPS_EXEMPT_PATHS=%q gave %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestLoadRejectsUnusableHTTPSExemptPaths(t *testing.T) {
	t.Run("the root path", func(t *testing.T) {
		t.Setenv("FORCE_HTTPS_EXEMPT_PATHS", "/healthz,/")
		_, err := Load()
		if err == nil {
			t.Fatal("expected an error")
		}
		for _, part := range []string{"FORCE_HTTPS_EXEMPT_PATHS", `"/"`, "every page", "FORCE_HTTPS=false"} {
			if !strings.Contains(err.Error(), part) {
				t.Errorf("error message %q should mention %q", err.Error(), part)
			}
		}
	})
	for _, entry := range []string{"healthz", "/a b", "/healthz?x=1", "/healthz#top", "//healthz", "/a//b", "/a/../b", "/./healthz", "/probe/..", "/a%2Fb", "*"} {
		t.Run(entry, func(t *testing.T) {
			t.Setenv("FORCE_HTTPS_EXEMPT_PATHS", "/healthz,"+entry)
			_, err := Load()
			if err == nil {
				t.Fatalf("FORCE_HTTPS_EXEMPT_PATHS entry %q accepted", entry)
			}
			for _, part := range []string{"FORCE_HTTPS_EXEMPT_PATHS", strconv.Quote(entry), "start with /", "none"} {
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

func TestLoadDefaultsPlacementTiming(t *testing.T) {
	for _, key := range []string{"IPT_TEST_DURATION", "IPT_POLL_INTERVAL", "IPT_EVENTS_INTERVAL", "IPT_SEARCH_MARGIN", "IPT_SPAM_FOLDERS"} {
		t.Setenv(key, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.IPTTestDuration != 10*time.Minute || cfg.IPTPollInterval != 30*time.Second || cfg.IPTEventsInterval != 5*time.Second || cfg.IPTSearchMargin != 2*time.Minute {
		t.Fatalf("timing = %s, %s, %s, %s; want 10m, 30s, 5s, 2m", cfg.IPTTestDuration, cfg.IPTPollInterval, cfg.IPTEventsInterval, cfg.IPTSearchMargin)
	}
	if got := strings.Join(cfg.IPTSpamFolders, ","); got != "Spam,Junk,[Gmail]/Spam,Bulk Mail,Bulk,Junk E-Mail" {
		t.Fatalf("IPT_SPAM_FOLDERS default = %q", got)
	}
}

func TestLoadParsesPlacementTiming(t *testing.T) {
	t.Setenv("IPT_TEST_DURATION", "3m")
	t.Setenv("IPT_POLL_INTERVAL", "10s")
	t.Setenv("IPT_EVENTS_INTERVAL", "2s")
	t.Setenv("IPT_SEARCH_MARGIN", "0s")
	t.Setenv("IPT_SPAM_FOLDERS", " Junk , Werbung ")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.IPTTestDuration != 3*time.Minute || cfg.IPTPollInterval != 10*time.Second || cfg.IPTEventsInterval != 2*time.Second || cfg.IPTSearchMargin != 0 {
		t.Fatalf("timing = %s, %s, %s, %s; want 3m, 10s, 2s, 0s", cfg.IPTTestDuration, cfg.IPTPollInterval, cfg.IPTEventsInterval, cfg.IPTSearchMargin)
	}
	if got := strings.Join(cfg.IPTSpamFolders, "|"); got != "Junk|Werbung" {
		t.Fatalf("IPT_SPAM_FOLDERS = %q, want Junk and Werbung", got)
	}
}

func TestLoadSearchesInboxAloneWithoutSpamFolders(t *testing.T) {
	t.Setenv("IPT_SPAM_FOLDERS", "none")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.IPTSpamFolders == nil || len(cfg.IPTSpamFolders) != 0 {
		t.Fatalf("IPT_SPAM_FOLDERS=none gives %q, want an empty list", cfg.IPTSpamFolders)
	}
}

func TestLoadRejectsPlacementTimingOutsideItsBounds(t *testing.T) {
	cases := []struct {
		key, value string
		parts      []string
	}{
		{"IPT_TEST_DURATION", "30s", []string{"IPT_TEST_DURATION=30s", "1m to 1h", "use 10m"}},
		{"IPT_TEST_DURATION", "2h", []string{"IPT_TEST_DURATION=2h", "1m to 1h"}},
		{"IPT_TEST_DURATION", "90s", []string{"IPT_TEST_DURATION=1m30s", "whole number of minutes", "10m"}},
		{"IPT_TEST_DURATION", "zehn", []string{"IPT_TEST_DURATION", `"zehn"`, "not a duration", "10m"}},
		{"IPT_POLL_INTERVAL", "1s", []string{"IPT_POLL_INTERVAL=1s", "5s to 5m", "use 30s"}},
		{"IPT_EVENTS_INTERVAL", "2m", []string{"IPT_EVENTS_INTERVAL=2m", "1s to 1m", "use 5s"}},
		{"IPT_SEARCH_MARGIN", "-1m", []string{"IPT_SEARCH_MARGIN=-1m", "0s to 1h", "use 2m"}},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
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

func TestLoadKeepsThePollIntervalBelowTheTestDuration(t *testing.T) {
	t.Setenv("IPT_TEST_DURATION", "1m")
	t.Setenv("IPT_POLL_INTERVAL", "1m")
	_, err := Load()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, part := range []string{"IPT_POLL_INTERVAL=1m", "IPT_TEST_DURATION=1m", "not shorter"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("error message %q should mention %q", err.Error(), part)
		}
	}
	t.Setenv("IPT_POLL_INTERVAL", "59s")
	if _, err := Load(); err != nil {
		t.Fatalf("IPT_POLL_INTERVAL=59s below IPT_TEST_DURATION=1m rejected: %v", err)
	}
}

func TestLoadRejectsUnusableSpamFolders(t *testing.T) {
	many := make([]string, MaxIPTSpamFolders+1)
	for i := range many {
		many[i] = "Ordner" + strconv.Itoa(i)
	}
	cases := []struct {
		value string
		parts []string
	}{
		{strings.Join(many, ","), []string{"IPT_SPAM_FOLDERS", "21 folders", "at most 20"}},
		{"Spam,Sp\x07am", []string{"IPT_SPAM_FOLDERS", `"Sp\aam"`, "control characters", "none"}},
		{strings.Repeat("x", MaxIPTSpamFolderChars+1), []string{"IPT_SPAM_FOLDERS", "up to 100 characters"}},
	}
	for i, tc := range cases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Setenv("IPT_SPAM_FOLDERS", tc.value)
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

func TestFormatDurationWritesTheSettingsForm(t *testing.T) {
	for d, want := range map[time.Duration]string{
		10 * time.Minute: "10m",
		time.Hour:        "1h",
		90 * time.Minute: "1h30m",
		30 * time.Second: "30s",
		90 * time.Second: "1m30s",
		0:                "0s",
	} {
		if got := FormatDuration(d); got != want {
			t.Errorf("FormatDuration(%v) = %q, want %q", d, got, want)
		}
	}
}
