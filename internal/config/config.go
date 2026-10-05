package config

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppName              string
	HTTPListenAddr       string
	EnableTLS            bool
	TLSCertFile          string
	TLSKeyFile           string
	ForceHTTPS           bool
	SMTPListenAddr       string
	PublicBaseURL        string
	SMTPDomain           string
	DBPath               string
	DataDir              string
	MailboxTTL           time.Duration
	RetentionTTL         time.Duration
	CleanupInterval      time.Duration
	MaxMessageBytes      int64
	MaxActivePerIP       int
	MaxActiveGlobal      int
	WebRateLimitPerMin   int
	WebBurstPer10Sec     int
	SMTPRateLimitPerHour int
	SMTPBurstPerMin      int
	EnableRBLChecks      bool
	RBLProviders         []string
	// Group C — opt-in third-party reputation checks (contact external services
	// with the sender/link domain; off by default for privacy).
	EnableDomainAge          bool
	EnableDomainBlocklist    bool
	DomainBlocklistProviders []string
	EnableBrokenLinks        bool
	EnableSpamAssassin       bool
	SpamAssassinHostPort     string
	EnableRspamd             bool
	RspamdURL                string
	RspamdPassword           string
	AlertWebhookURL          string
	TrustedProxyCIDRs        []string
	// Mailbox extension
	MailboxMaxExtendDays int
	// Privacy page operator info
	PrivacyOperatorName     string
	PrivacyOperatorAddress  string
	PrivacyOperatorEmail    string
	PrivacyHideTemplateNote bool
	// Inbox Placement Testing — operator-configured seed accounts.
	EnableInboxPlacement bool          // ENABLE_INBOX_PLACEMENT
	SeedAccountsFile     string        // SEED_ACCOUNTS_FILE (path to seeds.json)
	IPTCheckInterval     time.Duration // IPT_CHECK_INTERVAL (default 6h)
	IPTAlertEmail        string        // IPT_ALERT_EMAIL — admin recipient
	IPTAlertSMTPAddr     string        // IPT_ALERT_SMTP_ADDR host:port (465=TLS, else STARTTLS)
	IPTAlertSMTPFrom     string        // IPT_ALERT_SMTP_FROM
	IPTAlertSMTPUser     string        // IPT_ALERT_SMTP_USER (optional)
	IPTAlertSMTPPass     string        // IPT_ALERT_SMTP_PASS (optional)
	IPTAlertIncludeRaw   bool          // IPT_ALERT_INCLUDE_RAW_ERRORS (default true)
	// Web interface
	UIDefaultTheme string // UI_DEFAULT_THEME — display option for visitors who have not picked one (see UIThemes)
	// Cookies
	CookieSecure      string // COOKIE_SECURE — when cookies carry the Secure attribute (see CookieSecureModes)
	LangCookieName    string // LANG_COOKIE_NAME — cookie with the language picked in the switcher
	LangCookieDays    int    // LANG_COOKIE_DAYS — how many days the browser keeps that choice
	MailboxCookieName string // MAILBOX_COOKIE_NAME — cookie with the mailbox created without JavaScript
}

// UIThemes lists the display options of the web interface: "auto" follows the
// visitor's system setting, "light" and "dark" are the two colour modes and
// "werkbank" is the workbench look on top of the light mode. Visitors switch
// in the navbar menu; UI_DEFAULT_THEME picks what they see first.
var UIThemes = []string{"auto", "light", "dark", "werkbank"}

// CookieSecureModes lists the values of COOKIE_SECURE. "auto" marks cookies
// Secure on requests that arrived over HTTPS, directly or through a trusted
// proxy, and on every request once PUBLIC_BASE_URL starts with https://.
// "always" marks every cookie Secure, "never" suits plain-HTTP test setups.
var CookieSecureModes = []string{"auto", "always", "never"}

// MaxCookieDays is the longest lifetime browsers grant a cookie.
const MaxCookieDays = 400

// cookieNamePattern accepts cookie names that every browser and proxy passes
// through unchanged.
var cookieNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func Load() (Config, error) {
	langCookieDays, err := getEnvIntChecked("LANG_COOKIE_DAYS", 365)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		AppName:                  getEnv("APP_NAME", "sender.report"),
		HTTPListenAddr:           getEnv("HTTP_LISTEN_ADDR", ":8080"),
		EnableTLS:                getEnvBool("ENABLE_TLS", false),
		TLSCertFile:              getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:               getEnv("TLS_KEY_FILE", ""),
		ForceHTTPS:               getEnvBool("FORCE_HTTPS", false),
		SMTPListenAddr:           getEnv("SMTP_LISTEN_ADDR", ":2525"),
		PublicBaseURL:            strings.TrimRight(getEnv("PUBLIC_BASE_URL", ""), "/"),
		SMTPDomain:               strings.ToLower(getEnv("SMTP_DOMAIN", "")),
		DBPath:                   getEnv("DB_PATH", "/data/sender-report.db"),
		DataDir:                  getEnv("DATA_DIR", "/data"),
		MailboxTTL:               getEnvDuration("MAILBOX_TTL", 24*time.Hour),
		RetentionTTL:             getEnvDuration("DATA_RETENTION_TTL", 7*24*time.Hour),
		CleanupInterval:          getEnvDuration("CLEANUP_INTERVAL", 30*time.Minute),
		MaxMessageBytes:          getEnvInt64("MAX_MESSAGE_BYTES", 2*1024*1024),
		MaxActivePerIP:           getEnvInt("MAX_ACTIVE_MAILBOXES_PER_IP", 20),
		MaxActiveGlobal:          getEnvInt("MAX_ACTIVE_MAILBOXES_GLOBAL", 2000),
		WebRateLimitPerMin:       getEnvInt("WEB_RATE_LIMIT_PER_MIN", 60),
		WebBurstPer10Sec:         getEnvInt("WEB_BURST_PER_10_SEC", 20),
		SMTPRateLimitPerHour:     getEnvInt("SMTP_RATE_LIMIT_PER_HOUR", 200),
		SMTPBurstPerMin:          getEnvInt("SMTP_BURST_PER_MIN", 40),
		EnableRBLChecks:          getEnvBool("ENABLE_RBL_CHECKS", false),
		RBLProviders:             splitCSV(getEnv("RBL_PROVIDERS", "zen.spamhaus.org,bl.spamcop.net,b.barracudacentral.org,psbl.surriel.com,dnsbl.dronebl.org,bl.blocklist.de")),
		EnableDomainAge:          getEnvBool("ENABLE_DOMAIN_AGE", false),
		EnableDomainBlocklist:    getEnvBool("ENABLE_DOMAIN_BLOCKLIST", false),
		DomainBlocklistProviders: splitCSV(getEnv("DOMAIN_BLOCKLIST_PROVIDERS", "dbl.spamhaus.org,multi.uribl.com")),
		EnableBrokenLinks:        getEnvBool("ENABLE_BROKEN_LINKS", false),
		EnableSpamAssassin:       getEnvBool("ENABLE_SPAMASSASSIN", false),
		SpamAssassinHostPort:     getEnv("SPAMASSASSIN_HOSTPORT", "spamd:783"),
		EnableRspamd:             getEnvBool("ENABLE_RSPAMD", false),
		RspamdURL:                getEnv("RSPAMD_URL", "http://rspamd:11334/checkv2"),
		RspamdPassword:           getEnv("RSPAMD_PASSWORD", ""),
		AlertWebhookURL:          getEnv("ALERT_WEBHOOK_URL", ""),
		TrustedProxyCIDRs:        splitCSV(getEnv("TRUSTED_PROXY_CIDRS", "")),
		MailboxMaxExtendDays:     getEnvInt("MAILBOX_MAX_EXTEND_DAYS", 7),
		PrivacyOperatorName:      getEnv("PRIVACY_OPERATOR_NAME", ""),
		PrivacyOperatorAddress:   getEnv("PRIVACY_OPERATOR_ADDRESS", ""),
		PrivacyOperatorEmail:     getEnv("PRIVACY_OPERATOR_EMAIL", ""),
		PrivacyHideTemplateNote:  getEnvBool("PRIVACY_HIDE_TEMPLATE_NOTE", false),
		EnableInboxPlacement: getEnvBool("ENABLE_INBOX_PLACEMENT", false),
		SeedAccountsFile:     getEnv("SEED_ACCOUNTS_FILE", ""),
		IPTCheckInterval:     getEnvDuration("IPT_CHECK_INTERVAL", 6*time.Hour),
		IPTAlertEmail:        getEnv("IPT_ALERT_EMAIL", ""),
		IPTAlertSMTPAddr:     getEnv("IPT_ALERT_SMTP_ADDR", ""),
		IPTAlertSMTPFrom:     getEnv("IPT_ALERT_SMTP_FROM", ""),
		IPTAlertSMTPUser:     getEnv("IPT_ALERT_SMTP_USER", ""),
		IPTAlertSMTPPass:     getEnv("IPT_ALERT_SMTP_PASS", ""),
		IPTAlertIncludeRaw:   getEnvBool("IPT_ALERT_INCLUDE_RAW_ERRORS", true),
		UIDefaultTheme:       strings.ToLower(getEnv("UI_DEFAULT_THEME", "auto")),
		CookieSecure:         strings.ToLower(getEnv("COOKIE_SECURE", "auto")),
		LangCookieName:       getEnv("LANG_COOKIE_NAME", "sr_lang"),
		LangCookieDays:       langCookieDays,
		MailboxCookieName:    getEnv("MAILBOX_COOKIE_NAME", "sr_mailbox"),
	}

	if cfg.EnableTLS && (cfg.TLSCertFile == "" || cfg.TLSKeyFile == "") {
		return cfg, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must be set when ENABLE_TLS=true")
	}
	if cfg.MaxMessageBytes < 512*1024 {
		return cfg, fmt.Errorf("MAX_MESSAGE_BYTES too low, must be >= 524288")
	}
	if cfg.MaxActivePerIP <= 0 || cfg.MaxActiveGlobal <= 0 || cfg.WebRateLimitPerMin <= 0 || cfg.WebBurstPer10Sec <= 0 || cfg.SMTPRateLimitPerHour <= 0 || cfg.SMTPBurstPerMin <= 0 {
		return cfg, fmt.Errorf("rate and mailbox limits must be > 0")
	}
	if cfg.MailboxTTL <= 0 || cfg.RetentionTTL <= 0 || cfg.CleanupInterval <= 0 {
		return cfg, fmt.Errorf("TTL and cleanup intervals must be > 0")
	}
	if !slices.Contains(UIThemes, cfg.UIDefaultTheme) {
		return cfg, fmt.Errorf("UI_DEFAULT_THEME=%q is not a display option of the web interface; set it to one of %s, or remove it to follow the visitor's system setting", cfg.UIDefaultTheme, strings.Join(UIThemes, ", "))
	}
	if err := checkCookieSettings(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// checkCookieSettings validates COOKIE_SECURE, the cookie names and the
// lifetime of the language cookie.
func checkCookieSettings(cfg Config) error {
	if !slices.Contains(CookieSecureModes, cfg.CookieSecure) {
		return fmt.Errorf("COOKIE_SECURE=%q is not one of %s; auto marks cookies Secure on HTTPS requests and whenever PUBLIC_BASE_URL starts with https://", cfg.CookieSecure, strings.Join(CookieSecureModes, ", "))
	}
	for _, c := range []struct{ key, name string }{
		{"LANG_COOKIE_NAME", cfg.LangCookieName},
		{"MAILBOX_COOKIE_NAME", cfg.MailboxCookieName},
	} {
		if !cookieNamePattern.MatchString(c.name) {
			return fmt.Errorf("%s=%q cannot serve as a cookie name; use 1 to 64 letters, digits, '-', '_' or '.'", c.key, c.name)
		}
	}
	if cfg.LangCookieName == cfg.MailboxCookieName {
		return fmt.Errorf("LANG_COOKIE_NAME and MAILBOX_COOKIE_NAME are both %q; give the two cookies different names", cfg.LangCookieName)
	}
	if cfg.LangCookieDays < 1 || cfg.LangCookieDays > MaxCookieDays {
		return fmt.Errorf("LANG_COOKIE_DAYS=%d is outside 1 to %d; browsers keep a cookie for at most %d days", cfg.LangCookieDays, MaxCookieDays, MaxCookieDays)
	}
	return nil
}

func getEnv(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func getEnvInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

// getEnvIntChecked reads a whole number like getEnvInt and reports a value
// that is none, where getEnvInt falls back to the default.
func getEnvIntChecked(key string, fallback int) (int, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a whole number; set a value like %d", key, v, fallback)
	}
	return n, nil
}

func getEnvInt64(key string, fallback int64) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

func getEnvBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
