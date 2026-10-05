package config

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
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
	// PAYLOAD_RATE_LIMIT_PER_MIN — encrypted reports one IP address may fetch
	// per minute; rechecks and simulator runs each count separately against
	// the same number.
	PayloadRateLimitPerMin int
	EnableRBLChecks        bool
	RBLProviders           []string
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
	IPTRateLimitPerHour  int           // IPT_RATE_LIMIT_PER_HOUR — placement tests one IP address may start per hour
	IPTTokenLength       int           // IPT_TOKEN_LENGTH — hexadecimal characters in the subject token of a new placement test
	IPTTestDuration      time.Duration // IPT_TEST_DURATION — how long a placement test waits for its message, in whole minutes
	IPTPollInterval      time.Duration // IPT_POLL_INTERVAL — pause between two IMAP lookups in one seed account
	IPTEventsInterval    time.Duration // IPT_EVENTS_INTERVAL — how often the open placement dialog receives the state of its test
	IPTSearchMargin      time.Duration // IPT_SEARCH_MARGIN — how far before the start of a test the IMAP search reaches back
	IPTSpamFolders       []string      // IPT_SPAM_FOLDERS — folders a placement test searches after INBOX, in this order
	// Web interface
	UIDefaultTheme string // UI_DEFAULT_THEME — display option for visitors who have not picked one (see UIThemes)
	// Cookies
	CookieSecure      string // COOKIE_SECURE — when cookies carry the Secure attribute (see CookieSecureModes)
	LangCookieName    string // LANG_COOKIE_NAME — cookie with the language picked in the switcher
	LangCookieDays    int    // LANG_COOKIE_DAYS — how many days the browser keeps that choice
	MailboxCookieName string // MAILBOX_COOKIE_NAME — cookie with the mailbox created without JavaScript
	// FORCE_HTTPS_EXEMPT_PATHS — paths that answer over plain HTTP although
	// FORCE_HTTPS is set; an entry ending in / covers the paths below it.
	ForceHTTPSExemptPaths []string
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

// Defaults and upper bounds of the per-IP request limits; the lower bound of
// each is 1. The window is part of each setting's name:
// PAYLOAD_RATE_LIMIT_PER_MIN counts per minute, IPT_RATE_LIMIT_PER_HOUR per
// hour. Each placement test logs in to the seed accounts of every selected
// provider throughout its run, so the upper bound of IPT_RATE_LIMIT_PER_HOUR
// also protects those accounts from being locked by their provider.
const (
	DefaultPayloadRateLimitPerMin = 30
	MaxPayloadRateLimitPerMin     = 600
	DefaultIPTRateLimitPerHour    = 3
	MaxIPTRateLimitPerHour        = 60
)

// Default and bounds of IPT_TOKEN_LENGTH, in hexadecimal characters of 4
// random bits each: 32 characters carry 128 bits, 16 characters (64 bits) are
// the least that keeps a token unguessable, and 64 characters keep the tag
// short enough to add to a subject line.
const (
	DefaultIPTTokenLength = 32
	MinIPTTokenLength     = 16
	MaxIPTTokenLength     = 64
)

// Defaults and bounds of the timing of a placement test. IPT_TEST_DURATION
// counts in whole minutes because the dialog names it in minutes, and
// IPT_POLL_INTERVAL stays below it, so every seed account gets at least two
// lookups. IPT_SEARCH_MARGIN moves the start of the IMAP search back, so a
// provider whose clock runs behind still finds the message.
const (
	DefaultIPTTestDuration   = 10 * time.Minute
	MinIPTTestDuration       = time.Minute
	MaxIPTTestDuration       = time.Hour
	DefaultIPTPollInterval   = 30 * time.Second
	MinIPTPollInterval       = 5 * time.Second
	MaxIPTPollInterval       = 5 * time.Minute
	DefaultIPTEventsInterval = 5 * time.Second
	MinIPTEventsInterval     = time.Second
	MaxIPTEventsInterval     = time.Minute
	DefaultIPTSearchMargin   = 2 * time.Minute
	MaxIPTSearchMargin       = time.Hour
)

// DefaultIPTSpamFolders lists the spam folders of the common providers, in the
// order a placement test searches them after INBOX. NoSpamFolders as
// IPT_SPAM_FOLDERS searches INBOX alone.
const (
	DefaultIPTSpamFolders = "Spam,Junk,[Gmail]/Spam,Bulk Mail,Bulk,Junk E-Mail"
	NoSpamFolders         = "none"
	MaxIPTSpamFolders     = 20
	MaxIPTSpamFolderChars = 100
)

// DefaultForceHTTPSExemptPaths lists the paths that answer over plain HTTP
// although FORCE_HTTPS is set: the health and readiness checks, so a
// healthcheck inside the container reaches them on http://127.0.0.1
// regardless of PUBLIC_BASE_URL.
const DefaultForceHTTPSExemptPaths = "/healthz,/readyz"

// NoExemptPaths as FORCE_HTTPS_EXEMPT_PATHS redirects every path. An empty
// value stands for the default, as with every setting.
const NoExemptPaths = "none"

// exemptPathPattern accepts an absolute path of one or more segments with an
// optional trailing slash, made of the characters RFC 3986 allows in a path.
var exemptPathPattern = regexp.MustCompile(`^(/[A-Za-z0-9._~!$&'()*+,;=:@-]+)+/?$`)

// cookieNamePattern accepts cookie names that every browser and proxy passes
// through unchanged.
var cookieNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func Load() (Config, error) {
	langCookieDays, err := getEnvIntChecked("LANG_COOKIE_DAYS", 365)
	if err != nil {
		return Config{}, err
	}
	payloadRateLimit, err := getEnvIntChecked("PAYLOAD_RATE_LIMIT_PER_MIN", DefaultPayloadRateLimitPerMin)
	if err != nil {
		return Config{}, err
	}
	iptRateLimit, err := getEnvIntChecked("IPT_RATE_LIMIT_PER_HOUR", DefaultIPTRateLimitPerHour)
	if err != nil {
		return Config{}, err
	}
	iptTokenLength, err := getEnvIntChecked("IPT_TOKEN_LENGTH", DefaultIPTTokenLength)
	if err != nil {
		return Config{}, err
	}
	iptTiming := make(map[string]time.Duration, 4)
	for _, d := range []struct {
		key      string
		fallback time.Duration
	}{
		{"IPT_TEST_DURATION", DefaultIPTTestDuration},
		{"IPT_POLL_INTERVAL", DefaultIPTPollInterval},
		{"IPT_EVENTS_INTERVAL", DefaultIPTEventsInterval},
		{"IPT_SEARCH_MARGIN", DefaultIPTSearchMargin},
	} {
		if iptTiming[d.key], err = getEnvDurationChecked(d.key, d.fallback); err != nil {
			return Config{}, err
		}
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
		PayloadRateLimitPerMin:   payloadRateLimit,
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
		EnableInboxPlacement:     getEnvBool("ENABLE_INBOX_PLACEMENT", false),
		SeedAccountsFile:         getEnv("SEED_ACCOUNTS_FILE", ""),
		IPTCheckInterval:         getEnvDuration("IPT_CHECK_INTERVAL", 6*time.Hour),
		IPTAlertEmail:            getEnv("IPT_ALERT_EMAIL", ""),
		IPTAlertSMTPAddr:         getEnv("IPT_ALERT_SMTP_ADDR", ""),
		IPTAlertSMTPFrom:         getEnv("IPT_ALERT_SMTP_FROM", ""),
		IPTAlertSMTPUser:         getEnv("IPT_ALERT_SMTP_USER", ""),
		IPTAlertSMTPPass:         getEnv("IPT_ALERT_SMTP_PASS", ""),
		IPTAlertIncludeRaw:       getEnvBool("IPT_ALERT_INCLUDE_RAW_ERRORS", true),
		IPTRateLimitPerHour:      iptRateLimit,
		IPTTokenLength:           iptTokenLength,
		IPTTestDuration:          iptTiming["IPT_TEST_DURATION"],
		IPTPollInterval:          iptTiming["IPT_POLL_INTERVAL"],
		IPTEventsInterval:        iptTiming["IPT_EVENTS_INTERVAL"],
		IPTSearchMargin:          iptTiming["IPT_SEARCH_MARGIN"],
		IPTSpamFolders:           splitFolderList(getEnv("IPT_SPAM_FOLDERS", DefaultIPTSpamFolders)),
		UIDefaultTheme:           strings.ToLower(getEnv("UI_DEFAULT_THEME", "auto")),
		CookieSecure:             strings.ToLower(getEnv("COOKIE_SECURE", "auto")),
		LangCookieName:           getEnv("LANG_COOKIE_NAME", "sr_lang"),
		LangCookieDays:           langCookieDays,
		MailboxCookieName:        getEnv("MAILBOX_COOKIE_NAME", "sr_mailbox"),
		ForceHTTPSExemptPaths:    splitPathList(getEnv("FORCE_HTTPS_EXEMPT_PATHS", DefaultForceHTTPSExemptPaths)),
	}

	if cfg.EnableTLS && (cfg.TLSCertFile == "" || cfg.TLSKeyFile == "") {
		return cfg, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must be set when ENABLE_TLS=true")
	}
	if err := checkHTTPSExemptPaths(cfg.ForceHTTPSExemptPaths); err != nil {
		return cfg, err
	}
	if cfg.MaxMessageBytes < 512*1024 {
		return cfg, fmt.Errorf("MAX_MESSAGE_BYTES=%d is below 524288 (512 KiB); set a larger value, or remove it to use the default", cfg.MaxMessageBytes)
	}
	for _, l := range []struct {
		key   string
		value int
	}{
		{"MAX_ACTIVE_MAILBOXES_PER_IP", cfg.MaxActivePerIP},
		{"MAX_ACTIVE_MAILBOXES_GLOBAL", cfg.MaxActiveGlobal},
		{"WEB_RATE_LIMIT_PER_MIN", cfg.WebRateLimitPerMin},
		{"WEB_BURST_PER_10_SEC", cfg.WebBurstPer10Sec},
		{"SMTP_RATE_LIMIT_PER_HOUR", cfg.SMTPRateLimitPerHour},
		{"SMTP_BURST_PER_MIN", cfg.SMTPBurstPerMin},
	} {
		if l.value <= 0 {
			return cfg, fmt.Errorf("%s=%d is below 1; set a whole number of at least 1, or remove it to use the default", l.key, l.value)
		}
	}
	if err := checkRequestLimits(cfg); err != nil {
		return cfg, err
	}
	if cfg.IPTTokenLength < MinIPTTokenLength || cfg.IPTTokenLength > MaxIPTTokenLength {
		return cfg, fmt.Errorf("IPT_TOKEN_LENGTH=%d is outside %d to %d; the subject token of a placement test needs at least %d hexadecimal characters (%d random bits) to stay unguessable; remove it to use %d", cfg.IPTTokenLength, MinIPTTokenLength, MaxIPTTokenLength, MinIPTTokenLength, MinIPTTokenLength*4, DefaultIPTTokenLength)
	}
	if err := checkIPTTiming(cfg); err != nil {
		return cfg, err
	}
	if err := checkIPTSpamFolders(cfg.IPTSpamFolders); err != nil {
		return cfg, err
	}
	for _, d := range []struct {
		key   string
		value time.Duration
	}{
		{"MAILBOX_TTL", cfg.MailboxTTL},
		{"DATA_RETENTION_TTL", cfg.RetentionTTL},
		{"CLEANUP_INTERVAL", cfg.CleanupInterval},
	} {
		if d.value <= 0 {
			return cfg, fmt.Errorf("%s=%s is not a positive duration; set a value like 30m or 24h, or remove it to use the default", d.key, d.value)
		}
	}
	if !slices.Contains(UIThemes, cfg.UIDefaultTheme) {
		return cfg, fmt.Errorf("UI_DEFAULT_THEME=%q is not a display option of the web interface; set it to one of %s, or remove it to follow the visitor's system setting", cfg.UIDefaultTheme, strings.Join(UIThemes, ", "))
	}
	if err := checkCookieSettings(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// checkHTTPSExemptPaths validates FORCE_HTTPS_EXEMPT_PATHS: every entry is an
// absolute path without empty, "." or ".." segments, and "/" alone, which
// would cover every page, is refused.
func checkHTTPSExemptPaths(paths []string) error {
	for _, p := range paths {
		if p == "/" {
			return fmt.Errorf(`FORCE_HTTPS_EXEMPT_PATHS contains "/", which covers every page and would serve the whole site over plain HTTP; list single paths such as /healthz, or set FORCE_HTTPS=false`)
		}
		if !exemptPathPattern.MatchString(p) || hasDotSegment(p) {
			return fmt.Errorf("FORCE_HTTPS_EXEMPT_PATHS contains %q, which is not a usable path; list paths such as /healthz that start with / and hold no spaces, ?, #, %%, // or . and .. segments, or set %s to redirect every path", p, NoExemptPaths)
		}
	}
	return nil
}

// hasDotSegment reports whether the path p has a "." or ".." segment.
func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// checkRequestLimits validates the per-IP limits for report payloads and
// placement tests against their bounds.
func checkRequestLimits(cfg Config) error {
	if cfg.PayloadRateLimitPerMin < 1 || cfg.PayloadRateLimitPerMin > MaxPayloadRateLimitPerMin {
		return fmt.Errorf("PAYLOAD_RATE_LIMIT_PER_MIN=%d is outside 1 to %d; it sets how many encrypted reports one IP address may fetch per minute, and as many rechecks and simulator runs; remove it to use %d", cfg.PayloadRateLimitPerMin, MaxPayloadRateLimitPerMin, DefaultPayloadRateLimitPerMin)
	}
	if cfg.IPTRateLimitPerHour < 1 || cfg.IPTRateLimitPerHour > MaxIPTRateLimitPerHour {
		return fmt.Errorf("IPT_RATE_LIMIT_PER_HOUR=%d is outside 1 to %d; it sets how many placement tests one IP address may start per hour; remove it to use %d", cfg.IPTRateLimitPerHour, MaxIPTRateLimitPerHour, DefaultIPTRateLimitPerHour)
	}
	return nil
}

// checkIPTTiming validates the timing of placement tests against its bounds:
// the test duration in whole minutes, the IMAP lookups below it, the updates
// of the dialog and the margin of the IMAP search.
func checkIPTTiming(cfg Config) error {
	for _, d := range []struct {
		key          string
		value        time.Duration
		least, most  time.Duration
		what         string
		defaultValue time.Duration
	}{
		{"IPT_TEST_DURATION", cfg.IPTTestDuration, MinIPTTestDuration, MaxIPTTestDuration, "how long a placement test waits for its message", DefaultIPTTestDuration},
		{"IPT_POLL_INTERVAL", cfg.IPTPollInterval, MinIPTPollInterval, MaxIPTPollInterval, "the pause between two IMAP lookups in one seed account", DefaultIPTPollInterval},
		{"IPT_EVENTS_INTERVAL", cfg.IPTEventsInterval, MinIPTEventsInterval, MaxIPTEventsInterval, "how often the open placement dialog receives the state of its test", DefaultIPTEventsInterval},
		{"IPT_SEARCH_MARGIN", cfg.IPTSearchMargin, 0, MaxIPTSearchMargin, "how far before the start of a test the IMAP search reaches back", DefaultIPTSearchMargin},
	} {
		if d.value < d.least || d.value > d.most {
			return fmt.Errorf("%s=%s is outside %s to %s; it sets %s; remove it to use %s", d.key, FormatDuration(d.value), FormatDuration(d.least), FormatDuration(d.most), d.what, FormatDuration(d.defaultValue))
		}
	}
	if cfg.IPTTestDuration%time.Minute != 0 {
		return fmt.Errorf("IPT_TEST_DURATION=%s is not a whole number of minutes; the placement dialog names the duration in minutes, so set a value like 10m", FormatDuration(cfg.IPTTestDuration))
	}
	if cfg.IPTPollInterval >= cfg.IPTTestDuration {
		return fmt.Errorf("IPT_POLL_INTERVAL=%s is not shorter than IPT_TEST_DURATION=%s; every seed account needs a second IMAP lookup within a test, so shorten the interval or lengthen the test", FormatDuration(cfg.IPTPollInterval), FormatDuration(cfg.IPTTestDuration))
	}
	return nil
}

// checkIPTSpamFolders validates IPT_SPAM_FOLDERS: at most MaxIPTSpamFolders
// names of up to MaxIPTSpamFolderChars characters each, without control
// characters.
func checkIPTSpamFolders(folders []string) error {
	if len(folders) > MaxIPTSpamFolders {
		return fmt.Errorf("IPT_SPAM_FOLDERS lists %d folders; a placement test searches at most %d after INBOX, so shorten the list", len(folders), MaxIPTSpamFolders)
	}
	for _, f := range folders {
		if len([]rune(f)) > MaxIPTSpamFolderChars || strings.IndexFunc(f, unicode.IsControl) >= 0 {
			return fmt.Errorf("IPT_SPAM_FOLDERS contains %q, which is not a usable folder name; list names of up to %d characters without control characters, separated by commas, or set %s to search INBOX alone", f, MaxIPTSpamFolderChars, NoSpamFolders)
		}
	}
	return nil
}

// FormatDuration writes d the way the settings take it: 10m for ten minutes,
// 1h30m for an hour and a half.
func FormatDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
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

// getEnvDurationChecked reads a duration like getEnvDuration and reports a
// value that is none, where getEnvDuration falls back to the default.
func getEnvDurationChecked(key string, fallback time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a duration; set a value like %s", key, v, FormatDuration(fallback))
	}
	return d, nil
}

// splitFolderList reads a comma-separated list of IMAP folders; the value none
// (NoSpamFolders) stands for an empty list.
func splitFolderList(s string) []string {
	if strings.EqualFold(strings.TrimSpace(s), NoSpamFolders) {
		return []string{}
	}
	return splitCSV(s)
}

// splitPathList reads a comma-separated list of paths; the value none
// (NoExemptPaths) stands for an empty list.
func splitPathList(s string) []string {
	if strings.EqualFold(strings.TrimSpace(s), NoExemptPaths) {
		return []string{}
	}
	return splitCSV(s)
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
