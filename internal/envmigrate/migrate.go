// Package envmigrate keeps the operator's .env file in sync with the canonical
// list of known variables whenever a new image is pulled and the container
// restarts (e.g. via Watchtower).
//
// On startup, if ENV_FILE points to the mounted .env, every variable that is
// listed in [All] but absent from the file is appended with its default value
// and a short comment.  Existing values are NEVER changed.
//
// To add a new env var:
//  1. Add it to config.go (getEnv / getEnvBool / …)
//  2. Add it to the All slice below (same order as .env.example)
//  3. Add it to .env.example for documentation
package envmigrate

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/brightcolor/sender-report/internal/version"
)

// VarDef describes one environment variable.
type VarDef struct {
	Key     string // env variable name
	Default string // default value written when the key is missing
	Comment string // single-line comment added above the entry
	Group   string // section header; printed once before the first var in a group
}

// All is the canonical, ordered list of every env variable the application
// and its docker-compose setup understand.  Keep this in sync with config.go
// and .env.example.
//
//nolint:gochecknoglobals
var All = []VarDef{
	// ── App ──────────────────────────────────────────────────────────────────
	{Group: "App", Key: "APP_NAME", Default: "Sender-Report", Comment: "Application display name"},

	// ── Listen addresses ─────────────────────────────────────────────────────
	{Group: "Listen addresses (do NOT change when using Docker)", Key: "HTTP_LISTEN_ADDR", Default: ":8080", Comment: "Internal HTTP listen address inside the container"},
	{Key: "SMTP_LISTEN_ADDR", Default: ":2525", Comment: "Internal SMTP listen address inside the container"},

	// ── Public URLs ───────────────────────────────────────────────────────────
	{Group: "Public URLs", Key: "PUBLIC_BASE_URL", Default: "", Comment: "Override auto-detected public base URL, e.g. https://sender-report.example.com"},
	{Key: "SMTP_DOMAIN", Default: "", Comment: "SMTP domain for generated addresses; defaults to request host"},

	// ── TLS ───────────────────────────────────────────────────────────────────
	{Group: "TLS", Key: "ENABLE_TLS", Default: "false", Comment: "Enable built-in TLS for the web server"},
	{Key: "TLS_CERT_FILE", Default: "", Comment: "Path to TLS certificate (required when ENABLE_TLS=true)"},
	{Key: "TLS_KEY_FILE", Default: "", Comment: "Path to TLS private key (required when ENABLE_TLS=true)"},
	{Key: "FORCE_HTTPS", Default: "false", Comment: "Redirect plain HTTP to HTTPS"},

	// ── Docker / Compose ─────────────────────────────────────────────────────
	{Group: "Docker / Compose", Key: "SENDER_REPORT_IMAGE", Default: "ghcr.io/brightcolor/sender-report:latest", Comment: "Container image used by docker-compose"},
	{Key: "HTTP_PORT", Default: "9090", Comment: "Host port mapped to the web UI (container always uses :8080)"},
	{Key: "SMTP_PORT", Default: "25", Comment: "Host port for inbound SMTP (use 25 in production)"},
	{Key: "HEALTHCHECK_URL", Default: "http://127.0.0.1:9090/healthz", Comment: "Health-check URL used by the compose healthcheck"},

	// ── Storage ───────────────────────────────────────────────────────────────
	{Group: "Storage", Key: "DATA_DIR", Default: "/data", Comment: "Base directory for persistent data"},
	{Key: "DB_PATH", Default: "/data/sender-report.db", Comment: "Path to the SQLite database file"},

	// ── Lifetime & cleanup ────────────────────────────────────────────────────
	{Group: "Lifetime & cleanup", Key: "MAILBOX_TTL", Default: "24h", Comment: "How long a mailbox is valid"},
	{Key: "MAILBOX_MAX_EXTEND_DAYS", Default: "7", Comment: "Maximum days a mailbox lifetime can be extended from now"},
	{Key: "DATA_RETENTION_TTL", Default: "168h", Comment: "How long emails and reports are kept (7 days)"},
	{Key: "CLEANUP_INTERVAL", Default: "30m", Comment: "How often the cleanup job runs"},

	// ── Limits ────────────────────────────────────────────────────────────────
	{Group: "Limits", Key: "MAX_MESSAGE_BYTES", Default: "2097152", Comment: "Maximum email size in bytes (2 MiB)"},
	{Key: "MAX_ACTIVE_MAILBOXES_PER_IP", Default: "20", Comment: "Max active mailboxes per IP address"},
	{Key: "MAX_ACTIVE_MAILBOXES_GLOBAL", Default: "2000", Comment: "Max active mailboxes globally"},
	{Key: "WEB_RATE_LIMIT_PER_MIN", Default: "60", Comment: "Web requests allowed per minute per IP"},
	{Key: "WEB_BURST_PER_10_SEC", Default: "20", Comment: "Web request burst per 10 s per IP"},
	{Key: "SMTP_RATE_LIMIT_PER_HOUR", Default: "200", Comment: "SMTP connections allowed per hour per IP"},
	{Key: "SMTP_BURST_PER_MIN", Default: "40", Comment: "SMTP burst per minute per IP"},
	{Key: "TRUSTED_PROXY_CIDRS", Default: "", Comment: "Comma-separated CIDRs whose X-Forwarded-For header is trusted"},

	// ── Optional checks ───────────────────────────────────────────────────────
	{Group: "Optional checks", Key: "ENABLE_RBL_CHECKS", Default: "false", Comment: "Enable DNSBL/RBL IP reputation checks"},
	{Key: "RBL_PROVIDERS", Default: "zen.spamhaus.org,bl.spamcop.net,b.barracudacentral.org,psbl.surriel.com,dnsbl.dronebl.org,bl.blocklist.de", Comment: "Comma-separated list of RBL zones"},
	{Key: "ENABLE_DOMAIN_AGE", Default: "false", Comment: "Opt-in: domain registration age via RDAP (third-party rdap.org)"},
	{Key: "ENABLE_DOMAIN_BLOCKLIST", Default: "false", Comment: "Opt-in: sender/link domains against domain/URI blocklists (third-party)"},
	{Key: "DOMAIN_BLOCKLIST_PROVIDERS", Default: "dbl.spamhaus.org,multi.uribl.com", Comment: "Comma-separated domain/URI blocklist zones"},
	{Key: "ENABLE_RSPAMD", Default: "true", Comment: "Enable Rspamd integration (default: true — requires rspamd service)"},
	{Key: "RSPAMD_URL", Default: "http://rspamd:11334/checkv2", Comment: "Rspamd checkv2 endpoint"},
	{Key: "RSPAMD_PASSWORD", Default: "", Comment: "Rspamd controller password (leave empty when using secure_ip)"},
	{Key: "ENABLE_SPAMASSASSIN", Default: "false", Comment: "Enable SpamAssassin integration (optional, disabled by default)"},
	{Key: "SPAMASSASSIN_HOSTPORT", Default: "spamd:783", Comment: "SpamAssassin spamd address (only used when ENABLE_SPAMASSASSIN=true)"},

	// ── Alerting ──────────────────────────────────────────────────────────────
	{Group: "Alerting", Key: "ALERT_WEBHOOK_URL", Default: "", Comment: "Webhook URL for error/warning notifications (JSON POST)"},

	// ── Privacy page ──────────────────────────────────────────────────────────
	{Group: "Privacy page", Key: "PRIVACY_OPERATOR_NAME", Default: "", Comment: "Legal name of the operator shown in the Datenschutzerklärung"},
	{Key: "PRIVACY_OPERATOR_ADDRESS", Default: "", Comment: "Postal address of the operator"},
	{Key: "PRIVACY_OPERATOR_EMAIL", Default: "", Comment: "Contact email of the operator"},
	{Key: "PRIVACY_HIDE_TEMPLATE_NOTE", Default: "false", Comment: "Set to true to hide the 'this is a template' notice once operator details are filled in"},

	// ── Env migration ─────────────────────────────────────────────────────────
	{Group: "Env migration", Key: "ENV_FILE", Default: "/config/.env", Comment: "Path inside the container to the mounted .env file; enables automatic migration on startup"},
}

// MigrateFile reads the .env file at path, appends every variable from [All]
// that is not yet present, and writes the result back.
// It returns the keys that were added (empty slice = nothing to do).
// If path is empty or the file does not exist the function returns without error.
func MigrateFile(path string) (added []string, err error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}

	existing, raw, err := parseEnvFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no file yet – nothing to migrate
		}
		return nil, fmt.Errorf("envmigrate: read %s: %w", path, err)
	}

	// Build the block of new entries grouped by section.
	var newLines []string
	currentGroup := ""
	for _, v := range All {
		if existing[v.Key] {
			continue // already present – never touch it
		}
		added = append(added, v.Key)
		if v.Group != "" && v.Group != currentGroup {
			currentGroup = v.Group
			newLines = append(newLines, "")
			newLines = append(newLines, "# ── "+currentGroup+" ──")
		}
		if v.Comment != "" {
			newLines = append(newLines, "# "+v.Comment)
		}
		newLines = append(newLines, v.Key+"="+v.Default)
	}

	if len(added) == 0 {
		return nil, nil // nothing to do
	}

	// Build header for the new block.
	header := []string{
		"",
		"# ══════════════════════════════════════════════════════════════════════════════",
		fmt.Sprintf("# Auto-added by Sender-Report %s on %s", version.Version, time.Now().UTC().Format("2006-01-02")),
		"# New variables were found that are not yet in this file.",
		"# Review the values below and restart the container when done.",
		"# ══════════════════════════════════════════════════════════════════════════════",
	}

	all := append(raw, header...)
	all = append(all, newLines...)
	all = append(all, "") // trailing newline

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("envmigrate: write %s: %w", path, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, line := range all {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return nil, fmt.Errorf("envmigrate: write line: %w", err)
		}
	}
	return added, w.Flush()
}

// parseEnvFile returns a set of keys already defined in the file plus the raw
// lines (for rewriting).
func parseEnvFile(path string) (keys map[string]bool, lines []string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	keys = make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		lines = append(lines, line)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Handle  KEY=value  and  export KEY=value
		trimmed = strings.TrimPrefix(trimmed, "export ")
		key, _, _ := strings.Cut(trimmed, "=")
		key = strings.TrimSpace(key)
		if key != "" {
			keys[key] = true
		}
	}
	return keys, lines, sc.Err()
}
