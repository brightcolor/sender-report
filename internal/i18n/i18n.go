// Package i18n provides simple two-language (DE/EN) support for the web UI.
// Language is determined by:
//  1. The "sr_lang" cookie (manual user override, set via the switcher).
//  2. The Accept-Language request header (browser preference).
//  3. Default: English.
//
// German is served when the primary language tag is "de"; everything else
// falls back to English.
package i18n

import (
	"net/http"
	"strings"
)

// Lang represents a supported UI language.
type Lang string

const (
	DE Lang = "de"
	EN Lang = "en"
)

// CookieName is the cookie used for the manual language override.
const CookieName = "sr_lang"

// Detect returns the preferred language for the given request.
func Detect(r *http.Request) Lang {
	// 1. Manual override cookie.
	if c, err := r.Cookie(CookieName); err == nil {
		if l := Lang(c.Value); l == DE || l == EN {
			return l
		}
	}
	// 2. Accept-Language header.
	return detectFromHeader(r.Header.Get("Accept-Language"))
}

func detectFromHeader(header string) Lang {
	for _, part := range strings.Split(header, ",") {
		tag := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		primary := strings.SplitN(strings.ToLower(tag), "-", 2)[0]
		if primary == "de" {
			return DE
		}
		if primary == "en" {
			return EN
		}
	}
	return EN
}

// T returns the translation of key in the given language.
// Falls back to the key itself if not found.
func T(lang Lang, key string) string {
	var m map[string]string
	if lang == DE {
		m = de
	} else {
		m = en
	}
	if s, ok := m[key]; ok {
		return s
	}
	// Fallback: English then raw key.
	if s, ok := en[key]; ok {
		return s
	}
	return key
}

// ── String tables ─────────────────────────────────────────────────────────────

var de = map[string]string{
	// ── Nav / shared ──────────────────────────────────────────────────────────
	"nav.home":           "sender.report",
	"nav.about":          "Über",
	"nav.privacy":        "Datenschutz",
	"nav.mailbox":        "Mailbox",
	"nav.report":         "Report",
	"nav.more":           "Mehr",
	"nav.about_checks":   "Was wird geprüft?",
	"nav.theme_toggle":   "Theme wechseln",

	// ── Home page ─────────────────────────────────────────────────────────────
	"home.title":         "E-Mail-Zustellbarkeit testen",
	"home.subtitle":      "Prüf in Sekunden ob deine Mails bei Gmail, Outlook und Co. ankommen – kostenlos, anonym und Ende-zu-Ende verschlüsselt.",
	"home.widget_title":  "Deine Test-Mailbox",
	"home.e2e_badge":     "Ende-zu-Ende verschlüsselt",
	"home.loading":       "Mailbox wird vorbereitet …",
	"home.copy_hint":     "Klicken zum Kopieren",
	"home.copy_link":     "Link kopieren (inkl. Schlüssel)",
	"home.start":         "Check starten",
	"home.new_address":   "Neue Mailbox",
	"home.adv_checks":    "Erweiterte Reputations-Checks",
	"home.waiting":       "Warte auf eingehende E-Mail …",
	"home.idle":          "Noch keine E-Mail für diese Mailbox geprüft.",
	"home.expires":       "Gültig bis",
	"home.e2e_footer":    "E2E verschlüsselt",
	"home.prev_title":    "Frühere Mailboxen",
	"home.trust_title":   "Sicher – ganz ohne Aufwand für dich",
	"home.features_title": "Was wird geprüft?",
	"home.feat_auth":     "SPF · DKIM · DMARC",
	"home.feat_auth_desc": "Kryptografisch verifiziert – genau wie echte Mailserver.",
	"home.feat_dns":      "PTR · MX · HELO",
	"home.feat_dns_desc": "DNS-Infrastruktur auf Konfigurationsfehler prüfen.",
	"home.feat_spam":     "SpamAssassin · Rspamd · RBL",
	"home.feat_spam_desc": "Externe Filter-Scores und Blocklist-Status.",
	"home.feat_content":  "MIME · Links · Betreff",
	"home.feat_content_desc": "Inhalt und Format auf Spam-Signale analysieren.",
	"home.feat_advanced": "Domain-Alter · Blocklisten",
	"home.feat_advanced_desc": "Optionale Reputations-Checks – opt-in.",
	"home.open_report":    "Report öffnen",
	"home.mail_received":  "E-Mail empfangen",
	"home.mail_analysed":  "Analysiert",
	"home.cancel":         "Abbrechen",
	"home.apply":          "Auswahl übernehmen",
	"home.adv_modal_title": "Erweiterte Reputations-Checks",
	"nav.close":           "Schließen",

	// ── Mailbox page ──────────────────────────────────────────────────────────
	"mailbox.send_to":           "Sende deine Testmail an",
	"mailbox.auto_update":       "aktualisiert automatisch",
	"mailbox.waiting":           "Warte auf eingehende E-Mail …",
	"mailbox.expires":           "Mailbox läuft ab",
	"mailbox.extend":            "Verlängern",
	"mailbox.new_check":         "Neuer Check",
	"mailbox.no_messages":       "Noch keine Mails empfangen.",
	"mailbox.valid_until":       "Gültig bis",
	"mailbox.extend_title":      "Gültigkeit verlängern",
	"mailbox.direct_link":       "Direktlink",
	"mailbox.copy_link":         "Link kopieren",
	"mailbox.received_messages": "Empfangene Nachrichten",
	"mailbox.newest_first":      "Neueste zuerst",
	"mailbox.col_message":       "Nachricht",
	"mailbox.col_actions":       "Aktionen",
	"mailbox.no_email_yet":      "Noch keine E-Mail empfangen",
	"mailbox.auto_updates_msg":  "Diese Seite aktualisiert sich automatisch, sobald eine Nachricht eingeht.",
	"mailbox.analysing":         "Analyse …",
	"mailbox.modal_close":       "Schließen",
	"mailbox.modal_new_duration": "Neue Laufzeit ab jetzt",
	"mailbox.modal_or_date":     "Oder exaktes Datum & Uhrzeit wählen",
	"mailbox.modal_cancel":      "Abbrechen",
	"nav.home_link":             "Startseite",

	// ── Report page ───────────────────────────────────────────────────────────
	"report.score_label":   "Gesamtscore",
	"report.e2e_badge":     "E2E verschlüsselt",
	"report.e2e_unlocked":  "Entschlüsselt",
	"report.passed":        "bestanden",
	"report.warnings":      "Warnungen",
	"report.errors":        "Fehler",
	"report.infos":         "Infos",
	"report.subject":       "Betreff",
	"report.received":      "Empfangen",
	"report.from":          "Envelope-From",
	"report.source":        "Quelle (IP / HELO)",
	"report.size":          "Größe",
	"report.share_title":   "Report teilen",
	"report.share_full":    "Vollständiger Link (inkl. Schlüssel)",
	"report.share_nokey":   "Link ohne Schlüssel",
	"report.share_key":     "Nur der Schlüssel",
	"report.copy":          "Klicken zum Kopieren",
	"report.copied":        "Kopiert!",

	// Check body
	"check.explanation":   "Erklärung",
	"check.how_to_fix":    "Wie wird's gemacht?",
	"check.sources":       "Quellen & Tools",
	"check.raw_data":      "Rohdaten anzeigen",
	"check.raw_hide":      "Rohdaten ausblenden",

	// Group statuses
	"group.action_needed": "Handlungsbedarf",
	"group.check_recommended": "Prüfen empfohlen",
	"group.all_good":      "Alles in Ordnung",
	"group.reload":        "Ganze Sektion neu prüfen",
	"group.reload_check":  "Neu prüfen (frische DNS-/Reputations-Abfrage)",

	// Category names
	"cat.auth":      "Authentifizierung",
	"cat.dns":       "DNS und Infrastruktur",
	"cat.spam":      "Spamfilter",
	"cat.content":   "Format und Inhalt",
	"cat.headers":   "Header und Rohdaten",

	// Category hints
	"hint.auth":    "Beweist, dass die Mail wirklich von deiner Domain stammt. SPF, DKIM und DMARC sind heute der wichtigste Faktor für die Zustellung – Gmail und Outlook lehnen ohne sie zunehmend ab.",
	"hint.dns":     "Prüft, ob deine sendende IP und deine Hostnamen sauber im DNS hinterlegt sind (Reverse DNS, HELO, MX, A/AAAA, TLS). Inkonsistenzen hier wirken wie ein schlecht konfigurierter oder gekaperter Server.",
	"hint.spam":    "Externe Reputations- und Inhaltsfilter (SpamAssassin, Rspamd, DNSBL). Zeigt, wie verbreitete Filter deine Mail bewerten und welche Einzelsignale dabei zählen.",
	"hint.content": "Aufbau der Nachricht: MIME-Struktur, Text/HTML-Verhältnis, Links, Betreff und Anhänge. Schlechtes Format ist ein klassisches Spam-Signal und kann die Darstellung beim Empfänger zerstören.",
	"hint.headers": "Technische Basis-Header (Date, Message-ID, Received-Kette). Fehlende oder unplausible Pflichtfelder deuten auf einen fehlkonfigurierten Mailserver hin.",

	// Status labels
	"status.pass": "Bestanden",
	"status.warn": "Warnung",
	"status.fail": "Fehler",
	"status.info": "Info",
	"status.na":   "N/A",

	// Importance labels
	"imp.critical":    "Kritisch",
	"imp.important":   "Wichtig",
	"imp.recommended": "Empfohlen",
	"imp.optional":    "Optional",

	// Mail type labels
	"mailtype.personal":      "Persönlich",
	"mailtype.transactional": "Transactional",
	"mailtype.bulk":          "Newsletter/Bulk",
	"mailtype.unknown":       "Unbekannt",
	"mailtype.detected":      "Automatisch erkannter Mail-Typ",

	// PDF / Share / Recommendations side panel
	"report.download_pdf":    "Als PDF",
	"report.recommendations": "Empfehlungen",
	"report.spam_signals":    "Spam-Indikatoren",
	"report.links_title":     "Gefundene Links",
	"report.links_clean":     "Alle Links unauffällig",
	"report.no_links":        "Keine Links in der Mail gefunden.",
	"report.raw_headers":     "Rohe Header",
	"report.advanced_title":  "Erweiterte Checks",
	"report.advanced_info":   "Erweiterte Reputations-Checks",

	// RBL
	"rbl.listed_on":          "Gelistet auf",
	"rbl.before_delisting":   "Vor dem Delisting",
	"rbl.template_letter":    "Formulierungshilfe anzeigen (DE / EN)",
	"rbl.delisting_hints":    "Delisting-Hinweise anzeigen",
	"rbl.delisting_btn":      "Delisting",

	// Recheck
	"recheck.updated": "Aktualisiert",
	"recheck.saved":   "Gespeichert",
	"recheck.failed":  "Aktualisiert ✓ (Speichern fehlgeschlagen)",

	// Misc
	"misc.encrypted_content": "🔒 verschlüsselt",
	"misc.no_subject":        "(kein Betreff)",
	"misc.unknown":           "unbekannt",
	"misc.none":              "–",
}

var en = map[string]string{
	// ── Nav / shared ──────────────────────────────────────────────────────────
	"nav.home":           "sender.report",
	"nav.about":          "About",
	"nav.privacy":        "Privacy",
	"nav.mailbox":        "Mailbox",
	"nav.report":         "Report",
	"nav.more":           "More",
	"nav.about_checks":   "What gets checked?",
	"nav.theme_toggle":   "Toggle theme",

	// ── Home page ─────────────────────────────────────────────────────────────
	"home.title":         "Test your email deliverability",
	"home.subtitle":      "Check in seconds whether your emails reach Gmail, Outlook and others – free, anonymous and end-to-end encrypted.",
	"home.widget_title":  "Your test mailbox",
	"home.e2e_badge":     "End-to-end encrypted",
	"home.loading":       "Preparing mailbox …",
	"home.copy_hint":     "Click to copy",
	"home.copy_link":     "Copy link (incl. key)",
	"home.start":         "Start check",
	"home.new_address":   "New mailbox",
	"home.adv_checks":    "Advanced reputation checks",
	"home.waiting":       "Waiting for incoming email …",
	"home.idle":          "No email received for this mailbox yet.",
	"home.expires":       "Valid until",
	"home.e2e_footer":    "E2E encrypted",
	"home.prev_title":    "Previous mailboxes",
	"home.trust_title":   "Secure – no effort required",
	"home.features_title": "What gets checked?",
	"home.feat_auth":     "SPF · DKIM · DMARC",
	"home.feat_auth_desc": "Cryptographically verified – exactly like real mail servers.",
	"home.feat_dns":      "PTR · MX · HELO",
	"home.feat_dns_desc": "Check DNS infrastructure for misconfigurations.",
	"home.feat_spam":     "SpamAssassin · Rspamd · RBL",
	"home.feat_spam_desc": "External filter scores and blocklist status.",
	"home.feat_content":  "MIME · Links · Subject",
	"home.feat_content_desc": "Analyse content and format for spam signals.",
	"home.feat_advanced": "Domain age · Blocklists",
	"home.feat_advanced_desc": "Optional reputation checks – opt-in.",
	"home.open_report":    "Open report",
	"home.mail_received":  "Email received",
	"home.mail_analysed":  "Analysed",
	"home.cancel":         "Cancel",
	"home.apply":          "Apply",
	"home.adv_modal_title": "Advanced Reputation Checks",
	"nav.close":           "Close",

	// ── Mailbox page ──────────────────────────────────────────────────────────
	"mailbox.send_to":           "Send your test email to",
	"mailbox.auto_update":       "updates automatically",
	"mailbox.waiting":           "Waiting for incoming email …",
	"mailbox.expires":           "Mailbox expires",
	"mailbox.extend":            "Extend",
	"mailbox.new_check":         "New check",
	"mailbox.no_messages":       "No emails received yet.",
	"mailbox.valid_until":       "Valid until",
	"mailbox.extend_title":      "Extend validity",
	"mailbox.direct_link":       "Direct link",
	"mailbox.copy_link":         "Copy link",
	"mailbox.received_messages": "Received messages",
	"mailbox.newest_first":      "Newest first",
	"mailbox.col_message":       "Message",
	"mailbox.col_actions":       "Actions",
	"mailbox.no_email_yet":      "No email received yet",
	"mailbox.auto_updates_msg":  "This page updates automatically as soon as a message arrives.",
	"mailbox.analysing":         "Analysing …",
	"mailbox.modal_close":       "Close",
	"mailbox.modal_new_duration": "New duration from now",
	"mailbox.modal_or_date":     "Or choose an exact date & time",
	"mailbox.modal_cancel":      "Cancel",
	"nav.home_link":             "Home",

	// ── Report page ───────────────────────────────────────────────────────────
	"report.score_label":   "Overall score",
	"report.e2e_badge":     "E2E encrypted",
	"report.e2e_unlocked":  "Decrypted",
	"report.passed":        "passed",
	"report.warnings":      "warnings",
	"report.errors":        "errors",
	"report.infos":         "infos",
	"report.subject":       "Subject",
	"report.received":      "Received",
	"report.from":          "Envelope-From",
	"report.source":        "Source (IP / HELO)",
	"report.size":          "Size",
	"report.share_title":   "Share report",
	"report.share_full":    "Full link (incl. key)",
	"report.share_nokey":   "Link without key",
	"report.share_key":     "Key only",
	"report.copy":          "Click to copy",
	"report.copied":        "Copied!",

	// Check body
	"check.explanation":   "Explanation",
	"check.how_to_fix":    "How to fix it",
	"check.sources":       "Sources & tools",
	"check.raw_data":      "Show raw data",
	"check.raw_hide":      "Hide raw data",

	// Group statuses
	"group.action_needed": "Action needed",
	"group.check_recommended": "Review recommended",
	"group.all_good":      "All good",
	"group.reload":        "Re-check entire section",
	"group.reload_check":  "Re-check (fresh DNS / reputation lookup)",

	// Category names
	"cat.auth":      "Authentication",
	"cat.dns":       "DNS & Infrastructure",
	"cat.spam":      "Spam filters",
	"cat.content":   "Format & content",
	"cat.headers":   "Headers & raw data",

	// Category hints
	"hint.auth":    "Proves the email genuinely comes from your domain. SPF, DKIM and DMARC are the most important factor for deliverability today – Gmail and Outlook increasingly reject mail without them.",
	"hint.dns":     "Checks whether your sending IP and hostnames are correctly set up in DNS (reverse DNS, HELO, MX, A/AAAA, TLS). Inconsistencies here look like a misconfigured or hijacked server.",
	"hint.spam":    "External reputation and content filters (SpamAssassin, Rspamd, DNSBL). Shows how common filters score your email and which individual signals contribute.",
	"hint.content": "Message structure: MIME layout, text/HTML ratio, links, subject and attachments. Poor formatting is a classic spam signal and can break rendering for recipients.",
	"hint.headers": "Technical base headers (Date, Message-ID, Received chain). Missing or implausible mandatory fields indicate a misconfigured mail server.",

	// Status labels
	"status.pass": "Passed",
	"status.warn": "Warning",
	"status.fail": "Failed",
	"status.info": "Info",
	"status.na":   "N/A",

	// Importance labels
	"imp.critical":    "Critical",
	"imp.important":   "Important",
	"imp.recommended": "Recommended",
	"imp.optional":    "Optional",

	// Mail type labels
	"mailtype.personal":      "Personal",
	"mailtype.transactional": "Transactional",
	"mailtype.bulk":          "Newsletter/Bulk",
	"mailtype.unknown":       "Unknown",
	"mailtype.detected":      "Auto-detected mail type",

	// PDF / Share / Recommendations side panel
	"report.download_pdf":    "Download PDF",
	"report.recommendations": "Recommendations",
	"report.spam_signals":    "Spam signals",
	"report.links_title":     "Links found",
	"report.links_clean":     "All links are clean",
	"report.no_links":        "No links found in this email.",
	"report.raw_headers":     "Raw headers",
	"report.advanced_title":  "Advanced checks",
	"report.advanced_info":   "Advanced reputation checks",

	// RBL
	"rbl.listed_on":          "Listed on",
	"rbl.before_delisting":   "Before requesting delisting",
	"rbl.template_letter":    "Show template letter (DE / EN)",
	"rbl.delisting_hints":    "Show delisting hints",
	"rbl.delisting_btn":      "Delisting",

	// Recheck
	"recheck.updated": "Updated",
	"recheck.saved":   "Saved",
	"recheck.failed":  "Updated ✓ (save failed)",

	// Misc
	"misc.encrypted_content": "🔒 encrypted",
	"misc.no_subject":        "(no subject)",
	"misc.unknown":           "unknown",
	"misc.none":              "–",
}
