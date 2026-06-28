# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.22.3] - 2026-06-29

### Fixed
- **SPF redirect= not recognised in strictness check** — records like
  `v=spf1 redirect=XXXXX.de.spf.hornetdmarc.com` have no `all` mechanism of their
  own; per RFC 7208 §6.1 the redirect target's policy (including its `all`) is
  authoritative. The analyser now follows the redirect one DNS level deep and
  evaluates the target's `all` qualifier. The report shows the effective `all`
  with a `(via redirect=...)` note, and the raw + resolved records in the detail
  panel. Previously these records always produced a spurious "no all mechanism"
  warning.

## [1.22.2] - 2026-06-29

### Fixed
- **SPF false-positive on forwarded mail** — when a mail passes through a forwarding
  MTA, SPF always fails at the final hop because the forwarder's IP is not listed in
  the original sender's SPF record. This is expected and unavoidable, not a sender
  misconfiguration. The analyzer now detects forwarding and adjusts the verdict:
  - `fail/softfail` with forwarding → `warn` (−0.3) instead of `fail` (−1.4) with an
    explanatory message pointing to DKIM as the robust alternative.
  - DMARC alignment check similarly downgraded when SPF alignment breaks at a forwarder
    but DKIM alignment is intact.
  - Forwarding detected via: `arc=pass`/`arc=fail` in Authentication-Results, presence
    of ARC-Seal / ARC-Message-Signature headers, `Resent-From`/`Resent-To`/`Resent-Sender`
    headers, and `X-Forwarded-To` header.

## [1.22.1] - 2026-06-23

### Added
- **IPT seed account health monitoring** — the server now checks every configured
  seed account at startup and periodically (default every 6 hours) via a TLS IMAP
  login/logout ping.
  - Failed accounts are marked as unavailable; the UI shows them with a grey "N/A"
    badge and the checkbox is disabled so users cannot select broken providers.
  - `iptStartAPI` filters out providers whose accounts are all unhealthy and returns
    `unavailable_providers` in the response.
  - Admin alert emails are sent when an account transitions from healthy to failed
    (one email per event, not every check cycle). Recovery is logged server-side.
  - Alert emails include the raw IMAP/TLS error string when
    `IPT_ALERT_INCLUDE_RAW_ERRORS=true` (default).
  - New environment variables: `IPT_CHECK_INTERVAL`, `IPT_ALERT_EMAIL`,
    `IPT_ALERT_SMTP_ADDR`, `IPT_ALERT_SMTP_FROM`, `IPT_ALERT_SMTP_USER`,
    `IPT_ALERT_SMTP_PASS`, `IPT_ALERT_INCLUDE_RAW_ERRORS`.
  - Supports port 465 (implicit TLS) and port 587/25 (STARTTLS) for outbound SMTP.

## [1.22.0] - 2026-06-23

### Added
- **Inbox Placement Testing** — operator-configurable seed accounts let users verify
  whether a test mail actually lands in the inbox or spam folder at real providers.
  - Operators configure seed accounts in `seeds.json` (multiple accounts per provider
    pooled; one is picked at random per test to avoid overloading individual accounts).
  - Users choose which providers to test via checkboxes in the UI; a unique subject
    token (`[SR-xxxxxx]`) is generated per test so the system can identify the mail.
  - Users send the mail directly from their own server to the displayed seed addresses
    — no relay, no header modification.
  - The system polls IMAP every 30 s (TLS-only, port 993) for up to 10 minutes and
    delivers live results via SSE (same pattern as mailbox events).
  - Results: `inbox`, `spam`, or `not arrived` (timeout).
  - Available from the home page (after mailbox creation) and from the report toolbar.
  - New environment variables: `ENABLE_INBOX_PLACEMENT`, `SEED_ACCOUNTS_FILE`.
  - Privacy: seed credentials are never exposed to clients; TLS-only IMAP; a privacy
    notice is shown in the UI before each test.

### Fixed
- **Simulator score parity** — `spf_strictness`, `dmarc_policy`, and `broken_links`
  were incorrectly listed as Group B sim-placeholder checks, causing duplicate `info`
  entries and a corrupted score when comparing simulator vs. report results.
  All three run in Group A (synchronous header/content checks) and must not appear
  in the Group B placeholder list.

## [1.21.0] - 2026-06-22

### Added
- **Mail Simulator (`/simulate`)** — paste any RFC 2822 email source into the editor
  and see live check results and score updates without sending a real test mail.
  - Content/header checks (Group A) run on each keystroke, debounced 600 ms.
  - DNS/network checks (Group B) and opt-in checks (Group C) are skipped by default
    and shown as placeholder info results; each can be triggered individually via a
    per-check "Jetzt prüfen / Run now" recheck button.
  - Score bar with live progress, delta indicator vs. original report score.
  - "Mail simulieren" button on the report page opens the simulator pre-loaded with
    the current mail source (stored in sessionStorage).
  - New API endpoints: `POST /api/simulate` and `POST /api/simulate/recheck/{token}`.
  - `analyzer.Input.SimulationMode` flag skips Group B/C goroutine pool and injects
    placeholder `info` results enriched through the normal enrichment pipeline.

## [1.20.0] - 2026-06-22

### Added
- **New check `x_google_dkim`** — parses `x-google-dkim=` from Authentication-Results.
  info if not present (only relevant for Google-routed mail); warn(-0.2) on fail.
  Category: Authentifizierung, Importance: Optional.
- **New check `too_many_links`** — >30 links in a mail is a recognised spam signal.
  warn(-0.3); info for 5–30 links; silent below 5.
  Category: Format und Inhalt, Importance: Empfohlen.
- **New check `no_reply_reply_to`** — From is a no-reply address but Reply-To is absent.
  warn(-0.2); recipients' replies go nowhere.
  Category: Header und Rohdaten, Importance: Empfohlen.
- **New check `link_domain_mismatch`** — link text shows a different domain than the
  actual href target (phishing pattern). fail(-0.8) when detected; pass otherwise.
  Uses the html.Node parser for accurate anchor text extraction.
  Category: Format und Inhalt, Importance: Kritisch.
- **Broken-Link-Check opt-in** — new optional check `broken_links` that makes HTTP GET
  requests (max 50 unique URLs, 5 concurrent, 8 s timeout) to all links in the email.
  Shown as info("disabled") when not enabled. Full opt-in stack:
  - DB migration: `check_broken_links` column on mailboxes table.
  - `model.Mailbox.CheckBrokenLinks`, `analyzer.Options/Input.EnableBrokenLinks`,
    `config.EnableBrokenLinks` / env `ENABLE_BROKEN_LINKS`.
  - `/api/mailboxes/{token}/checks` API accepts `check_broken_links`.
  - Home-page advanced-checks modal: new checkbox with bilingual inline privacy
    warning (explains that HTTP requests are made to destination servers).
  - app.js: `broken_links` persisted in `sr:advchecks` localStorage, synced to server.

### All new checks include full DE/EN enrichment (name, explanation, summary, recommendation).

## [1.19.1] - 2026-06-22

### Added
- **New check `image_alt` – Image Alt Text.**
  Parses the HTML body and counts `<img>` tags missing an `alt` attribute.
  Pass if all images have alt; warn(-0.2) if some are missing; warn(-0.4) if all
  are missing; info if no images. Helps with image-to-text ratio and client
  rendering when images are blocked.
- **New check `harmful_html` – Harmful HTML Elements.**
  Detects `<script>` tags (fail, -0.7) and `<meta http-equiv=refresh>` redirects
  (warn, -0.4) in the HTML body. Both are strong spam signals: no email client
  executes JavaScript or meta-redirects, but many spam filters heavily penalise
  their presence. Category: Format und Inhalt, Importance: Wichtig.
- **New check `fake_reply` – Fake Reply Prefix.**
  Detects when the Subject starts with a reply/forward prefix (Re:, Fwd:, Aw:,
  Wg: and 10 other localisations) but neither `In-Reply-To` nor `References`
  headers are present — the classic "fake-reply spam" trick. Warn(-0.4) when
  detected; no check added otherwise.
- **New check `message_id_format` – Message-ID Format.**
  Validates that an existing Message-ID follows RFC 5322 format
  (`<local@domain>`). Warn(-0.3) for invalid format; pass otherwise. Only
  evaluated when a Message-ID is present (the `message_id` presence check
  already covers the missing case).

## [1.19.0] - 2026-06-21

### Added
- **New check `from_domain_rcv` – From Domain Reachability.**
  DNS lookup (MX → A/AAAA fallback) on the From: header domain to verify that
  replies and bounces are actually deliverable. Pass if MX found, info if only
  A/AAAA, warn (-0.4) if neither. Runs concurrently with other DNS checks.
  Skipped (info) when From domain equals bounce/envelope domain to avoid
  duplicate penalties.
- **New check `one_click_unsub` – One-Click Unsubscribe (RFC 8058).**
  For bulk mail with a List-Unsubscribe header: checks whether the
  `List-Unsubscribe-Post: List-Unsubscribe=One-Click` header is present.
  Pass (+0.1) if compliant, warn (-0.3) if missing. N/A for personal and
  transactional mail. Google and Yahoo mandated RFC 8058 for bulk senders
  (>5 000 mails/day) starting February 2024.
- **New check `template_urls` – Template Placeholders in Links.**
  Detects unreplaced ESP merge-tag placeholders in links
  (`{var}`, `{{var}}`, `*|VAR|*`, `${var}`, `%7B…%7D`).
  Fail (-0.6) if found (broken links for recipients), N/A for personal/
  transactional mail, info if no links present.
- **Enhanced ARC check.**
  Now parses the `arc=` result from `Authentication-Results` headers.
  `arc=pass` → info(0.0) "chain verified"; `arc=fail` → warn(-0.2)
  "chain broken"; headers present but no result → info; no headers → info
  (unchanged from before, only relevant in forwarding scenarios).

### Changed
- **Scoring adjustments — more realistic impact weights:**
  - `tls_transport` (no TLS evidence): `info(0.0)` → `warn(-0.2)`.
    TLS in transit is a baseline expectation in 2024/2025.
  - `plain_text` (missing text part): delta -0.8 → -0.5.
  - `hidden_html` (excessive hidden content): delta -0.6 → -0.4.
  - `envelope_mx` (bounce domain without MX): delta -0.4 → -0.5.
- **Improved `image_text_ratio` algorithm.**
  Replaced the crude two-state check (`>=4 images AND <240 chars`) with a
  graduated four-tier check:
  - fail(-0.7): images present, virtually no text (<80 chars) — pure image mail
  - warn(-0.4): ≥3 images, little text (<250 chars)
  - warn(-0.3): image-to-text ratio >60 % (overweight on images)
  - info(0.0): everything else

## [1.18.3] - 2026-06-10

### Fixed
- **report.html: all remaining hardcoded German strings translated.**
  The i18n agent in v1.18.0 missed many static strings in report.html.
  Everything is now language-aware via `{{t .Lang "..."}}` / `{{if eq .Lang "de"}}` / `LANG===` ternaries:
  - Navbar: "More/Mehr", "About/Über", "What gets checked?/Was wird geprüft?",
    "Privacy/Datenschutz", "Toggle theme/Theme wechseln", "New test/Neuer Test"
  - Metadata boxes: "(no subject)/(kein Betreff)", "🔒 encrypted/verschlüsselt",
    "(empty)/(leer)", date locale (en-GB / de-DE)
  - Filter bar: "Filter:/Anzeigen:", "All/Alle", status labels
  - E2E lock banner: full text + "Enter key/Schlüssel eingeben" + "Decrypting…"
  - Key-entry modal: title, hint, placeholder, Cancel/Abbrechen, Decrypt/Entschlüsseln
  - PDF modal: all labels, checkboxes, warnings, button text
  - Raw data card header
  - RBL "Show all checked lists" button
  - Mail-type badge title
  - JS decrypt flow error/status messages
  - Recheck toasts (section recheck, save, failure messages)
  - PDF error alerts

## [1.18.2] - 2026-06-10

### Fixed
- **E2E decryption broken after i18n changes.** The background agent that
  introduced the language-aware labels in `renderDecCheckItem` used curly/smart
  quotes (U+2018/U+2019) as JavaScript string delimiters instead of straight
  ASCII quotes. This caused a JS syntax error that aborted the entire encrypted
  IIFE before any event listeners (DOMContentLoaded auto-decrypt, key-submit
  click) could register — resulting in "nothing happens" on all decryption
  paths. All smart quotes replaced with straight ASCII `'` quotes.

## [1.18.0] - 2026-06-09

### Added
- **DE/EN language support.** The UI is now available in German and English.
  Language is selected automatically from the browser's Accept-Language header
  and can be overridden by clicking the DE/EN switcher in every navbar.
  The preference is stored in the `sr_lang` cookie.

  Scope of the translation:
  - All templates (home, mailbox, report): UI chrome, labels, buttons,
    section names, status pills, group status text, category hints.
  - JavaScript: statusLbl, groupStatusHTML, GROUP_HINTS, importance badges,
    RBL detail labels, check body headings, mail type badge.
  - Analyzer: every check result now carries parallel English fields
    (`name_en`, `summary_en`, `explanation_en`, `recommendation_en`) for
    the most important checks (SPF, DKIM, DMARC, PTR, RBL, alignments,
    policy checks, etc.); stored in the encrypted payload so existing
    reports can be viewed in either language.
  - New endpoint `POST /lang` sets the language cookie and redirects back.
  - New package `internal/i18n` with language detection and string tables.

## [1.17.0] - 2026-06-09

### Added
- **RBL details in encrypted reports.** The rich RBL display (impact banner,
  per-provider hit list with delisting buttons, collapsible delisting hints,
  pre-delisting checklist, DE/EN template letter) already existed for
  non-encrypted reports. Added `renderRblDetails()` in JS so E2E-encrypted
  reports render the identical structured output after client-side decryption.

## [1.16.5] - 2026-06-07

### Changed
- **Exact score and delta display (no rounding).** Score deltas are now shown
  with up to 2 decimal places, stripping trailing zeros: `-0.25` instead of
  `-0.3`, `-0.6` instead of `-0.6` (unchanged here), `–` for zero. The total
  score is similarly shown without forced single-decimal rounding: `9.15`
  instead of `9.2`. This makes the individual deltas add up visibly to the
  total score without apparent discrepancies.

## [1.16.4] - 2026-06-07

### Added
- **`dmarc_policy` live recheck.** The DMARC policy strength check now has
  a refresh icon like all other DNS-based checks. Clicking it re-fetches the
  `_dmarc.<domain>` TXT record and re-evaluates the `p=` tag (none /
  quarantine / reject) without re-sending a mail.

## [1.16.3] - 2026-06-07

### Changed
- **Mail-type default flipped to "personal".** If no explicit bulk signals
  are present (`Precedence`, `List-*`, `Feedback-ID`) and no transactional
  `Auto-Submitted` header, the mail is now classified as `personal` instead
  of `unknown`. Bulk mailers always carry at least one of these headers;
  everything else (custom domains, Google Workspace, self-hosted, etc.)
  is treated as a human-sent message and bulk-only checks (`return_path`,
  `list_unsub`) are marked N/A.

## [1.16.2] - 2026-06-07

### Fixed
- **Mail-type detection for webmail clients.** Gmail, Outlook.com, Yahoo,
  iCloud, GMX, web.de, ProtonMail and ~30 other consumer webmail providers
  set no `X-Mailer`/`User-Agent` header via their web UI, causing mails to
  fall back to "unknown" instead of "personal". Added `isConsumerWebmail()`
  that matches the From-address domain against a list of known consumer
  providers, so `return_path` and `list_unsub` are correctly marked N/A for
  personal mails sent via webmail.

## [1.16.1] - 2026-06-07

### Changed
- **Monospace link fields.** All fields that show the mailbox address or share
  link (`mp-addr-inline`, `mp-share-text`) now use the same cool monospace stack
  (`Cascadia Code` → `JetBrains Mono` → `ui-monospace` → `Consolas`) and
  `font-weight: 600` for a slightly bolder, technical look.

## [1.16.0] - 2026-06-07

### Added
- **Mail-type auto-detection.** The analyzer now detects the mail type from headers
  (`Precedence`, `List-Unsubscribe`, `List-ID`, `Feedback-ID`, `Auto-Submitted`,
  `X-Mailer`, `User-Agent`) and classifies each message as `personal`, `transactional`,
  `bulk`, or `unknown`. The detected type is stored in `AnalysisReport.MailType` and
  included in the E2E-encrypted payload.
- **N/A check status.** Checks that are irrelevant for a given mail type are now marked
  `na` (not applicable) instead of being scored as failures. Affected checks:
  - `return_path` → N/A for personal and transactional mails
  - `list_unsub` → N/A for personal and transactional; always enforced for bulk
  N/A checks show a grey dash icon, carry no score delta, and display a full
  explanation of why they are not applicable.
- **Mail-type badge in the report hero.** A small badge (🧑 Persönlich /
  ⚙️ Transactional / 📬 Newsletter/Bulk) appears next to the score heading.
  For E2E-encrypted reports it is populated by JS after decryption; for
  cleartext reports it is rendered server-side.
- **N/A count in section headers.** Sections with N/A checks show a grey "– N" badge
  alongside the existing pass/warn/fail/info counters.

## [1.15.2] - 2026-06-04

### Fixed
- **Rspamd DNS resolution.** Pinned Rspamd's resolver to public nameservers
  (`8.8.8.8` / `1.1.1.1`) via `rspamd/local.d/options.inc`, so DNSBL/URIBL/SPF/DKIM
  lookups work instead of failing through Docker's embedded resolver. Also mount
  `rspamd/local.d` into the rspamd service in `docker-compose.yml` and the standalone
  example (the quickstart override already mounted it).

### Added
- `THIRD_PARTY_NOTICES.md` reproducing the licenses of all statically linked Go
  modules (MIT / BSD-3-Clause) plus the bundled frontend assets; generated by
  `scripts/gen-third-party-notices.js`. `LICENSE` + the notices now ship inside the
  container image.

### Changed / Fixed (license hygiene)
- Restored the public-domain attribution header on `tweetnacl.min.js`.
- Moved the Inter font (OFL-1.1, with its `LICENSE.txt`) out of the `vvveb/` path to
  `vendor/inter/`; updated the `@font-face` URLs.
- Removed the unused Vvveb `admin.css` and the now-unused `vvveb/` folder (nothing
  from the Vvveb template was referenced anymore).
- `LICENSE` copyright holder renamed to "sender.report contributors".

### Added
- **SPF strictness is now re-checkable** (refresh icon, fresh SPF-record lookup +
  strictness re-evaluation).
- **Section reload**: each section header has a refresh icon that re-runs *all*
  re-checkable checks in that group at once, updates each item in place
  (preserving open/collapsed state), refreshes the section's counters/status pill,
  and saves once at the end.

### Changed
- The theme toggle now always flips the currently *visible* theme on the first
  click. Default is still "auto" (follow the system), but e.g. with a dark system
  theme the first click switches straight to light (previously the first click
  set "dark" explicitly, which looked like nothing happened).

## [1.14.4] - 2026-06-04

### Changed
- The coloured status squares in the report's check list now contain an icon
  matching the status: ✓ (pass), ! (warn), i (info), ✗ (fail). Applied to both the
  server-rendered and the E2E client-rendered report.

## [1.14.3] - 2026-06-04

### Changed
- A recheck now leaves the check's open/collapsed state exactly as it was — it no
  longer force-opens (or closes) the item.

## [1.14.2] - 2026-06-04

### Changed
- Recheck UX: the recheck control is now a compact **refresh icon in the check's
  header** (with a spinner while running, larger tap target on mobile) instead of
  a button in the body. After a recheck the check **stays open** so the fresh
  result is visible, and a small toast confirms "Aktualisiert / Gespeichert ✓".

### Added
- **Rechecks are now persisted** (they survive a reload). Because reports are
  end-to-end encrypted, the browser re-seals the updated report with the rechecked
  value and the recomputed score and sends the new ciphertext to a new endpoint
  (`POST /api/recheck-persist/{token}/{msgref}`). The server validates the sealed
  blob, recomputes the authoritative score/label from the supplied checks
  (`analyzer.ComputeScore`), overwrites `messages.payload_enc`, and updates the
  cleartext report row (score, label, stripped checks) — without touching the
  cumulative counters. The score ring on the report updates immediately too.

### Added
- **Per-check "Neu prüfen" (live recheck).** Fixed a DNS record? You can now
  re-run an individual external-dependent check straight from the report — no need
  to send a new test mail. Each re-checkable check shows a small button with a
  spinner; the value updates in place when the fresh result comes back.
  - Covers the DNS/RDAP/blocklist checks: SPF & DMARC *record* presence,
    MX, A/AAAA, DKIM key length, bounce-MX, MTA-STS, TLS-RPT, BIMI, DNSSEC,
    DANE/TLSA, PTR + PTR pattern, domain age, domain/link blocklist.
  - The core SPF/DKIM/DMARC *verdicts* (which cryptographically verify the actual
    message) still require a real send, so DKIM offers its key-length recheck and
    SPF/DMARC re-check their DNS record.
  - New endpoint `POST /api/recheck/{token}/{msgref}`; the client supplies the
    externally-observable inputs (domain/IP/…) from the already-decrypted report,
    so nothing extra is stored. Rate-limited; analysis bounded by a 20s timeout
    and panic-isolated.

### Changed
- **A perfect 10 must now be earned.** The score is capped below 10 unless every
  essential check is a clean *pass* — SPF, DKIM, DMARC and PTR. This closes the
  loophole where an unconfirmed/neutral essential (e.g. an ambiguous SPF result
  with a 0 score impact) could still leave a message at a full 10.

## [1.13.0] - 2026-06-04

### Changed
- **Reworked the scoring to be importance-weighted and realistic.** The score now
  starts at 10 and *only* goes down for problems — no more inflation from
  "expected" passes. Each check's impact is derived consistently from its
  importance × status (mirroring how real mail systems weight things):
  - Authentication & reputation dominate: a **critical** failure (SPF/DKIM/DMARC,
    PTR, RBL, domain/link blocklist) costs ~−2.6; **important** ~−1.3; **recommended**
    ~−0.5; **optional** signals (DNSSEC, DANE, BIMI, MTA-STS, …) never penalise.
    So one critical failure outweighs a handful of cosmetic content nits.
  - **Domain age is now dynamic/continuous**: a brand-new domain is penalised
    strongly and the penalty fades smoothly to zero as the domain matures (~1 year),
    instead of the old fixed steps.
  - Reputation checks recalibrated: RBL scales with the number of lists hit
    (−1.3 → −3.0); SpamAssassin "spam" is a fail (−1.6); Rspamd reject −2.2 /
    soft-reject −1.5 / add-header −0.8.
  - Importance tiers updated accordingly (domain-/link-blocklist → Kritisch;
    From-display-name and Received-chain → Wichtig); the /about reference reflects this.

### Removed
- **The home-page scan animation (terminal/score-ring/modal) is gone.** The flow
  is now simply: send the test mail → the page waits for it → as soon as the report
  is ready it briefly confirms "Mail empfangen — Report wird geöffnet" and opens
  the report. No terminal, no animation, no "Zum Report" button.
- Dropped the `ENABLE_CHECK_ANIMATION` setting (config, env migration, .env.example)
  and all related JS/CSS/markup.

## [1.11.1] - 2026-06-04

### Changed
- The scan terminal is now **scrollable**: the full transcript is kept (auto-scroll
  to the newest line during the run; scroll up afterwards to review every check),
  with a slim custom scrollbar and a slightly refined dark look.

## [1.11.0] - 2026-06-04

### Changed
- The scanner now opens in a **larger terminal-window modal** (traffic-light title
  bar, monospace, `✕` to close) that is **fullscreen on mobile** — much roomier
  than the cramped inline box. The encryption finale shows the **full scheme**
  (`X25519 + HKDF-SHA256 + AES-256-GCM`) and wraps instead of truncating. Closing
  the modal restores the idle widget; the "Zum Report" button still ends the flow.

### Changed
- **The scanner animation now looks like a real terminal and uses real data.**
  On the home page the message is decrypted client-side (the key is already local,
  same trust model as the report page) so the terminal shows a shell prompt, the
  actual **sender, source IP, HELO, subject and size**, then every check grouped
  by area (`[OK]/[WARN]/[FAIL]/[INFO]` with score deltas), the total score, and a
  credible, accurate encryption finale ("Klartext wird aus dem Arbeitsspeicher
  entfernt …" → "Verschlüsselt · AES-256-GCM + X25519" → "Schlüssel nur in deinem
  Link"). Pacing is a bit slower so it's readable; falls back to the stored check
  list if decryption isn't available.

### Changed
- The scanner animation now **plays for every visitor** — it is no longer gated
  behind `prefers-reduced-motion` (which silently disabled it for many users
  without them changing anything). The terminal feed and ring count-up always run.
- **No more auto-redirect** at the end of the scan: the report opens via a clear
  **"Zum Report"** button (with the decryption key in the link) instead of jumping
  there automatically.

## [1.9.1] - 2026-06-04

### Fixed
- The home-page scanner animation appeared to "not run" (the score ring flashed
  and it jumped straight to the report) whenever the OS/browser had **reduce
  motion** enabled — the code skipped the whole effect. Now reduced motion still
  shows the full check list and the final score ring, held briefly for reading,
  before redirecting; full motion (terminal feed + ring count-up) plays when the
  user hasn't requested reduced motion.

## [1.9.0] - 2026-06-04

### Changed
- **Home-page statistics are now live.** Stats are read straight from the DB
  counters (always current) and pushed to the browser via **Server-Sent Events**
  (`GET /api/stats/events`, ~3 s cadence, only on change), so the counters tick up
  within seconds instead of after the old 30 s/60 s poll. `/api/stats` now also
  serves live DB values and remains the polling fallback when SSE is unavailable.

### Removed
- The plain-text `stat_*` files in the data volume and the 5-minute file writer
  (`internal/statsfiles`). They added staleness and an editable-override path that
  is no longer needed now that everything comes from the DB. To adjust the
  displayed numbers, edit the `counters` table directly (e.g.
  `UPDATE counters SET value = 0;`).

### Changed
- The home-page scanner animation now lists **every check** from the report (one
  line each, with result and score delta), ordered by category then severity —
  instead of ~12 grouped phases. The total run time stays bounded (the per-line
  speed adapts to the number of checks), and the score ring still counts up to the
  final score.

## [1.8.1] - 2026-06-04

### Changed
- The home-page scanner animation is now **on by default (opt-out)**:
  `ENABLE_CHECK_ANIMATION` defaults to `true`; set it to `false` to fall back to
  the brief "received → analysed → redirect" status.

## [1.8.0] - 2026-06-04

### Added
- **Opt-in "scanner" animation on the home page** (`ENABLE_CHECK_ANIMATION`,
  default `false`). When enabled, waiting for the report shows a live monospace
  terminal tickering through the checks while a central score ring fills and counts
  up to the final score, then pulses and redirects. Honors
  `prefers-reduced-motion` (skips straight to the final state).
  - Default (off): a brief, calm "Mail empfangen → Mail analysiert → Weiterleitung
    zum Report" and then the redirect — no flashy animation.
  - New env var documented in `.env.example` and the env migration.

## [1.7.0] - 2026-06-04

### Added
- **Per-check importance badge** (Kritisch / Wichtig / Empfohlen / Optional) shown
  directly on each check row in the report (server-rendered and E2E views), so
  priorities are visible at a glance — not only in the /about reference.
- **Friendly German labels for raw data.** The "Rohdaten" key/value tables now use
  human-readable labels (e.g. `dkim_domain` → "DKIM-Domain (d=)") from a single
  Go map shared with the client, with a humanised fallback for unknown keys.
- **Animated count-up** for the home-page statistics on first load; the stats bar
  is hidden on a fresh instance (all-zero) and revealed automatically once there
  is real activity.
- More unit tests: concurrent check runner (ordering + panic isolation),
  importance classification, registrable-domain extraction, and an
  Analyze-doesn't-panic-on-garbage-input guard.

### Changed
- **Network-bound checks now run concurrently** (DNS, RBL, RDAP,
  SpamAssassin/Rspamd, MTA-STS/DNSSEC/DANE, …) with bounded parallelism instead of
  sequentially, so reports are produced noticeably faster.

### Fixed / Hardened
- **Crash & hang protection.** Every check is panic-isolated and the whole
  analysis is wrapped in a recover, so a single malformed mail can no longer take
  down the process or drop the message; the SMTP connection handler also recovers
  from panics as a last resort.
- **Timeouts.** Inbound processing is bounded (45 s) and the analysis itself has a
  30 s deadline, so a slow or unreachable DNS / third-party service can never hang
  an SMTP worker indefinitely.

## [1.6.2] - 2026-06-03

### Changed
- Per-check summaries in the report list are no longer truncated with an ellipsis;
  they now wrap and are shown in full (the check title wraps too instead of being cut).

## [1.6.1] - 2026-06-03

### Changed
- Reverted the shortened section-header hints back to the full explanations
  (shown in full on their own line beneath the section title).

## [1.6.0] - 2026-06-03

### Added
- **SEO.** The public pages are now discoverable:
  - Rich `<head>` metadata on the home and about pages: keyword-focused title &
    description, `canonical`, Open Graph + Twitter Card tags, and a social share
    image (`/static/og-image.svg`).
  - JSON-LD structured data: `WebApplication` on the home page and a `FAQPage`
    on the about page (eligible for FAQ rich results).
  - `GET /robots.txt` (allows public pages, disallows token-scoped private pages
    and `/api/`, links the sitemap) and `GET /sitemap.xml` (home, about, privacy).
  - Private, token-scoped pages (`/report/*`, `/mailbox/*`) are marked
    `noindex,nofollow` so report contents never get indexed.
  - All absolute URLs derive from `PUBLIC_BASE_URL` (or the request host when
    unset) — set `PUBLIC_BASE_URL` for correct canonical/OG/sitemap links.

### Changed
- Report section headers now glow softly across the whole header in their status
  colour (green / yellow / red) instead of a uniform blue.
- The section intro hints are shortened to a single concise line.

## [1.5.2] - 2026-06-03

### Changed
- Within each report section, checks are now ordered by severity so the most
  actionable surface first: **Fehler → Warnungen → Infos → Bestanden** (passed
  checks sink to the bottom, ties broken alphabetically). Applied consistently to
  the server-rendered report, the client-side decrypted E2E view, and the PDF
  export. (Previously passed checks could appear above informational notices.)

## [1.5.1] - 2026-06-03

### Fixed
- **Stale-cache bug after updates.** Static assets (`app.js`, `app.css`,
  `crypto.js`, `pdf-report.js`) were served without cache-busting, so browsers
  could keep an outdated `app.js` after a release. The visible symptom: the
  „Erweiterte Reputations-Checks" modal opened but the *Übernehmen* button did
  nothing — the page had the new modal markup (fresh HTML) but the old JavaScript
  (cached) that lacked the save handler, so the modal never closed and no active
  indicator appeared.
  - App-owned assets now carry a `?v=<version>` query that changes every release,
    forcing a fresh fetch.
  - Static responses send `Cache-Control: immutable` for versioned URLs and
    `no-cache` (revalidate) for versionless ones, so a stale `app.js` can never
    linger again.
  - (The underlying opt-in logic was already correct — verified end-to-end in a
    real browser; the only issue was asset caching.)

## [1.5.0] - 2026-06-03

### Changed
- **Report check-groups are now collapsible and collapsed by default.** Each group
  header shows an at-a-glance status indicator — „Handlungsbedarf" (red),
  „Prüfen empfohlen" (yellow) or „Alles in Ordnung" (green) — plus a coloured left
  accent on the card, so the whole report can be scanned without opening anything.
  The status filter (Alle / Bestanden / …) auto-expands the matching groups.
- The group intro hint now always sits on its own line below the title.
- Mobile polish: the score ring is centred (instead of left-aligned) when the hero
  wraps, the summary pills centre with it, and the group header reflows cleanly on
  narrow screens.
- The score ring is a bit thicker on all screen sizes for better legibility.

(Applies to both the server-rendered report and the client-side decrypted E2E view.)

## [1.4.0] - 2026-06-03

### Added
- **User-controlled opt-in for third-party reputation checks.** The previously
  operator-only checks (domain age via RDAP, domain/link blocklists) can now be
  enabled per mailbox by each user directly on the home page, via a new
  "Erweiterte Reputations-Checks" modal that explains — discreetly but in detail —
  what each check does and which data (domain names only, never mail content) is
  sent to which external service. The choice is stored as a local preference and
  applied to the user's mailbox; default remains OFF.
  - New per-mailbox columns `check_domain_age` / `check_domain_blocklist`
    (idempotent migration, default 0).
  - New endpoint `POST /api/mailboxes/{token}/checks` to update the opt-ins; the
    create endpoint also accepts `check_domain_age` / `check_domain_blocklist`.
  - `analyzer.Input` carries per-request flags, OR-combined with the operator
    `Options` defaults, so the existing global `ENABLE_DOMAIN_AGE` /
    `ENABLE_DOMAIN_BLOCKLIST` env switches keep working as a force-on default.
- **Complete check reference on the About page** (`/about#checks-detail`): every
  check, grouped into the five categories, with an importance rating
  (Kritisch / Wichtig / Empfohlen / Optional), a plain-language explanation of
  what it is and why it matters, and authoritative further-reading links
  (RFCs, dmarc.org, Spamhaus, rspamd, BIMI, …).

### Changed
- Privacy policy: documents that the domain-age and blocklist checks are
  user-activated per mailbox (consent under Art. 6 (1)(a) GDPR, revocable by
  toggling off) and reiterates that only domain names are transmitted.

## [1.3.0] - 2026-06-02

### Added
- Opt-in third-party reputation checks (batch C — OFF by default; contact external services with the sender/link domain):
  - **Domain age** (`domain_age`): registration age via RDAP (rdap.org). Domains < 30 days are flagged strongly, < 90 days mildly. Enable with `ENABLE_DOMAIN_AGE=true`.
  - **Domain blocklist** (`domain_blocklist`): the sender's registrable domain checked against domain blocklists (Spamhaus DBL etc.).
  - **Link-domain blocklist** (`link_blocklist`): registrable domains of all links checked against URI blocklists (URIBL/SURBL/DBL). Both enabled with `ENABLE_DOMAIN_BLOCKLIST=true`, providers via `DOMAIN_BLOCKLIST_PROVIDERS`.
- New config: `ENABLE_DOMAIN_AGE`, `ENABLE_DOMAIN_BLOCKLIST`, `DOMAIN_BLOCKLIST_PROVIDERS` (documented in `.env.example` and env migration).
- Privacy policy updated to disclose these optional third-party data flows (RDAP, domain/URI blocklists) in sections 2.2 and 5.
- New dependency `golang.org/x/net/publicsuffix` for registrable-domain (eTLD+1) extraction.

## [1.2.0] - 2026-06-02

### Added
- DNS maturity / transport-security checks (batch B):
  - **MTA-STS** (`mta_sts`): detects a published `_mta-sts` policy (enforced TLS transport).
  - **TLS-RPT** (`tls_rpt`): detects `_smtp._tls` reporting configuration.
  - **BIMI** (`bimi`): detects a `default._bimi` brand-indicator record.
  - **DNSSEC** (`dnssec`): checks whether the sender zone is DNSSEC-signed (DNSKEY present).
  - **DANE/TLSA** (`dane_tlsa`): checks for TLSA records on the primary MX host.
- New dependency `github.com/miekg/dns` for DNSKEY/TLSA record types the stdlib resolver cannot query. DNSSEC/DANE use only the operator's configured system resolver (no public-resolver fallback) and degrade gracefully when none is available; all five checks are informational/bonus signals and never penalise a sender for not using these optional features.

## [1.1.0] - 2026-06-02

### Added
- Deeper deliverability checks (batch A — derived from already-available data, no extra third-party calls):
  - **DMARC policy strength** (`dmarc_policy`): rates `p=none`/`quarantine`/`reject` and flags a missing `rua=` reporting address.
  - **SPF strictness** (`spf_strictness`): evaluates the trailing `all` qualifier (`-all`/`~all`/`?all`/dangerous `+all`) and warns when the top-level DNS-lookup count approaches the RFC 7208 limit of 10.
  - **DKIM key length** (`dkim_keylength`): fetches the DKIM public key via DNS and flags weak RSA keys (<2048 bit); recognises Ed25519.
  - **PTR hostname pattern** (`ptr_pattern`): flags generic/dynamic-looking reverse-DNS hostnames (a strong spam signal even when FCrDNS passes).
  - **From display-name spoofing** (`display_name`): flags brand impersonation and foreign e-mail addresses embedded in the From display name.
  - **Bounce-domain MX** (`envelope_mx`): verifies the Return-Path/Envelope-From domain can actually receive bounces (DSN/NDR).

## [1.0.0] - 2026-06-02

First stable release. Consolidates the large body of work accumulated since
0.1.0 — full E2E encryption, the score-first web UI, client-side PDF export,
live statistics, the privacy policy, and the rename to sender.report — into a
clean 1.0 baseline. Going forward this project follows Semantic Versioning:
new features bump the MINOR version, fixes bump PATCH, breaking changes bump MAJOR.

### Changed
- **Renamed the project from MailProbe to Sender-Report** (complete rename): display name, Go module path (`github.com/brightcolor/sender-report`), `cmd/` folder, binary, Docker image (`ghcr.io/brightcolor/sender-report`), `SENDER_REPORT_IMAGE` env var, Prometheus metric prefix (`sender_report_*`), and the brand mark (`SR`). Internal storage keys, cookies, the SQLite filename and cryptographic protocol constants are intentionally kept stable for backward compatibility.
- **Completed the rename down to internal identifiers (breaking, hard reset).** The remaining `mailprobe` references were removed too: browser storage keys are now `sr:*` (theme, consent, mailboxes, lastmsg), the fallback cookie is `sr_mailbox`, the SQLite filename default is `sender-report.db`, and the cryptographic domain-separation constants are now `senderreport-id-v1` / `senderreport-content-v1`. This **invalidates any pre-existing encrypted mailboxes and mailbox links** and changes all mailbox addresses — a deliberate clean break, no backward compatibility. The `MPE1` blob magic is unchanged. (The `mailprobe` name remains only in this changelog as project history.)

### Added
- Client-side PDF report export (jsPDF) with a section/status filter modal — generated entirely in the browser, so it also works for end-to-end-encrypted reports without exposing plaintext to the server.
- Live platform statistics on the home page (cumulative counters for created mailboxes, analyzed mails, generated reports, and the average score), backed by plain-text counter files in the data volume.
- SVG favicon served via `/static/favicon.svg` with a `/favicon.ico` redirect.
- Home-page security explainer describing the brief plaintext-analysis → immediate-encryption flow and the "your link is the key" model, plus a green "Ende-zu-Ende verschlüsselt" badge.
- Added provider-specific RBL/DNSBL delisting guidance, lookup evidence, TXT evidence, and pre-delisting remediation steps.
- Added optional built-in HTTPS serving via `ENABLE_TLS`, `TLS_CERT_FILE`, and `TLS_KEY_FILE`.
- Added configurable HTTP-to-HTTPS redirects via `FORCE_HTTPS`.
- Added request-derived public URL and mailbox domain detection so `PUBLIC_BASE_URL` and `SMTP_DOMAIN` can stay empty by default.
- Added local Vvveb Admin Template vendor assets (`admin.css`, Inter fonts, Apache-2.0 license) for the web UI.
- Added explicit light/dark/auto theme switching with persisted browser preference.
- Added structured German check detail output with `technical_details`, `explanation`, `recommendation`, `severity`, and `category` fields.
- Added explicit MX, A/AAAA, SPF alignment, DKIM alignment, DMARC alignment, Reply-To, and TLS transport checks to the analyzer.
- Added a colorful report dashboard with score hero, grouped check cards, status icons, collapsible technical details, raw-data accordions, and copy buttons.
- Added tokenized JSON report export at `GET /api/reports/<mailbox-token>/<message-ref>` for automation and integrations.
- Added JSON report links to mailbox and report pages.
- Added a score-first web UI with a guided send-and-check flow, live mailbox status, prioritized report checks, and clearer export actions.
- Added in-place test address generation without a full page reload.
- Added sandboxed rendered HTML mail preview alongside raw HTML source.
- Added SemVer Docker image tags, immutable commit SHA image tags, and a validated release-tag workflow for safer rollbacks.
- Documented `TRUSTED_PROXY_CIDRS` in the environment template and README.

### Changed
- Brought the privacy policy in line with the actual data flow: transient in-memory plaintext analysis, encrypted-at-rest storage of sensitive fields, the mailbox-creation IP retained for abuse protection, anonymous aggregate counters, and the client-side PDF export.
- Switched the home-page statistics to cumulative counters that survive cleanup and mailbox expiry (they only ever increase); only the "currently active" figure is a live count.
- Hardened the home page layout for narrow/mobile screens (card-header badge wrap, action-button wrapping, tighter padding).
- Reduced repeated technical detail noise in report check accordions by attaching only check-specific values to each check.
- Expanded explanations and remediation text for authentication, DNS/infrastructure, SpamAssassin, and RBL findings.
- Made `SMTP_DOMAIN` an optional override instead of a required setting; SMTP acceptance still requires an active temporary mailbox.
- Updated quickstart defaults to leave `PUBLIC_BASE_URL` and `SMTP_DOMAIN` empty unless explicitly provided.
- Removed visible Metrics/Health navigation from the web UI while keeping the endpoints available.
- Removed EventSource/SSE usage in the web UI and switched mailbox/check updates to polling to avoid broken event-stream states behind proxies.
- Removed the left sidebar from the Vvveb-based shell in favor of a top navigation layout.
- Show check remediation as "Wie wird's gemacht?" only for warning and failing checks.
- Group report links by domain and show total link counts.
- Rebuilt the home, mailbox, and report screens around a Vvveb-style topbar dashboard shell.
- Enriched existing analysis checks with concrete remediation guidance, DNS/MTA examples, and raw values where available.
- Grouped report checks by authentication, DNS/infrastructure, spam filters, content/format, and header/raw-data categories.
- Redesigned the home, mailbox, and report pages into a more focused email testing workflow with prominent test address, status panels, score summary, diagnostics, and raw data sections.
- Adjusted the web UI closer to a mail-tester-style flow: central test address, clear check button, compact metadata, and accordion-style report checks.

### Fixed
- Fixed a startup crash after restart where the cumulative-counter backfill used a non-idempotent `INSERT` and hit a `UNIQUE` constraint on `counters.key`.
- Extract links from decoded HTML source as well as visible text so `href` URLs are included in reports.
- Only trust `X-Forwarded-For` when the direct client IP matches `TRUSTED_PROXY_CIDRS`, preventing spoofed client IPs from bypassing web rate limits.
- Decode folded and RFC 2047 encoded `Subject` headers before storing message metadata.
- Decode transfer encoding and declared charsets for displayed text and HTML mail bodies.

## [0.1.0] - 2026-04-22

### Added
- Initial self-hosted Sender-Report implementation.
- Single-binary Go backend with integrated SMTP receiver and web UI.
- SQLite persistence for mailboxes, messages, and reports.
- Deliverability and spam heuristics (SPF, DKIM, DMARC, PTR, HELO, MIME, links, headers, newsletter checks, Unicode checks, optional RBL).
- Dockerfile + docker-compose stack with healthchecks and persistent volume.
- Cleanup worker for TTL-based deletion of old mailboxes/messages.
- Reverse proxy examples for NGINX and Caddy.
- Documentation, environment template, and MIT license.
- GitHub Actions CI for tests and multi-arch container publishing to GHCR.
- Optional Rspamd integration via controller API (`/checkv2`) with report scoring.
- Added `scripts/quickstart.sh` to install Docker/Compose (if missing) and deploy Sender-Report in one command.
- Quickstart now prompts for optional `rspamd` and `redis`, writes `.env` flags, and generates `docker-compose.override.yml` accordingly.
- Rspamd analysis now surfaces top positive symbols and concrete remediation guidance in report checks.
