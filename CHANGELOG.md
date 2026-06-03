# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
