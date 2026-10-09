<div align="center">

# sender.report

**Self-hosted e-mail deliverability test — like a real mail server, only transparent.**

Send a test mail to a throwaway address and get a score (0–10) in seconds, with 50+
explainable checks: SPF, DKIM, DMARC, spam score, blacklists, DNS and more.

[![CI](https://github.com/brightcolor/sender-report/actions/workflows/ci.yml/badge.svg)](https://github.com/brightcolor/sender-report/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Made with Go](https://img.shields.io/badge/Go-1.26-00ADD8.svg?logo=go&logoColor=white)](https://go.dev)
[![Contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](./CONTRIBUTING.md)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/brightcolor/sender-report/main/scripts/quickstart.sh)
```

</div>

---

## What it is

`sender.report` accepts test mails on temporary addresses, analyzes them **like a
receiving mail server**, and shows a clear report with a score, findings, and concrete
remediation steps. No account, no tracking, no CDN — a single Go binary that runs on a
small VPS.

> **Privacy by design.** As soon as a message is analyzed, its content is stored
> **end-to-end encrypted**. The key lives only in your link — not even the server can read
> the report's content.

## Highlights

- **Real authentication checks** — SPF, DKIM and DMARC are **cryptographically verified**
  (DKIM signature via `go-msgauth`, SPF against the sending IP, DMARC alignment), not just
  guessed from headers.
- **Inbox Placement Testing** — verify whether your test mail actually lands in inbox or spam
  at real providers (Gmail, Outlook, GMX, web.de, T-Online, Yahoo, …). Operator-configured
  seed accounts; one picked at random per test. Live results via SSE. Privacy-first: seed
  credentials never leave the server, TLS-only IMAP, privacy notice shown before each test.
- **65+ checks across 5 areas** — Authentication (SPF, DKIM, DMARC, ARC, X-Google-DKIM) ·
  DNS & infrastructure (PTR/FCR, HELO, MX, TLS, MTA-STS, TLS-RPT, BIMI, DNSSEC, DANE,
  From domain reachability) · Spam filters (SpamAssassin, Rspamd, DNSBL) ·
  Format & content (RFC 8058 one-click unsubscribe, template placeholders, image alt text,
  harmful HTML, link domain mismatch, too many links, image/text ratio, HTML validity,
  **opt-in broken link check**) · Headers & raw data (fake reply prefix, Message-ID format,
  no-reply without Reply-To).
- **Practical scoring** — importance-weighted like real filters: authentication & reputation
  dominate, cosmetics barely count. Domain age contributes dynamically. A perfect 10 is only
  awarded when the essential checks are genuinely clean.
- **End-to-end encryption** — X25519 + HKDF-SHA256 + AES-256-GCM; plaintext only briefly in
  RAM during analysis.
- **Live recheck** — fixed your DNS? Re-run individual checks or whole sections right in the
  report, without sending a new mail. The result is re-encrypted and stored.
- **Mail Simulator (`/simulate`)** — paste RFC 2822 source into an editor and see live
  check results on every keystroke (debounced). DNS checks run on-demand per button.
  Open it directly from any report with one click.
- **Client-side PDF export** — a client-presentable report, generated entirely in the browser
  (works for encrypted reports too).
- **Opt-in reputation checks** — domain age (RDAP) and domain/link blocklists, enabled per
  mailbox by the user, informed and on demand.
- **Live statistics** on the home page (via SSE), mobile-friendly, with four display options
  in the navbar: **System**, **Light**, **Dark** and **Werkbank** (a warm paper look with bold
  display type). The choice stays in the browser; `UI_DEFAULT_THEME` sets it for new visitors.
- **Small & self-contained** — one Go binary (HTTP + SMTP + analysis + cleanup), SQLite,
  Docker Compose.

## How it works

```
1. Open the web UI         →  a temporary mailbox is created (key stays in the browser)
2. Send a test mail to it  →  SMTP intake + analysis in memory
3. Open the report         →  score, checks, recommendations, raw data, PDF/JSON export
```

After analysis the content is stored encrypted; the mailbox expires automatically.

## Quick start

**Fully automatic** (installs Docker + Compose if missing):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/brightcolor/sender-report/main/scripts/quickstart.sh)
```

The installer asks about optional services (`rspamd`, `redis`) and writes a matching
`docker-compose.override.yml` + `.env`.

**Manual:**

```bash
cp .env.example .env          # adjust image, ports, optional TLS/proxy
docker compose pull
mkdir -p data && sudo chown -R 100:101 data   # the container user, see below
docker compose up -d
```

UI: `http://<host>:9090` (or your reverse-proxy URL).

### Container user and data directory

The container runs as the unprivileged user `app` (uid 100, gid 101) and keeps its
data in `DATA_DIR` (`./data` on the host). A `./data` that Docker creates itself
belongs to root, so a new installation hands it over once:
`sudo chown -R 100:101 ./data`. The quickstart script does this for you.
Installations that ran an earlier image already have `./data` owned by `app`.

At startup the server checks that it can write `DATA_DIR` and the database files.
If it cannot, it stops with a log line (`docker compose logs sender-report`) that
names the path and the `chown` command. Containers started as root
(`user: root`) hand `DATA_DIR` to `app` themselves and then run the server as `app`.

## Requirements

- Docker + Docker Compose
- VPS with a public IP and a domain/subdomain you control
- inbound SMTP routed to the host (`25 → SMTP_PORT`)

## DNS & SMTP

```
A   sender.example.org        → <server-ip>
MX  mx-test.example.org   10  → sender.example.org
```

- Keep the web behind a reverse proxy/TLS (`443 → 9090`); route SMTP `25` to the container
  port (`2525`).
- Behind a proxy, set `PUBLIC_BASE_URL` (and `TRUSTED_PROXY_CIDRS`) so links, canonical/OG
  tags and `sitemap.xml` are correct.
- SMTP is **not** an open relay: it only accepts existing, active test mailboxes.

### Your own recursive resolver is a requirement, not an extra

Every check here is a DNS question — SPF, DKIM, DMARC, MX, PTR, DNSSEC, DANE, and above all
the blocklists. The compose file therefore ships an `unbound` container and points both
`sender-report` and `rspamd` at it. **Do not replace it with a public resolver.**

- **Spamhaus, URIBL and SURBL refuse queries arriving through shared resolvers** such as
  `8.8.8.8` or `1.1.1.1`. They reply with an error code in `127.255.255.0/24`, which means
  neither "listed" nor "clean" — the reputation half of every report stops working. Since
  v1.29.0 the report says so instead of reporting a clean result, but the checks still
  produce no verdict.
- **Docker's built-in resolver** (`127.0.0.11`) is a forwarder. It rate-limits under the
  query volume Rspamd generates and cannot return DNSKEY or TLSA records, so DNSSEC and DANE
  report nothing useful.

If you already run a recursive resolver, point the `dns:` entries at it and drop the
`unbound` service. If you run neither, expect the blocklist, DNSSEC and DANE checks to be
unanswerable — the report will label them as such rather than passing them.

Examples: `deploy/examples/nginx.conf` · `Caddyfile` · `docker-compose.rspamd.yml` ·
`docker-compose.spamassassin.yml`.

## Configuration

Everything via `.env` (see `.env.example`). The most important variables:

| Variable | Purpose |
|---|---|
| `SENDER_REPORT_IMAGE` | container image (pin a version for production) |
| `PUBLIC_BASE_URL` | public URL; empty = derive from the request. With `FORCE_HTTPS` its host is the redirect target |
| `SMTP_DOMAIN` | domain of generated addresses; empty = request host |
| `HTTP_PORT` / `SMTP_PORT` | host ports (container: `:8080` / `:2525`) |
| `ENABLE_TLS`, `TLS_CERT_FILE`, `TLS_KEY_FILE`, `FORCE_HTTPS` | built-in TLS / redirect |
| `FORCE_HTTPS_EXEMPT_PATHS` | paths that answer over plain HTTP although `FORCE_HTTPS` is set, so the container healthcheck reaches them regardless of `PUBLIC_BASE_URL` (default `/healthz,/readyz`; an entry ending in `/` covers the paths below it, `none` redirects every path) |
| `TRUSTED_PROXY_CIDRS` | only these proxy CIDRs may set `X-Forwarded-*` |
| `MAILBOX_TTL`, `DATA_RETENTION_TTL`, `CLEANUP_INTERVAL` | lifetime & cleanup |
| `MAX_MESSAGE_BYTES`, `MAX_ACTIVE_MAILBOXES_PER_IP/_GLOBAL` | limits |
| `WEB_RATE_LIMIT_PER_MIN`, `SMTP_RATE_LIMIT_PER_HOUR`, … | rate limits |
| `PAYLOAD_RATE_LIMIT_PER_MIN` | encrypted reports one IP address may fetch per minute; rechecks and simulator runs count separately against the same number (default 30, 1 to 600) |
| `IPT_RATE_LIMIT_PER_HOUR` | placement tests one IP address may start per hour (default 3, 1 to 60) |
| `IPT_TOKEN_LENGTH` | hexadecimal characters in the subject token of a new placement test (default 32 = 128 bits, 16 to 64); a test with a shorter token answers to it until the test expires |
| `IPT_TEST_DURATION` | how long a placement test waits for its message, in whole minutes; the placement dialog names it (default `10m`, `1m` to `1h`) |
| `IPT_POLL_INTERVAL` | pause between two IMAP lookups in one seed account, shorter than `IPT_TEST_DURATION` (default `30s`, `5s` to `5m`) |
| `IPT_EVENTS_INTERVAL` | how often the open placement dialog receives the state of its test (default `5s`, `1s` to `1m`) |
| `IPT_SEARCH_MARGIN` | how far before the start of a test the IMAP search reaches back, so a provider whose clock runs behind still finds the message (default `2m`, `0s` to `1h`) |
| `IPT_SPAM_FOLDERS` | folders a placement test searches after INBOX, in this order (default `Spam,Junk,[Gmail]/Spam,Bulk Mail,Bulk,Junk E-Mail`, at most 20; `none` searches INBOX alone) |
| `ENABLE_RBL_CHECKS`, `RBL_PROVIDERS` | DNSBL/RBL (IP reputation), optional |
| `ENABLE_SPAMASSASSIN`, `ENABLE_RSPAMD`, … | external spam filters, optional |
| `ENABLE_DOMAIN_AGE`, `ENABLE_DOMAIN_BLOCKLIST`, `DOMAIN_BLOCKLIST_PROVIDERS` | force third-party checks on globally (default off) |
| `ENABLE_INBOX_PLACEMENT`, `SEED_ACCOUNTS_FILE` | inbox placement testing via operator-configured seed accounts (default off) |
| `ALERT_WEBHOOK_URL` | webhook on processing failures |
| `UI_DEFAULT_THEME` | display option for new visitors: `auto` (follows the system, default), `light`, `dark` or `werkbank` |
| `COOKIE_SECURE` | Secure attribute of cookies: `auto` (default; HTTPS requests and an `https://` `PUBLIC_BASE_URL`), `always` or `never` (plain-HTTP test setups) |
| `LANG_COOKIE_NAME`, `LANG_COOKIE_DAYS`, `MAILBOX_COOKIE_NAME` | cookie names (`sr_lang`, `sr_mailbox`) and the days the language choice is kept (365, at most 400) |

> The third-party checks (domain age, blocklists) contact external providers with
> **domain names** (never mail content) and are off by default. Each user can enable them per
> mailbox under "Erweiterte Reputations-Checks", informed and on demand — details at
> `/about#checks-detail`, data flows at `/privacy`.

### Built-in TLS (without a reverse proxy)

```env
ENABLE_TLS=true
TLS_CERT_FILE=/certs/fullchain.pem
TLS_KEY_FILE=/certs/privkey.pem
HEALTHCHECK_URL=https://127.0.0.1:8080/healthz
```

Mount the cert directory as a volume (`./certs:/certs:ro`). Behind a proxy use
`ENABLE_TLS=false`, terminate TLS at the proxy, and set `TRUSTED_PROXY_CIDRS`.

## Security & privacy

- **End-to-end encryption** of mail content (key only in the link/browser).
- No open relay; SMTP recipients are validated against active mailboxes.
- Rate limits (web, SMTP, report payloads, placement tests), maximum message size, per-IP
  mailbox limits.
- TTL-based data lifecycle (automatic deletion).
- No external CDNs/trackers — all assets are served locally.
- Cookies carry `HttpOnly`, `SameSite=Lax` and, over HTTPS, `Secure`.
- The container runs as the unprivileged user `app`; binary, templates and static
  files belong to root.

## API

| Endpoint | Description |
|---|---|
| `GET /api/reports/<token>/<msgref>` | mailbox/message metadata + full report (JSON) |
| `GET /api/mailboxes/<token>/status` | current mailbox status + latest message |
| `GET /api/mailboxes/<token>/events` | Server-Sent-Events stream for live updates |
| `GET /api/stats` · `GET /api/stats/events` | platform statistics (live) |
| `GET /healthz` · `GET /readyz` · `GET /metrics` | health & Prometheus metrics |

Every check result is explainable: in addition to `id/name/status/score_delta/summary`,
reports carry `category`, `severity`, `importance`, `technical_details`, `explanation`,
`recommendation` and `doc_links`.

## Architecture

```
cmd/sender-report   bootstrap & service wiring
internal/smtp       lightweight SMTP receiver
internal/analyzer   parsing · checks · scoring · recheck
internal/sealedbox  E2E crypto (X25519 + HKDF + AES-256-GCM)
internal/store, db  SQLite persistence (WAL)
internal/web        SSR pages · API · SSE
internal/cleanup    TTL/retention cleanup
```

Reusable design building blocks: `docs/design-system.md` + `docs/sender-report-theme.css`.

## Container images

`ghcr.io/brightcolor/sender-report:<tag>`

| Tag | Meaning |
|---|---|
| `latest` / `main` | newest image from the `main` branch |
| `sha-<shortsha>` | immutable image per commit |
| `vX.Y.Z` | immutable release tag |
| `X.Y.Z`, `X.Y`, `X` | SemVer aliases |

Pin a version for production:

```bash
SENDER_REPORT_IMAGE=ghcr.io/brightcolor/sender-report:v1.15.1
docker compose pull && docker compose up -d
```

## Resources

Runs on small servers (Compose defaults: `mem_limit: 512m`, `cpus: 0.50`). Optional checks
(RBL, SpamAssassin, Rspamd, third-party services) increase load and latency.

## Non-goals

Not a production MTA, not an outbound relay, not a replacement for proprietary provider
filters.

## Roadmap

- RBL/blacklist as a dedicated UI widget
- Score history across multiple test runs
- API-key auth for private deployments
- Internationalization (DE/EN)

## License

MIT — see [`LICENSE`](./LICENSE). Licenses of the bundled third-party components (Go modules
+ frontend assets) are in [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md) and ship with
the container image.
