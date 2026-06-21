<div align="center">

# sender.report

**Self-hosted e-mail deliverability test — like a real mail server, only transparent.**

Send a test mail to a throwaway address and get a score (0–10) in seconds, with 50+
explainable checks: SPF, DKIM, DMARC, spam score, blacklists, DNS and more.

[![CI](https://github.com/brightcolor/sender-report/actions/workflows/ci.yml/badge.svg)](https://github.com/brightcolor/sender-report/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Made with Go](https://img.shields.io/badge/Go-1.25-00ADD8.svg?logo=go&logoColor=white)](https://go.dev)
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
- **55+ checks across 5 areas** — Authentication · DNS & infrastructure (PTR, HELO, MX, TLS,
  MTA-STS, TLS-RPT, BIMI, DNSSEC, DANE, **From domain reachability**) · Spam filters
  (SpamAssassin, Rspamd, DNSBL) · Format & content (**RFC 8058 one-click unsubscribe,
  template placeholder detection**, image/text ratio, HTML validity) · Headers & raw data.
- **Practical scoring** — importance-weighted like real filters: authentication & reputation
  dominate, cosmetics barely count. Domain age contributes dynamically. A perfect 10 is only
  awarded when the essential checks are genuinely clean.
- **End-to-end encryption** — X25519 + HKDF-SHA256 + AES-256-GCM; plaintext only briefly in
  RAM during analysis.
- **Live recheck** — fixed your DNS? Re-run individual checks or whole sections right in the
  report, without sending a new mail. The result is re-encrypted and stored.
- **Client-side PDF export** — a client-presentable report, generated entirely in the browser
  (works for encrypted reports too).
- **Opt-in reputation checks** — domain age (RDAP) and domain/link blocklists, enabled per
  mailbox by the user, informed and on demand.
- **Live statistics** on the home page (via SSE), **dark mode**, mobile-friendly.
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
docker compose up -d
```

UI: `http://<host>:9090` (or your reverse-proxy URL).

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

Examples: `deploy/examples/nginx.conf` · `Caddyfile` · `docker-compose.rspamd.yml` ·
`docker-compose.spamassassin.yml`.

## Configuration

Everything via `.env` (see `.env.example`). The most important variables:

| Variable | Purpose |
|---|---|
| `SENDER_REPORT_IMAGE` | container image (pin a version for production) |
| `PUBLIC_BASE_URL` | public URL; empty = derive from the request |
| `SMTP_DOMAIN` | domain of generated addresses; empty = request host |
| `HTTP_PORT` / `SMTP_PORT` | host ports (container: `:8080` / `:2525`) |
| `ENABLE_TLS`, `TLS_CERT_FILE`, `TLS_KEY_FILE`, `FORCE_HTTPS` | built-in TLS / redirect |
| `TRUSTED_PROXY_CIDRS` | only these proxy CIDRs may set `X-Forwarded-*` |
| `MAILBOX_TTL`, `DATA_RETENTION_TTL`, `CLEANUP_INTERVAL` | lifetime & cleanup |
| `MAX_MESSAGE_BYTES`, `MAX_ACTIVE_MAILBOXES_PER_IP/_GLOBAL` | limits |
| `WEB_RATE_LIMIT_PER_MIN`, `SMTP_RATE_LIMIT_PER_HOUR`, … | rate limits |
| `ENABLE_RBL_CHECKS`, `RBL_PROVIDERS` | DNSBL/RBL (IP reputation), optional |
| `ENABLE_SPAMASSASSIN`, `ENABLE_RSPAMD`, … | external spam filters, optional |
| `ENABLE_DOMAIN_AGE`, `ENABLE_DOMAIN_BLOCKLIST`, `DOMAIN_BLOCKLIST_PROVIDERS` | force third-party checks on globally (default off) |
| `ALERT_WEBHOOK_URL` | webhook on processing failures |

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
- Rate limits (web & SMTP), maximum message size, per-IP mailbox limits.
- TTL-based data lifecycle (automatic deletion).
- No external CDNs/trackers — all assets are served locally.

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
