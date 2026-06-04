<div align="center">

# sender.report

**Self-hosted E-Mail-Deliverability-Test — wie ein echter Mailserver, nur transparent.**

Schick eine Testmail an eine Wegwerf-Adresse und bekomme in Sekunden einen Score (0–10)
mit über 50 nachvollziehbaren Checks: SPF, DKIM, DMARC, Spam-Score, Blacklists, DNS und mehr.

[![CI](https://github.com/brightcolor/sender-report/actions/workflows/ci.yml/badge.svg)](https://github.com/brightcolor/sender-report/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Made with Go](https://img.shields.io/badge/Go-1.25-00ADD8.svg?logo=go&logoColor=white)](https://go.dev)
[![Contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](./CONTRIBUTING.md)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/brightcolor/sender-report/main/scripts/quickstart.sh)
```

</div>

---

## Was es ist

`sender.report` nimmt Testmails auf temporären Adressen an, analysiert sie **wie ein
empfangender Mailserver** und zeigt einen verständlichen Report mit Score, Befunden und
konkreten Handlungsempfehlungen. Kein Account, kein Tracking, kein CDN — ein einzelnes
Go-Binary, das auf einem kleinen VPS läuft.

> **Privacy by design.** Sobald eine Mail analysiert ist, wird ihr Inhalt **Ende-zu-Ende
> verschlüsselt** gespeichert. Der Schlüssel steckt nur in deinem Link — nicht einmal der
> Server kann den Report-Inhalt lesen.

## Highlights

- **Echte Authentifizierungs-Prüfung** — SPF, DKIM und DMARC werden **kryptografisch
  verifiziert** (DKIM-Signatur via `go-msgauth`, SPF gegen die sendende IP, DMARC-Alignment),
  nicht nur aus Headern geraten.
- **Über 50 Checks in 5 Bereichen** — Authentifizierung · DNS & Infrastruktur (PTR, HELO, MX,
  TLS, MTA-STS, TLS-RPT, BIMI, DNSSEC, DANE) · Spamfilter (SpamAssassin, Rspamd, DNSBL) ·
  Format & Inhalt · Header & Rohdaten.
- **Praxis-Scoring** — importance-gewichtet wie echte Filter: Authentifizierung & Reputation
  dominieren, Kosmetik zählt wenig. Domain-Alter fließt dynamisch ein. Die volle 10 gibt es
  nur, wenn die essenziellen Checks wirklich sauber sind.
- **Ende-zu-Ende-Verschlüsselung** — X25519 + HKDF-SHA256 + AES-256-GCM; Klartext nur kurz im
  RAM während der Analyse.
- **Live-Recheck** — DNS gefixt? Einzelne Checks oder ganze Sektionen direkt im Report neu
  prüfen, ohne neue Mail. Ergebnis wird neu verschlüsselt und gespeichert.
- **Client-seitiger PDF-Export** — kundentauglicher Report, vollständig im Browser erzeugt
  (funktioniert auch für verschlüsselte Reports).
- **Opt-in Reputations-Checks** — Domain-Alter (RDAP) und Domain-/Link-Blocklists, pro Mailbox
  vom Nutzer selbst und informiert aktivierbar.
- **Live-Statistiken** auf der Startseite (per SSE), **Dark Mode**, mobil-optimiert.
- **Klein & autark** — ein Go-Binary (HTTP + SMTP + Analyse + Cleanup), SQLite, Docker-Compose.

## Wie es funktioniert

```
1. Web-UI öffnen          →  temporäre Mailbox wird erzeugt (Schlüssel bleibt im Browser)
2. Testmail dorthin senden →  SMTP-Empfang + Analyse im Arbeitsspeicher
3. Report öffnen          →  Score, Checks, Empfehlungen, Rohdaten, PDF/JSON-Export
```

Nach der Analyse wird der Inhalt verschlüsselt abgelegt; die Mailbox läuft automatisch ab.

## Quick Start

**Vollautomatisch** (installiert bei Bedarf Docker + Compose):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/brightcolor/sender-report/main/scripts/quickstart.sh)
```

Der Installer fragt nach optionalen Diensten (`rspamd`, `redis`) und schreibt eine passende
`docker-compose.override.yml` + `.env`.

**Manuell:**

```bash
cp .env.example .env          # Image, Ports, optional TLS/Proxy anpassen
docker compose pull
docker compose up -d
```

UI: `http://<host>:9090` (oder deine Reverse-Proxy-URL).

## Voraussetzungen

- Docker + Docker Compose
- VPS mit öffentlicher IP und einer Domain/Subdomain
- eingehender SMTP-Verkehr auf den Host (`25 → SMTP_PORT`)

## DNS & SMTP

```
A   sender.example.org        → <server-ip>
MX  mx-test.example.org   10  → sender.example.org
```

- Web hinter Reverse Proxy/TLS (`443 → 9090`), SMTP `25` auf den Container-Port (`2525`).
- Setze `PUBLIC_BASE_URL` (und `TRUSTED_PROXY_CIDRS`) hinter einem Proxy, damit Links,
  Canonical-/OG-Tags und `sitemap.xml` korrekt sind.
- SMTP ist **kein** offenes Relay: akzeptiert werden nur existierende, aktive Test-Mailboxen.

Beispiele: `deploy/examples/nginx.conf` · `Caddyfile` · `docker-compose.rspamd.yml` ·
`docker-compose.spamassassin.yml`.

## Konfiguration

Alles über `.env` (siehe `.env.example`). Die wichtigsten Variablen:

| Variable | Zweck |
|---|---|
| `SENDER_REPORT_IMAGE` | Container-Image (für Produktion auf eine Version pinnen) |
| `PUBLIC_BASE_URL` | öffentliche URL; leer = aus Request ableiten |
| `SMTP_DOMAIN` | Domain der generierten Adressen; leer = Request-Host |
| `HTTP_PORT` / `SMTP_PORT` | Host-Ports (Container: `:8080` / `:2525`) |
| `ENABLE_TLS`, `TLS_CERT_FILE`, `TLS_KEY_FILE`, `FORCE_HTTPS` | eingebautes TLS / Redirect |
| `TRUSTED_PROXY_CIDRS` | nur diese Proxy-CIDRs dürfen `X-Forwarded-*` setzen |
| `MAILBOX_TTL`, `DATA_RETENTION_TTL`, `CLEANUP_INTERVAL` | Lebensdauer & Aufräumen |
| `MAX_MESSAGE_BYTES`, `MAX_ACTIVE_MAILBOXES_PER_IP/_GLOBAL` | Limits |
| `WEB_RATE_LIMIT_PER_MIN`, `SMTP_RATE_LIMIT_PER_HOUR`, … | Rate-Limits |
| `ENABLE_RBL_CHECKS`, `RBL_PROVIDERS` | DNSBL/RBL (IP-Reputation), optional |
| `ENABLE_SPAMASSASSIN`, `ENABLE_RSPAMD`, … | externe Spamfilter, optional |
| `ENABLE_DOMAIN_AGE`, `ENABLE_DOMAIN_BLOCKLIST`, `DOMAIN_BLOCKLIST_PROVIDERS` | Dritt-Dienste global erzwingen (Default aus) |
| `ALERT_WEBHOOK_URL` | Webhook bei Verarbeitungsfehlern |

> Die Dritt-Dienst-Checks (Domain-Alter, Blocklists) kontaktieren externe Anbieter mit
> **Domainnamen** (nie Mailinhalt) und sind standardmäßig **aus**. Jeder Nutzer kann sie pro
> Mailbox unter „Erweiterte Reputations-Checks" informiert selbst einschalten — Details unter
> `/about#checks-detail`, Datenflüsse unter `/privacy`.

### Eingebautes TLS (ohne Reverse Proxy)

```env
ENABLE_TLS=true
TLS_CERT_FILE=/certs/fullchain.pem
TLS_KEY_FILE=/certs/privkey.pem
HEALTHCHECK_URL=https://127.0.0.1:8080/healthz
```

Cert-Verzeichnis als Volume mounten (`./certs:/certs:ro`). Hinter einem Proxy stattdessen
`ENABLE_TLS=false`, TLS am Proxy terminieren und `TRUSTED_PROXY_CIDRS` setzen.

## Sicherheit & Privatsphäre

- **Ende-zu-Ende-Verschlüsselung** der Mailinhalte (Schlüssel nur im Link/Browser).
- Kein offenes Relay; SMTP-Empfänger werden gegen aktive Mailboxen validiert.
- Rate-Limits (Web & SMTP), maximale Nachrichtengröße, Mailbox-Limits pro IP.
- TTL-basierter Daten-Lebenszyklus (automatische Löschung).
- Keine externen CDNs/Tracker — alle Assets werden lokal ausgeliefert.

## API

| Endpoint | Beschreibung |
|---|---|
| `GET /api/reports/<token>/<msgref>` | Mailbox-/Message-Metadaten + vollständiger Report (JSON) |
| `GET /api/mailboxes/<token>/status` | aktueller Mailbox-Status + letzte Message |
| `GET /api/mailboxes/<token>/events` | Server-Sent-Events-Stream für Live-Updates |
| `GET /api/stats` · `GET /api/stats/events` | Plattform-Statistiken (live) |
| `GET /healthz` · `GET /readyz` · `GET /metrics` | Health & Prometheus-Metriken |

Jedes Check-Ergebnis ist erklärbar: zusätzlich zu `id/name/status/score_delta/summary`
liefern Reports `category`, `severity`, `importance`, `technical_details`, `explanation`,
`recommendation` und `doc_links`.

## Architektur

```
cmd/sender-report   Bootstrap & Service-Wiring
internal/smtp       schlanker SMTP-Empfänger
internal/analyzer   Parsing · Checks · Scoring · Recheck
internal/sealedbox  E2E-Krypto (X25519 + HKDF + AES-256-GCM)
internal/store, db  SQLite-Persistenz (WAL)
internal/web        SSR-Seiten · API · SSE
internal/cleanup    TTL-/Retention-Aufräumer
```

Design-Bausteine zum Wiederverwenden: `docs/design-system.md` + `docs/sender-report-theme.css`.

## Container-Images

`ghcr.io/brightcolor/sender-report:<tag>`

| Tag | Bedeutung |
|---|---|
| `latest` / `main` | neuestes Image vom `main`-Branch |
| `sha-<shortsha>` | unveränderliches Image pro Commit |
| `vX.Y.Z` | unveränderlicher Release-Tag |
| `X.Y.Z`, `X.Y`, `X` | SemVer-Aliase |

Für Produktion auf eine Version pinnen:

```bash
SENDER_REPORT_IMAGE=ghcr.io/brightcolor/sender-report:v1.15.0
docker compose pull && docker compose up -d
```

## Ressourcen

Läuft auf kleinen Servern (Compose-Defaults: `mem_limit: 512m`, `cpus: 0.50`). Optionale
Checks (RBL, SpamAssassin, Rspamd, Dritt-Dienste) erhöhen Last und Latenz.

## Nicht-Ziele

Kein produktiver MTA, kein Outbound-Relay, kein Ersatz für proprietäre Provider-Filter.

## Roadmap

- RBL/Blacklist als eigenständiges UI-Widget
- Score-Verlauf über mehrere Testläufe
- API-Key-Auth für private Deployments
- Internationalisierung (DE/EN)

## Lizenz

MIT — siehe [`LICENSE`](./LICENSE).
