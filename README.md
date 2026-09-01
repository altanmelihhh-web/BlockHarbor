# BlockHarbor — Threat Intelligence Platform

BlockHarbor is a self-hosted threat intelligence platform that sits between public
threat feeds and the network devices that have to act on them. It ingests IoCs from
external sources, reduces false positives against warninglists, enriches indicators
with third-party reputation data, and republishes the result as a firewall-consumable
blocklist, a TAXII 2.1 collection, and a REST API.

It exists because the useful part of a blocklist is rarely the raw feed. A feed has to
be deduplicated, subtracted against a whitelist, aggregated into CIDR blocks a firewall
can actually hold, tracked back to the source that reported it, and audited when someone
removes an entry. BlockHarbor does that work and keeps a verifiable record of it.

## Features

**Distribution**
- **TAXII 2.1 server** — discovery, api-root, collection and object endpoints, serving
  IoCs as STIX 2.1 `indicator` objects (`taxii.php`)
- **REST API** — `stats`, `iocs`, `search`, `export`, `add`, `audit` actions behind an
  `X-API-Key` header with per-key roles (`api.php`)
- **Firewall feed** — a flat blocklist rebuilt from every enabled source with whitelist
  subtraction and atomic writes, ready for a firewall to pull (`lib_firewall_feed.php`)

**Ingest**
- **8 external feeds** — Spamhaus DROP/EDROP, Firehol Level 1, CI Badguys, URLhaus,
  StevenBlack, MalwareBazaar, USOM (TR-CERT) — with per-source health tracking
- **CSAF 2.0 fetcher** and **vendor PSIRT RSS** for Cisco, Red Hat, Palo Alto and
  others, filtered by a configurable vendor watchlist and CVSS floor
- **ThreatFox** IoC ingestion and **sightings API** for pushing observations from a SIEM

**Analysis**
- **Enrichment** — VirusTotal v3, GreyNoise Community, Shodan InternetDB and
  ipgeolocation.io, each cached on disk with a TTL to stay inside free-tier quotas
- **IoC pivot** — cross-references an indicator against CVEs, customer assets and
  Shodan exposure data
- **Provenance** — every indicator keeps which source reported it, when it was first
  and last seen, and how many sources agree
- **CIDR aggregation** — collapses scattered single IPs into `/24` blocks once a
  configurable threshold is crossed, with a dry-run mode and automatic backup
- **Warninglists** — RFC 1918, IANA reserved, public DNS resolvers and the Tranco
  top-10k are checked before an indicator is accepted, to suppress obvious false positives

**Operations**
- **Verifiable audit log** — every entry is `sha256(prev_hash + "|" + json)`, forming a
  hash chain from a fixed genesis. `bin/verify-audit-chain` detects any tampering or
  deletion in the middle of the log
- **RBAC** — `admin` / `operator` / `viewer` roles enforced server-side on every mutating
  endpoint, not only in the UI
- **Notifications** — email and webhook hooks on blacklist, whitelist, user and feed events
- **False-positive reporting** and per-source feed health dashboards

## Architecture

```
                        EXTERNAL SOURCES
   Spamhaus · Firehol · URLhaus · USOM · MalwareBazaar · StevenBlack
   ThreatFox · NVD/KEV · Vendor PSIRT (RSS) · CSAF 2.0 advisories
                               │
                               ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  INGEST            sources_manager · csaf_fetcher             │
   │                    psirt_rss_fetcher · cve_fetch · threatfox  │
   │                    api.php (ingest) · sighting.php (SIEM)     │
   └───────────────────────────────┬───────────────────────────────┘
                                   ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  NORMALISE & FILTER                                           │
   │    warninglists  →  RFC1918 · IANA reserved · public DNS      │
   │                     Tranco top-10k                            │
   │    whitelist subtraction · dedup · TTL expiry                 │
   └───────────────────────────────┬───────────────────────────────┘
                                   ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  STORE           blacklist.txt · lists_dyn/ · lists.json      │
   │                  blacklist_meta.json  ← provenance per IoC    │
   └───────────────────────────────┬───────────────────────────────┘
                                   ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  ENRICH & ANALYSE                                             │
   │    VirusTotal · GreyNoise · Shodan · ipgeolocation (cached)   │
   │    ioc_pivot · ioc_provenance · ioc_history                   │
   │    cidr_aggregate · fp_report · feed_health                   │
   └───────────────────────────────┬───────────────────────────────┘
                                   ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  DISTRIBUTE                                                   │
   │    taxii.php        →  TAXII 2.1 / STIX 2.1  →  TIP, MISP     │
   │    api.php          →  REST + X-API-Key      →  SOAR, scripts │
   │    firewall feed    →  flat blocklist        →  FortiGate,    │
   │                                                 pfSense, F5   │
   └───────────────────────────────────────────────────────────────┘

   CROSS-CUTTING
     blacklist_admin_auth.php  →  RBAC (admin / operator / viewer)
     audit_log.php             →  sha256 hash-chained audit trail
     lib_safe_write.php        →  atomic writes (tmp + rename)
     notify.php                →  email / webhook events
```

**Stack:** PHP 8.5, PostgreSQL (auth/audit in the `archive/blockharbor-modern` branch),
Apache, Docker. No framework — deliberately, so the deployment surface stays small
enough to audit.

## Screenshots

<!-- Add screenshots to docs/screenshots/ and link them here. -->

| View | Screenshot |
|---|---|
| Dashboard — KPI chips, feed health, action-required queue | _TODO_ |
| IoC pivot — enrichment and provenance for a single indicator | _TODO_ |
| List management — per-list view, bulk actions, TLP tagging | _TODO_ |
| Audit log — hash-chained entries with chain verification | _TODO_ |

## Live demo

A read-only public demo runs from `render.yaml` (Render, free plan):

| | |
|---|---|
| Login | `demo` / `demo` |
| Data | synthetic — RFC 5737 addresses only, unassigned CVE identifiers |
| Writes | disabled |

Demo mode is switched on with `DEMO_MODE=true` and is enforced by
`demo_mode.php`, which PHP loads ahead of every request via `auto_prepend_file`.
Doing it at the front door rather than per endpoint is deliberate: a handful of
scripts in this codebase ship without an auth check of their own, so an
entry-point gate is the only way to be sure nothing was missed.

What the flag changes:

- **Read-only.** Anything other than `GET`/`HEAD` is refused, except the login
  and logout forms. Scripts that mutate state on `GET` — migrations, feed
  fetchers, user management — are refused outright.
- **No admin account.** `login.php` accepts only `demo`/`demo` as a viewer, and
  `auth_config.php` generates an unusable random hash instead of the
  `admin`/`admin` fallback, so the default credentials cannot work.
- **No outbound calls.** VirusTotal, GreyNoise, Shodan and the geolocation
  provider return deterministic stub responses; nothing leaves the container.
- **No scheduled jobs.** The feed-fetch cron is not installed.
- **A banner** on every HTML page. JSON and TAXII responses are left untouched.
- **A fresh dataset on every boot**, generated by `bin/seed-demo.php`.

Mount point is configurable with `CWE_BASE_PATH` — `/` for the demo, and the
historical `/blacklist/cyberwebeyeos` remains the default for existing
deployments.

Run it locally:

```bash
DEMO_MODE=true CWE_BASE_PATH=/ docker compose up --build
```

---

## Quick Start

### Step 1 — Install Docker (if not already installed)

```bash
# Ubuntu / Debian
sudo apt install docker.io docker-compose-v2 -y
sudo systemctl enable --now docker
```

### Step 2 — Run

```bash
git clone https://github.com/altanmelihhh-web/BlockHarbor.git
cd BlockHarbor
bash bin/docker-up.sh
```

The script:
- Creates `.env` from `.env.example` automatically
- Seeds runtime state (`users.json`, `whitelist.txt`, ...) from the shipped
  `*.example` templates on first boot
- Detects port conflicts and prompts for a different port if needed
- Builds the image and starts the container

Access at: **http://localhost:8090/blacklist/cyberwebeyeos/**

Default login: `admin` / `admin` — change your password immediately after first login.

> **Non-interactive / CI:** `bash bin/docker-up.sh --auto-port` (skips prompts, auto-picks next free port)

---

## Configuration

Copy `.env.example` to `.env` and set:

| Variable | Description |
|---|---|
| `HTTP_PORT` | Host port (default: 8090) |
| `CWE_ADMIN_USERNAME` | Admin username (default: admin) |
| `CWE_ADMIN_PASSWORD_HASH` | bcrypt hash of admin password |
| `CWE_VT_API_KEY` | VirusTotal v3 API key (optional) |
| `CWE_GREYNOISE_API_KEY` | GreyNoise community key (optional, 50/day) |
| `CWE_IPGEOLOCATION_API_KEY` | ipgeolocation.io key (optional) |
| `CWE_API_KEYS` | JSON array of REST API keys (optional) |

### Runtime state files

These hold credentials and operational data, so they are **gitignored** and only
their templates ship with the repo. One command creates them, along with the
writable files and directories the application appends to but will not create
itself:

```bash
sh bin/init-state.sh
```

The Docker entrypoint runs the same script, so container and native installs
bootstrap identically. It is idempotent — existing files are left alone.

Never commit these files back — they are excluded in `.gitignore` on purpose.

Generate a password hash:
```bash
docker compose exec app php -r "echo password_hash('yourpassword', PASSWORD_BCRYPT) . PHP_EOL;"
```

## Data Persistence

All runtime data (feeds, blacklist, state files) is stored in the `cwe_data` Docker named volume. It survives container restarts.

To reset all data:
```bash
docker compose down -v
bash bin/docker-up.sh
```

## Scheduled Jobs (Cron)

Feed fetching and CVE sync are defined in `cron/cyberwebeyeos-tip`. To install on the host:

```bash
sudo cp cron/cyberwebeyeos-tip /etc/cron.d/cyberwebeyeos-tip
sudo systemctl reload cron
```

## REST API

Pass `X-API-Key: <key>` header. Keys are configured via `CWE_API_KEYS` env var.

```bash
curl -H "X-API-Key: your-key" http://localhost:8090/blacklist/cyberwebeyeos/api.php?action=list
```

## TAXII 2.1

Discovery endpoint: `GET /blacklist/cyberwebeyeos/taxii2/`

## Production Notes

- Run behind a reverse proxy (nginx/caddy) that terminates TLS
- Rotate `CWE_API_KEYS` before exposing to external clients
- Set `CWE_ADMIN_PASSWORD_HASH` to a strong bcrypt hash in `.env`

## License

MIT — see [LICENSE](LICENSE).
