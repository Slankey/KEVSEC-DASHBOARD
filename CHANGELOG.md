# Changelog

All notable changes to KEVSEC Intelligence Dashboard are documented here.

---

## [Unreleased]

---

## 2026-04-29

### Added
- **Public landing page** (`kevsec.com`) — a professional cyber operations website served at `/` with animated ticker, capabilities grid, live intel feed, and system status panel. No visible login link.
- **Hidden login trigger** — type `kev` anywhere on the landing page to reveal the authentication modal. Login form posts to `/ops`.
- **`/ops` route** — new hidden login endpoint; replaces `/` as the auth entry point.
- **`/api/public/uptime`** — unauthenticated endpoint exposing server uptime for landing page display.
- **`/api/public/stats`** — unauthenticated endpoint exposing honeypot trap counts for landing page stats.
- **Module-level constants** — `HDRS`, `_DATE_PAT`, `_EVENT_PAT`, `_WS_PAT` extracted from inline definitions across 12+ routes.

### Changed
- **Polls feed** — replaced NPR top stories with Marquette Law Poll, Gallup, and Pew Research for higher-signal polling coverage.
- **Presidential schedule** — rewired to scrape `rollcall.com/factbase/trump/calendar/` daily (86400s TTL) instead of Factbase JSON + 3 WH RSS feeds. Returns structured `schedule` array with date, time, title, type, and source fields.
- **`/` route** — now serves the public landing page; authentication moved to `/ops`.
- **Steam entry** — deduplicated in external services list (kept `Steam`, dropped `Steam Store`).
- **Empty-string guard** — `ev_title.lower() in ('', 'tbd')` simplified to `not ev_title or ev_title.lower() == 'tbd'`.

### Removed
- **Dead variables** — `current_date` and `current_date_obj` removed from `api_president_intel`.

---

## 2026-04-28

### Added
- **`HDRS` constant** — `{"User-Agent": "KEVSec/1.0 ops@kevsec.com"}` extracted to module level; all inline dicts replaced.
- **README** — project overview, architecture diagram, setup instructions, and feature list.
- **`.gitignore`** — excludes `.env`, `__pycache__`, cache data, logs, and DB files.

### Changed
- **Honeypot panel** — "UFW — Raw Firewall Drops" renamed "Honeypot — Recent Probe Catches"; source changed from empty `ufw.log` to `/var/log/honeypot/access.log`.
- **Presidential schedule** — removed WH RSS feeds; switched to Roll Call / Factbase HTML scrape.
- **Cyber Ops layout** — IP Management and Server Health panels moved to right column beside Firewall & Fail2Ban.
- **Service grid** — removed `rtorrent@slankey`, `autobrr`, `rTorrent` from service lists and allowed service controls.
- **`api_nuke`** — `NUKE_HASH` moved from hardcoded string to `os.environ.get("NUKE_PASSWORD_HASH", "")`.
- **Proxmox defaults** — sanitized default host/user to generic values.
- **Username default** — `slankey` → `admin`.
- **User-Agent** — all routes updated from personal email to `ops@kevsec.com`.

### Removed
- **Large Files panel** — `api_bigfiles`, `loadBigFiles()`, and all related UI elements removed.
- **Downdetector links panel** — removed from Cyber Ops tab and quick-access bar.
- **rTorrent / autobrr** — all service references purged.
- **Warm cache presidential block** — 48-line warm_cache block removed (24hr TTL makes it unnecessary).

---

## Initial Commit

- Flask app with 40+ API routes across Intel, Weather, Cyber Ops, Comms, and Command Center tabs.
- In-memory + disk cache with per-endpoint TTLs (5min–24hr).
- Session auth with SHA-256 password hash, CSRF protection on all POST routes.
- Honeypot endpoints + fail2ban integration.
- Proxmox VM telemetry, systemd service grid, network interface stats.
- CVE feed, space weather, USGS earthquakes, GDACS events.
- Notes, memos, reminders, and quick notepad.
