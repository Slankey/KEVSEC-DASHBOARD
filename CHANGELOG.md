# Changelog

All notable changes to KEVSEC Intelligence Dashboard are documented here.

---

## [v1.2] — 2026-04-30

### Added
- **Operative profile section** on landing page — personal bio, ID card with LinkedIn/GitHub links, specialization grid (OSINT, Threat Intel, Active Defense, Malware Analysis, Infrastructure, Digital Forensics)
- **Government portal login modal** — full-screen takeover on `kev` trigger: eagle seal 🦅, `E PLURIBUS UNUM`, "EXECUTIVE INTELLIGENCE PORTAL" in Playfair Display, gold/navy color scheme, live ZULU clock, `Authenticating...` button state
- **Classification banners** — red TOP SECRET CODEWORD KEVSEC NOFORN banners top and bottom of login overlay
- **Podcast player panel** in Intel Feed tab — 10 feeds: BBC Global News, NPR Hourly/Up First/Consider This, CNN 5 Things, Fox News Rundown, The Daily (NYT), Pod Save America, Axios Today, FT News Briefing; click-to-play with HTML5 audio bar
- **`/api/podcasts`** — fetches latest episode per feed in parallel, extracts audio URL from enclosures, returns name/episode/duration/published/audio_url; 15-min TTL
- **`/api/public/uptime`** — unauthenticated endpoint, returns server uptime string
- **`/api/public/stats`** — unauthenticated endpoint, reads nftables blacklist IP count (3.4M+) and honeypot log line count; 1hr cache
- **Live hero stats** on landing page — IPs Blocked and Probes Caught pulled from `/api/public/stats`, displayed in hero and status panel

### Changed
- **Landing page — legal warning** — replaced generic federal law cite with accurate CFAA citation: *Computer Fraud and Abuse Act (CFAA) — 18 U.S.C. § 1030* and *Electronic Communications Privacy Act — 18 U.S.C. §§ 2510–2523*; clarified as private system, not government
- **Landing page — scrubbed sensitive data** — removed all specific tool names (endlessh, fail2ban, nftables, honeypot, nginx, Proxmox, swizzin) from ticker, about text, terminal card, capabilities, and status panel; replaced operational specifics with CLASSIFIED/REDACTED markers
- **Landing page — ticker** — generic operational language, no tool names disclosed
- **Landing page — terminal card** — generic service labels (`perimeter-defense`, `intel-aggregator`, `edge-enforcement`); uptime returns `permission denied — [CLASSIFIED]`
- **Landing page — footer** — removed `SWIZZIN // PROXMOX` build string → `[CLASSIFIED]`
- **Landing page — nav** — added Operative section link
- **Polls feed** — replaced NPR top stories with Marquette Law Poll, Gallup, and Pew Research for higher-signal polling coverage
- **`/api/public/stats` IP count** — reads actual IPv4 addresses from `/etc/nftables-blacklist/blacklist.nft` via regex match

### Fixed
- **Login modal CSRF bug** — removed `/api/csrf` fetch from landing page login (pre-auth route doesn't need CSRF token, endpoint requires auth)

---

## [v1.1] — 2026-04-29

### Added
- **Public landing page** (`kevsec.com`) — professional cyber ops website at `/` with animated ticker, capabilities grid, defense posture panel, and system status. No visible login link.
- **Hidden login trigger** — type `kev` anywhere on the page (not in an input) to reveal the auth modal. 2-second sequence timeout.
- **`/ops` route** — hidden login endpoint; replaces `/` as the authentication entry point
- **Module-level constants** — `HDRS`, `_DATE_PAT`, `_EVENT_PAT`, `_WS_PAT` extracted from inline definitions across 12+ routes

### Changed
- **Presidential schedule** — rewired to scrape `rollcall.com/factbase/trump/calendar/` daily (86400s TTL); returns structured `schedule` array with date, time, title, type, source
- **`/` route** — now serves public landing page; authentication moved to `/ops`
- **Steam entry** — deduplicated in ext_services (kept `Steam`, dropped `Steam Store`)
- **Empty-string guard** in `api_president_intel` — `ev_title.lower() in ('', 'tbd')` → `not ev_title or ev_title.lower() == 'tbd'`

### Removed
- **Dead variables** — `current_date` and `current_date_obj` from `api_president_intel`
- **Warm cache presidential block** — 48-line block removed (24hr TTL makes proactive warm unnecessary)

---

## [v1.0] — 2026-04-28

### Added
- **`HDRS` constant** — `{"User-Agent": "KEVSec/1.0 ops@kevsec.com"}` at module level; replaced 12 inline dicts
- **README** — full project overview, architecture diagram, feature list, setup instructions
- **`.gitignore`** — excludes `.env`, `__pycache__`, cache data, logs, DB files

### Changed
- **Honeypot panel** — "UFW — Raw Firewall Drops" → "Honeypot — Recent Probe Catches"; reads `/var/log/honeypot/access.log`
- **Cyber Ops layout** — IP Management + Server Health moved to right column beside Firewall & Fail2Ban
- **Service grid** — removed `rtorrent@slankey`, `autobrr`, `rTorrent`
- **`api_nuke`** — `NUKE_HASH` moved to `os.environ.get("NUKE_PASSWORD_HASH", "")`
- **Proxmox defaults** — sanitized to generic `proxmox.local` / `root@pve`
- **Username default** — `slankey` → `admin`
- **User-Agent** — all routes updated to `ops@kevsec.com`

### Removed
- **Large Files panel** — `api_bigfiles`, `loadBigFiles()`, all UI elements
- **Downdetector links panel** — removed from Cyber Ops tab and quick-access bar
- **rTorrent / autobrr** — all service references purged

---

## [v0.1] — Initial Commit

- Flask app, 40+ API routes across Intel, Weather, Cyber Ops, Comms, Command Center tabs
- In-memory + disk cache, per-endpoint TTLs (5min–24hr)
- Session auth (SHA-256 password hash), CSRF protection on all POST routes
- Honeypot endpoints + fail2ban + Cloudflare auto-ban integration
- Proxmox VM telemetry, systemd service grid, network interface stats
- CVE feed, NOAA space weather, USGS earthquakes, GDACS events
- Notes, memos, reminders, quick notepad
