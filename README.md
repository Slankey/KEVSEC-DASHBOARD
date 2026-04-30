# KEVSEC Intelligence Dashboard

A personal security operations dashboard and public-facing cyber intelligence platform. Aggregates threat intelligence, live data feeds, server telemetry, cyber ops tooling, and personal health tracking into a single command interface.

**Version:** 1.5

---

## Public Website

The public-facing landing page features a matrix rain background, live attack log widget, THREAT DETECTED/NEUTRALIZED toast notifications, global threat map links (Bitdefender, Kaspersky, FortiGuard, Check Point), and a visitor tracking panel. Live attack feed is built daily from real honeypot logs.

---

## Dashboard Features

### Intel Feed
- 20+ RSS news feeds aggregated and deduplicated
- NOAA space weather (SWPC) — solar flares, geomagnetic storms
- USGS earthquake feed — real-time seismic events
- CVE feed — latest vulnerability disclosures from NVD
- Active wildfire map (NIFC)
- NASA Astronomy Picture of the Day
- Wikipedia featured article
- **Podcast player** — BBC Global News, NPR (Hourly/Up First/Consider This), CNN 5 Things, Fox News Rundown, The Daily, Pod Save America, Axios Today, FT News Briefing

### Weather Ops
- NWS weather forecasts
- Aviation METAR/TAF data
- NDBC Lake Michigan buoy data
- NWS alerts filtered by county
- Wisconsin DNR burn ban status
- Air quality (AirNow AQI)

### Command Center
- Live server stats — CPU, RAM, disk, swap
- 14-service systemd status grid
- Proxmox VM telemetry
- Network interface rx/tx stats
- System package update tracker

### Cyber Ops
- **Firewall & Fail2Ban** — honeypot probe catches + automated ban tracking
- **IP Management** — manual ban/unban, blacklist sync, jail summary
- **Tarpit Stats** — SSH tarpit analytics (connections trapped, time wasted, unique IPs)
- **CVE Feed** — latest CVEs from NVD
- **Space Weather** — NOAA SWPC geomagnetic/solar activity

### Personal
- **Medication Tracker** — log injection dates, track days since last dose, next due date, overdue alerts with progress bar (supports multiple medications with configurable intervals)
- **Weight & BMI** — weight log with BMI calculation, category tracking, and line chart history
- **Psoriasis Log** — severity rating (1–10), body area tracking, notes per entry
- **Shower Log** — date/time logging with consecutive day streak counter
- **Daily Health Journal** — freeform daily notes log
- **Health & Fitness News** — aggregated RSS from Psoriasis Foundation, Bodybuilding.com, Men's Health, Runner's World, and more

### Comms
- Notes (Markdown, Obsidian export)
- Memos (file upload/manage)
- Quick notepad
- Reminders with notification support

### Political Intel
- Presidential schedule (Roll Call / Factbase daily scrape)
- Congress status
- 2026 midterm race ratings and prediction markets
- Polling aggregators (Marquette Law Poll, Gallup, Pew Research, FiveThirtyEight, RCP)

### Other
- Stock ticker (Yahoo Finance)
- F1 standings + race schedule
- GLERL Great Lakes satellite imagery
- USCG Local Notice to Mariners

---

## Architecture

```
Flask (Python 3) — port 5555
├── app.py                          — all routes and API logic
├── data/
│   ├── attack_feed.json            — daily-built honeypot IP feed
│   └── personal_health.json        — personal health data store
├── scripts/
│   └── build_attack_feed.py        — cron: parses honeypot log → attack_feed.json
├── templates/
│   ├── landing.html                — public-facing website
│   ├── dashboard.html              — authenticated ops center
│   └── login.html                  — login page
└── static/
    ├── css/style.css
    └── js/main.js
```

**Caching:** In-memory + disk-persisted cache with per-endpoint TTLs (5min–24hr)  
**Auth:** SHA-256 password hash via environment variable, session-based, 24hr lifetime  
**Security:** CSRF protection on all state-changing routes, fail2ban integration, security audit logging, Cloudflare auto-ban on honeypot hits  
**Honeypot:** 30+ trap routes (WordPress, admin panels, AWS IMDS, Kubernetes API, Docker API, Vault, SSH keys, etc.) → fail2ban → nftables blacklist + Cloudflare firewall  
**Attack Feed:** Built daily at 3am by cron from honeypot access log — IPs shuffled and served as static JSON, displayed on landing page with randomized delay  
**Public stats:** `/api/public/stats`, `/api/public/uptime`, `/api/public/feed` — unauthenticated, safe to expose

---

## Setup

### Requirements
```bash
pip install flask python-dotenv requests feedparser
```

### Configuration
Copy `.env.example` to `.env`:
```
KEVSEC_USERNAME=
KEVSEC_PASSWORD_HASH=
NUKE_PASSWORD_HASH=
PROXMOX_HOST=
PROXMOX_USER=
PROXMOX_PASS=
ABUSEIPDB_KEY=
NASA_API_KEY=
CF_ZONE_ID=
CF_API_TOKEN=
```

Generate a password hash:
```bash
echo -n "yourpassword" | sha256sum
```

### Run
```bash
python app.py
# or with gunicorn:
gunicorn -w 2 -b 127.0.0.1:5555 app:app
```

### Attack Feed Cron
```bash
# Add to crontab — builds honeypot IP feed daily at 3am
0 3 * * * /path/to/venv/bin/python /path/to/scripts/build_attack_feed.py
```

---

## Changelog

### v1.5
- Added **Personal tab** — medication tracker, weight/BMI logger with chart, psoriasis log, shower streak tracker, daily health journal, health news feed
- Fixed CSRF handling for DELETE requests across all personal endpoints
- Centralized all service logs to `/mnt/hdd/logs/`

### v1.4
- Honeypot expanded to 30+ trap routes — AWS IMDS, Kubernetes API, Docker API, HashiCorp Vault, SSH key files, XML-RPC, config probes, Apache server-status
- Landing page: matrix rain background, live attack log widget, THREAT DETECTED toasts, global threat maps, visitor tracking panel, mobile responsive layout

### v1.3
- Real attack feed — daily cron parses honeypot log, builds static JSON served to landing page
- Attack log widget drips entries at randomized 12–30s intervals

### v1.2
- Political intel tab — presidential schedule, congress status, midterm ratings, polling
- Podcast player
- F1 standings and GLERL Great Lakes imagery

---

## Security Notes

- All sensitive credentials loaded from environment variables — never hardcoded
- `.env` is gitignored
- Designed for personal/homelab use behind a reverse proxy (nginx + Cloudflare)
- Dashboard login hidden behind public landing page
- Pre-auth honeypot traps common credential stuffing attempts with Cloudflare auto-ban
