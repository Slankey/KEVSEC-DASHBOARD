# KEVSEC Intelligence Dashboard

A personal security operations dashboard and public-facing cyber intelligence platform. Aggregates threat intelligence, live data feeds, server telemetry, and cyber ops tooling into a single command interface.

**Version:** 1.2

---

## Public Website

The public-facing landing page shows live threat stats (IPs blocked, probes caught), an operative profile, and a capabilities overview.

---

## Dashboard Features

### Intel Feed
- 20+ RSS news feeds aggregated and deduplicated
- NOAA space weather (SWPC) — solar flares, geomagnetic storms
- USGS earthquake feed — real-time seismic events
- CVE feed — latest vulnerability disclosures
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
├── app.py              — all routes and API logic (~4200 lines)
├── templates/
│   ├── landing.html    — public-facing kevsec.com website
│   ├── dashboard.html  — authenticated ops center
│   └── login.html      — gov portal login page (kevsec.com/ops)
└── static/
    ├── css/style.css
    └── js/main.js
```

**Caching:** In-memory + disk-persisted cache with per-endpoint TTLs (5min–24hr)  
**Auth:** SHA-256 password hash via environment variable, session-based, 24hr lifetime  
**Security:** CSRF protection on all POST routes, fail2ban integration, security audit logging, Cloudflare auto-ban on honeypot hits  
**Honeypot:** Routes scanner paths → fail2ban → nftables blacklist + Cloudflare firewall rules  
**Public stats:** `/api/public/stats` and `/api/public/uptime` — unauthenticated, safe to expose

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

---

## Security Notes

- All sensitive credentials loaded from environment variables — never hardcoded
- `.env` is gitignored
- Designed for personal/homelab use behind a reverse proxy (nginx + Cloudflare)
- Dashboard login hidden behind public landing page — no visible login link
- Pre-auth honeypot traps common credential stuffing attempts (admin/password etc.) with Cloudflare auto-ban
