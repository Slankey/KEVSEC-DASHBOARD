# KEVSEC Intelligence Dashboard

A personal security operations dashboard built from scratch. Aggregates threat intelligence, live data feeds, server telemetry, and cyber ops tooling into a single command interface.

## What It Does

### Intel Feed
- 20+ RSS news feeds aggregated and deduplicated
- NOAA space weather (SWPC) — solar flares, geomagnetic storms
- USGS earthquake feed — real-time seismic events
- CVE feed — latest vulnerability disclosures
- Active wildfire map (NIFC)
- NASA Astronomy Picture of the Day
- Wikipedia featured article

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
- Large file scanner

### Cyber Ops
- **Firewall & Fail2Ban** — honeypot probe catches + automated ban tracking
- **IP Management** — manual ban/unban, blacklist sync, jail summary
- **Tarpit Stats** — endlessh SSH tarpit analytics (connections trapped, time wasted, unique IPs)
- **CVE Feed** — latest CVEs from NVD
- **Space Weather** — NOAA SWPC geomagnetic/solar activity

### Comms
- Notes (Markdown, Obsidian export)
- Memos (file upload/manage)
- Quick notepad
- Reminders with notification support

### Other
- Political intel — White House RSS, Congress status, midterm market data
- Stock ticker (Yahoo Finance)
- GLERL Great Lakes satellite imagery
- USCG Local Notice to Mariners

## Architecture

```
Flask (Python 3) — port 5555
├── app.py          — all routes and API logic (~4000 lines)
├── templates/      — Jinja2 HTML templates
│   └── dashboard.html
└── static/
    ├── css/style.css
    └── js/main.js
```

**Caching:** In-memory + disk-persisted cache with per-endpoint TTLs (5min–24hr)  
**Auth:** SHA-256 password hash via environment variable, session-based login  
**Security:** CSRF protection on all POST routes, fail2ban integration, security audit logging  
**Honeypot:** nginx routes scanner paths → honeypot → fail2ban → nftables blacklist

## Setup

### Requirements
```bash
pip install flask python-dotenv requests
```

### Configuration
Copy `.env.example` to `.env` and fill in your values:
```
KEVSEC_USERNAME=admin
KEVSEC_PASSWORD_HASH=<sha256 of your password>
PROXMOX_HOST=https://proxmox.local:8006/api2/json
PROXMOX_USER=root@pve
PROXMOX_PASS=
ABUSEIPDB_KEY=
NASA_API_KEY=DEMO_KEY
NUKE_PASSWORD_HASH=<sha256 of nuke auth code>
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

## Notes

- All sensitive credentials are loaded from environment variables — never hardcoded
- The `.env` file is gitignored
- Designed for personal/homelab use behind a reverse proxy (nginx + Cloudflare)
