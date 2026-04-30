import os, json, time, hashlib, secrets, datetime, subprocess, re, threading, random, logging, sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from flask import Flask, render_template, request, session, redirect, url_for, jsonify, send_file

import feedparser
import requests
import urllib3
urllib3.disable_warnings()

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "kev-sec-dash-2026-xK9mPqR7vL2nW5sT")

# Security logging — fail2ban watches this file
_sec_log = logging.getLogger("kevsec.security")
_sec_handler = logging.FileHandler("/mnt/hdd/logs/kevsec-auth.log")
_sec_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
_sec_log.addHandler(_sec_handler)
_sec_log.setLevel(logging.WARNING)

def _real_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
app.permanent_session_lifetime = datetime.timedelta(hours=24)

USERNAME      = os.environ.get("KEVSEC_USERNAME", "admin")
PASSWORD_HASH = os.environ.get("KEVSEC_PASSWORD_HASH",
                               hashlib.sha256(b"changeme").hexdigest())
DATA_DIR      = "/opt/kevsec-dashboard/data"
NOTEPAD_FILE  = f"{DATA_DIR}/notepad.txt"
REMINDERS_FILE= f"{DATA_DIR}/reminders.json"
MEMOS_DIR     = f"{DATA_DIR}/memos"
NOTES_DIR     = f"{DATA_DIR}/notes"
PROXMOX       = os.environ.get("PROXMOX_HOST", "https://proxmox.local:8006/api2/json")
PROXMOX_USER  = os.environ.get("PROXMOX_USER", "root@pve")
PROXMOX_PASS  = os.environ.get("PROXMOX_PASS", "")
ABUSEIPDB_KEY     = os.environ.get("ABUSEIPDB_KEY", "")
FAA_CLIENT_ID     = os.environ.get("FAA_CLIENT_ID", "")
FAA_CLIENT_SECRET = os.environ.get("FAA_CLIENT_SECRET", "")
NASA_API_KEY      = os.environ.get("NASA_API_KEY", "DEMO_KEY")
CF_ZONE_ID        = os.environ.get("CF_ZONE_ID", "")
CF_API_TOKEN      = os.environ.get("CF_API_TOKEN", "")
ENV_FILE          = os.path.join(os.path.dirname(__file__), ".env")
os.makedirs(MEMOS_DIR, exist_ok=True)
os.makedirs(NOTES_DIR, exist_ok=True)

HDRS = {"User-Agent": "KEVSec/1.0"}

# Presidential schedule regex — compiled once at module level
_DATE_PAT = re.compile(
    r'text-\[#5C5B5B\][^>]*>\s*([\w]+,)\s*</span>\s*'
    r'<span[^>]*text-gray-700[^>]*>\s*([\w]+ \d+, \d{4})\s*</span>',
    re.DOTALL)
_EVENT_PAT = re.compile(
    r'data-tooltip="([^"]+)".*?'
    r'text-sm font-light">(\d+:\d+ [AP]M)</div>.*?'
    r'text-sm font-light text-gray-600 mt-2">\s*(.*?)\s*</div>',
    re.DOTALL)
_WS_PAT = re.compile(r'\s+')

_cache = {}
CACHE_TTL        = 300    # 5 min — live/frequent data (stocks, METAR, buoy, server stats)
TARPIT_RESET_FILE = os.path.join(DATA_DIR, "tarpit_reset.json")
CACHE_TTL_LONG   = 21600  # 6 hr  — weather, news, SWPC, AirNow, CVEs, threat
CACHE_TTL_DAY    = 86400  # 24 hr — APOD, Wikipedia (rate-limited or near-static)

# All major data keys are persisted to disk so service restarts don't re-fetch
DISK_CACHE_KEYS = {
    "apod", "wikipedia",            # rate-limited / daily
    "news",                         # 20 RSS feeds — slow to fetch
    "weather", "swpc", "airnow", "wildfires",  # NWS / NOAA — be a good citizen
    "threat", "cves", "quakes",     # external APIs
    "stocks",                       # Yahoo Finance
    "lnm",                          # USCG daily
    "lake",                         # NDBC buoy + AFD — survives restarts
    "burn_ban", "president_intel", "congress_status", "midterm_intel",
    "f1", "polls", "govt_intel", "gdacs",
}
DISK_CACHE_DIR = os.path.join(DATA_DIR, "cache")
os.makedirs(DISK_CACHE_DIR, exist_ok=True)

def _disk_path(k):
    return os.path.join(DISK_CACHE_DIR, f"{k}.json")

def _ts():
    """Return current local time with timezone label, e.g. '14:32 CDT'."""
    import zoneinfo as _zi
    ct = datetime.datetime.now(tz=_zi.ZoneInfo("America/Chicago"))
    return ct.strftime("%H:%M %Z")

def get_tarpit_week_offset():
    """Return total_seconds saved at last Sunday 23:59 reset."""
    try:
        with open(TARPIT_RESET_FILE) as f:
            return json.load(f).get("offset_seconds", 0)
    except Exception:
        return 0

def save_tarpit_week_offset(total_seconds):
    """Persist current total_seconds as the weekly offset."""
    try:
        with open(TARPIT_RESET_FILE, "w") as f:
            json.dump({"offset_seconds": total_seconds,
                       "reset_at": datetime.datetime.now().isoformat()}, f)
    except Exception as e:
        app.logger.warning("tarpit_reset save failed: %s", e)

def cache_get(k, ttl=None, force=False):
    if force:
        return None  # caller wants a fresh fetch
    effective_ttl = ttl if ttl is not None else CACHE_TTL
    # Memory first
    if k in _cache:
        d, ts = _cache[k]
        if time.time() - ts < effective_ttl:
            return d
    # Disk fallback for persisted keys
    if k in DISK_CACHE_KEYS:
        path = _disk_path(k)
        try:
            with open(path) as f:
                entry = json.load(f)
            ts = entry.get("_cached_at", 0)
            if time.time() - ts < effective_ttl:
                d = entry.get("_data")
                _cache[k] = (d, ts)
                return d
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            pass
    return None

def cache_set(k, d):
    now = time.time()
    _cache[k] = (d, now)
    if k in DISK_CACHE_KEYS:
        path = _disk_path(k)
        try:
            with open(path, "w") as f:
                json.dump({"_cached_at": now, "_data": d}, f)
        except Exception:
            pass

def pve_auth():
    r = requests.post(f"{PROXMOX}/access/ticket", verify=False, timeout=5,
        data={"username": PROXMOX_USER, "password": PROXMOX_PASS})
    d = r.json()["data"]
    return {"Cookie": f"PVEAuthCookie={d['ticket']}", "CSRFPreventionToken": d["CSRFPreventionToken"]}

# ── CSRF token helpers ─────────────────────────────────────
def _csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

def csrf_required(f):
    """Validate CSRF token on state-changing API calls."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            token = (request.get_json(silent=True) or {}).get("_csrf") or request.headers.get("X-CSRF-Token", "")
            if not token or token != session.get("csrf_token"):
                return jsonify({"error": "invalid csrf token"}), 403
        return f(*args, **kwargs)
    return decorated

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

reset_tokens = {}

@app.route("/")
def landing():
    return render_template("landing.html", error=None, show_modal=False)

@app.route("/ops", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u == USERNAME and hashlib.sha256(p.encode()).hexdigest() == PASSWORD_HASH:
            session["user"] = u
            session.permanent = True
            return redirect(url_for("dashboard"))
        error = "AUTHENTICATION FAILED — CREDENTIALS REJECTED"
        _sec_log.warning("LOGIN_FAILED user=%s ip=%s", u, _real_ip())
        # Trap credentials — common attacker usernames/passwords = instant ban
        _DASH_TRAPS = {
            "admin":["admin","password","123456","admin123","letmein","qwerty"],
            "root":["root","password","123456","toor"],
            "administrator":["administrator","password","admin","123456"],
            "test":["test","test123","password"],
            "guest":["guest","password","guest123"],
            "user":["user","password","user123"],
            "cpanel":["cpanel","password","admin"],
            "wordpress":["wordpress","admin","password"],
        }
        _ip = _real_ip()
        if u.lower() in _DASH_TRAPS and p.lower() in [x.lower() for x in _DASH_TRAPS.get(u.lower(),[])]:
            _sec_log.warning("HONEYPOT TRAP_HIT reason=dashboard_trap_creds ip=%s", _ip)
            def _cf_ban(ip):
                if not CF_ZONE_ID or not CF_API_TOKEN:
                    return
                try:
                    requests.post(
                        f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/firewall/access_rules/rules",
                        headers={"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"},
                        json={"mode": "block", "configuration": {"target": "ip", "value": ip}, "notes": f"dashboard_honeypot:{u}"},
                        timeout=10
                    )
                except Exception as e:
                    app.logger.warning("CF ban failed for %s: %s", ip, e)
            threading.Thread(target=_cf_ban, args=(_ip,), daemon=True).start()
            with open("/var/log/honeypot/permanent_bans.log", "a") as _f:
                _f.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | BANNED | {_ip:<18} | dashboard_trap_creds      | user={u} pass={p}\n")
    return render_template("landing.html", error=error, show_modal=True)

@app.route("/api/public/uptime")
def api_public_uptime():
    """Public — server uptime string, no auth required."""
    try:
        out = subprocess.check_output(["uptime", "-p"], text=True).strip()
        return jsonify({"uptime": out})
    except Exception:
        return jsonify({"uptime": None})

@app.route("/api/public/stats")
def api_public_stats():
    """Public — IP block count from nftables blacklist + honeypot probe count."""
    cached = cache_get("public_stats", ttl=3600)
    if cached:
        return jsonify(cached)
    blocked = 0
    caught = 0
    try:
        # Count IPs in the nftables blacklist file (comma-separated inside add element blocks)
        with open("/etc/nftables-blacklist/blacklist.nft") as f:
            content = f.read()
        import re as _re
        blocked = len(_re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content))
    except Exception:
        pass
    try:
        with open("/var/log/honeypot/access.log") as f:
            caught = sum(1 for _ in f)
    except Exception:
        pass
    result = {"blocked": blocked, "caught": caught}
    cache_set("public_stats", result)
    return jsonify(result)

@app.route("/api/public/feed")
def api_public_feed():
    """Public — serve pre-built attack feed JSON (built daily by cron)."""
    feed_file = os.path.join(os.path.dirname(__file__), "data", "attack_feed.json")
    try:
        with open(feed_file) as f:
            return jsonify(json.load(f))
    except Exception:
        return jsonify({"feed": []})

@app.route("/admin", methods=["GET", "POST"])
@app.route("/wp-admin", methods=["GET", "POST"])
@app.route("/wp-login.php", methods=["GET", "POST"])
@app.route("/phpmyadmin", methods=["GET", "POST"])
@app.route("/cpanel", methods=["GET", "POST"])
@app.route("/manager/html", methods=["GET", "POST"])
def honeypot():
    ip = _real_ip()
    path = request.path
    _sec_log.warning("HONEYPOT_HIT ip=%s path=%s ua=%s", ip, path, request.headers.get("User-Agent",""))
    # Return a convincing fake login page to keep them engaged while ban fires
    return '''<!DOCTYPE html><html><head><title>Login</title></head><body>
<form method="post"><p>Username: <input name="user"></p>
<p>Password: <input type="password" name="pass"></p>
<p><input type="submit" value="Login"></p></form></body></html>''', 200

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    msg = None
    if request.method == "POST":
        u = request.form.get("username", "")
        if u == USERNAME:
            token = secrets.token_urlsafe(20)
            reset_tokens[token] = time.time()
            app.logger.warning(f"[RESET TOKEN] /reset/{token}")
            msg = "RESET LINK GENERATED. CHECK SERVER LOGS: /var/log/kevsec-dashboard.log"
        else:
            msg = "UNKNOWN OPERATIVE. ACCESS DENIED."
    return render_template("forgot.html", msg=msg)

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_pw(token):
    if token not in reset_tokens or time.time() - reset_tokens[token] > 3600:
        return render_template("forgot.html", msg="TOKEN EXPIRED OR INVALID.")
    if request.method == "POST":
        new_pw = request.form.get("password", "")
        if len(new_pw) >= 8:
            global PASSWORD_HASH
            new_hash = hashlib.sha256(new_pw.encode()).hexdigest()
            PASSWORD_HASH = new_hash
            del reset_tokens[token]
            # Persist new hash to .env so it survives restarts
            try:
                with open(ENV_FILE, "r") as f:
                    env_text = f.read()
                env_text = re.sub(
                    r"^KEVSEC_PASSWORD_HASH=.*$",
                    f"KEVSEC_PASSWORD_HASH={new_hash}",
                    env_text, flags=re.MULTILINE
                )
                with open(ENV_FILE, "w") as f:
                    f.write(env_text)
            except Exception as e:
                app.logger.error("Failed to persist password hash to .env: %s", e)
            return render_template("forgot.html", msg="PASSWORD UPDATED. PROCEED TO LOGIN.")
    return render_template("reset.html", token=token)

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=session.get("user"), csrf_token=_csrf_token())

@app.route("/api/csrf")
@login_required
def api_csrf():
    return jsonify({"token": _csrf_token()})

@app.route("/api/internal/warm")
def api_internal_warm():
    """Localhost-only endpoint to trigger cache warm without auth. Used by cron."""
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify({"error": "forbidden"}), 403
    import threading
    t = threading.Thread(target=_warm_cache, kwargs={"force": True}, daemon=True)
    t.start()
    return jsonify({"status": "warming", "ts": datetime.datetime.now().isoformat()})

@app.route("/api/news")
@login_required
def api_news():
    force = request.args.get("force") == "1"
    cached = cache_get("news", ttl=CACHE_TTL_LONG, force=force)
    if cached:
        return jsonify(cached)
    feeds = [
        ("NPR",            "https://feeds.npr.org/1001/rss.xml"),
        ("Reuters",        "https://feeds.reuters.com/reuters/topNews"),
        ("The Guardian",   "https://www.theguardian.com/world/rss"),
        ("The Hill",       "https://thehill.com/feed/"),
        ("Fox News",       "https://moxie.foxnews.com/google-publisher/latest.xml"),
        ("Politico",       "https://rss.politico.com/politics-news.xml"),
        ("NYT",            "https://rss.nytimes.com/services/xml/rss/ntt/HomePage.xml"),
        ("WPR",            "https://www.wpr.org/feed"),
        ("TMJ4 (WI)",      "https://www.tmj4.com/news/local/rss"),
        ("CBS58 (WI)",     "https://www.cbs58.com/news/local-news.rss"),
        ("AP News",        "https://feeds.apnews.com/rss/apf-topnews"),
        ("BBC World",      "http://feeds.bbci.co.uk/news/world/rss.xml"),
        ("Milwaukee Journal Sentinel", "https://rss.jsonengage.com/milwaukee-journal-sentinel/"),
        ("CNBC",           "https://www.cnbc.com/id/100727362/device/rss/rss.html"),
        ("Yahoo Finance",  "https://finance.yahoo.com/news/rssindex"),
        ("Investing.com",  "https://www.investing.com/rss/news.rss"),
        ("AllSides",       "https://www.allsides.com/news/rss"),
        # Google News topic feeds (CNN killed their RSS in 2023; GNews is current)
        ("Google News",    "https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en"),
        ("Google: World",  "https://news.google.com/rss/topics/CAAqJggKIiBDQkFTRWdvSUwyMHZNRGx1YlY4U0FtVnVHZ0pWVXlnQVAB?hl=en-US&gl=US&ceid=US:en"),
        ("Google: Tech",   "https://news.google.com/rss/topics/CAAqJggKIiBDQkFTRWdvSUwyMHZNRGRqTVhZU0FtVnVHZ0pWVXlnQVAB?hl=en-US&gl=US&ceid=US:en"),
        ("Google: Business","https://news.google.com/rss/topics/CAAqJggKIiBDQkFTRWdvSUwyMHZNRGx6TVdZU0FtVnVHZ0pWVXlnQVAB?hl=en-US&gl=US&ceid=US:en"),
    ]
    articles = []
    for source, url in feeds:
        try:
            f = feedparser.parse(url)
            for e in f.entries[:8]:
                summary = re.sub(r"<[^>]+>", "", e.get("summary", ""))[:220]
                articles.append({
                    "source": source,
                    "title": e.get("title", "")[:120],
                    "link": e.get("link", "#"),
                    "published": e.get("published", "")[:25],
                    "summary": summary
                })
        except:
            pass
    result = {"articles": articles, "fetched": datetime.datetime.now().strftime("%H:%M:%S")}
    cache_set("news", result)
    return jsonify(result)

@app.route("/api/history")
@login_required
def api_history():
    cached = cache_get("history")
    if cached:
        return jsonify(cached)
    events, births, deaths = [], [], []
    try:
        feed_map = [
            ("https://www.onthisday.com/rss/today-in-history.xml", events),
            ("https://www.onthisday.com/rss/historical-events.xml", events),
            ("https://www.onthisday.com/rss/famous-birthdays.xml", births),
        ]
        for url, lst in feed_map:
            try:
                f = feedparser.parse(url)
                for e in f.entries[:6]:
                    lst.append({"title": e.get("title", ""), "link": e.get("link", "#")})
            except:
                pass
        # Deaths from historical events feed usually tagged
        for e in events[:]:
            if any(w in e["title"].lower() for w in ["died", "death", "killed", "executed", "murdered", "assassinated"]):
                deaths.append(e)
    except:
        pass
    result = {"events": events, "births": births, "deaths": deaths,
              "date": datetime.date.today().strftime("%B %d")}
    cache_set("history", result)
    return jsonify(result)

@app.route("/api/threat_level")
@login_required
def api_threat_level():
    force = request.args.get("force") == "1"
    cached = cache_get("threat", ttl=CACHE_TTL_LONG, force=force)
    if cached:
        return jsonify(cached)
    alerts = []
    try:
        f = feedparser.parse("https://www.dhs.gov/ntas/alerts/rss.xml")
        for e in f.entries[:3]:
            alerts.append({
                "title": e.get("title", ""),
                "summary": re.sub(r"<[^>]+>", "", e.get("summary", ""))[:300],
                "link": e.get("link", "#"),
                "published": e.get("published", "")[:25]
            })
    except:
        pass
    level = "ELEVATED"
    if alerts:
        t = alerts[0]["title"].upper()
        if "IMMINENT" in t: level = "HIGH"
    # CISA Known Exploited Vulnerabilities (latest additions)
    cisa_kev = []
    try:
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                         timeout=15, headers={"User-Agent":"Mozilla/5.0"})
        vulns = r.json().get("vulnerabilities", [])
        for v in vulns[:10]:
            cisa_kev.append({
                "id":      v.get("cveID",""),
                "name":    v.get("vulnerabilityName","")[:90],
                "product": v.get("product",""),
                "vendor":  v.get("vendorProject",""),
                "added":   v.get("dateAdded",""),
                "due":     v.get("dueDate",""),
                "action":  v.get("requiredAction","")[:120],
            })
    except: pass
    result = {"alerts": alerts, "level": level, "cisa_kev": cisa_kev}
    cache_set("threat", result)
    return jsonify(result)

@app.route("/api/metar")
@login_required
def api_metar():
    force = request.args.get("force") == "1"
    cached = cache_get("metar", 600, force=force)
    if cached:
        return jsonify(cached)
    try:
        r = requests.get(
            "https://aviationweather.gov/api/data/metar",
            params={"ids": "KMKE,KETB,KMWC,KSBM", "format": "json"},
            headers=HDRS,
            timeout=10)
        stations = []
        for m in r.json():
            stations.append({
                "id":   m.get("icaoId",""),
                "raw":  m.get("rawOb",""),
                "temp": m.get("temp"),
                "dewp": m.get("dewp"),
                "wspd": m.get("wspd"),
                "wdir": m.get("wdir"),
                "wgst": m.get("wgst"),
                "vis":  m.get("visib"),
                "time": m.get("reportTime","")[:16],
                "sky":  m.get("sky",""),
                "wx":   m.get("wxString",""),
            })
        result = {"stations": stations, "fetched": datetime.datetime.now().strftime("%H:%M:%S")}
        cache_set("metar", result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e), "stations": []})

@app.route("/api/stocks")
@login_required
def api_stocks():
    force = request.args.get("force") == "1"
    cached = cache_get("stocks", ttl=CACHE_TTL, force=force)
    if cached:
        return jsonify(cached)
    symbols = [
        # US Equities & Volatility
        ("S&P 500", "^GSPC"), ("Dow Jones", "^DJI"), ("NASDAQ", "^IXIC"),
        ("Russell 2000", "^RUT"), ("VIX", "^VIX"),
        # Global Indices
        ("Nikkei 225", "^N225"), ("FTSE 100", "^FTSE"), ("DAX", "^GDAXI"),
        ("Hang Seng", "^HSI"),
        # Commodities
        ("Oil (WTI)", "CL=F"), ("Brent Crude", "BZ=F"), ("Gold", "GC=F"),
        ("Silver", "SI=F"), ("Copper", "HG=F"), ("Nat Gas", "NG=F"),
        # Crypto & Rates
        ("Bitcoin", "BTC-USD"), ("Ethereum", "ETH-USD"), ("10Y Treasury", "^TNX"),
        # FX
        ("EUR/USD", "EURUSD=X"), ("GBP/USD", "GBPUSD=X"), ("USD/JPY", "JPY=X"),
        ("USD/CAD", "CAD=X"), ("AUD/USD", "AUD=X"), ("USD Index", "DX-Y.NYB"),
    ]
    def _fetch_symbol(name, sym):
        try:
            r = requests.get(
                f"https://query1.finance.yahoo.com/v8/finance/chart/{sym}",
                params={"interval": "1d", "range": "2d"},
                headers={"User-Agent": "Mozilla/5.0"}, timeout=6)
            meta = r.json()["chart"]["result"][0]["meta"]
            price = meta.get("regularMarketPrice", 0)
            prev = meta.get("chartPreviousClose", price)
            chg = price - prev
            pct = (chg / prev * 100) if prev else 0
            return {"name": name, "price": round(price, 2), "change": round(chg, 2), "pct": round(pct, 2)}
        except Exception as e:
            app.logger.warning("stock fetch failed for %s: %s", sym, e)
            return {"name": name, "price": 0, "change": 0, "pct": 0}

    data = [None] * len(symbols)
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_fetch_symbol, name, sym): i for i, (name, sym) in enumerate(symbols)}
        for fut in as_completed(futures):
            data[futures[fut]] = fut.result()

    result = {"stocks": data, "fetched": datetime.datetime.now().strftime("%H:%M:%S")}
    cache_set("stocks", result)
    return jsonify(result)

def nws_val(obj):
    """Extract numeric value from NWS unit object."""
    if obj is None: return None
    v = obj.get("value")
    return v

def _frost_status(today):
    m, d = today.month, today.day
    if (m, d) < (4, 15):
        return {"risk": "HIGH",   "label": "Frost risk HIGH — hold tender plants indoors", "color": "#cc4400"}
    if (m, d) < (5, 7):
        return {"risk": "MEDIUM", "label": "Frost still possible — watch overnight lows",  "color": "#cc7700"}
    if (m, d) < (5, 15):
        return {"risk": "LOW",    "label": "Frost unlikely but watch nights below 35°F",   "color": "#cc9900"}
    if (m, d) < (10, 8):
        return {"risk": "NONE",   "label": "Full growing season — frost unlikely",          "color": "#4a9c4a"}
    if (m, d) < (10, 20):
        return {"risk": "MEDIUM", "label": "First frost possible — cover tender plants",    "color": "#cc7700"}
    return     {"risk": "HIGH",   "label": "First frost expected — protect or harvest",     "color": "#cc4400"}

@app.route("/api/watering")
@login_required
def api_watering():
    """Serve the pre-computed watering schedule. force=1 re-runs watering-calc.py first."""
    force = request.args.get("force") == "1"
    f = os.path.join(DISK_CACHE_DIR, "watering_schedule.json")
    if force:
        try:
            import subprocess
            venv_py = "/opt/kevsec-dashboard/venv/bin/python"
            script  = "/usr/local/bin/watering-calc.py"
            subprocess.run([venv_py, script], timeout=60, check=True,
                           capture_output=True)
        except Exception as e:
            app.logger.warning("watering-calc.py run failed: %s", e)
    try:
        with open(f) as fh:
            data = json.load(fh)
        data["cache_age_min"] = round((time.time() - os.path.getmtime(f)) / 60, 0)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e), "schedules": {}})


@app.route("/api/garden")
@login_required
def api_garden():
    """Garden & lawn care intelligence for Port Washington WI 53074 (zone 5b).
    Plants: Azaleas, Wildflowers, Lawn.
    Uses Open-Meteo for historical precip + ET + forecast."""
    force = request.args.get("force") == "1"
    cached = cache_get("garden", ttl=3600, force=force)
    if cached:
        return jsonify(cached)

    LAT, LON = 43.3875, -87.8756
    today = datetime.date.today()
    mm_to_in = 0.0393701

    # ── Historical precipitation: last 14 days ────────────────────────────
    precip_history = []
    try:
        r = requests.get(
            "https://historical-forecast-api.open-meteo.com/v1/forecast",
            params={
                "latitude": LAT, "longitude": LON,
                "start_date": (today - datetime.timedelta(days=13)).isoformat(),
                "end_date":   today.isoformat(),
                "daily": "precipitation_sum,temperature_2m_max,temperature_2m_min",
                "timezone": "America/Chicago",
            }, timeout=12)
        d = r.json().get("daily", {})
        for i, dt in enumerate(d.get("time", [])):
            pmm = d.get("precipitation_sum", [None])[i] or 0
            tmx = d.get("temperature_2m_max", [None])[i]
            tmn = d.get("temperature_2m_min", [None])[i]
            precip_history.append({
                "date":      dt,
                "precip_in": round(pmm * mm_to_in, 2),
                "tmax_f":    round(tmx * 9/5 + 32, 1) if tmx is not None else None,
                "tmin_f":    round(tmn * 9/5 + 32, 1) if tmn is not None else None,
            })
    except Exception as e:
        app.logger.warning("garden hist: %s", e)

    # ── 7-day forecast: precip + ET ───────────────────────────────────────
    forecast_7d = []
    try:
        r = requests.get(
            "https://api.open-meteo.com/v1/forecast",
            params={
                "latitude": LAT, "longitude": LON,
                "daily": ("precipitation_sum,precipitation_probability_max,"
                          "temperature_2m_max,temperature_2m_min,"
                          "et0_fao_evapotranspiration"),
                "timezone": "America/Chicago",
                "forecast_days": 7,
            }, timeout=10)
        d = r.json().get("daily", {})
        for i, dt in enumerate(d.get("time", [])):
            pmm  = d.get("precipitation_sum", [0])[i] or 0
            prob = d.get("precipitation_probability_max", [0])[i] or 0
            tmx  = d.get("temperature_2m_max", [None])[i]
            tmn  = d.get("temperature_2m_min", [None])[i]
            et   = d.get("et0_fao_evapotranspiration", [0])[i] or 0
            forecast_7d.append({
                "date":     dt,
                "rain_in":  round(pmm * mm_to_in, 2),
                "rain_prob":prob,
                "tmax_f":   round(tmx * 9/5 + 32, 1) if tmx is not None else None,
                "tmin_f":   round(tmn * 9/5 + 32, 1) if tmn is not None else None,
                "et_in":    round(et  * mm_to_in, 2),
            })
    except Exception as e:
        app.logger.warning("garden fc: %s", e)

    # ── Rainfall summaries ────────────────────────────────────────────────
    rain_7d  = round(sum(x["precip_in"] for x in precip_history[-7:]),  2)
    rain_14d = round(sum(x["precip_in"] for x in precip_history),        2)
    rain_3d_ahead = round(sum(x["rain_in"]  for x in forecast_7d[:3]),   2)
    frost = _frost_status(today)

    def _plant(name, icon, need_in, notes, extra_tip):
        deficit = max(0, need_in - rain_7d)
        ok      = rain_7d >= need_in * 0.75
        wtr_now = not ok and rain_3d_ahead < 0.25
        if ok:
            status = "GOOD"
            tip = ("Rainfall adequate (%.2f\" in 7 days). "
                   "Check 2\" soil depth — if dry, a light supplement helps.") % rain_7d
        elif deficit < 0.4:
            status = "LOW"
            action = "Water today if no rain by evening." if wtr_now else "Rain expected soon — hold off."
            tip = ("Slightly dry (%.2f\" vs %.1f\" needed). %s") % (rain_7d, need_in, action)
        else:
            status = "DRY"
            if wtr_now:
                action = "Water now: apply %.1f\" slowly at soil level." % need_in
            else:
                action = "Some rain coming (%.2f\") — supplement if deficit persists." % rain_3d_ahead
            tip = ("Water deficit: %.2f\". %s") % (deficit, action)
        if extra_tip:
            tip += " " + extra_tip
        return {"name": name, "icon": icon, "need_in": need_in,
                "rain_7d": rain_7d, "deficit": round(deficit, 2),
                "status": status, "water_now": wtr_now, "tip": tip, "notes": notes}

    plants = [
        _plant("Azaleas", "🌸", 1.0,
            ["Water at base — overhead watering causes leaf fungus",
             "Mulch 3\" around base to retain moisture & acidity",
             "Yellow leaves = needs Holly-tone acidic fertilizer",
             "Zone 5b: safe to transplant after May 15",
             "Bloom time ~May: don't fertilize until after blooms drop"],
            "Azaleas hate soggy roots — ensure good drainage."),
        _plant("Wildflowers", "🌻", 0.75,
            ["Newly seeded: keep moist daily until 3\" tall",
             "Established: drought tolerant — water only in 10+ day dry spells",
             "Don't mow blooming areas May–Sep",
             "Leave seed heads for winter bird food",
             "WI natives (coneflower, black-eyed susan) thrive with neglect"],
            "Once established, less is more with wildflowers."),
        _plant("Lawn", "🌿", 1.25,
            ["Water 1-2×/week deeply vs. light daily (promotes deep roots)",
             "Best time: 6–10am — reduces evaporation & fungal risk",
             "Don't mow until 3.5\" tall; cut to 3\" (never below 2.5\")",
             "Overseed thin areas: early May or September",
             "Fertilize after May 15 — not before last frost"],
            "Lawn can go dormant (tan/brown) in summer heat — it recovers."),
    ]

    # ── 7-day watering schedule ───────────────────────────────────────────
    running_deficit = max(0, 1.25 - rain_7d)  # start from current lawn deficit
    schedule = []
    for day in forecast_7d:
        r_in  = day["rain_in"]
        prob  = day["rain_prob"]
        et    = day["et_in"]
        tmx   = day.get("tmax_f")
        net   = round(r_in - et, 2)

        if r_in >= 0.5:   icon = "🌧"
        elif r_in >= 0.15: icon = "🌦"
        elif prob >= 50:   icon = "🌥"
        elif tmx and tmx >= 70: icon = "☀"
        else:              icon = "🌤"

        # Recommend watering on a day if: minimal rain, low probability, and deficit exists
        water_lawn    = r_in < 0.15 and prob < 35 and running_deficit > 0.3
        water_azalea  = r_in < 0.15 and prob < 35 and (rain_7d + r_in) < 0.75
        water_flowers = r_in < 0.1  and prob < 25

        running_deficit = max(0, running_deficit - r_in + et * 0.5)

        schedule.append({
            "date": day["date"], "icon": icon,
            "rain_in": r_in, "rain_prob": prob,
            "tmax_f": tmx, "tmin_f": day.get("tmin_f"),
            "net_in": net,
            "water_lawn": water_lawn,
            "water_azalea": water_azalea,
            "water_flowers": water_flowers,
        })

    result = {
        "plants":    plants,
        "frost":     frost,
        "schedule":  schedule,
        "rain_7d":   rain_7d,
        "rain_14d":  rain_14d,
        "rain_3d_ahead": rain_3d_ahead,
        "precip_history": precip_history[-7:],
        "location":  "Port Washington, WI 53074 — USDA Zone 5b",
        "fetched":   _ts(),
    }
    cache_set("garden", result)
    return jsonify(result)

@app.route("/api/weather")
@login_required
def api_weather():
    force = request.args.get("force") == "1"
    cached = cache_get("weather", ttl=3600, force=force)
    if cached:
        return jsonify(cached)
    hdrs = HDRS
    forecast, alerts, obs = [], [], {}
    try:
        pt = requests.get("https://api.weather.gov/points/43.3875,-87.8756",
                          headers=hdrs, timeout=15).json()
        props = pt.get("properties", {})
        fc = requests.get(props.get("forecast", ""), headers=hdrs, timeout=15).json()
        periods = fc.get("properties", {}).get("periods", [])[:8]
        forecast = [{"name": p["name"], "temp": p["temperature"],
                     "unit": p["temperatureUnit"], "wind": p.get("windSpeed",""),
                     "short": p.get("shortForecast",""),
                     "detail": p.get("detailedForecast","")[:200]} for p in periods]
    except Exception as e:
        pass
    try:
        # WIZ055 = Ozaukee County, LMZ645 = adjacent Lake Michigan zone (Port Wash → Milwaukee)
        alerts_r = requests.get(
            "https://api.weather.gov/alerts/active?zone=WIZ055,LMZ645",
            headers=hdrs, timeout=12).json()
        alerts = []
        for a in alerts_r.get("features", []):
            p = a.get("properties", {})
            alerts.append({
                "headline":    p.get("headline", ""),
                "severity":    p.get("severity", ""),
                "urgency":     p.get("urgency", ""),
                "event":       p.get("event", ""),
                "description": (p.get("description") or "")[:400],
                "instruction": (p.get("instruction") or "")[:200],
                "effective":   (p.get("effective") or "")[:16].replace("T", " "),
                "expires":     (p.get("expires") or "")[:16].replace("T", " "),
                "url":         a.get("id", ""),  # NWS API URL for this alert
                "areas":       p.get("areaDesc", ""),
            })
    except:
        pass
    for station in ["KETB", "KMWC", "KSBM"]:  # KETB=West Bend (~10mi), KMWC=Timmerman (~25mi)
        try:
            ob = requests.get(
                f"https://api.weather.gov/stations/{station}/observations/latest",
                headers=hdrs, timeout=10).json()
            p = ob.get("properties", {})
            def c2f(v): return round(v * 9/5 + 32, 1) if v is not None else None
            def ms2mph(v): return round(v * 0.621371, 1) if v is not None else None
            def pa2inhg(v): return round(v / 3386.39, 2) if v is not None else None
            def m2mi(v): return round(v / 1609.34, 1) if v is not None else None
            wdir = nws_val(p.get("windDirection"))
            obs = {
                "station": station,
                "time": p.get("timestamp","")[:16].replace("T"," ") + " UTC",
                "condition": p.get("textDescription",""),
                "temp_f": c2f(nws_val(p.get("temperature"))),
                "dewpoint_f": c2f(nws_val(p.get("dewpoint"))),
                "humidity": round(nws_val(p.get("relativeHumidity")) or 0, 1),
                "wind_speed_mph": ms2mph(nws_val(p.get("windSpeed"))),
                "wind_gust_mph": ms2mph(nws_val(p.get("windGust"))),
                "wind_dir_deg": wdir,
                "wind_dir": deg_to_compass(wdir) if wdir else "---",
                "wind_chill_f": c2f(nws_val(p.get("windChill"))),
                "heat_index_f": c2f(nws_val(p.get("heatIndex"))),
                "pressure_inhg": pa2inhg(nws_val(p.get("barometricPressure"))),
                "visibility_mi": m2mi(nws_val(p.get("visibility"))),
                "clouds": [{"base_ft": round(cl["base"]["value"] * 3.28084) if cl["base"]["value"] else None,
                            "amount": cl.get("amount","")}
                           for cl in p.get("cloudLayers",[])],
            }
            break
        except:
            pass
    # UV index from Open-Meteo (NWS doesn't provide it)
    uv_index = None
    try:
        uv_r = requests.get("https://api.open-meteo.com/v1/forecast",
                            params={"latitude": 43.39, "longitude": -87.88,
                                    "current": "uv_index", "timezone": "America/Chicago"},
                            timeout=8)
        uv_index = round(uv_r.json().get("current", {}).get("uv_index", 0), 1)
    except:
        pass
    if obs and uv_index is not None:
        obs["uv_index"] = uv_index
    result = {"forecast": forecast, "alerts": alerts, "obs": obs,
              "fetched": datetime.datetime.now().strftime("%H:%M:%S")}
    if forecast:  # only cache if we got real data
        cache_set("weather", result)
    return jsonify(result)

@app.route("/api/airnow")
@login_required
def api_airnow():
    force = request.args.get("force") == "1"
    cached = cache_get("airnow", ttl=CACHE_TTL_LONG, force=force)
    if cached:
        return jsonify(cached)
    try:
        r = requests.get(
            "https://air-quality-api.open-meteo.com/v1/air-quality",
            params={
                "latitude": 43.39, "longitude": -87.88,
                "current": "us_aqi,pm10,pm2_5,carbon_monoxide,nitrogen_dioxide,ozone,dust",
                "domains": "cams_global"
            }, timeout=10)
        d = r.json().get("current", {})
        aqi = d.get("us_aqi", 0)
        if aqi <= 50:    cat, color = "Good", "#4caf50"
        elif aqi <= 100: cat, color = "Moderate", "#ffeb3b"
        elif aqi <= 150: cat, color = "Unhealthy (Sensitive)", "#ff9800"
        elif aqi <= 200: cat, color = "Unhealthy", "#f44336"
        elif aqi <= 300: cat, color = "Very Unhealthy", "#9c27b0"
        else:            cat, color = "Hazardous", "#7b0000"
        result = {
            "aqi": aqi, "category": cat, "color": color,
            "pm25": round(d.get("pm2_5", 0), 1),
            "pm10": round(d.get("pm10", 0), 1),
            "ozone": round(d.get("ozone", 0), 1),
            "no2": round(d.get("nitrogen_dioxide", 0), 1),
            "co": round(d.get("carbon_monoxide", 0), 0),
            "time": d.get("time",""),
            "fetched": datetime.datetime.now().strftime("%H:%M:%S")
        }
        cache_set("airnow", result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e), "aqi": 0, "category": "Unavailable"})

@app.route("/api/wildfires")
@login_required
def api_wildfires():
    force = request.args.get("force") == "1"
    cached = cache_get("wildfires", ttl=10800, force=force)
    if cached:
        return jsonify(cached)
    try:
        # NIFC WFIGS — active wildfire incident locations (IRWIN)
        r = requests.get(
            "https://services3.arcgis.com/T4QMspbfLg3qTGWY/arcgis/rest/services"
            "/WFIGS_Incident_Locations_Current/FeatureServer/0/query",
            params={
                "where": "IncidentTypeCategory='WF' AND IncidentSize>100",
                "outFields": "IncidentName,IncidentSize,PercentContained,POOState,POOCounty,"
                             "FireDiscoveryDateTime,TotalIncidentPersonnel",
                "orderByFields": "IncidentSize DESC",
                "resultRecordCount": 20,
                "f": "json"
            }, timeout=15)
        fires = []
        for feat in r.json().get("features", []):
            a = feat.get("attributes", {})
            ts = a.get("FireDiscoveryDateTime")
            discovered = ""
            if ts:
                try:
                    discovered = datetime.datetime.fromtimestamp(ts / 1000).strftime("%b %d")
                except: pass
            contained = a.get("PercentContained")
            fires.append({
                "name":       a.get("IncidentName", "Unknown"),
                "acres":      round(a.get("IncidentSize", 0) or 0),
                "contained":  int(contained) if contained is not None else None,
                "state":      (a.get("POOState") or "").replace("US-", ""),
                "county":     a.get("POOCounty") or "",
                "personnel":  a.get("TotalIncidentPersonnel") or 0,
                "discovered": discovered,
            })
        result = {"fires": fires, "fetched": datetime.datetime.now().strftime("%H:%M:%S")}
        cache_set("wildfires", result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e), "fires": []})

@app.route("/api/swpc")
@login_required
def api_swpc():
    force = request.args.get("force") == "1"
    cached = cache_get("swpc", ttl=CACHE_TTL_DAY, force=force)
    if cached:
        return jsonify(cached)
    result = {"kp": None, "solar_wind": {}, "alerts": [], "fetched": datetime.datetime.now().strftime("%H:%M:%S")}
    try:
        # Kp index (1-minute)
        r = requests.get("https://services.swpc.noaa.gov/json/planetary_k_index_1m.json", timeout=10)
        kp_data = r.json()
        recent = [d for d in kp_data if d.get("estimated_kp") is not None]
        if recent:
            latest = recent[-1]
            kp = latest.get("estimated_kp", 0)
            result["kp"] = round(kp, 2)
            result["kp_tag"] = latest.get("kp","")
            if kp < 4:   result["kp_label"], result["kp_color"] = "Quiet", "#4caf50"
            elif kp < 5: result["kp_label"], result["kp_color"] = "Active", "#ffeb3b"
            elif kp < 6: result["kp_label"], result["kp_color"] = "G1 — Minor Storm", "#ff9800"
            elif kp < 7: result["kp_label"], result["kp_color"] = "G2 — Moderate Storm", "#ff5722"
            elif kp < 8: result["kp_label"], result["kp_color"] = "G3 — Strong Storm", "#f44336"
            elif kp < 9: result["kp_label"], result["kp_color"] = "G4 — Severe Storm", "#9c27b0"
            else:        result["kp_label"], result["kp_color"] = "G5 — EXTREME STORM", "#cc0000"
    except: pass
    try:
        # Solar wind (proton speed, density, temp) — active source
        r = requests.get("https://services.swpc.noaa.gov/json/rtsw/rtsw_wind_1m.json", timeout=10)
        wind_data = r.json()
        active = [d for d in reversed(wind_data) if d.get("active") and d.get("proton_speed")]
        if active:
            w = active[0]
            result["solar_wind"] = {
                "speed_kms": round(w["proton_speed"], 0),
                "density": round(w.get("proton_density") or 0, 2),
                "temp_K": int(w.get("proton_temperature") or 0),
                "source": w.get("source",""),
                "time": w.get("time_tag","")[:16].replace("T"," ")
            }
    except: pass
    try:
        # Bz (southward = storm driver)
        r = requests.get("https://services.swpc.noaa.gov/json/rtsw/rtsw_mag_1m.json", timeout=10)
        mag_data = r.json()
        active_mag = [d for d in reversed(mag_data) if d.get("active") and d.get("bz_gsm") is not None]
        if active_mag:
            m = active_mag[0]
            result["solar_wind"]["bz_gsm"] = round(m["bz_gsm"], 2)
            result["solar_wind"]["bt"] = round(m.get("bt") or 0, 2)
    except: pass
    try:
        # SANS ISC diary RSS feed
        f = feedparser.parse("https://isc.sans.edu/rssfeed_full.xml")
        result["sans_isc"] = [{"title": e.get("title",""), "link": e.get("link","#"),
                                "summary": re.sub(r"<[^>]+>","",e.get("summary",""))[:300],
                                "published": e.get("published","")[:25]}
                               for e in f.entries[:8]]
    except: result["sans_isc"] = []
    try:
        # Krebs on Security RSS
        f = feedparser.parse("https://krebsonsecurity.com/feed/")
        result["krebs"] = [{"title": e.get("title",""), "link": e.get("link","#"),
                             "summary": re.sub(r"<[^>]+>","",e.get("summary",""))[:300],
                             "published": e.get("published","")[:25]}
                            for e in f.entries[:8]]
    except: result["krebs"] = []
    try:
        # BleepingComputer — use requests to bypass feedparser UA block
        _bc_ua = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
        _bc_r = requests.get("https://www.bleepingcomputer.com/feed/", timeout=15, headers={"User-Agent": _bc_ua})
        _bc_f = feedparser.parse(_bc_r.content)
        result["bleeping"] = [{"title": e.get("title",""), "link": e.get("link","#"),
                                "summary": re.sub(r"<[^>]+>","",e.get("summary",""))[:200],
                                "published": e.get("published","")[:25]}
                               for e in _bc_f.entries[:8]]
    except: result["bleeping"] = []
    try:
        # The Hacker News RSS
        _thn_r = requests.get("https://feeds.feedburner.com/TheHackersNews", timeout=15, headers={"User-Agent": _bc_ua})
        _thn_f = feedparser.parse(_thn_r.content)
        result["thn"] = [{"title": e.get("title",""), "link": e.get("link","#"),
                           "summary": re.sub(r"<[^>]+>","",e.get("summary",""))[:200],
                           "published": e.get("published","")[:25]}
                          for e in _thn_f.entries[:8]]
    except: result["thn"] = []
    try:
        # X-ray flux → flare class + R-scale (radio blackout)
        r = requests.get("https://services.swpc.noaa.gov/json/goes/primary/xrays-1-minute.json", timeout=10)
        xray_data = r.json()
        long_wave = [d for d in reversed(xray_data) if d.get("energy") == "0.1-0.8nm" and d.get("flux") is not None]
        if long_wave:
            flux = long_wave[0]["flux"]
            result["xray_flux"] = flux
            result["xray_time"] = long_wave[0].get("time_tag","")[:16].replace("T"," ")
            if   flux >= 1e-3: fc, r_scale = "X10+", "R3+"
            elif flux >= 1e-4: fc, r_scale = f"X{flux/1e-4:.1f}", "R3"
            elif flux >= 1e-5: fc, r_scale = f"M{flux/1e-5:.1f}", "R2"
            elif flux >= 1e-6: fc, r_scale = f"C{flux/1e-6:.1f}", "R1"
            elif flux >= 1e-7: fc, r_scale = f"B{flux/1e-7:.1f}", "R0"
            else:              fc, r_scale = f"A{flux/1e-8:.1f}", "R0"
            result["flare_class"] = fc
            result["r_scale"] = r_scale
            result["r_color"] = "#f44336" if r_scale.startswith("R3") else "#ff9800" if r_scale in ("R1","R2") else "#4caf50"
    except: pass
    try:
        # Proton flux → S-scale (radiation storm)
        r = requests.get("https://services.swpc.noaa.gov/json/goes/primary/integral-protons-1-minute.json", timeout=10)
        proton_data = r.json()
        p10 = [d for d in reversed(proton_data) if d.get("energy") == ">=10 MeV" and d.get("flux") is not None]
        if p10:
            pf = p10[0]["flux"]
            result["proton_flux"] = round(pf, 2)
            result["proton_time"] = p10[0].get("time_tag","")[:16].replace("T"," ")
            if   pf >= 1e5: s_scale, s_color = "S5", "#cc0000"
            elif pf >= 1e4: s_scale, s_color = "S4", "#9c27b0"
            elif pf >= 1e3: s_scale, s_color = "S3", "#f44336"
            elif pf >= 1e2: s_scale, s_color = "S2", "#ff5722"
            elif pf >= 10:  s_scale, s_color = "S1", "#ff9800"
            else:           s_scale, s_color = "S0", "#4caf50"
            result["s_scale"] = s_scale
            result["s_color"] = s_color
    except: pass
    try:
        # Sunspot number (latest observed)
        r = requests.get("https://services.swpc.noaa.gov/json/solar-cycle/observed-solar-cycle-indices.json", timeout=10)
        sc_data = r.json()
        latest_sc = [d for d in sc_data if d.get("ssn") is not None]
        if latest_sc:
            last = latest_sc[-1]
            result["sunspot_number"] = last.get("ssn")
            result["sunspot_month"] = last.get("time-tag","")[:7]
    except: pass
    try:
        # Active space weather alerts
        r = requests.get("https://services.swpc.noaa.gov/products/alerts.json", timeout=10)
        for alert in r.json()[:8]:
            msg = alert.get("message","").replace("\r\n","\n")
            lines = msg.split("\n")
            keywords = ("ALERT:","WARNING:","WATCH:","EXTENDED WARNING:","SUMMARY:","CANCEL WATCH:")
            title = next((l.strip() for l in lines if any(l.strip().startswith(k) for k in keywords)), "")
            if not title:
                title = next((l.strip() for l in lines[3:8] if l.strip()), "")
            result["alerts"].append({
                "title": title,
                "issued": alert.get("issue_datetime","")[:16],
                "full": msg[:600],
            })
    except: pass
    try:
        # 3-day forecast: max Kp, rationale, storm probabilities
        r = requests.get("https://services.swpc.noaa.gov/text/3-day-forecast.txt", timeout=10)
        txt = r.text
        issued_m = re.search(r":Issued:\s*(.+)", txt)
        result["forecast_issued"] = issued_m.group(1).strip() if issued_m else ""
        max_kp_m = re.search(r"greatest expected 3 hr Kp.*?is\s+([\d.]+)\s*\(NOAA Scale\s+(\w+)\)", txt, re.IGNORECASE)
        result["forecast_max_kp"] = max_kp_m.group(1) if max_kp_m else ""
        result["forecast_max_scale"] = max_kp_m.group(2) if max_kp_m else ""
        rat_m = re.search(r"Rationale:\s*(.+?)(?:\n\n|\Z)", txt, re.DOTALL)
        result["forecast_rationale"] = rat_m.group(1).strip().replace("\n"," ") if rat_m else ""
        scale = result.get("forecast_max_scale","")
        if scale in ("G3","G4","G5"): result["forecast_color"] = "#f44336"
        elif scale in ("G1","G2"):   result["forecast_color"] = "#ff9800"
        else:                        result["forecast_color"] = "#4caf50"
        # Storm probabilities — extract Day 1 middle latitudes line
        prob_m = re.search(r"Day 1[^\n]*\n\s*([\d]+)%\s+([\d]+)%\s+([\d]+)%\s+([\d]+)%", txt)
        if prob_m:
            result["storm_prob"] = {
                "active": prob_m.group(1), "g1": prob_m.group(2),
                "g2": prob_m.group(3),     "g3plus": prob_m.group(4)
            }
    except: pass
    try:
        # 27-day outlook for solar flux (F10.7) and geomagnetic Ap
        r = requests.get("https://services.swpc.noaa.gov/text/27-day-outlook.txt", timeout=10)
        lines = [l for l in r.text.splitlines() if re.match(r"^\d{4}\s", l.strip())]
        if lines:
            parts = lines[0].split()
            result["f107"] = parts[3] if len(parts) > 3 else None
            result["ap_index"] = parts[4] if len(parts) > 4 else None
    except: pass
    cache_set("swpc", result)
    return jsonify(result)

@app.route("/api/wikipedia")
@login_required
def api_wikipedia():
    force = request.args.get("force") == "1"
    cached = cache_get("wikipedia", CACHE_TTL_LONG, force=force)
    if cached:
        return jsonify(cached)
    today = datetime.date.today()
    mm = today.strftime("%m")
    dd = today.strftime("%d")
    hdrs = HDRS
    result = {"tfa": {}, "dyk": [], "news": [], "onthisday": [],
              "date": today.strftime("%B %d, %Y"),
              "fetched": _ts()}
    last_exc = None
    for attempt in range(3):
        try:
            r = requests.get(
                f"https://en.wikipedia.org/api/rest_v1/feed/featured/{today.year}/{mm}/{dd}",
                headers=hdrs, timeout=15)
            r.raise_for_status()
            d = r.json()

            # Today's Featured Article
            tfa = d.get("tfa", {})
            result["tfa"] = {
                "title": tfa.get("normalizedtitle", tfa.get("title","")),
                "extract": tfa.get("extract","")[:600],
                "thumbnail": (tfa.get("thumbnail") or {}).get("source",""),
                "url": (tfa.get("content_urls",{}).get("desktop",{}) or {}).get("page","#"),
            }

            # Did You Know
            result["dyk"] = []
            for item in d.get("dyk", [])[:6]:
                text = item.get("text","") if isinstance(item, dict) else str(item)
                text = re.sub(r"<[^>]+>", "", text).strip()
                if text:
                    result["dyk"].append(text[:280])

            # In the News
            result["news"] = []
            for item in d.get("news", [])[:6]:
                raw = item.get("story","")
                text = re.sub(r"<!--.*?-->", "", raw, flags=re.DOTALL)
                text = re.sub(r"<[^>]+>", "", text).strip()
                links = re.findall(r'href="\.\/([^"]+)"', raw)
                full_links = re.findall(r'href="(https://en\.wikipedia\.org/wiki/[^"]+)"', raw)
                url = full_links[0] if full_links else (
                      f"https://en.wikipedia.org/wiki/{links[0]}" if links else "#")
                result["news"].append({"text": text[:280], "url": url})

            # On This Day
            result["onthisday"] = []
            for item in d.get("onthisday", [])[:14]:
                pages = item.get("pages", [])
                url = (pages[0].get("content_urls",{}).get("desktop",{}) or {}).get("page","#") if pages else "#"
                result["onthisday"].append({
                    "year": item.get("year",""),
                    "text": item.get("text","")[:220],
                    "url": url,
                })
            last_exc = None
            break  # success
        except Exception as e:
            last_exc = e
            if attempt < 2:
                time.sleep(2 * (attempt + 1))

    if last_exc:
        # Return stale disk cache if available rather than an error
        stale = None
        try:
            with open(_disk_path("wikipedia")) as f:
                stale = json.load(f)
        except Exception:
            pass
        if stale and stale.get("tfa"):
            stale["stale"] = True
            return jsonify(stale)
        result["error"] = str(last_exc)
    else:
        cache_set("wikipedia", result)
    return jsonify(result)

@app.route("/api/apod")
@login_required
def api_apod():
    force = request.args.get("force") == "1"
    # Try memory/disk cache first (86400s = 24hr)
    cached = cache_get("apod", CACHE_TTL_DAY, force=force)
    if cached and cached.get("title"):
        return jsonify(cached)
    try:
        r = requests.get("https://api.nasa.gov/planetary/apod",
                         params={"api_key": NASA_API_KEY}, timeout=12)
        d = r.json()
        # NASA returns an error dict when rate-limited — don't cache that
        if "error" in d:
            # Return stale disk cache if we have it, even if expired
            path = _disk_path("apod")
            try:
                with open(path) as f:
                    entry = json.load(f)
                stale = entry.get("_data", {})
                if stale.get("title"):
                    stale["_stale"] = True
                    return jsonify(stale)
            except: pass
            return jsonify({"error": "NASA DEMO_KEY rate limit reached — try again later",
                            "apod_url": "https://apod.nasa.gov/apod/astropix.html"})
        result = {
            "title":      d.get("title",""),
            "date":       d.get("date",""),
            "explanation":d.get("explanation","")[:600],
            "url":        d.get("url",""),
            "hdurl":      d.get("hdurl", d.get("url","")),
            "media_type": d.get("media_type","image"),
            "copyright":  d.get("copyright","NASA"),
            "fetched":    datetime.datetime.now().strftime("%H:%M:%S")
        }
        cache_set("apod", result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e), "apod_url": "https://apod.nasa.gov/apod/astropix.html"})

@app.route("/api/earthquakes")
@login_required
def api_earthquakes():
    force = request.args.get("force") == "1"
    cached = cache_get("quakes", ttl=CACHE_TTL_DAY, force=force)
    if cached:
        return jsonify(cached)
    try:
        data = requests.get(
            "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/significant_week.geojson",
            timeout=10).json()
        import zoneinfo
        central = zoneinfo.ZoneInfo("America/Chicago")
        def _fmt_quake_time(ms):
            dt_utc = datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc)
            dt_ct  = dt_utc.astimezone(central)
            ampm   = dt_ct.strftime("%I:%M %p").lstrip("0")
            return dt_ct.strftime("%Y-%m-%d ") + ampm + " CT"
        quakes = [{"place": f["properties"].get("place",""),
                   "mag": f["properties"].get("mag",0),
                   "time": _fmt_quake_time(f["properties"]["time"]),
                   "url": f["properties"].get("url","#")}
                  for f in data.get("features",[])[:10]]
        result = {"earthquakes": quakes, "fetched": datetime.datetime.now().strftime("%H:%M:%S")}
        cache_set("quakes", result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e), "earthquakes": []})

@app.route("/api/gdacs")
@login_required
def api_gdacs():
    """GDACS — Global Disaster Alert and Coordination System."""
    force = request.args.get("force") == "1"
    cached = cache_get("gdacs", ttl=3600, force=force)
    if cached:
        return jsonify(cached)
    try:
        hdrs = HDRS
        f = feedparser.parse("https://www.gdacs.org/xml/rss.xml")
        events = []
        for e in f.entries[:20]:
            title = e.get("title", "")
            link  = e.get("link", "#")
            pub   = e.get("published", "")[:10]
            # GDACS uses custom tags: gdacs:alertlevel, gdacs:eventtype, gdacs:country
            alert   = getattr(e, "gdacs_alertlevel", None) or e.get("gdacs_alertlevel", "")
            evtype  = getattr(e, "gdacs_eventtype",  None) or e.get("gdacs_eventtype",  "")
            country = getattr(e, "gdacs_country",    None) or e.get("gdacs_country",    "")
            # Fallback: parse from title
            if not evtype:
                for kw in ["Earthquake","Tropical Cyclone","Flood","Volcano","Drought","Wildfire"]:
                    if kw.lower() in title.lower():
                        evtype = kw; break
            icon = {"Earthquake":"🌍","Tropical Cyclone":"🌀","Flood":"🌊",
                    "Volcano":"🌋","Drought":"🏜","Wildfire":"🔥"}.get(evtype,"⚠")
            color = {"Red":"#cc3333","Orange":"#cc7700","Green":"#4a9c4a"}.get(alert,"#888")
            events.append({"title":title,"link":link,"date":pub,"alert":alert,
                           "type":evtype,"country":country,"icon":icon,"color":color})
        result = {"events": events, "fetched": _ts()}
        cache_set("gdacs", result)
        return jsonify(result)
    except Exception as ex:
        return jsonify({"error": str(ex), "events": []})


@app.route("/api/server_stats")
@login_required
def api_server_stats():
    force = request.args.get("force") == "1"
    cached = cache_get("server_stats", ttl=15, force=force)
    if cached:
        return jsonify(cached)
    try:
        free_out = subprocess.run(["free","-m"], capture_output=True, text=True).stdout.split("\n")
        mem  = free_out[1].split()
        swap = free_out[2].split() if len(free_out) > 2 else []
        disk = subprocess.run(["df","-h","/mnt/hdd"], capture_output=True, text=True
                              ).stdout.split("\n")[1].split()
        load = open("/proc/loadavg").read().split()[:3]
        uptime = subprocess.run(["uptime","-p"], capture_output=True, text=True).stdout.strip()
        # Read CPU from /proc/stat (two samples 200ms apart) — avoids spawning top
        def _cpu_pct():
            def _read():
                with open("/proc/stat") as f:
                    return [int(x) for x in f.readline().split()[1:]]
            s1 = _read(); time.sleep(0.2); s2 = _read()
            d = [b - a for a, b in zip(s1, s2)]
            idle = d[3]; total = sum(d)
            return round((1 - idle / total) * 100, 1) if total else 0
        cpu_pct = _cpu_pct()
        # Batch all service checks into one subprocess call
        svc_names = ["jellyfin", "librarian-bot",
                     "reminder-bot", "kevsec-dashboard", "presidential-sim",
                     "honeypot", "endlessh", "fail2ban", "sonarr", "radarr", "prowlarr", "nginx",
                     "dj-atticus"]
        sr = subprocess.run(["systemctl", "is-active"] + svc_names,
                            capture_output=True, text=True)
        statuses = sr.stdout.strip().split("\n")
        svcs = {s: (statuses[i] if i < len(statuses) else "unknown")
                for i, s in enumerate(svc_names)}
        result = {
            "cpu": cpu_pct,
            "mem_used": int(mem[2]), "mem_total": int(mem[1]),
            "mem_pct": round(int(mem[2])/int(mem[1])*100, 1),
            "disk_used": disk[2] if len(disk)>2 else "?",
            "disk_total": disk[1] if len(disk)>1 else "?",
            "disk_pct": disk[4].replace("%","") if len(disk)>4 else "0",
            "uptime": uptime, "load": load, "services": svcs,
            "ts": datetime.datetime.now().strftime("%H:%M:%S")
        }
        if len(swap) >= 3:
            swap_used  = int(swap[2])
            swap_total = int(swap[1])
            result["swap_used"]  = swap_used
            result["swap_total"] = swap_total
            result["swap_pct"]   = round(swap_used / swap_total * 100, 1) if swap_total else 0
        cache_set("server_stats", result)
        return jsonify(result)
    except Exception as e:
        app.logger.error("server_stats error: %s", e)
        return jsonify({"error": str(e)})

@app.route("/api/ext_services")
@login_required
def api_ext_services():
    """Check external service status via official Statuspage APIs + HTTP pings."""
    force = request.args.get("force") == "1"
    cached = cache_get("ext_services", ttl=300, force=force)  # 5-min cache
    if cached:
        return jsonify(cached)

    # Services with confirmed working Statuspage APIs
    STATUSPAGE_SERVICES = [
        ("GitHub",       "https://www.githubstatus.com/api/v2/summary.json"),
        ("Discord",      "https://discordstatus.com/api/v2/summary.json"),
        ("Cloudflare",   "https://www.cloudflarestatus.com/api/v2/summary.json"),
        ("Reddit",       "https://www.redditstatus.com/api/v2/summary.json"),
        ("Zoom",         "https://status.zoom.us/api/v2/summary.json"),
    ]

    # Services to check via simple HTTP GET (2xx/3xx = up)
    PING_SERVICES = [
        ("Netflix",      "https://www.netflix.com/"),
        ("YouTube",      "https://www.youtube.com/"),
        ("Steam",        "https://store.steampowered.com/"),
        ("Spectrum",     "https://www.spectrum.com/"),
        ("Google",       "https://www.google.com/"),
        ("Twitch",       "https://www.twitch.tv/"),
        ("Slack",        "https://slack.com/"),
        ("Dropbox",      "https://www.dropbox.com/"),
        ("GitHub.com",   "https://github.com/"),
        ("Twitter/X",    "https://x.com/"),
        ("OpenAI",       "https://openai.com/"),
        ("Amazon",       "https://www.amazon.com/"),
        ("Spotify",      "https://www.spotify.com/"),
        ("Snapchat",     "https://www.snapchat.com/"),
        ("Hulu",         "https://www.hulu.com/"),
        ("Steam",        "https://store.steampowered.com/"),
        ("CS2 Servers",  "https://www.valvesoftware.com/en/"),
    ]

    results = []
    hdrs = HDRS

    def indicator_to_status(ind):
        return {"none": "operational", "minor": "degraded",
                "major": "outage", "critical": "outage"}.get(ind, "unknown")

    for name, url in STATUSPAGE_SERVICES:
        try:
            r = requests.get(url, headers=hdrs, timeout=6)
            ind = r.json().get("status", {}).get("indicator", "unknown")
            desc = r.json().get("status", {}).get("description", "")
            results.append({"name": name, "status": indicator_to_status(ind),
                            "indicator": ind, "desc": desc})
        except Exception:
            results.append({"name": name, "status": "unknown", "indicator": "unknown", "desc": ""})

    for name, url in PING_SERVICES:
        try:
            r = requests.get(url, headers=hdrs, timeout=6, allow_redirects=True)
            ok = r.status_code < 400
            results.append({"name": name, "status": "operational" if ok else "degraded",
                            "indicator": "none" if ok else "minor", "desc": f"HTTP {r.status_code}"})
        except Exception as e:
            results.append({"name": name, "status": "outage", "indicator": "major",
                            "desc": str(e)[:60]})

    # ── Local service uptime check (systemd) ────────────────────────────
    LOCAL_SERVICES = [
        ("Jellyfin",       "jellyfin"),
        ("Librarian Bot",  "librarian-bot"),
        ("Reminder Bot",   "reminder-bot"),
        ("Dashboard",      "kevsec-dashboard"),
        ("Pres. Sim",      "presidential-sim"),
        ("Nginx",          "nginx"),
        ("Sonarr",         "sonarr"),
        ("Radarr",         "radarr"),
        ("Fail2ban",       "fail2ban"),
        ("Honeypot",       "honeypot"),
        ("Endlessh",       "endlessh"),
    ]
    local_results = []
    for display_name, svc in LOCAL_SERVICES:
        try:
            out = subprocess.run(["systemctl", "is-active", svc],
                                 capture_output=True, text=True, timeout=3).stdout.strip()
            up = out == "active"
            local_results.append({
                "name": display_name, "service": svc,
                "status": "operational" if up else "outage",
                "indicator": "none" if up else "major",
                "desc": out, "local": True
            })
        except Exception as ex:
            local_results.append({
                "name": display_name, "service": svc,
                "status": "unknown", "indicator": "unknown",
                "desc": str(ex)[:40], "local": True
            })

    result = {"services": results, "local": local_results,
              "fetched": datetime.datetime.now().strftime("%H:%M:%S")}
    cache_set("ext_services", result)
    return jsonify(result)

@app.route("/api/proxmox")
@login_required
def api_proxmox():
    cached = cache_get("proxmox")
    if cached:
        return jsonify(cached)
    try:
        hdrs = pve_auth()
        nodes = requests.get(f"{PROXMOX}/nodes", headers=hdrs,
                             verify=False, timeout=5).json().get("data",[])
        vms = []
        for node in nodes:
            n = node["node"]
            for vm in requests.get(f"{PROXMOX}/nodes/{n}/qemu", headers=hdrs,
                                   verify=False, timeout=5).json().get("data",[]):
                vms.append({"vmid": vm["vmid"], "name": vm.get("name","?"),
                             "status": vm.get("status","?"), "node": n,
                             "mem": vm.get("mem",0), "maxmem": vm.get("maxmem",0),
                             "cpu": round(vm.get("cpu",0)*100, 1)})
        result = {"nodes": [{"node": n["node"], "mem": n.get("mem",0),
                              "maxmem": n.get("maxmem",0),
                              "cpu": round(n.get("cpu",0)*100,1)} for n in nodes],
                  "vms": vms, "fetched": datetime.datetime.now().strftime("%H:%M:%S")}
        cache_set("proxmox", result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e), "nodes":[], "vms":[]})

_updates_cache = {"data": None, "ts": 0, "running": False}

def _fetch_updates_bg():
    if _updates_cache["running"]:
        return
    _updates_cache["running"] = True
    try:
        r = subprocess.run(["apt", "list", "--upgradable", "--no-all-versions"],
                           capture_output=True, text=True, timeout=30)
        pkgs = [l.split("/")[0] for l in r.stdout.strip().split("\n") if "/" in l]
        _updates_cache["data"] = {"updates": pkgs, "count": len(pkgs),
                                  "fetched": datetime.datetime.now().strftime("%H:%M:%S")}
        _updates_cache["ts"] = time.time()
    except Exception as e:
        _updates_cache["data"] = {"error": str(e), "updates": [], "count": 0}
    finally:
        _updates_cache["running"] = False

@app.route("/api/tarpit_stats")
@login_required
def api_tarpit_stats():
    """Endlessh SSH tarpit stats + honeypot access.log summary."""
    force = request.args.get("force") == "1"
    cached = cache_get("tarpit_stats", ttl=60, force=force)
    if cached:
        return jsonify(cached)
    result = {
        "accepts": 0, "closes": 0, "unique_ips": 0,
        "total_seconds": 0, "weekly_seconds": 0, "tarpit_log": [],
        "honeypot_hits": 0, "honeypot_bans": 0, "permanent_bans": 0,
        "honeypot_log": [],
        "fetched": _ts()
    }

    def clean_ip(raw):
        """Strip ::ffff: prefix from IPv4-mapped IPv6 addresses."""
        return raw.replace("::ffff:", "") if raw else raw

    # ── Endlessh journal ────────────────────────────────────
    try:
        r = subprocess.run(
            ["journalctl", "-u", "endlessh", "--no-pager", "-n", "2000", "--output=cat"],
            capture_output=True, text=True, timeout=10
        )
        lines = r.stdout.splitlines()
        accepts = [l for l in lines if "ACCEPT" in l]
        closes  = [l for l in lines if "CLOSE"  in l]
        unique_ips = set()
        total_secs = 0
        close_map = {}  # (host,port) -> seconds trapped

        for l in closes:
            mh = re.search(r"host=([\d.a-f:]+)", l)
            mp = re.search(r"port=(\d+)", l)
            mt = re.search(r"time=([\d.]+)", l)
            if mh and mt:
                ip = clean_ip(mh.group(1))
                secs = float(mt.group(1))
                total_secs += secs
                key = (ip, mp.group(1) if mp else "")
                close_map[key] = secs

        # Build tarpit_log from accepts (most recent 20)
        tarpit_log = []
        seen_in_log = set()
        for l in reversed(accepts):
            mh = re.search(r"host=([\d.a-f:]+)", l)
            mp = re.search(r"port=(\d+)", l)
            mt = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", l)
            if mh:
                ip = clean_ip(mh.group(1))
                unique_ips.add(ip)
                port = mp.group(1) if mp else ""
                secs = close_map.get((ip, port))
                ts = mt.group(1).replace("T", " ") if mt else ""
                entry = {"ip": ip, "port": port, "ts": ts,
                         "seconds": round(secs) if secs else None}
                tarpit_log.append(entry)
                if len(tarpit_log) >= 20:
                    break

        # Also collect unique IPs from closes
        for l in closes:
            m = re.search(r"host=([\d.a-f:]+)", l)
            if m:
                unique_ips.add(clean_ip(m.group(1)))

        week_offset = get_tarpit_week_offset()
        result.update({
            "accepts": len(accepts), "closes": len(closes),
            "unique_ips": len(unique_ips),
            "total_seconds": int(total_secs),
            "weekly_seconds": max(0, int(total_secs) - int(week_offset)),
            "tarpit_log": tarpit_log,
        })
    except Exception as e:
        app.logger.warning("tarpit_stats journal error: %s", e)

    # ── Honeypot access.log ─────────────────────────────────
    try:
        with open("/var/log/honeypot/access.log") as f:
            access_lines = f.readlines()
        honeypot_log = []
        hp_unique = set()
        bans = 0
        for l in reversed(access_lines):
            parts = [p.strip() for p in l.split("|")]
            if len(parts) < 4:
                continue
            ts, event, ip, path = parts[0], parts[1], parts[2], parts[3]
            ip = clean_ip(ip)
            if ip in ("127.0.0.1", "::1", ""):
                continue
            hp_unique.add(ip)
            if event in ("TRAP_HIT", "TRAP_CREDS"):
                bans += 1
            if len(honeypot_log) < 20:
                honeypot_log.append({"ip": ip, "ts": ts, "path": path, "event": event})
        result.update({
            "honeypot_hits": len(access_lines),
            "honeypot_bans": bans,
            "honeypot_unique_ips": len(hp_unique),
            "honeypot_log": honeypot_log,
        })
    except Exception as e:
        app.logger.warning("tarpit_stats access.log error: %s", e)

    # ── Permanent bans log ──────────────────────────────────
    try:
        with open("/var/log/honeypot/permanent_bans.log") as f:
            result["permanent_bans"] = sum(1 for l in f if l.strip())
    except Exception:
        result["permanent_bans"] = 0

    cache_set("tarpit_stats", result)
    return jsonify(result)

@app.route("/api/pending_updates")
@login_required
def api_pending_updates():
    age = time.time() - _updates_cache["ts"]
    if _updates_cache["data"] and age < 1800:          # serve cache if < 30 min old
        return jsonify(_updates_cache["data"])
    threading.Thread(target=_fetch_updates_bg, daemon=True).start()
    if _updates_cache["data"]:                         # return stale while refreshing
        return jsonify({**_updates_cache["data"], "_stale": True})
    return jsonify({"updates": [], "count": 0, "_pending": True})

@app.route("/api/firewall_drops")
@login_required
def api_firewall_drops():
    force = request.args.get("force") == "1"
    cached = cache_get("firewall_drops", ttl=60, force=force)
    if cached:
        return jsonify(cached)
    events = []
    # Honeypot probe catches (replaces empty UFW log — server uses nftables, not UFW)
    try:
        r = subprocess.run(["sudo","tail","-n","400","/var/log/honeypot/access.log"],
                           capture_output=True, text=True)
        seen = set()
        for line in r.stdout.split("\n"):
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 4:
                continue
            ip = parts[2].strip() if len(parts) > 2 else ""
            if not ip or ip in seen:
                continue
            seen.add(ip)
            ts_str = parts[0][:16] if parts[0] else ""  # "2026-04-29 07:09"
            path   = parts[3][:40] if len(parts) > 3 else ""
            events.append({
                "time":   ts_str[5:] if len(ts_str) >= 5 else ts_str,
                "src":    ip,
                "port":   "80/443",
                "proto":  parts[1] if len(parts) > 1 else "",
                "source": "HONEYPOT"
            })
    except: pass
    # Fail2ban — get currently banned IPs from all jails via fail2ban-client
    try:
        jails_r = subprocess.run(["sudo","fail2ban-client","status"],
                                 capture_output=True, text=True, timeout=10)
        jail_line = re.search(r"Jail list:\s*(.+)", jails_r.stdout)
        jails = [j.strip() for j in jail_line.group(1).split(",")] if jail_line else []
        for jail in jails:
            st = subprocess.run(["sudo","fail2ban-client","status", jail],
                                capture_output=True, text=True, timeout=10)
            ip_line = re.search(r"Banned IP list:\s*(.+)", st.stdout)
            total_m = re.search(r"Total banned:\s*(\d+)", st.stdout)
            banned_ips = ip_line.group(1).split() if ip_line else []
            for ip_addr in banned_ips[:20]:
                events.append({
                    "time":   "",
                    "src":    ip_addr,
                    "port":   "",
                    "proto":  "",
                    "source": f"f2b/{jail}",
                    "total":  int(total_m.group(1)) if total_m else 0
                })
    except Exception as e:
        app.logger.warning("fail2ban-client status error: %s", e)
        # Fallback: parse log file
        try:
            r = subprocess.run(["tail","-n","2000","/var/log/fail2ban.log"],
                               capture_output=True, text=True)
            for line in r.stdout.split("\n"):
                if "NOTICE" not in line or " Ban " not in line:
                    continue
                ts   = re.search(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                jail = re.search(r"\[(\w[\w-]*)\] Ban", line)
                ip_m = re.search(r"Ban (\S+)", line)
                if not ip_m: continue
                events.append({
                    "time":   ts.group(1)[5:] if ts else "",
                    "src":    ip_m.group(1),
                    "port":   "",
                    "proto":  "",
                    "source": "f2b/" + jail.group(1) if jail else "fail2ban"
                })
        except: pass
    ufw_events = [e for e in events if e["source"] == "HONEYPOT"]
    f2b_events = [e for e in events if e["source"] != "HONEYPOT"]
    ufw_events.sort(key=lambda x: x["time"], reverse=True)
    f2b_events.sort(key=lambda x: x["time"], reverse=True)
    ufw_top = ufw_events[:50]
    f2b_top = f2b_events[:30]

    # AbuseIPDB enrichment — batch unique IPs
    if ABUSEIPDB_KEY:
        unique_ips = list({e["src"] for e in ufw_top + f2b_top if e.get("src")})[:30]
        abuse_map = {}
        for ip in unique_ips:
            cached = cache_get(f"abuse_{ip}", ttl=3600)
            if cached:
                abuse_map[ip] = cached
                continue
            try:
                ar = requests.get("https://api.abuseipdb.com/api/v2/check",
                                  params={"ipAddress": ip, "maxAgeInDays": 30},
                                  headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                                  timeout=5)
                d = ar.json().get("data", {})
                info = {"score": d.get("abuseConfidenceScore", 0),
                        "country": d.get("countryCode", "??"),
                        "domain": d.get("domain", ""),
                        "isp": d.get("isp", "")}
                cache_set(f"abuse_{ip}", info)
                abuse_map[ip] = info
            except: pass
        for e in ufw_top + f2b_top:
            e["abuse"] = abuse_map.get(e.get("src"), None)

    result = {
        "drops":   ufw_top,
        "f2b":     f2b_top,
        "fetched": datetime.datetime.now().strftime("%H:%M:%S"),
        "abuseipdb_enabled": bool(ABUSEIPDB_KEY)
    }
    cache_set("firewall_drops", result)
    return jsonify(result)

@app.route("/api/cves")
@login_required
def api_cves():
    force = request.args.get("force") == "1"
    cached = cache_get("cves", ttl=CACHE_TTL_LONG, force=force)
    if cached:
        return jsonify(cached)
    try:
        now = datetime.datetime.utcnow()
        pub_start = (now - datetime.timedelta(days=21)).strftime("%Y-%m-%dT00:00:00.000")
        pub_end   = now.strftime("%Y-%m-%dT23:59:59.999")
        base_params = {"pubStartDate": pub_start, "pubEndDate": pub_end}

        def _fetch_severity(sev, count=15):
            r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                             params={**base_params, "cvssV3Severity": sev, "resultsPerPage": count},
                             timeout=15)
            items = []
            for item in r.json().get("vulnerabilities", []):
                cve = item.get("cve", {})
                desc = cve.get("descriptions", [{}])[0].get("value", "")[:200]
                m = cve.get("metrics", {})
                score, severity = 0, sev
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if m.get(key):
                        score = m[key][0]["cvssData"]["baseScore"]
                        severity = m[key][0]["cvssData"].get("baseSeverity", sev)
                        break
                items.append({"id": cve.get("id", ""), "desc": desc,
                               "score": score, "severity": severity,
                               "published": cve.get("published", "")[:10],
                               "epss": None, "epss_pct": None})
            return items

        crit = _fetch_severity("CRITICAL", 10)
        high = _fetch_severity("HIGH", 15)
        # Recency-weighted sort: recent CVEs get a bonus so they surface over older ones
        for c in crit + high:
            try:
                pub = datetime.datetime.strptime(c["published"], "%Y-%m-%d")
                days_old = (now - pub).days
            except Exception:
                days_old = 21
            recency_bonus = 3.0 if days_old <= 3 else (2.0 if days_old <= 7 else (1.0 if days_old <= 14 else 0.0))
            c["_sort_score"] = c["score"] + recency_bonus
        seen = set()
        cves = []
        for c in sorted(crit + high, key=lambda x: x["_sort_score"], reverse=True):
            if c["id"] not in seen:
                seen.add(c["id"])
                cves.append(c)
        cves = cves[:20]

        # Enrich with EPSS scores (Exploit Prediction Scoring System)
        try:
            ids = ",".join(c["id"] for c in cves if c["id"])
            epss_r = requests.get("https://api.first.org/data/v1/epss",
                                  params={"cve": ids}, timeout=10)
            epss_map = {e["cve"]: e for e in epss_r.json().get("data", [])}
            for c in cves:
                if c["id"] in epss_map:
                    e = epss_map[c["id"]]
                    c["epss"]     = round(float(e.get("epss", 0)) * 100, 2)
                    c["epss_pct"] = round(float(e.get("percentile", 0)) * 100, 1)
        except: pass
        result = {"cves": cves, "fetched": datetime.datetime.now().strftime("%H:%M:%S")}
        cache_set("cves", result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e), "cves": []})

def deg_to_compass(deg):
    """Convert wind degrees to compass direction."""
    try:
        deg = float(deg)
    except:
        return "---"
    dirs = ["N","NNE","NE","ENE","E","ESE","SE","SSE",
            "S","SSW","SW","WSW","W","WNW","NW","NNW"]
    return dirs[round(deg / 22.5) % 16]

def ms_to_mph(v):
    try:
        return round(float(v) * 2.23694, 1)
    except:
        return None

def c_to_f(v):
    try:
        return round(float(v) * 9/5 + 32, 1)
    except:
        return None

def ndbc_parse(text, n_rows=12):
    """Parse NDBC realtime2 text, return list of dicts for the latest n_rows readings."""
    lines = [l for l in text.strip().split("\n") if l.strip()]
    if len(lines) < 3:
        return []
    headers = lines[0].replace("#","").split()
    rows = []
    for line in lines[2:2+n_rows]:
        parts = line.split()
        if len(parts) < len(headers):
            continue
        rows.append(dict(zip(headers, parts)))
    return rows

@app.route("/api/lake_michigan")
@login_required
def api_lake_michigan():
    force = request.args.get("force") == "1"
    cached = cache_get("lake", ttl=CACHE_TTL, force=force)
    if cached:
        return jsonify(cached)
    hdrs = HDRS
    result = {
        "pwaw3": {},
        "pwaw3_trend": [],
        "marine_text": "",
        "marine_sections": [],
        "afd_text": "",
        "afd_issued": "",
        "fetched": datetime.datetime.now().strftime("%H:%M:%S")
    }

    # ── PWAW3 — Port Washington Met Station ──────────────────────────────
    try:
        r = requests.get("https://www.ndbc.noaa.gov/data/realtime2/PWAW3.txt",
                         headers=hdrs, timeout=10)
        rows = ndbc_parse(r.text, n_rows=12)
        if rows:
            # Current = first valid reading
            cur = None
            for row in rows:
                if row.get("WSPD","MM") != "MM" or row.get("ATMP","MM") != "MM":
                    cur = row; break
            if not cur:
                cur = rows[0]

            wdir = cur.get("WDIR","MM")
            wspd = cur.get("WSPD","MM")
            gst  = cur.get("GST","MM")
            atmp = cur.get("ATMP","MM")
            pres = cur.get("PRES","MM")
            ptdy = cur.get("PTDY","MM")

            result["pwaw3"] = {
                "obs_time": f"{cur.get('YY','')} {cur.get('MM','')} {cur.get('DD','')} {cur.get('hh','')}:{cur.get('mm','')} UTC",
                "wind_dir_deg": wdir if wdir != "MM" else None,
                "wind_dir": deg_to_compass(wdir) if wdir != "MM" else "---",
                "wind_speed_mph": ms_to_mph(wspd) if wspd != "MM" else None,
                "wind_gust_mph": ms_to_mph(gst) if gst != "MM" else None,
                "air_temp_f": c_to_f(atmp) if atmp != "MM" else None,
                "pressure_mb": pres if pres != "MM" else None,
                "pressure_trend": ptdy if ptdy != "MM" else None,
            }

            # Trend: last 12 readings with timestamps
            trend = []
            for row in rows:
                wspd_v = row.get("WSPD","MM")
                gst_v  = row.get("GST","MM")
                wdir_v = row.get("WDIR","MM")
                trend.append({
                    "t":    f"{row.get('hh','?')}:{row.get('mm','?')}",
                    "wspd": ms_to_mph(wspd_v) if wspd_v != "MM" else None,
                    "gust": ms_to_mph(gst_v)  if gst_v  != "MM" else None,
                    "dir":  deg_to_compass(wdir_v) if wdir_v != "MM" else "---",
                    "atmp": c_to_f(row.get("ATMP","MM")) if row.get("ATMP","MM") != "MM" else None,
                })
            result["pwaw3_trend"] = trend
    except Exception as e:
        result["pwaw3_error"] = str(e)

    # ── NWS Nearshore Marine Forecast (NSH) — Full MKX text ──────────────────
    try:
        r = requests.get("https://api.weather.gov/products?type=NSH&location=MKX",
                         headers=hdrs, timeout=10)
        items = r.json().get("@graph", [])
        if items:
            prod = requests.get(items[0]["@id"], headers=hdrs, timeout=10).json()
            full_text = prod.get("productText", "")
            result["marine_text"] = full_text.strip()

            # Split into named sections for structured rendering
            # Zone headers look like: LMZ740-645-etc / description\n
            # Also capture the synopsis block before first zone
            sections = []
            # Find synopsis (text before first LMZ zone header)
            first_zone = re.search(r"(?m)^LMZ\d", full_text)
            if first_zone:
                synopsis = full_text[:first_zone.start()].strip()
                if synopsis:
                    sections.append({"header": "SYNOPSIS", "body": synopsis})
            # Split remaining text at each "LMZxxx-..." zone header line
            zone_blocks = re.split(r"(?m)^(LMZ[\d\-]+[^\n]*)\n", full_text)
            i = 1
            while i < len(zone_blocks) - 1:
                header = zone_blocks[i].strip()
                body   = zone_blocks[i + 1].strip() if i + 1 < len(zone_blocks) else ""
                sections.append({"header": header, "body": body})
                i += 2
            result["marine_sections"] = sections
    except:
        pass

    # ── NWS Area Forecast Discussion (AFD) — MKX meteorologist analysis ──────
    try:
        r = requests.get("https://api.weather.gov/products?type=AFD&location=MKX",
                         headers=hdrs, timeout=12)
        r.raise_for_status()
        items = r.json().get("@graph", [])
        if items:
            prod_r = requests.get(items[0]["@id"], headers=hdrs, timeout=12)
            prod_r.raise_for_status()
            prod = prod_r.json()
            result["afd_text"]   = prod.get("productText", "").strip()
            result["afd_issued"] = prod.get("issuanceTime", "")[:16].replace("T", " ")
            app.logger.info(f"[AFD] Fetched {len(result['afd_text'])} chars, issued {result['afd_issued']}")
        else:
            app.logger.warning("[AFD] No items returned from NWS products API")
    except Exception as e:
        app.logger.warning(f"[AFD] Fetch failed: {e}")

    cache_set("lake", result)
    return jsonify(result)

@app.route("/api/wi_warnings")
@login_required
def api_wi_warnings():
    force = request.args.get("force") == "1"
    cached = cache_get("wi_warnings", ttl=300, force=force)
    if cached:
        return jsonify(cached)
    alerts = []
    try:
        r = requests.get("https://api.weather.gov/alerts/active?area=WI",
                         headers={"User-Agent": "kevsec-dashboard/1.0", "Accept": "application/geo+json"},
                         timeout=12)
        for feat in r.json().get("features", []):
            p = feat.get("properties", {})
            alerts.append({
                "event":     p.get("event", ""),
                "severity":  p.get("severity", "Unknown"),
                "urgency":   p.get("urgency", ""),
                "headline":  p.get("headline", ""),
                "areas":     p.get("areaDesc", ""),
                "effective": p.get("effective", ""),
                "expires":   p.get("expires", ""),
                "url":       p.get("web", "") or p.get("@id", ""),
            })
        # Sort: Extreme first, then Severe, Moderate, Minor
        sev_order = {"Extreme": 0, "Severe": 1, "Moderate": 2, "Minor": 3, "Unknown": 4}
        alerts.sort(key=lambda a: sev_order.get(a["severity"], 4))
    except Exception as e:
        return jsonify({"alerts": [], "error": str(e)})
    result = {"alerts": alerts, "fetched": datetime.datetime.now().strftime("%H:%M:%S")}
    cache_set("wi_warnings", result)
    return jsonify(result)

@app.route("/api/lnm")
@login_required
def api_lnm():
    """USCG Local Notice to Mariners — District 9 (Great Lakes)."""
    force = request.args.get("force") == "1"
    cached = cache_get("lnm", ttl=86400, force=force)
    if cached:
        return jsonify(cached)
    try:
        hdrs = HDRS
        src_url = "https://www.navcen.uscg.gov/local-notices-to-mariners?district=9+0&subdistrict=n"
        r = requests.get(src_url, headers=hdrs, timeout=15)
        notices = []
        base = "https://www.navcen.uscg.gov"
        seen = set()
        for m in re.finditer(r'href="(/sites/default/files/pdf/lnms/([^"]+\.pdf))"', r.text):
            path, fname = m.group(1), m.group(2)
            if fname in seen:
                continue
            seen.add(fname)
            # Build a readable title from the filename
            # e.g. lnm09152026.pdf → "LNM D9 Week 15/2026"
            # or D09_LNM_Special_Notice_Bridge_Winter_Hours_2026.pdf → human name
            clean = fname.replace(".pdf", "").replace("_", " ")
            wk = re.match(r"lnm09(\d{2})(\d{4})", fname)
            if wk:
                clean = f"LNM D9 Week {wk.group(1).lstrip('0') or '0'} / {wk.group(2)}"
            notices.append({"title": clean.title(), "url": base + path, "fname": fname})
        result = {"notices": notices[:20], "fetched": datetime.datetime.now().strftime("%H:%M:%S"),
                  "source_url": src_url}
        cache_set("lnm", result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"notices": [], "error": str(e)})

# ── Voice Memos ───────────────────────────────────────────
import mimetypes

ALLOWED_AUDIO = {".webm", ".ogg", ".wav", ".mp4", ".m4a", ".mp3"}

@app.route("/api/memos", methods=["GET"])
@login_required
def api_memos_list():
    files = []
    for fname in sorted(os.listdir(MEMOS_DIR), reverse=True):
        ext = os.path.splitext(fname)[1].lower()
        if ext not in ALLOWED_AUDIO:
            continue
        path = os.path.join(MEMOS_DIR, fname)
        stat = os.stat(path)
        files.append({
            "name": fname,
            "size": stat.st_size,
            "created": datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
        })
    return jsonify({"memos": files})

@app.route("/api/memos", methods=["POST"])
@login_required
def api_memos_upload():
    f = request.files.get("audio")
    name = re.sub(r"[^a-zA-Z0-9 _\-]", "", request.form.get("name", "memo")).strip() or "memo"
    if not f:
        return jsonify({"error": "no file"}), 400
    ext = os.path.splitext(f.filename)[1].lower() or ".webm"
    if ext not in ALLOWED_AUDIO:
        return jsonify({"error": "invalid file type"}), 400
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{ts}_{name}{ext}"
    f.save(os.path.join(MEMOS_DIR, filename))
    return jsonify({"status": "saved", "name": filename})

@app.route("/api/memos/<path:filename>", methods=["GET"])
@login_required
def api_memos_serve(filename):
    filename = os.path.basename(filename)  # prevent path traversal
    path = os.path.join(MEMOS_DIR, filename)
    if not os.path.exists(path):
        return "Not found", 404
    mime = mimetypes.guess_type(path)[0] or "audio/webm"
    return send_file(path, mimetype=mime)

@app.route("/api/memos/<path:filename>", methods=["DELETE"])
@login_required
def api_memos_delete(filename):
    filename = os.path.basename(filename)
    path = os.path.join(MEMOS_DIR, filename)
    if os.path.exists(path):
        os.remove(path)
    return jsonify({"status": "deleted"})

@app.route("/api/memos/rename", methods=["POST"])
@login_required
def api_memos_rename():
    data = request.json or {}
    old = os.path.basename(data.get("old", ""))
    new_name = re.sub(r"[^a-zA-Z0-9 _\-]", "", data.get("new", "")).strip()
    if not old or not new_name:
        return jsonify({"error": "missing params"}), 400
    old_path = os.path.join(MEMOS_DIR, old)
    if not os.path.exists(old_path):
        return jsonify({"error": "not found"}), 404
    ext = os.path.splitext(old)[1]
    # Preserve the timestamp prefix
    ts_prefix = old.split("_")[0] + "_" + old.split("_")[1] if "_" in old else ""
    new_fname = f"{ts_prefix}_{new_name}{ext}" if ts_prefix else f"{new_name}{ext}"
    os.rename(old_path, os.path.join(MEMOS_DIR, new_fname))
    return jsonify({"status": "renamed", "name": new_fname})

# ── Obsidian / Writing Export ─────────────────────────────
@app.route("/api/obsidian_export")
@login_required
def api_obsidian_export():
    """Compile current intel into a Markdown snapshot for Obsidian."""
    now = datetime.datetime.now()
    lines = [
        f"# KEVSEC Intel Snapshot — {now.strftime('%Y-%m-%d %H:%M')}",
        "",
        f"> Generated by KEVSEC Executive Intelligence Portal  ",
        f"> Classification: Personal / Research",
        "",
    ]
    # News headlines
    news = cache_get("news", ttl=86400) or {}
    if news.get("articles"):
        lines += ["## Current Headlines", ""]
        for a in news["articles"][:20]:
            lines.append(f"- **[{a['source']}]** [{a['title']}]({a['link']})")
        lines.append("")
    # Active CVEs
    cves = cache_get("cves", ttl=86400) or {}
    if cves.get("cves"):
        lines += ["## Active CVEs (NVD Recent)", ""]
        lines.append("| CVE ID | Score | Severity | EPSS% | Summary |")
        lines.append("|--------|-------|----------|-------|---------|")
        for c in cves["cves"][:10]:
            epss = f"{c['epss']}%" if c.get("epss") is not None else "—"
            lines.append(f"| [{c['id']}](https://nvd.nist.gov/vuln/detail/{c['id']}) "
                         f"| {c['score']} | {c['severity']} | {epss} | {c['desc'][:80]}... |")
        lines.append("")
    # Weather alerts
    wx = cache_get("weather", ttl=86400) or {}
    if wx.get("alerts"):
        lines += ["## Active Weather Alerts", ""]
        for a in wx["alerts"]:
            lines.append(f"- **{a.get('event','')}** — {a.get('headline','')}")
        lines.append("")
    # Threat level
    threat = cache_get("threat", ttl=86400) or {}
    if threat:
        lines += [f"## Homeland Threat Level", "",
                  f"**Level:** {threat.get('level','Unknown')}  ",
                  ""]
        for alert in threat.get("alerts", [])[:5]:
            lines.append(f"- {alert.get('title','')} ({alert.get('date','')})")
        lines.append("")
    # Notepad contents
    try:
        with open(NOTEPAD_FILE) as f:
            note_content = f.read().strip()
        if note_content:
            lines += ["## Field Notes", "", note_content, ""]
    except: pass
    lines += [
        "---",
        f"*Snapshot exported from KEVSEC Dashboard at {now.isoformat()}*",
    ]
    md = "\n".join(lines)
    fname = f"KEVSEC_Snapshot_{now.strftime('%Y%m%d_%H%M%S')}.md"
    import io
    buf = io.BytesIO(md.encode("utf-8"))
    buf.seek(0)
    return send_file(buf, mimetype="text/markdown",
                     as_attachment=True, download_name=fname)

# ── Notes Library ─────────────────────────────────────────

@app.route("/api/notes", methods=["GET"])
@login_required
def api_notes_list():
    """List all saved notes."""
    notes = []
    for fname in sorted(os.listdir(NOTES_DIR), reverse=True):
        if not fname.endswith(".txt") and not fname.endswith(".md"):
            continue
        path = os.path.join(NOTES_DIR, fname)
        stat = os.stat(path)
        # strip timestamp prefix for display title
        display = re.sub(r"^\d{8}_\d{6}_", "", fname)
        display = os.path.splitext(display)[0].replace("_", " ")
        notes.append({
            "fname": fname,
            "title": display,
            "size": stat.st_size,
            "modified": datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
        })
    return jsonify({"notes": notes})

@app.route("/api/notes/<path:fname>", methods=["GET"])
@login_required
def api_notes_get(fname):
    fname = os.path.basename(fname)
    path = os.path.join(NOTES_DIR, fname)
    if not os.path.exists(path):
        return jsonify({"error": "not found"}), 404
    with open(path, encoding="utf-8") as f:
        content = f.read()
    return jsonify({"fname": fname, "content": content})

@app.route("/api/notes", methods=["POST"])
@login_required
def api_notes_create():
    """Create or update a note."""
    data = request.json or {}
    title = re.sub(r"[^\w\s\-]", "", data.get("title", "untitled")).strip()[:80] or "untitled"
    content = data.get("content", "")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = data.get("fname")
    if fname:
        # Update existing — keep same filename
        fname = os.path.basename(fname)
    else:
        fname = f"{ts}_{title.replace(' ','_')}.txt"
    path = os.path.join(NOTES_DIR, fname)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return jsonify({"status": "saved", "fname": fname, "title": title,
                    "modified": datetime.datetime.now().strftime("%Y-%m-%d %H:%M")})

@app.route("/api/notes/<path:fname>", methods=["DELETE"])
@login_required
def api_notes_delete(fname):
    fname = os.path.basename(fname)
    path = os.path.join(NOTES_DIR, fname)
    if os.path.exists(path):
        os.remove(path)
    return jsonify({"status": "deleted"})

@app.route("/api/notes/<path:fname>/rename", methods=["POST"])
@login_required
def api_notes_rename(fname):
    old_fname = os.path.basename(fname)
    new_title = re.sub(r"[^\w\s\-]", "", (request.json or {}).get("title", "")).strip()[:80]
    if not new_title:
        return jsonify({"error": "empty title"}), 400
    old_path = os.path.join(NOTES_DIR, old_fname)
    if not os.path.exists(old_path):
        return jsonify({"error": "not found"}), 404
    # preserve timestamp prefix if present
    m = re.match(r"^(\d{8}_\d{6}_)", old_fname)
    prefix = m.group(1) if m else ""
    new_fname = f"{prefix}{new_title.replace(' ','_')}.txt"
    os.rename(old_path, os.path.join(NOTES_DIR, new_fname))
    return jsonify({"status": "renamed", "fname": new_fname})

@app.route("/api/notes/<path:fname>/download", methods=["GET"])
@login_required
def api_notes_download(fname):
    fname = os.path.basename(fname)
    path = os.path.join(NOTES_DIR, fname)
    if not os.path.exists(path):
        return jsonify({"error": "not found"}), 404
    return send_file(path, as_attachment=True, download_name=fname)


GOALS_FILE = f"{DATA_DIR}/goals.md"

@app.route("/api/goals", methods=["GET","POST"])
@login_required
@csrf_required
def api_goals():
    """Daily goals / Today's Objectives — reads/writes a simple markdown checklist."""
    if request.method == "POST":
        content = (request.json or {}).get("content","")
        with open(GOALS_FILE,"w") as f:
            f.write(content)
        return jsonify({"status":"saved"})
    try:
        with open(GOALS_FILE) as f:
            raw = f.read()
    except Exception:
        raw = "# Today's Objectives\n\n- [ ] Add your goals here\n"
    # Parse markdown checklist into structured items
    items = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("- [ ]") or line.startswith("* [ ]"):
            items.append({"done": False, "text": line[5:].strip()})
        elif line.startswith("- [x]") or line.startswith("- [X]") or line.startswith("* [x]"):
            items.append({"done": True,  "text": line[5:].strip()})
    done_count = sum(1 for i in items if i["done"])
    return jsonify({"items": items, "raw": raw, "done": done_count, "total": len(items),
                    "fetched": _ts()})


@app.route("/api/notepad", methods=["GET","POST"])
@login_required
@csrf_required
def api_notepad():
    if request.method == "POST":
        content = (request.json or {}).get("content","")
        with open(NOTEPAD_FILE,"w") as f:
            f.write(content)
        return jsonify({"status":"saved","ts":datetime.datetime.now().strftime("%H:%M:%S")})
    try:
        with open(NOTEPAD_FILE) as f:
            content = f.read()
    except Exception as e:
        app.logger.warning("notepad read failed: %s", e)
        content = ""
    return jsonify({"content": content})

@app.route("/api/reminders", methods=["GET","POST","DELETE"])
@login_required
def api_reminders():
    try:
        with open(REMINDERS_FILE) as f:
            reminders = json.load(f)
    except:
        reminders = []
    if request.method == "POST":
        data = request.json
        r = {"id": int(time.time()*1000), "text": data.get("text",""),
             "remind_at": data.get("remind_at",""),
             "created": datetime.datetime.now().isoformat()}
        reminders.append(r)
        with open(REMINDERS_FILE,"w") as f:
            json.dump(reminders, f, indent=2)
        return jsonify({"status":"added","reminder":r})
    elif request.method == "DELETE":
        rid = request.json.get("id")
        reminders = [r for r in reminders if r.get("id") != rid]
        with open(REMINDERS_FILE,"w") as f:
            json.dump(reminders, f, indent=2)
        return jsonify({"status":"deleted"})
    return jsonify({"reminders": reminders})

# ══════════════════════════════════════════════════════════ PERSONAL HEALTH ═══

HEALTH_FILE = f"{DATA_DIR}/personal_health.json"
HEALTH_DB   = f"{DATA_DIR}/health.db"

def _db():
    conn = sqlite3.connect(HEALTH_DB)
    conn.row_factory = sqlite3.Row
    return conn

def _init_health_db():
    with _db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS config (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS medications (
            med_id        TEXT PRIMARY KEY,
            label         TEXT,
            interval_days INTEGER,
            indication    TEXT
        );
        CREATE TABLE IF NOT EXISTS doses (
            id     INTEGER PRIMARY KEY AUTOINCREMENT,
            med_id TEXT,
            date   TEXT,
            notes  TEXT
        );
        CREATE TABLE IF NOT EXISTS weight_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            date       TEXT UNIQUE,
            weight_lbs REAL,
            bmi        REAL,
            notes      TEXT
        );
        CREATE TABLE IF NOT EXISTS shower_log (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            date  TEXT,
            time  TEXT,
            notes TEXT
        );
        CREATE TABLE IF NOT EXISTS skin_log (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            date     TEXT,
            severity INTEGER,
            areas    TEXT,
            notes    TEXT
        );
        CREATE TABLE IF NOT EXISTS health_log (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            date  TEXT,
            notes TEXT
        );
        """)
        # Seed default medications if missing
        for med_id, label, interval, indication in [
            ("skyrizi", "Skyrizi", 84, "Plaque Psoriasis"),
            ("zepbound", "Zepbound", 7, "Weight Management"),
        ]:
            conn.execute(
                "INSERT OR IGNORE INTO medications (med_id, label, interval_days, indication) VALUES (?,?,?,?)",
                (med_id, label, interval, indication)
            )
        # Migrate from JSON if it exists and DB is empty
        _migrate_json_to_db(conn)

def _migrate_json_to_db(conn):
    if not os.path.exists(HEALTH_FILE):
        return
    try:
        with open(HEALTH_FILE) as f:
            data = json.load(f)
    except Exception:
        return
    # Only migrate if all tables are empty (fresh DB)
    count = conn.execute("SELECT COUNT(*) FROM doses").fetchone()[0]
    if count > 0:
        return
    if data.get("height_in"):
        conn.execute("INSERT OR REPLACE INTO config VALUES ('height_in', ?)", (str(data["height_in"]),))
    for med_id, cfg in data.get("medications", {}).items():
        conn.execute("INSERT OR REPLACE INTO medications VALUES (?,?,?,?)",
                     (med_id, cfg["label"], cfg["interval_days"], cfg["indication"]))
        for dose in cfg.get("doses", []):
            conn.execute("INSERT INTO doses (med_id, date, notes) VALUES (?,?,?)",
                         (med_id, dose["date"], dose.get("notes", "")))
    for w in data.get("weight_log", []):
        conn.execute("INSERT OR IGNORE INTO weight_log (date, weight_lbs, bmi, notes) VALUES (?,?,?,?)",
                     (w["date"], w["weight_lbs"], w["bmi"], w.get("notes", "")))
    for s in data.get("shower_log", []):
        conn.execute("INSERT INTO shower_log (date, time, notes) VALUES (?,?,?)",
                     (s["date"], s.get("time", ""), s.get("notes", "")))
    for sk in data.get("skin_log", []):
        conn.execute("INSERT INTO skin_log (date, severity, areas, notes) VALUES (?,?,?,?)",
                     (sk["date"], sk["severity"], json.dumps(sk.get("areas", [])), sk.get("notes", "")))
    for h in data.get("health_log", []):
        conn.execute("INSERT INTO health_log (date, notes) VALUES (?,?)",
                     (h["date"], h.get("notes", "")))
    logging.getLogger(__name__).info("health: migrated JSON to SQLite")

_init_health_db()

def _load_health():
    with _db() as conn:
        height_in = float((conn.execute("SELECT value FROM config WHERE key='height_in'").fetchone() or ("70",))[0])
        meds = {}
        for m in conn.execute("SELECT * FROM medications"):
            doses = [{"date": d["date"], "notes": d["notes"]}
                     for d in conn.execute("SELECT date, notes FROM doses WHERE med_id=? ORDER BY date", (m["med_id"],))]
            meds[m["med_id"]] = {"label": m["label"], "interval_days": m["interval_days"],
                                  "indication": m["indication"], "doses": doses}
        weight_log = [dict(r) for r in conn.execute("SELECT date, weight_lbs, bmi, notes FROM weight_log ORDER BY date")]
        shower_log = [dict(r) for r in conn.execute("SELECT id, date, time, notes FROM shower_log ORDER BY date, time")]
        skin_log   = [{"id": r["id"], "date": r["date"], "severity": r["severity"],
                        "areas": json.loads(r["areas"] or "[]"), "notes": r["notes"]}
                      for r in conn.execute("SELECT * FROM skin_log ORDER BY date")]
        health_log = [dict(r) for r in conn.execute("SELECT id, date, notes FROM health_log ORDER BY date")]
    return {"height_in": height_in, "medications": meds,
            "weight_log": weight_log, "shower_log": shower_log,
            "skin_log": skin_log, "health_log": health_log}

@app.route("/api/personal/health", methods=["GET"])
@login_required
def api_personal_health():
    return jsonify(_load_health())

@app.route("/api/personal/meds", methods=["POST"])
@login_required
@csrf_required
def api_personal_meds_log():
    body  = request.json or {}
    med   = body.get("med", "")
    date  = body.get("date", datetime.date.today().isoformat())
    notes = body.get("notes", "")
    with _db() as conn:
        exists = conn.execute("SELECT 1 FROM medications WHERE med_id=?", (med,)).fetchone()
        if not exists:
            return jsonify({"error": "unknown medication"}), 400
        conn.execute("INSERT INTO doses (med_id, date, notes) VALUES (?,?,?)", (med, date, notes))
    return jsonify({"ok": True, "last": date})

@app.route("/api/personal/meds/<med>/<int:idx>", methods=["DELETE"])
@login_required
@csrf_required
def api_personal_meds_delete(med, idx):
    with _db() as conn:
        rows = conn.execute("SELECT id FROM doses WHERE med_id=? ORDER BY date", (med,)).fetchall()
        if 0 <= idx < len(rows):
            conn.execute("DELETE FROM doses WHERE id=?", (rows[idx]["id"],))
    return jsonify({"ok": True})

@app.route("/api/personal/weight", methods=["POST"])
@login_required
@csrf_required
def api_personal_weight_add():
    body = request.json or {}
    wlbs = float(body.get("weight_lbs", 0))
    with _db() as conn:
        h_in = float((conn.execute("SELECT value FROM config WHERE key='height_in'").fetchone() or ("70",))[0])
        h_in = float(body.get("height_in") or h_in)
        bmi  = round((wlbs / (h_in ** 2)) * 703, 1) if h_in and wlbs else 0
        date = body.get("date", datetime.date.today().isoformat())
        conn.execute("INSERT OR REPLACE INTO config VALUES ('height_in', ?)", (str(h_in),))
        conn.execute("INSERT OR REPLACE INTO weight_log (date, weight_lbs, bmi, notes) VALUES (?,?,?,?)",
                     (date, wlbs, bmi, body.get("notes", "")))
    return jsonify({"ok": True, "bmi": bmi})

@app.route("/api/personal/weight/<date>", methods=["DELETE"])
@login_required
@csrf_required
def api_personal_weight_delete(date):
    with _db() as conn:
        conn.execute("DELETE FROM weight_log WHERE date=?", (date,))
    return jsonify({"ok": True})

@app.route("/api/personal/shower", methods=["POST"])
@login_required
@csrf_required
def api_personal_shower_log():
    body = request.json or {}
    with _db() as conn:
        conn.execute("INSERT INTO shower_log (date, time, notes) VALUES (?,?,?)", (
            body.get("date",  datetime.date.today().isoformat()),
            body.get("time",  datetime.datetime.now().strftime("%H:%M")),
            body.get("notes", ""),
        ))
    return jsonify({"ok": True})

@app.route("/api/personal/shower/<int:row_id>", methods=["DELETE"])
@login_required
@csrf_required
def api_personal_shower_delete(row_id):
    with _db() as conn:
        conn.execute("DELETE FROM shower_log WHERE id=?", (row_id,))
    return jsonify({"ok": True})

@app.route("/api/personal/skin", methods=["POST"])
@login_required
@csrf_required
def api_personal_skin_log():
    body = request.json or {}
    with _db() as conn:
        conn.execute("INSERT INTO skin_log (date, severity, areas, notes) VALUES (?,?,?,?)", (
            body.get("date",     datetime.date.today().isoformat()),
            int(body.get("severity", 5)),
            json.dumps(body.get("areas", [])),
            body.get("notes", ""),
        ))
    return jsonify({"ok": True})

@app.route("/api/personal/skin/<int:row_id>", methods=["DELETE"])
@login_required
@csrf_required
def api_personal_skin_delete(row_id):
    with _db() as conn:
        conn.execute("DELETE FROM skin_log WHERE id=?", (row_id,))
    return jsonify({"ok": True})

@app.route("/api/personal/log", methods=["POST"])
@login_required
@csrf_required
def api_personal_log_add():
    body = request.json or {}
    with _db() as conn:
        conn.execute("INSERT INTO health_log (date, notes) VALUES (?,?)", (
            body.get("date", datetime.date.today().isoformat()),
            body.get("notes", ""),
        ))
    return jsonify({"ok": True})

@app.route("/api/personal/log/<int:row_id>", methods=["DELETE"])
@login_required
@csrf_required
def api_personal_log_delete(row_id):
    with _db() as conn:
        conn.execute("DELETE FROM health_log WHERE id=?", (row_id,))
    return jsonify({"ok": True})

@app.route("/api/personal/height", methods=["POST"])
@login_required
@csrf_required
def api_personal_height():
    with _db() as conn:
        conn.execute("INSERT OR REPLACE INTO config VALUES ('height_in', ?)",
                     (str(float((request.json or {}).get("height_in", 70))),))
    return jsonify({"ok": True})

@app.route("/api/personal/news")
@login_required
def api_personal_news():
    cached = cache_get("personal_news", ttl=7200)
    if cached:
        return jsonify(cached)
    feeds = [
        ("Bodybuilding.com",    "https://www.bodybuilding.com/rss/articles.xml"),
        ("Muscle & Fitness",    "https://www.muscleandfitness.com/feed/"),
        ("Men's Health",        "https://www.menshealth.com/rss/all.xml"),
        ("T-Nation",            "https://www.t-nation.com/feed/"),
        ("Healthline",          "https://www.healthline.com/rss/health-news"),
        ("Psoriasis Foundation","https://www.psoriasis.org/rss"),
        ("Breaking Muscle",     "https://breakingmuscle.com/feed/"),
    ]
    from concurrent.futures import ThreadPoolExecutor as _TPE
    articles = []
    def _fetch(item):
        src, url = item
        try:
            f = feedparser.parse(url)
            return [{"source": src, "title": e.get("title","")[:120], "link": e.get("link","#"),
                     "published": e.get("published","")[:25],
                     "summary": re.sub(r"<[^>]+>","",e.get("summary",""))[:200]}
                    for e in f.entries[:5]]
        except Exception:
            return []
    with _TPE(max_workers=7) as ex:
        for results in ex.map(_fetch, feeds):
            articles.extend(results)
    result = {"articles": articles}
    cache_set("personal_news", result)
    return jsonify(result)

def _glerl_cache_key():
    """Return YYYY-MM-DD-HH rounded to 6-hour blocks (00, 06, 12, 18)."""
    now = datetime.datetime.utcnow()
    block = (now.hour // 6) * 6
    return f"{now.strftime('%Y-%m-%d')}-{block:02d}"

@app.route("/api/glerl/<img_name>")
@login_required
def api_glerl_image(img_name):
    """Proxy GLERL Lake Michigan model images, cached in 6-hour blocks."""
    allowed = {"temp", "btemp", "uv", "zeta", "wnd", "glsea"}
    if img_name not in allowed:
        return "Not found", 404
    from flask import Response, request as freq
    force = freq.args.get("force") == "1"
    cache_key = _glerl_cache_key()
    disk_path = os.path.join(DISK_CACHE_DIR, f"glerl_{img_name}_{cache_key}.png")
    # Delete cached file if force-refresh requested
    if force and os.path.exists(disk_path):
        try: os.remove(disk_path)
        except: pass
    # Serve from disk if current block's file exists
    if os.path.exists(disk_path):
        with open(disk_path, "rb") as f:
            return Response(f.read(), mimetype="image/png")
    # Fetch, save to disk, serve
    try:
        r = requests.get(f"https://www.glerl.noaa.gov/res/glcfs/mih/{img_name}.png",
                         timeout=15, headers={"User-Agent":"Mozilla/5.0"})
        if r.status_code == 200:
            with open(disk_path, "wb") as f:
                f.write(r.content)
            # Clean up older blocks for this image
            for old in os.listdir(DISK_CACHE_DIR):
                if old.startswith(f"glerl_{img_name}_") and old != f"glerl_{img_name}_{cache_key}.png":
                    try: os.remove(os.path.join(DISK_CACHE_DIR, old))
                    except: pass
            return Response(r.content, mimetype="image/png")
    except: pass
    return "Unavailable", 503

@app.route("/api/service_control", methods=["POST"])
@login_required
@csrf_required
def api_service_control():
    """Start / stop / restart a whitelisted systemd service."""
    ALLOWED_SERVICES = {
        "jellyfin", "honeypot", "endlessh",
        "librarian-bot", "reminder-bot", "presidential-sim",
        "prowlarr", "radarr", "sonarr", "nginx",
        "kevsec-dashboard",
    }
    ALLOWED_ACTIONS = {"start", "stop", "restart"}
    data = request.json or {}
    action  = data.get("action", "")
    service = data.get("service", "")
    if action not in ALLOWED_ACTIONS:
        return jsonify({"error": f"Invalid action: {action}"}), 400
    if service not in ALLOWED_SERVICES:
        return jsonify({"error": f"Service not allowed: {service}"}), 400
    _sec_log.warning("SERVICE %s %s by %s from %s", action.upper(), service,
                     session.get("user", "?"), _real_ip())
    try:
        r = subprocess.run(
            ["sudo", "/usr/local/bin/kevsec-svc-control.sh", action, service],
            capture_output=True, text=True, timeout=15
        )
        ok = r.returncode == 0
        # Get new status
        st = subprocess.run(["systemctl", "is-active", service],
                            capture_output=True, text=True, timeout=5)
        return jsonify({"ok": ok, "status": st.stdout.strip(),
                        "output": (r.stdout + r.stderr).strip()[:200]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/server_control", methods=["POST"])
@login_required
@csrf_required
def api_server_control():
    """Schedule or trigger a server restart / shutdown / cancel."""
    ALLOWED_ACTIONS = {"restart", "shutdown", "cancel", "update-restart"}
    data    = request.json or {}
    action  = data.get("action", "")
    delay   = int(data.get("delay", 0))   # minutes; 0 = immediate
    if action not in ALLOWED_ACTIONS:
        return jsonify({"error": f"Invalid action: {action}"}), 400
    if delay < 0 or delay > 1440:
        return jsonify({"error": "Delay must be 0–1440 minutes"}), 400
    _sec_log.warning("SERVER %s delay=%smin by %s from %s", action.upper(), delay,
                     session.get("user", "?"), _real_ip())
    try:
        if action == "update-restart":
            # Fire-and-forget — apt upgrade takes minutes, server restarts after
            subprocess.Popen(["sudo", "/usr/local/bin/kevsec-update-restart.sh"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
            return jsonify({"ok": True, "msg": "Update started — server will restart when complete (may take several minutes)"})
        r = subprocess.run(
            ["sudo", "/usr/local/bin/kevsec-server-control.sh", action, str(delay)],
            capture_output=True, text=True, timeout=10
        )
        return jsonify({"ok": r.returncode == 0,
                        "output": (r.stdout + r.stderr).strip()[:200]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tarpit_week_reset", methods=["POST"])
@login_required
def api_tarpit_week_reset():
    """Internal: save current tarpit total_seconds as weekly offset (called by cron)."""
    # Allow cron via secret token OR dashboard login
    token = request.args.get("token","")
    expected = os.environ.get("CRON_SECRET","")
    if not (session.get("logged_in") or (expected and token == expected)):
        return jsonify({"error":"unauthorized"}), 403
    # Compute current total
    try:
        r = subprocess.run(
            ["journalctl","-u","endlessh","--no-pager","-n","5000","--output=cat"],
            capture_output=True, text=True, timeout=15)
        total = sum(float(m.group(1)) for l in r.stdout.splitlines()
                    if "CLOSE" in l
                    for m in [re.search(r"time=([\d.]+)", l)] if m)
        save_tarpit_week_offset(int(total))
        return jsonify({"ok": True, "offset_seconds": int(total)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/nuke", methods=["POST"])
@login_required
@csrf_required
def api_nuke():
    """NUKE AUTHORITY — Tier-Omega destruction protocol. Triple-authenticated server wipe."""
    NUKE_HASH = os.environ.get("NUKE_PASSWORD_HASH", "")
    data = request.json or {}
    pw = data.get("password", "")
    if not pw:
        return jsonify({"error": "AUTHORIZATION CODE REQUIRED"}), 400
    if hashlib.sha256(pw.encode()).hexdigest() != NUKE_HASH:
        _sec_log.warning(f"NUKE AUTH FAILURE from {_real_ip()} — bad password")
        return jsonify({"error": "INVALID AUTHORIZATION CODE"}), 403
    _sec_log.warning(f"NUKE AUTHORITY EXECUTED by {session.get('user','?')} from {_real_ip()}")
    # Trigger nuke script as root in background — no wait
    subprocess.Popen(["sudo", "/usr/local/bin/nuke-server.sh", _real_ip()],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    return jsonify({"ok": True, "msg": "DETONATION SEQUENCE INITIATED"})

@app.route("/api/ban_ip", methods=["POST"])
@login_required
@csrf_required
def api_ban_ip():
    """Manually ban an IP: adds to custom.list and blocks via iptables immediately."""
    data = request.json or {}
    ip_addr = (data.get("ip") or "").strip()
    reason  = (data.get("reason") or "manual_dashboard_ban").strip()[:60]
    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$", ip_addr):
        return jsonify({"error": "Invalid IP address"}), 400
    # Block private/loopback
    if re.match(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)", ip_addr):
        return jsonify({"error": "Cannot ban private/loopback address"}), 400
    _sec_log.warning("MANUAL_BAN ip=%s reason=%s by=%s from=%s",
                     ip_addr, reason, session.get("user","?"), _real_ip())
    results = {}
    # 1. Add to custom.list
    try:
        custom_list = "/etc/nftables-blacklist/custom.list"
        r = subprocess.run(["sudo","bash","-c",
                            f"grep -qxF '{ip_addr}' {custom_list} || echo '{ip_addr}' >> {custom_list}"],
                           capture_output=True, text=True, timeout=5)
        results["custom_list"] = r.returncode == 0
    except Exception as e:
        results["custom_list"] = False
    # 2. Block immediately via iptables
    try:
        r = subprocess.run(["sudo","iptables","-I","INPUT","-s",ip_addr,"-j","DROP"],
                           capture_output=True, text=True, timeout=5)
        results["iptables"] = r.returncode == 0
    except Exception as e:
        results["iptables"] = False
    # 3. Block via fail2ban (logs it too)
    try:
        r = subprocess.run(["sudo","fail2ban-client","set","sshd","banip",ip_addr],
                           capture_output=True, text=True, timeout=10)
        results["fail2ban"] = r.returncode == 0
    except Exception as e:
        results["fail2ban"] = False
    return jsonify({"ok": True, "ip": ip_addr, "results": results})


@app.route("/api/f2b_unban", methods=["POST"])
@login_required
@csrf_required
def api_f2b_unban():
    """Unban an IP from all fail2ban jails."""
    data = request.json or {}
    ip_addr = (data.get("ip") or "").strip()
    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip_addr):
        return jsonify({"error": "Invalid IP address"}), 400
    _sec_log.warning("MANUAL_UNBAN ip=%s by=%s from=%s",
                     ip_addr, session.get("user","?"), _real_ip())
    results = {}
    try:
        jails_r = subprocess.run(["sudo","fail2ban-client","status"],
                                 capture_output=True, text=True, timeout=10)
        jail_line = re.search(r"Jail list:\s*(.+)", jails_r.stdout)
        jails = [j.strip() for j in jail_line.group(1).split(",")] if jail_line else []
        for jail in jails:
            r = subprocess.run(["sudo","fail2ban-client","set", jail,"unbanip",ip_addr],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                results[jail] = "unbanned"
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    # Also remove from iptables
    try:
        subprocess.run(["sudo","iptables","-D","INPUT","-s",ip_addr,"-j","DROP"],
                       capture_output=True, text=True, timeout=5)
    except: pass
    return jsonify({"ok": True, "ip": ip_addr, "results": results})


@app.route("/api/run_blacklist_update", methods=["POST"])
@login_required
@csrf_required
def api_run_blacklist_update():
    """Manually trigger honeypot blocklist collection + nftables update."""
    _sec_log.warning("BLACKLIST_UPDATE_MANUAL by=%s from=%s",
                     session.get("user","?"), _real_ip())
    try:
        r1 = subprocess.run(["sudo","/usr/local/bin/update-honeypot-blocklist.sh"],
                            capture_output=True, text=True, timeout=60)
        out1 = (r1.stdout + r1.stderr).strip()
        return jsonify({"ok": r1.returncode == 0, "output": out1[:500]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/network_stats")
@login_required
def api_network_stats():
    """Network rx/tx bytes for main interface."""
    try:
        with open("/proc/net/dev") as f:
            lines = f.readlines()
        ifaces = {}
        for line in lines[2:]:
            parts = line.split()
            if len(parts) < 10: continue
            iface = parts[0].rstrip(":")
            if iface in ("lo",): continue
            ifaces[iface] = {
                "rx_bytes": int(parts[1]),
                "tx_bytes": int(parts[9]),
                "rx_mb": round(int(parts[1]) / 1048576, 1),
                "tx_mb": round(int(parts[9]) / 1048576, 1),
            }
        # Top processes by memory
        r = subprocess.run(["ps","aux","--sort=-%mem","--no-header"],
                           capture_output=True, text=True, timeout=5)
        procs = []
        for line in r.stdout.strip().split("\n")[:10]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                procs.append({"user": parts[0], "pid": parts[1],
                               "cpu": parts[2], "mem": parts[3],
                               "cmd": parts[10][:40]})
        return jsonify({"interfaces": ifaces, "top_procs": procs,
                        "ts": datetime.datetime.now().strftime("%H:%M:%S")})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/api/burn_ban")
@login_required
def api_burn_ban():
    """Wisconsin DNR fire danger + burn restrictions. Highlights Ozaukee County."""
    cached = cache_get("burn_ban", ttl=1800)
    if cached:
        return jsonify(cached)
    try:
        r = requests.get(
            "https://apps.dnr.wi.gov/forestryapps/burnrestriction/json/",
            timeout=10, headers=HDRS
        )
        r.raise_for_status()
        data = r.json()
        counties = []
        ozaukee = None
        for entry in data:
            county = {
                "name":        entry.get("COUNTY_NAME", "").title(),
                "danger":      entry.get("DANGER_RATING_NAME", ""),
                "danger_code": entry.get("DANGER_RATING_CODE", 0),
                "color":       entry.get("DANGER_RATING_COLOR", ""),
                "restricted":  bool(entry.get("PERMIT_RESTRICTIONS")),
                "comments":    entry.get("ADDITIONAL_COMMENTS", "") or "",
            }
            counties.append(county)
            if "OZAUKEE" in entry.get("COUNTY_NAME", "").upper():
                ozaukee = county
        # Sort by danger code descending
        counties.sort(key=lambda x: x["danger_code"], reverse=True)
        result = {
            "ozaukee": ozaukee,
            "all": counties,
            "high_danger": [c for c in counties if c["danger_code"] >= 4],
            "fetched": datetime.datetime.now().strftime("%H:%M:%S"),
        }
        cache_set("burn_ban", result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e), "fetched": datetime.datetime.now().strftime("%H:%M:%S")})


@app.route("/api/ozaukee_alerts")
@login_required
def api_ozaukee_alerts():
    """NWS active alerts specifically for Ozaukee County (WIC089)."""
    cached = cache_get("ozaukee_alerts", ttl=300)
    if cached:
        return jsonify(cached)
    try:
        r = requests.get(
            "https://api.weather.gov/alerts/active?zone=WIC089",
            timeout=10, headers={**HDRS, "Accept": "application/geo+json"}
        )
        r.raise_for_status()
        features = r.json().get("features", [])
        alerts = []
        for f in features:
            p = f.get("properties", {})
            alerts.append({
                "event":    p.get("event", ""),
                "headline": p.get("headline", ""),
                "severity": p.get("severity", ""),
                "urgency":  p.get("urgency", ""),
                "expires":  p.get("expires", ""),
                "desc":     p.get("description", "")[:400],
            })
        result = {"alerts": alerts, "count": len(alerts),
                  "fetched": datetime.datetime.now().strftime("%H:%M:%S")}
        cache_set("ozaukee_alerts", result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"alerts": [], "count": 0, "error": str(e),
                        "fetched": datetime.datetime.now().strftime("%H:%M:%S")})


@app.route("/api/president_intel")
@login_required
def api_president_intel():
    """Presidential schedule scraped daily from Roll Call / Factbase calendar."""
    force = request.args.get("force") == "1"
    cached = cache_get("president_intel", ttl=86400, force=force)  # 24hr — daily scrape
    if cached:
        return jsonify(cached)

    hdrs = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    }
    schedule = []

    try:
        resp = requests.get(
            "https://rollcall.com/factbase/trump/calendar/",
            timeout=20, headers=hdrs)
        html = resp.text

        today = datetime.date.today()
        window_end = today + datetime.timedelta(days=14)

        # Find all date positions and event positions
        date_matches = list(_DATE_PAT.finditer(html))
        for i, dm in enumerate(date_matches):
            day_str = dm.group(1).strip().rstrip(',')
            date_str = dm.group(2).strip()
            try:
                date_obj = datetime.datetime.strptime(date_str, "%B %d, %Y").date()
            except Exception:
                continue
            if date_obj < today or date_obj > window_end:
                continue

            # Get the html slice between this date and the next
            start = dm.end()
            end = date_matches[i + 1].start() if i + 1 < len(date_matches) else len(html)
            chunk = html[start:end]

            for em in _EVENT_PAT.finditer(chunk):
                ev_type = em.group(1).strip()
                ev_time = em.group(2).strip()
                ev_title = _WS_PAT.sub(' ', em.group(3)).strip()
                if not ev_title or ev_title.lower() == 'tbd':
                    continue
                schedule.append({
                    "date":     date_obj.strftime("%a %b %-d"),
                    "day":      day_str,
                    "time":     ev_time,
                    "title":    ev_title[:160],
                    "type":     ev_type,
                    "source":   "Roll Call / Factbase",
                })

        schedule.sort(key=lambda x: (x["date"], x["time"]))
    except Exception as ex:
        app.logger.warning("president_intel scrape error: %s", ex)

    result = {
        "schedule":     schedule[:30],
        "fetched":      _ts(),
        "schedule_url": "https://rollcall.com/factbase/trump/calendar/",
    }
    cache_set("president_intel", result)
    return jsonify(result)


@app.route("/api/congress_status")
@login_required
def api_congress_status():
    """Congress session status + recent bills sorted by action date."""
    force = request.args.get("force") == "1"
    cached = cache_get("congress_status", ttl=3600, force=force)
    if cached:
        return jsonify(cached)
    from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed
    import urllib.parse
    hdrs = HDRS
    bills = []
    # Google News RSS — legislation/bills news
    bill_queries = [
        ("House Bill",   "House bill legislation passed 2026"),
        ("Senate Bill",  "Senate bill legislation passed 2026"),
        ("Congress",     "Congress legislation vote 2026"),
        ("Budget/Spending", "federal budget appropriations spending bill 2026"),
    ]
    def _fetch_bill_news(label, query):
        items = []
        try:
            url = f"https://news.google.com/rss/search?q={urllib.parse.quote(query)}&hl=en-US&gl=US&ceid=US:en"
            parsed = feedparser.parse(url)
            for e in parsed.entries[:4]:
                pub = e.get("published", e.get("updated", ""))
                items.append({"title": e.get("title","")[:140], "link": e.get("link","#"),
                               "date": pub[:10] if pub else "", "date_raw": pub, "source": label})
        except Exception:
            pass
        return items
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(_fetch_bill_news, lbl, q): lbl for lbl, q in bill_queries}
        for fut in _as_completed(futs):
            bills.extend(fut.result())
    # Deduplicate and sort by date
    seen_titles = set(); deduped = []
    for b in sorted(bills, key=lambda x: x.get("date_raw",""), reverse=True):
        key = b["title"][:60].lower()
        if key not in seen_titles:
            seen_titles.add(key); deduped.append(b)
    bills = deduped[:16]

    # Session heuristic — 119th Congress Jan 2025–Jan 2027
    now = datetime.datetime.now()
    today = datetime.date.today()
    month, day = now.month, now.day
    in_recess = False
    recess_label = ""
    next_session_date = ""
    recess_periods = [
        ((1,1),(1,6),"New Year Recess"),
        ((2,14),(2,25),"Presidents Day Recess"),
        ((4,11),(4,28),"Spring Recess"),
        ((5,26),(6,2),"Memorial Day Recess"),
        ((7,4),(7,7),"Independence Day Recess"),
        ((7,31),(9,7),"August Recess"),
        ((11,24),(12,1),"Thanksgiving Recess"),
        ((12,19),(1,3),"Christmas/New Year Recess"),
    ]
    for (sm,sd),(em,ed),lbl in recess_periods:
        if (month,day) >= (sm,sd) and (month,day) <= (em,ed):
            in_recess = True
            recess_label = lbl
            # Calculate the return date (day after recess ends)
            try:
                end_year = today.year if em >= sm else today.year + 1
                recess_end = datetime.date(end_year, em, ed)
                return_date = recess_end + datetime.timedelta(days=1)
                next_session_date = return_date.strftime("%A, %B %-d")
            except Exception:
                next_session_date = ""
            break

    # 119th Congress seat composition (updated from 2024 election results)
    seats = {
        "senate":  {"R": 53, "D": 45, "I": 2, "total": 100,
                    "note": "2 Independents caucus D (effective D+I=47)"},
        "house":   {"R": 220, "D": 213, "vacant": 2, "total": 435,
                    "note": "Fluctuates with special elections"},
    }

    result = {
        "bills": bills[:16],
        "in_session": not in_recess,
        "session_label": recess_label if in_recess else "119th Congress — In Session",
        "next_session_date": next_session_date,
        "congress": "119th",
        "seats": seats,
        "fetched": _ts(),
        "congress_url": "https://www.congress.gov/",
        "votes_url": "https://www.congress.gov/roll-call-votes",
    }
    cache_set("congress_status", result)
    return jsonify(result)


@app.route("/api/midterm_intel")
@login_required
def api_midterm_intel():
    """2026 Midterm election intelligence: race ratings, primary dates, prediction markets."""
    cached = cache_get("midterm_intel", ttl=3600)
    if cached:
        return jsonify(cached)

    # Key races (static — update as ratings change)
    key_races = [
        {"chamber":"Senate","state":"FL","type":"Special","desc":"Rubio Vacancy","rating":"Lean R","cook":"Lean R",
         "url":"https://ballotpedia.org/United_States_Senate_special_election_in_Florida,_2026"},
        {"chamber":"Senate","state":"OH","type":"Special","desc":"Vance Vacancy","rating":"Toss-up","cook":"Toss-up",
         "url":"https://ballotpedia.org/United_States_Senate_special_election_in_Ohio,_2026"},
        {"chamber":"Senate","state":"GA","type":"Regular","desc":"Ossoff seat","rating":"Toss-up","cook":"Toss-up",
         "url":"https://ballotpedia.org/United_States_Senate_election_in_Georgia,_2026"},
        {"chamber":"Senate","state":"MI","type":"Regular","desc":"Peters seat","rating":"Lean D","cook":"Lean D",
         "url":"https://ballotpedia.org/United_States_Senate_election_in_Michigan,_2026"},
        {"chamber":"Senate","state":"NH","type":"Regular","desc":"Open seat","rating":"Toss-up","cook":"Toss-up",
         "url":"https://ballotpedia.org/United_States_Senate_election_in_New_Hampshire,_2026"},
        {"chamber":"Senate","state":"NC","type":"Regular","desc":"Open seat","rating":"Lean R","cook":"Lean R",
         "url":"https://ballotpedia.org/United_States_Senate_election_in_North_Carolina,_2026"},
        {"chamber":"Senate","state":"WI","type":"Regular","desc":"Baldwin seat","rating":"Lean D","cook":"Lean D",
         "url":"https://ballotpedia.org/United_States_Senate_election_in_Wisconsin,_2026"},
        {"chamber":"Senate","state":"VA","type":"Regular","desc":"Warner seat","rating":"Lean D","cook":"Lean D",
         "url":"https://ballotpedia.org/United_States_Senate_election_in_Virginia,_2026"},
        {"chamber":"Senate","state":"AK","type":"Regular","desc":"Murkowski seat","rating":"Lean R","cook":"Lean R",
         "url":"https://ballotpedia.org/United_States_Senate_election_in_Alaska,_2026"},
        {"chamber":"House","state":"TX","type":"Redistricting","desc":"Mid-decade remap","rating":"Watch","cook":"",
         "url":"https://ballotpedia.org/Texas%27s_congressional_districts"},
        {"chamber":"House","state":"CA","type":"Redistricting","desc":"Mid-decade remap","rating":"Watch","cook":"",
         "url":"https://ballotpedia.org/California%27s_congressional_districts"},
    ]

    # Primary calendar
    primaries = [
        {"date":"2026-05-05","states":"Indiana, Ohio","note":"FL/OH Senate special elections"},
        {"date":"2026-05-19","states":"PA, KY, OR, GA, ID","note":"Blue wall baseline"},
        {"date":"2026-06-02","states":"CA, NJ, IA, MT, NM, SD","note":"CA redistricting results"},
        {"date":"2026-06-09","states":"MS, NC, SC, ND","note":"NC redistricting results"},
        {"date":"2026-08-04","states":"KS, MI, MO, WA","note":"MO redistricting results"},
        {"date":"2026-08-11","states":"WI","note":"LOCAL FOCUS — Wisconsin Primary"},
    ]

    # Macro indicators
    macros = [
        {"label":"Historical Avg Seat Loss","value":"-28 House seats","note":"Incumbent party midterm avg",
         "url":"https://ballotpedia.org/Historical_midterm_election_trends"},
        {"label":"Open Seats (retirements)","value":"55+","note":"Flip opportunity targets",
         "url":"https://ballotpedia.org/United_States_Congress_elections,_2026"},
        {"label":"Special Elec. Dem Overperform","value":"+11.5","note":"vs. 2024 baseline (Brookings/Apr)",
         "url":"https://www.brookings.edu/articles/midterm-elections-2026/"},
        {"label":"Prediction Markets (House)","value":"D +11.5 shift","note":"Kalshi/Polymarket consensus",
         "url":"https://kalshi.com/markets/elections"},
        {"label":"Redistricting States","value":"TX, CA, NC, MO","note":"Mid-decade remap active",
         "url":"https://ballotpedia.org/Redistricting_in_the_United_States"},
        {"label":"Senate Battlegrounds","value":"9","note":"Ballotpedia tracking",
         "url":"https://ballotpedia.org/United_States_Senate_elections,_2026"},
        {"label":"House Toss-ups","value":"42","note":"Ballotpedia tracking",
         "url":"https://ballotpedia.org/United_States_House_of_Representatives_elections,_2026"},
        {"label":"Presidential Approval","value":"~41%","note":"Trump avg — Gallup/Pew Apr 2026",
         "url":"https://news.gallup.com/poll/203207/trump-job-approval-weekly.aspx"},
        {"label":"Dem Generic Ballot Avg","value":"D +7","note":"Cook/538 composite Apr 2026",
         "url":"https://www.cookpolitical.com/charts/house-charts/generic-ballot-trend-chart"},
        {"label":"Trump Net Approval","value":"−14","note":"41% approve − 55% disapprove (Apr 2026)",
         "url":"https://projects.fivethirtyeight.com/polls/approval/donald-trump/"},
        {"label":"2024 Popular Vote Margin","value":"R +2.2","note":"First R pop. vote win since 2004",
         "url":"https://www.fec.gov/introduction-campaign-finance/election-and-voting-information/federal-elections-2024/"},
        {"label":"Days Until Midterms","value":str((datetime.date(2026,11,3)-datetime.date.today()).days)+" days",
         "note":"Nov 3, 2026 General Election"},
        {"label":"House Seats In Play","value":"73","note":"Competitive/Toss-up/Lean per Cook Apr 2026",
         "url":"https://www.cookpolitical.com/ratings/house-race-ratings"},
        {"label":"Net D Special Election Margin","value":"D +14.3","note":"2025–2026 specials vs 2024 baseline",
         "url":"https://www.brookings.edu/articles/midterm-elections-2026/"},
        {"label":"Senate Seats Up (2026)","value":"34","note":"33 class II + 1 special election",
         "url":"https://ballotpedia.org/United_States_Senate_elections,_2026"},
        {"label":"D Net Senate Target","value":"+4 needed","note":"Need 51 seats for majority (now 47)",
         "url":"https://ballotpedia.org/United_States_Senate_elections,_2026"},
    ]

    # Try Kalshi for live House control market
    kalshi_data = {}
    try:
        r = requests.get(
            "https://api.elections.kalshi.com/trade-api/v2/markets?limit=20&status=open",
            timeout=8, headers={"User-Agent": "KEVSec/1.0"}
        )
        if r.status_code == 200:
            markets = r.json().get("markets", [])
            for m in markets:
                ticker = m.get("ticker_name", "")
                if "HOUSE" in ticker.upper() or "SENATE" in ticker.upper() or "CONGRESS" in ticker.upper():
                    kalshi_data[ticker] = {
                        "title": m.get("title", ticker),
                        "yes_bid": m.get("yes_bid", ""),
                        "no_bid":  m.get("no_bid", ""),
                        "volume":  m.get("volume", ""),
                    }
    except Exception:
        pass

    result = {
        "key_races":  key_races,
        "primaries":  primaries,
        "macros":     macros,
        "kalshi":     kalshi_data,
        "fetched":    _ts(),
    }
    cache_set("midterm_intel", result)
    return jsonify(result)


@app.route("/api/govt_intel")
@login_required
def api_govt_intel():
    """Government agency intelligence: FBI, CENTCOM, DOJ, State Dept news."""
    force = request.args.get("force") == "1"
    cached = cache_get("govt_intel", ttl=3600, force=force)
    if cached:
        return jsonify(cached)
    from concurrent.futures import ThreadPoolExecutor, as_completed as _ac
    import urllib.parse as _up

    feeds = [
        ("FBI",       "https://www.fbi.gov/feeds/fbi-in-the-news/rss.xml"),
        ("CENTCOM",   "https://news.google.com/rss/search?q=CENTCOM+military+operations+US+Central+Command&hl=en-US&gl=US&ceid=US:en"),
        ("DOJ",       "https://news.google.com/rss/search?q=%22Department+of+Justice%22+press+release+indicted+charged&hl=en-US&gl=US&ceid=US:en"),
        ("State Dept","https://news.google.com/rss/search?q=%22State+Department%22+%22Secretary+Rubio%22+OR+%22foreign+policy%22+US+diplomacy&hl=en-US&gl=US&ceid=US:en"),
        ("Pentagon",  "https://news.google.com/rss/search?q=Pentagon+%22Department+of+Defense%22+military+budget+troops&hl=en-US&gl=US&ceid=US:en"),
        ("DHS",       "https://news.google.com/rss/search?q=%22Department+of+Homeland+Security%22+OR+%22Secretary+Noem%22+border+immigration&hl=en-US&gl=US&ceid=US:en"),
    ]

    def _fetch(src, url):
        items = []
        try:
            f = feedparser.parse(url)
            for e in f.entries[:5]:
                pub = e.get("published", e.get("updated", ""))
                items.append({
                    "source": src,
                    "title":  e.get("title", "")[:140],
                    "link":   e.get("link", "#"),
                    "date":   pub[:10] if pub else "",
                    "date_raw": pub,
                    "summary": re.sub(r"<[^>]+>", "", e.get("summary", ""))[:180],
                })
        except Exception:
            pass
        return items

    all_items = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(_fetch, src, url): src for src, url in feeds}
        for fut in _ac(futs):
            all_items.extend(fut.result())

    seen = set(); deduped = []
    for it in sorted(all_items, key=lambda x: x.get("date_raw",""), reverse=True):
        k = it["title"][:60].lower()
        if k not in seen:
            seen.add(k); deduped.append(it)
        if len(deduped) >= 40:
            break

    result = {"items": deduped, "fetched": _ts()}
    cache_set("govt_intel", result)
    return jsonify(result)


@app.route("/api/polls")
@login_required
def api_polls():
    """Recent political polls: FiveThirtyEight averages + news headlines."""
    force = request.args.get("force") == "1"
    cached = cache_get("polls", ttl=3600, force=force)
    if cached:
        return jsonify(cached)

    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Poll headlines from news RSS — parallelized across sources
    poll_news = []
    news_feeds = [
        ("Marquette Law Poll", "https://law.marquette.edu/poll/feed/"),
        ("Gallup",             "https://news.gallup.com/rss/home.aspx"),
        ("Pew Research",       "https://www.pewresearch.org/feed/"),
        ("FiveThirtyEight",    "https://fivethirtyeight.com/features/feed/"),
        ("AP Politics",        "https://feeds.apnews.com/rss/apf-politics"),
        ("RCP",                "https://www.realclearpolitics.com/rss/rss_politic.xml"),
        ("Politico",           "https://rss.politico.com/politics-news.xml"),
        ("The Hill",           "https://thehill.com/feed/"),
    ]
    POLL_KEYWORDS = ("poll", "survey", "approval", "favorability", "generic ballot",
                     "head-to-head", "matchup", "electorate", "voter", "midterm race")

    def _fetch_poll_feed(source_label, feed_url):
        items = []
        try:
            f = feedparser.parse(feed_url)
            for e in f.entries[:25]:
                title = e.get("title", "")
                if any(w in title.lower() for w in POLL_KEYWORDS):
                    items.append({
                        "title":     title[:140],
                        "link":      e.get("link", "#"),
                        "published": e.get("published", "")[:16],
                        "source":    source_label,
                    })
                    if len(items) >= 4:
                        break
        except Exception:
            pass
        return items

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_fetch_poll_feed, lbl, url): lbl for lbl, url in news_feeds}
        for fut in as_completed(futures):
            poll_news.extend(fut.result())

    # Sort by recency (rough — use published string), deduplicate by title
    seen_titles = set()
    deduped = []
    for item in sorted(poll_news, key=lambda x: x.get("published",""), reverse=True):
        key = item["title"][:60].lower()
        if key not in seen_titles:
            seen_titles.add(key)
            deduped.append(item)
        if len(deduped) >= 20:
            break
    poll_news = deduped

    # Polling aggregator links
    aggregators = [
        {"name": "FiveThirtyEight / ABC", "url": "https://projects.fivethirtyeight.com/polls/"},
        {"name": "RealClearPolitics",     "url": "https://www.realclearpolitics.com/epolls/latest_polls/"},
        {"name": "Ballotpedia Polling",   "url": "https://ballotpedia.org/Polling_averages"},
        {"name": "Polymarket Congress",   "url": "https://polymarket.com/elections"},
        {"name": "Kalshi Elections",      "url": "https://kalshi.com/markets/elections"},
        {"name": "Cook Political Report", "url": "https://www.cookpolitical.com/ratings"},
        {"name": "Sabato's Crystal Ball", "url": "https://centerforpolitics.org/crystalball/"},
    ]

    result = {
        "polls":       [],
        "news":        poll_news,
        "aggregators": aggregators,
        "fetched":     _ts(),
    }
    cache_set("polls", result)
    return jsonify(result)


@app.route("/api/pol_tweets")
@login_required
def api_pol_tweets():
    """Politician tweets from key 2026 battleground figures — updated daily by cron scraper."""
    cache_file = os.path.join(DISK_CACHE_DIR, "pol_tweets.json")
    try:
        if os.path.exists(cache_file):
            with open(cache_file) as f:
                data = json.load(f)
            age_hrs = round((time.time() - os.path.getmtime(cache_file)) / 3600, 1)
            data["cache_age_hrs"] = age_hrs
            return jsonify(data)
    except Exception as e:
        app.logger.warning("pol_tweets read error: %s", e)
    return jsonify({"politicians": [], "fetched": _ts(),
                    "error": "No data yet — run /usr/local/bin/scrape-pol-tweets.py first"})


@app.route("/api/podcasts")
@login_required
def api_podcasts():
    """Latest episode from each podcast feed with audio URL for in-browser playback."""
    force = request.args.get("force") == "1"
    cached = cache_get("podcasts", ttl=900, force=force)  # 15-min TTL
    if cached:
        return jsonify(cached)

    FEEDS = [
        ("BBC Global News",      "https://podcasts.files.bbci.co.uk/p02nq0gn.rss"),
        ("NPR Hourly News",      "https://feeds.npr.org/500005/podcast.xml"),
        ("NPR Up First",         "https://feeds.npr.org/510318/podcast.xml"),
        ("NPR Consider This",    "https://feeds.npr.org/510355/podcast.xml"),
        ("CNN 5 Things",         "http://rss.cnn.com/services/podcasting/5things/rss.xml"),
        ("Fox News Rundown",     "https://feeds.foxnews.com/foxnewsradio/the-rundown"),
        ("The Daily (NYT)",      "https://feeds.simplecast.com/54nAGcIl"),
        ("Pod Save America",     "https://feeds.megaphone.fm/crooked-pod-save-america"),
        ("Axios Today",          "https://feeds.simplecast.com/axiostoday"),
        ("FT News Briefing",     "https://feeds.acast.com/public/shows/ft-news-briefing"),
    ]

    def _fetch(name, url):
        try:
            f = feedparser.parse(url)
            if not f.entries:
                return None
            e = f.entries[0]
            audio_url = ""
            for enc in e.get("enclosures", []):
                if enc.get("type", "").startswith("audio"):
                    audio_url = enc.get("href", enc.get("url", ""))
                    break
            if not audio_url:
                # Try media_content
                for mc in e.get("media_content", []):
                    if mc.get("type", "").startswith("audio"):
                        audio_url = mc.get("url", "")
                        break
            if not audio_url:
                return None
            pub = e.get("published", e.get("updated", ""))
            dur = ""
            for tag in ("itunes_duration", "duration"):
                if e.get(tag):
                    dur = str(e[tag]); break
            return {
                "name":        name,
                "episode":     e.get("title", "")[:120],
                "summary":     re.sub(r"<[^>]+>", "", e.get("summary", ""))[:200].strip(),
                "published":   pub[:16] if pub else "",
                "duration":    dur,
                "audio_url":   audio_url,
                "feed_url":    url,
            }
        except Exception as ex:
            app.logger.debug("podcast feed %s: %s", name, ex)
            return None

    from concurrent.futures import ThreadPoolExecutor, as_completed
    podcasts = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(_fetch, name, url): name for name, url in FEEDS}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                podcasts.append(r)

    # Preserve display order
    order = [n for n, _ in FEEDS]
    podcasts.sort(key=lambda x: order.index(x["name"]) if x["name"] in order else 99)

    result = {"podcasts": podcasts, "fetched": _ts()}
    cache_set("podcasts", result)
    return jsonify(result)


@app.route("/api/f1")
@login_required
def api_f1():
    """Formula 1 — current standings, next 2 races. Via Jolpica/Ergast API."""
    force = request.args.get("force") == "1"
    cached = cache_get("f1", ttl=3600, force=force)
    if cached:
        return jsonify(cached)
    BASE = "https://api.jolpi.ca/ergast/f1"
    hdrs = HDRS

    driver_standings, constructor_standings, upcoming, last_result = [], [], [], {}

    try:
        r = requests.get(f"{BASE}/current/driverStandings.json", headers=hdrs, timeout=10).json()
        for s in r["MRData"]["StandingsTable"]["StandingsLists"][0]["DriverStandings"][:20]:
            d = s["Driver"]; c = s["Constructors"][0]
            driver_standings.append({
                "pos": int(s["position"]), "name": f"{d['givenName']} {d['familyName']}",
                "code": d.get("code","???"), "team": c["name"],
                "points": float(s["points"]), "wins": int(s["wins"]),
            })
    except Exception as e:
        app.logger.warning("f1 driver standings: %s", e)

    try:
        r = requests.get(f"{BASE}/current/constructorStandings.json", headers=hdrs, timeout=10).json()
        for s in r["MRData"]["StandingsTable"]["StandingsLists"][0]["ConstructorStandings"][:10]:
            c = s["Constructor"]
            constructor_standings.append({
                "pos": int(s["position"]), "name": c["name"],
                "points": float(s["points"]), "wins": int(s["wins"]),
            })
    except Exception as e:
        app.logger.warning("f1 constructor standings: %s", e)

    try:
        today = datetime.date.today().isoformat()
        r = requests.get(f"{BASE}/current.json", headers=hdrs, timeout=10).json()
        races = r["MRData"]["RaceTable"]["Races"]
        for race in races:
            if race["date"] >= today:
                t = race.get("time","")
                upcoming.append({
                    "round": int(race["round"]), "name": race["raceName"],
                    "circuit": race["Circuit"]["circuitName"],
                    "location": f"{race['Circuit']['Location']['locality']}, {race['Circuit']['Location']['country']}",
                    "date": race["date"], "time": t[:5] if t else "",
                })
                if len(upcoming) >= 2:
                    break
    except Exception as e:
        app.logger.warning("f1 schedule: %s", e)

    try:
        r = requests.get(f"{BASE}/current/last/results.json", headers=hdrs, timeout=10).json()
        rr = r["MRData"]["RaceTable"]["Races"][0]
        last_result = {
            "name": rr["raceName"], "date": rr["date"],
            "podium": [
                {"pos": res["position"],
                 "name": f"{res['Driver']['givenName']} {res['Driver']['familyName']}",
                 "team": res["Constructor"]["name"], "time": res.get("Time",{}).get("time","")}
                for res in rr["Results"][:3]
            ]
        }
    except Exception:
        pass

    result = {
        "driver_standings": driver_standings,
        "constructor_standings": constructor_standings,
        "upcoming": upcoming,
        "last_result": last_result,
        "season": datetime.date.today().year,
        "fetched": _ts(),
    }
    cache_set("f1", result)
    return jsonify(result)


def _warm_cache(force=False):
    """Pre-populate expensive caches at startup so first page load is instant."""
    time.sleep(2)  # let Flask fully start
    hdrs = HDRS
    today = datetime.date.today()
    mm = today.strftime("%m"); dd = today.strftime("%d")

    # News feeds
    try:
        feeds = [
            ("NPR","https://feeds.npr.org/1001/rss.xml"),("Reuters","https://feeds.reuters.com/reuters/topNews"),
            ("The Guardian","https://www.theguardian.com/world/rss"),("The Hill","https://thehill.com/feed/"),
            ("Fox News","https://moxie.foxnews.com/google-publisher/latest.xml"),
            ("Politico","https://rss.politico.com/politics-news.xml"),
            ("NYT","https://rss.nytimes.com/services/xml/rss/ntt/HomePage.xml"),
            ("WPR","https://www.wpr.org/feed"),
            ("TMJ4 (WI)","https://www.tmj4.com/news/local/rss"),("CBS58 (WI)","https://www.cbs58.com/news/local-news.rss"),
            ("AP News","https://feeds.apnews.com/rss/apf-topnews"),
            ("BBC World","http://feeds.bbci.co.uk/news/world/rss.xml"),
            ("Milwaukee Journal Sentinel","https://rss.jsonengage.com/milwaukee-journal-sentinel/"),
            ("CNBC","https://www.cnbc.com/id/100727362/device/rss/rss.html"),
            ("Yahoo Finance","https://finance.yahoo.com/news/rssindex"),
            ("Investing.com","https://www.investing.com/rss/news.rss"),
            ("AllSides","https://www.allsides.com/news/rss"),
            ("Google News","https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en"),
            ("Google: World","https://news.google.com/rss/topics/CAAqJggKIiBDQkFTRWdvSUwyMHZNRGx1YlY4U0FtVnVHZ0pWVXlnQVAB?hl=en-US&gl=US&ceid=US:en"),
            ("Google: Tech","https://news.google.com/rss/topics/CAAqJggKIiBDQkFTRWdvSUwyMHZNRGRqTVhZU0FtVnVHZ0pWVXlnQVAB?hl=en-US&gl=US&ceid=US:en"),
            ("Google: Business","https://news.google.com/rss/topics/CAAqJggKIiBDQkFTRWdvSUwyMHZNRGx6TVdZU0FtVnVHZ0pWVXlnQVAB?hl=en-US&gl=US&ceid=US:en"),
        ]
        articles = []
        for source, url in feeds:
            try:
                f = feedparser.parse(url)
                for e in f.entries[:8]:
                    summary = re.sub(r"<[^>]+>", "", e.get("summary", ""))[:220]
                    articles.append({"source": source, "title": e.get("title","")[:120],
                                     "link": e.get("link","#"), "published": e.get("published","")[:25],
                                     "summary": summary})
            except: pass
        if articles:
            cache_set("news", {"articles": articles, "fetched": datetime.datetime.now().strftime("%H:%M:%S")})
    except: pass

    # Wikipedia featured content
    try:
        r = requests.get(f"https://en.wikipedia.org/api/rest_v1/feed/featured/{today.year}/{mm}/{dd}",
                         headers=hdrs, timeout=15)
        d = r.json()
        tfa = d.get("tfa",{})
        news_items = []
        for item in d.get("news",[])[:12]:
            raw = item.get("story","")
            text = re.sub(r"<!--.*?-->","",raw,flags=re.DOTALL)
            text = re.sub(r"<[^>]+>","",text).strip()
            links = re.findall(r'href="\.\/([^"]+)"', raw)
            full_links = re.findall(r'href="(https://en\.wikipedia\.org/wiki/[^"]+)"', raw)
            url = full_links[0] if full_links else (f"https://en.wikipedia.org/wiki/{links[0]}" if links else "#")
            if text: news_items.append({"text": text[:280], "url": url})
        otd = []
        for x in d.get("onthisday",[])[:14]:
            pgs = x.get("pages",[])
            url = (pgs[0].get("content_urls",{}).get("desktop",{}) or {}).get("page","#") if pgs else "#"
            otd.append({"year": x.get("year",""), "text": x.get("text","")[:220], "url": url})
        dyk_raw = d.get("dyk",[])
        dyk = []
        for x in dyk_raw[:6]:
            t = x.get("text","") if isinstance(x,dict) else str(x)
            t = re.sub(r"<[^>]+>","",t).strip()
            if t: dyk.append(t[:280])
        cache_set("wikipedia", {
            "tfa": {"title": tfa.get("normalizedtitle",tfa.get("title","")),
                    "extract": tfa.get("extract","")[:600],
                    "thumbnail": (tfa.get("thumbnail") or {}).get("source",""),
                    "url": (tfa.get("content_urls",{}).get("desktop",{}) or {}).get("page","#")},
            "dyk": dyk, "news": news_items, "onthisday": otd,
            "date": today.strftime("%B %d, %Y"),
            "fetched": datetime.datetime.now().strftime("%H:%M:%S")
        })
    except: pass

    # APOD — only fetch if not already cached (rate-limited to 50/day with DEMO_KEY)
    if force or not cache_get("apod", CACHE_TTL_DAY):
        try:
            r = requests.get("https://api.nasa.gov/planetary/apod", params={"api_key": NASA_API_KEY}, timeout=12)
            d = r.json()
            if "error" not in d and d.get("title"):
                cache_set("apod", {"title": d.get("title",""), "date": d.get("date",""),
                                   "explanation": d.get("explanation","")[:600],
                                   "url": d.get("url",""), "hdurl": d.get("hdurl", d.get("url","")),
                                   "media_type": d.get("media_type","image"),
                                   "copyright": d.get("copyright","NASA"),
                                   "fetched": datetime.datetime.now().strftime("%H:%M:%S")})
        except: pass

    # Weather (NWS) — refresh every 1h or on force
    if force or not cache_get("weather", 3600):
        try:
            pt = requests.get("https://api.weather.gov/points/43.3875,-87.8756", headers=hdrs, timeout=15).json()
            props = pt.get("properties",{})
            fc = requests.get(props.get("forecast",""), headers=hdrs, timeout=15).json()
            periods = fc.get("properties",{}).get("periods",[])[:8]
            forecast = [{"name":p["name"],"temp":p["temperature"],"unit":p["temperatureUnit"],
                         "wind":p.get("windSpeed",""),"short":p.get("shortForecast",""),
                         "detail":p.get("detailedForecast","")[:200]} for p in periods]
            alerts_r = requests.get("https://api.weather.gov/alerts/active?zone=WIZ055,LMZ645", headers=hdrs, timeout=12).json()
            alerts = []
            for a in alerts_r.get("features", []):
                p = a.get("properties", {})
                alerts.append({"headline": p.get("headline",""), "severity": p.get("severity",""),
                                "urgency": p.get("urgency",""), "event": p.get("event",""),
                                "description": (p.get("description") or "")[:400],
                                "instruction": (p.get("instruction") or "")[:200],
                                "effective": (p.get("effective") or "")[:16].replace("T"," "),
                                "expires": (p.get("expires") or "")[:16].replace("T"," "),
                                "url": a.get("id",""), "areas": p.get("areaDesc",""),})
            obs = {}
            for station in ["KMWC","KETB","KSBM"]:
                try:
                    ob = requests.get(f"https://api.weather.gov/stations/{station}/observations/latest",
                                      headers=hdrs, timeout=10).json()
                    p = ob.get("properties",{})
                    def c2f(v): return round(v*9/5+32,1) if v is not None else None
                    def ms2mph(v): return round(v*0.621371,1) if v is not None else None
                    def pa2inhg(v): return round(v/3386.39,2) if v is not None else None
                    def m2mi(v): return round(v/1609.34,1) if v is not None else None
                    wdir = nws_val(p.get("windDirection"))
                    obs = {"station":station,"time":p.get("timestamp","")[:16].replace("T"," ")+" UTC",
                           "condition":p.get("textDescription",""),
                           "temp_f":c2f(nws_val(p.get("temperature"))),
                           "dewpoint_f":c2f(nws_val(p.get("dewpoint"))),
                           "humidity":round(nws_val(p.get("relativeHumidity")) or 0,1),
                           "wind_speed_mph":ms2mph(nws_val(p.get("windSpeed"))),
                           "wind_gust_mph":ms2mph(nws_val(p.get("windGust"))),
                           "wind_dir_deg":wdir,"wind_dir":deg_to_compass(wdir) if wdir else "---",
                           "wind_chill_f":c2f(nws_val(p.get("windChill"))),
                           "heat_index_f":c2f(nws_val(p.get("heatIndex"))),
                           "pressure_inhg":pa2inhg(nws_val(p.get("barometricPressure"))),
                           "visibility_mi":m2mi(nws_val(p.get("visibility"))),
                           "clouds":[{"base_ft":round(cl["base"]["value"]*3.28084) if cl["base"]["value"] else None,
                                      "amount":cl.get("amount","")} for cl in p.get("cloudLayers",[])]}
                    break
                except: pass
            if forecast:
                cache_set("weather", {"forecast":forecast,"alerts":alerts,"obs":obs,
                                      "fetched":datetime.datetime.now().strftime("%H:%M:%S")})
        except: pass

    # AirNow — refresh every 6h or on force
    if force or not cache_get("airnow", CACHE_TTL_LONG):
        try:
            r = requests.get("https://air-quality-api.open-meteo.com/v1/air-quality",
                params={"latitude":43.39,"longitude":-87.88,
                        "current":"us_aqi,pm10,pm2_5,carbon_monoxide,nitrogen_dioxide,ozone,dust",
                        "domains":"cams_global"}, timeout=10)
            d = r.json().get("current",{})
            aqi = d.get("us_aqi",0)
            if aqi<=50:    cat,color="Good","#4caf50"
            elif aqi<=100: cat,color="Moderate","#ffeb3b"
            elif aqi<=150: cat,color="Unhealthy (Sensitive)","#ff9800"
            elif aqi<=200: cat,color="Unhealthy","#f44336"
            elif aqi<=300: cat,color="Very Unhealthy","#9c27b0"
            else:          cat,color="Hazardous","#7b0000"
            cache_set("airnow", {"aqi":aqi,"category":cat,"color":color,
                                  "pm25":round(d.get("pm2_5",0),1),"pm10":round(d.get("pm10",0),1),
                                  "ozone":round(d.get("ozone",0),1),"no2":round(d.get("nitrogen_dioxide",0),1),
                                  "co":round(d.get("carbon_monoxide",0),0),"time":d.get("time",""),
                                  "fetched":datetime.datetime.now().strftime("%H:%M:%S")})
        except: pass

    # SWPC space weather — daily only
    if not cache_get("swpc", CACHE_TTL_DAY):
        try:
            swpc_result = {"kp":None,"solar_wind":{},"alerts":[],
                           "fetched":datetime.datetime.now().strftime("%H:%M:%S")}
            r = requests.get("https://services.swpc.noaa.gov/json/planetary_k_index_1m.json",timeout=10)
            kp_data = r.json()
            recent = [d for d in kp_data if d.get("estimated_kp") is not None]
            if recent:
                latest = recent[-1]; kp = latest.get("estimated_kp",0)
                swpc_result["kp"] = round(kp,2); swpc_result["kp_tag"] = latest.get("kp","")
                if kp<4:   swpc_result["kp_label"],swpc_result["kp_color"]="Quiet","#4caf50"
                elif kp<5: swpc_result["kp_label"],swpc_result["kp_color"]="Active","#ffeb3b"
                elif kp<6: swpc_result["kp_label"],swpc_result["kp_color"]="G1 — Minor Storm","#ff9800"
                elif kp<7: swpc_result["kp_label"],swpc_result["kp_color"]="G2 — Moderate Storm","#ff5722"
                elif kp<8: swpc_result["kp_label"],swpc_result["kp_color"]="G3 — Strong Storm","#f44336"
                elif kp<9: swpc_result["kp_label"],swpc_result["kp_color"]="G4 — Severe Storm","#9c27b0"
                else:      swpc_result["kp_label"],swpc_result["kp_color"]="G5 — EXTREME STORM","#cc0000"
            r2 = requests.get("https://services.swpc.noaa.gov/text/3-day-forecast.txt",timeout=10)
            txt = r2.text
            issued_m = re.search(r":Issued:\s*(.+)",txt)
            swpc_result["forecast_issued"] = issued_m.group(1).strip() if issued_m else ""
            max_kp_m = re.search(r"greatest expected 3 hr Kp.*?is\s+([\d.]+)\s*\(NOAA Scale\s+(\w+)\)",txt,re.IGNORECASE)
            swpc_result["forecast_max_kp"] = max_kp_m.group(1) if max_kp_m else ""
            swpc_result["forecast_max_scale"] = max_kp_m.group(2) if max_kp_m else ""
            rat_m = re.search(r"Rationale:\s*(.+?)(?:\n\n|\Z)",txt,re.DOTALL)
            swpc_result["forecast_rationale"] = rat_m.group(1).strip().replace("\n"," ") if rat_m else ""
            scale = swpc_result.get("forecast_max_scale","")
            if scale in ("G3","G4","G5"): swpc_result["forecast_color"]="#f44336"
            elif scale in ("G1","G2"):    swpc_result["forecast_color"]="#ff9800"
            else:                         swpc_result["forecast_color"]="#4caf50"
            # SANS ISC
            try:
                f = feedparser.parse("https://isc.sans.edu/rssfeed_full.xml")
                swpc_result["sans_isc"] = [{"title":e.get("title",""),"link":e.get("link","#"),
                                             "summary":re.sub(r"<[^>]+>","",e.get("summary",""))[:300],
                                             "published":e.get("published","")[:25]} for e in f.entries[:8]]
            except: swpc_result["sans_isc"] = []
            # Krebs on Security
            try:
                f = feedparser.parse("https://krebsonsecurity.com/feed/")
                swpc_result["krebs"] = [{"title":e.get("title",""),"link":e.get("link","#"),
                                          "summary":re.sub(r"<[^>]+>","",e.get("summary",""))[:300],
                                          "published":e.get("published","")[:25]} for e in f.entries[:8]]
            except: swpc_result["krebs"] = []
            # BleepingComputer — use requests to bypass feedparser's UA
            try:
                _bc_r = requests.get("https://www.bleepingcomputer.com/feed/", timeout=15,
                                     headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"})
                _bc_f = feedparser.parse(_bc_r.content)
                swpc_result["bleeping"] = [{"title":e.get("title",""),"link":e.get("link","#"),
                                             "summary":re.sub(r"<[^>]+>","",e.get("summary",""))[:200],
                                             "published":e.get("published","")[:25]} for e in _bc_f.entries[:8]]
            except: swpc_result["bleeping"] = []
            # The Hacker News
            try:
                _thn_r = requests.get("https://feeds.feedburner.com/TheHackersNews", timeout=15,
                                      headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"})
                _thn_f = feedparser.parse(_thn_r.content)
                swpc_result["thn"] = [{"title":e.get("title",""),"link":e.get("link","#"),
                                        "summary":re.sub(r"<[^>]+>","",e.get("summary",""))[:200],
                                        "published":e.get("published","")[:25]} for e in _thn_f.entries[:8]]
            except: swpc_result["thn"] = []
            cache_set("swpc", swpc_result)
        except: pass

    # GLERL Lake Michigan images — download fresh copies every 6 hours (or on force)
    try:
        cache_key = _glerl_cache_key()
        glerl_images = ["temp", "btemp", "uv", "zeta", "wnd", "glsea"]
        for img_name in glerl_images:
            disk_path = os.path.join(DISK_CACHE_DIR, f"glerl_{img_name}_{cache_key}.png")
            if force or not os.path.exists(disk_path):
                try:
                    r = requests.get(f"https://www.glerl.noaa.gov/res/glcfs/mih/{img_name}.png",
                                     timeout=20, headers={"User-Agent": "Mozilla/5.0"})
                    if r.status_code == 200:
                        with open(disk_path, "wb") as f:
                            f.write(r.content)
                        # Clean up older blocks
                        for old in os.listdir(DISK_CACHE_DIR):
                            if old.startswith(f"glerl_{img_name}_") and old != f"glerl_{img_name}_{cache_key}.png":
                                try: os.remove(os.path.join(DISK_CACHE_DIR, old))
                                except: pass
                        app.logger.info(f"[GLERL] Downloaded {img_name}.png ({cache_key})")
                except Exception as e:
                    app.logger.warning(f"[GLERL] Failed {img_name}: {e}")
    except Exception as e:
        app.logger.warning(f"[GLERL] Warm cache error: {e}")

    # Earthquakes — daily only
    if not cache_get("quakes", CACHE_TTL_DAY):
        try:
            data = requests.get("https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/significant_week.geojson",timeout=10).json()
            import zoneinfo as _zi; _ct = _zi.ZoneInfo("America/Chicago")
            def _fqt(ms):
                d = datetime.datetime.fromtimestamp(ms/1000, tz=datetime.timezone.utc).astimezone(_ct)
                return d.strftime("%Y-%m-%d ") + d.strftime("%I:%M %p").lstrip("0") + " CT"
            quakes = [{"place":f["properties"].get("place",""),"mag":f["properties"].get("mag",0),
                       "time":_fqt(f["properties"]["time"]),
                       "url":f["properties"].get("url","#")} for f in data.get("features",[])[:10]]
            cache_set("quakes", {"earthquakes":quakes,"fetched":datetime.datetime.now().strftime("%H:%M:%S")})
        except: pass

    # Stocks — parallel fetch (kept in sync with api_stocks symbol list)
    try:
        symbols = [
            ("S&P 500","^GSPC"),("Dow Jones","^DJI"),("NASDAQ","^IXIC"),("Russell 2000","^RUT"),("VIX","^VIX"),
            ("Nikkei 225","^N225"),("FTSE 100","^FTSE"),("DAX","^GDAXI"),("Hang Seng","^HSI"),
            ("Oil (WTI)","CL=F"),("Brent Crude","BZ=F"),("Gold","GC=F"),
            ("Silver","SI=F"),("Copper","HG=F"),("Nat Gas","NG=F"),
            ("Bitcoin","BTC-USD"),("Ethereum","ETH-USD"),("10Y Treasury","^TNX"),
            ("EUR/USD","EURUSD=X"),("GBP/USD","GBPUSD=X"),("USD/JPY","JPY=X"),
            ("USD/CAD","CAD=X"),("AUD/USD","AUD=X"),("USD Index","DX-Y.NYB"),
        ]
        def _fetch_sym(name, sym):
            try:
                r = requests.get(f"https://query1.finance.yahoo.com/v8/finance/chart/{sym}",
                    params={"interval":"1d","range":"2d"}, headers={"User-Agent":"Mozilla/5.0"}, timeout=6)
                meta = r.json()["chart"]["result"][0]["meta"]
                price = meta.get("regularMarketPrice",0); prev = meta.get("chartPreviousClose",price)
                chg = price-prev; pct = (chg/prev*100) if prev else 0
                return {"name":name,"price":round(price,2),"change":round(chg,2),"pct":round(pct,2)}
            except Exception as e:
                app.logger.warning("[warm_cache] stock %s failed: %s", sym, e)
                return {"name":name,"price":0,"change":0,"pct":0}
        stock_data = [None] * len(symbols)
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = {ex.submit(_fetch_sym, n, s): i for i, (n, s) in enumerate(symbols)}
            for fut in as_completed(futs):
                stock_data[futs[fut]] = fut.result()
        cache_set("stocks", {"stocks": stock_data, "fetched": _ts()})
    except Exception as e:
        app.logger.warning("[warm_cache] stocks failed: %s", e)

    # Wisconsin Burn Ban — 30-min TTL
    if force or not cache_get("burn_ban", 1800):
        try:
            r = requests.get("https://apps.dnr.wi.gov/forestryapps/burnrestriction/json/",
                             timeout=10, headers=hdrs)
            if r.status_code == 200:
                data = r.json(); counties = []; ozaukee = None
                for entry in data:
                    c = {"name": entry.get("COUNTY_NAME","").title(),
                         "danger": entry.get("DANGER_RATING_NAME",""),
                         "danger_code": entry.get("DANGER_RATING_CODE",0),
                         "color": entry.get("DANGER_RATING_COLOR",""),
                         "restricted": bool(entry.get("PERMIT_RESTRICTIONS")),
                         "comments": entry.get("ADDITIONAL_COMMENTS","") or ""}
                    counties.append(c)
                    if "OZAUKEE" in entry.get("COUNTY_NAME","").upper(): ozaukee = c
                counties.sort(key=lambda x: x["danger_code"], reverse=True)
                cache_set("burn_ban", {"ozaukee": ozaukee, "all": counties,
                    "high_danger": [c for c in counties if c["danger_code"] >= 4],
                    "fetched": _ts()})
        except Exception as e:
            app.logger.warning("[warm_cache] burn_ban: %s", e)

    # Presidential Intel — 24hr TTL; scraped on first daily request, no warm_cache needed

    # Congress Status — 1-hr TTL
    if force or not cache_get("congress_status", 3600):
        try:
            import urllib.parse as _up
            bill_queries = [
                ("House Bill",      "House bill legislation passed 2026"),
                ("Senate Bill",     "Senate bill legislation passed 2026"),
                ("Congress",        "Congress legislation vote 2026"),
                ("Budget/Spending", "federal budget appropriations spending bill 2026"),
            ]
            bills = []
            for label, query in bill_queries:
                try:
                    url = f"https://news.google.com/rss/search?q={_up.quote(query)}&hl=en-US&gl=US&ceid=US:en"
                    parsed = feedparser.parse(url)
                    for e in parsed.entries[:4]:
                        pub = e.get("published", e.get("updated",""))
                        bills.append({"title": e.get("title","")[:140], "link": e.get("link","#"),
                                      "date": pub[:10] if pub else "", "date_raw": pub, "source": label})
                except Exception: pass
            seen2 = set(); deduped2 = []
            for b in sorted(bills, key=lambda x: x.get("date_raw",""), reverse=True):
                k = b["title"][:60].lower()
                if k not in seen2: seen2.add(k); deduped2.append(b)
            now2 = datetime.datetime.now(); today2 = datetime.date.today()
            month2, day2 = now2.month, now2.day
            _recess_periods2 = [
                ((1,1),(1,6),"New Year Recess"),((2,14),(2,25),"Presidents Day Recess"),
                ((4,11),(4,28),"Spring Recess"),((5,26),(6,2),"Memorial Day Recess"),
                ((7,4),(7,7),"Independence Day Recess"),((7,31),(9,7),"August Recess"),
                ((11,24),(12,1),"Thanksgiving Recess"),((12,19),(1,3),"Christmas/New Year Recess"),
            ]
            in_recess2 = False; recess_lbl2 = ""; next_sess2 = ""
            for (_sm,_sd),(_em,_ed),_lbl2 in _recess_periods2:
                if (month2,day2)>=(_sm,_sd) and (month2,day2)<=(_em,_ed):
                    in_recess2 = True; recess_lbl2 = _lbl2
                    try:
                        _ey = today2.year if _em >= _sm else today2.year+1
                        _rd = datetime.date(_ey,_em,_ed)+datetime.timedelta(days=1)
                        next_sess2 = _rd.strftime("%A, %B %-d")
                    except Exception: pass
                    break
            cache_set("congress_status", {
                "bills": deduped2[:16], "in_session": not in_recess2,
                "session_label": recess_lbl2 if in_recess2 else "119th Congress — In Session",
                "next_session_date": next_sess2,
                "congress": "119th",
                "seats": {"senate": {"R":53,"D":45,"I":2,"total":100},
                          "house":  {"R":220,"D":213,"vacant":2,"total":435}},
                "fetched": _ts(), "congress_url": "https://www.congress.gov/",
                "votes_url": "https://www.congress.gov/roll-call-votes"})
        except Exception as e:
            app.logger.warning("[warm_cache] congress_status: %s", e)

    # Ozaukee Alerts — 5-min TTL
    if force or not cache_get("ozaukee_alerts", 300):
        try:
            r = requests.get("https://api.weather.gov/alerts/active?zone=WIC089",
                             timeout=10, headers={**hdrs, "Accept": "application/geo+json"})
            if r.status_code == 200:
                features = r.json().get("features",[])
                alerts = [{"event": f["properties"].get("event",""),
                           "headline": f["properties"].get("headline",""),
                           "severity": f["properties"].get("severity",""),
                           "expires": f["properties"].get("expires","")}
                          for f in features]
                cache_set("ozaukee_alerts", {"alerts": alerts, "count": len(alerts), "fetched": _ts()})
        except Exception as e:
            app.logger.warning("[warm_cache] ozaukee_alerts: %s", e)

    # Polls — 1-hr TTL (use same parallel logic as main endpoint)
    if force or not cache_get("polls", 3600):
        try:
            _poll_feeds = [
                ("Politico","https://rss.politico.com/politics-news.xml"),
                ("The Hill","https://thehill.com/feed/"),
                ("NPR","https://feeds.npr.org/1001/rss.xml"),
                ("FiveThirtyEight","https://fivethirtyeight.com/features/feed/"),
                ("AP Politics","https://feeds.apnews.com/rss/apf-politics"),
                ("RCP","https://www.realclearpolitics.com/rss/rss_politic.xml"),
            ]
            _kw = ("poll","survey","approval","favorability","generic ballot","midterm race")
            def _wpf(lbl, url):
                items = []
                try:
                    f = feedparser.parse(url)
                    for e in f.entries[:25]:
                        t = e.get("title","")
                        if any(w in t.lower() for w in _kw):
                            items.append({"title":t[:140],"link":e.get("link","#"),
                                         "published":e.get("published","")[:16],"source":lbl})
                            if len(items) >= 4: break
                except Exception: pass
                return items
            _raw = []
            with ThreadPoolExecutor(max_workers=6) as _ex:
                _futs = {_ex.submit(_wpf, l, u): l for l, u in _poll_feeds}
                for _ft in as_completed(_futs): _raw.extend(_ft.result())
            _seen = set(); _dedup = []
            for _it in sorted(_raw, key=lambda x: x.get("published",""), reverse=True):
                _k = _it["title"][:60].lower()
                if _k not in _seen: _seen.add(_k); _dedup.append(_it)
                if len(_dedup) >= 20: break
            cache_set("polls", {"polls":[], "news": _dedup,
                "aggregators":[
                    {"name":"FiveThirtyEight/ABC","url":"https://projects.fivethirtyeight.com/polls/"},
                    {"name":"RealClearPolitics","url":"https://www.realclearpolitics.com/epolls/latest_polls/"},
                    {"name":"Ballotpedia","url":"https://ballotpedia.org/Polling_averages"},
                    {"name":"Kalshi Elections","url":"https://kalshi.com/markets/elections"},
                    {"name":"Cook Political Report","url":"https://www.cookpolitical.com/ratings"},
                    {"name":"Sabato's Crystal Ball","url":"https://centerforpolitics.org/crystalball/"},
                ], "fetched": _ts()})
        except Exception as e:
            app.logger.warning("[warm_cache] polls: %s", e)

    # F1 — 1-hr TTL
    if force or not cache_get("f1", 3600):
        try:
            _f1h = {"User-Agent": "KEVSec/1.0"}
            def _f1get(url):
                return requests.get(url, headers=_f1h, timeout=10).json()
            ds = _f1get("https://api.jolpi.ca/ergast/f1/current/driverStandings.json")
            cs = _f1get("https://api.jolpi.ca/ergast/f1/current/constructorStandings.json")
            sc = _f1get("https://api.jolpi.ca/ergast/f1/current.json")
            lr = _f1get("https://api.jolpi.ca/ergast/f1/current/last/results.json")
            _ds = ds["MRData"]["StandingsTable"]["StandingsLists"]
            driver_standings = [{"pos":int(r["position"]),"name":r["Driver"]["givenName"]+" "+r["Driver"]["familyName"],
                "team":r["Constructors"][0]["name"] if r.get("Constructors") else "","points":float(r["points"]),"wins":int(r["wins"])}
                for r in (_ds[0]["DriverStandings"] if _ds else [])]
            _cs = cs["MRData"]["StandingsTable"]["StandingsLists"]
            ctor_standings = [{"pos":int(r["position"]),"name":r["Constructor"]["name"],
                "points":float(r["points"]),"wins":int(r["wins"])}
                for r in (_cs[0]["ConstructorStandings"] if _cs else [])]
            races = sc["MRData"]["RaceTable"].get("Races",[])
            today_str = datetime.date.today().isoformat()
            upcoming = [{"round":int(r["round"]),"name":r["raceName"],"date":r["date"],
                "time":r.get("time","")[:5],"location":r["Circuit"]["Location"]["locality"],
                "circuit":r["Circuit"]["circuitName"]}
                for r in races if r["date"] >= today_str][:2]
            last_races = lr["MRData"]["RaceTable"].get("Races",[])
            last_result = {}
            if last_races:
                lr2 = last_races[0]; results = lr2.get("Results",[])
                podium = [{"pos":int(r["position"]),"name":r["Driver"]["givenName"]+" "+r["Driver"]["familyName"],
                    "team":r["Constructor"]["name"],"time":r.get("Time",{}).get("time","")}
                    for r in results[:3]]
                last_result = {"name":lr2["raceName"],"date":lr2["date"],"podium":podium}
            cache_set("f1", {"driver_standings":driver_standings,"constructor_standings":ctor_standings,
                "upcoming":upcoming,"last_result":last_result,
                "season":datetime.date.today().year,"fetched":_ts()})
        except Exception as e:
            app.logger.warning("[warm_cache] f1: %s", e)

    # CVEs — 6hr TTL (recency-weighted sort)
    if force or not cache_get("cves", CACHE_TTL_LONG):
        try:
            _now = datetime.datetime.utcnow()
            _ps = (_now - datetime.timedelta(days=21)).strftime("%Y-%m-%dT00:00:00.000")
            _pe = _now.strftime("%Y-%m-%dT23:59:59.999")
            _bp = {"pubStartDate": _ps, "pubEndDate": _pe}
            def _fc(sev, n):
                _r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                                  params={**_bp, "cvssV3Severity": sev, "resultsPerPage": n}, timeout=15)
                _items = []
                for _item in _r.json().get("vulnerabilities", []):
                    _cve = _item.get("cve", {}); _m = _cve.get("metrics", {})
                    _desc = _cve.get("descriptions", [{}])[0].get("value", "")[:200]
                    _score, _sev = 0, sev
                    for _k in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                        if _m.get(_k):
                            _score = _m[_k][0]["cvssData"]["baseScore"]
                            _sev = _m[_k][0]["cvssData"].get("baseSeverity", sev); break
                    _items.append({"id": _cve.get("id",""), "desc": _desc, "score": _score,
                                   "severity": _sev, "published": _cve.get("published","")[:10],
                                   "epss": None, "epss_pct": None})
                return _items
            _all = _fc("CRITICAL", 10) + _fc("HIGH", 15)
            for _c in _all:
                try:
                    _pd = datetime.datetime.strptime(_c["published"], "%Y-%m-%d")
                    _days = (_now - _pd).days
                except Exception:
                    _days = 21
                _rb = 3.0 if _days <= 3 else (2.0 if _days <= 7 else (1.0 if _days <= 14 else 0.0))
                _c["_sort_score"] = _c["score"] + _rb
            _seen2 = set(); _cves2 = []
            for _c in sorted(_all, key=lambda x: x["_sort_score"], reverse=True):
                if _c["id"] not in _seen2: _seen2.add(_c["id"]); _cves2.append(_c)
            _cves2 = _cves2[:20]
            try:
                _ids = ",".join(_c["id"] for _c in _cves2 if _c["id"])
                _er = requests.get("https://api.first.org/data/v1/epss", params={"cve": _ids}, timeout=10)
                _em = {_e["cve"]: _e for _e in _er.json().get("data", [])}
                for _c in _cves2:
                    if _c["id"] in _em:
                        _c["epss"] = round(float(_em[_c["id"]].get("epss",0))*100,2)
                        _c["epss_pct"] = round(float(_em[_c["id"]].get("percentile",0))*100,1)
            except: pass
            cache_set("cves", {"cves": _cves2, "fetched": _ts()})
        except Exception as e:
            app.logger.warning("[warm_cache] cves: %s", e)

    # GDACS Global Disasters — 1hr TTL
    if force or not cache_get("gdacs", 3600):
        try:
            _gf = feedparser.parse("https://www.gdacs.org/xml/rss.xml")
            _gevents = []
            for _ge in _gf.entries[:20]:
                _gt = _ge.get("title",""); _gp = _ge.get("published","")[:10]
                _gal = _ge.get("gdacs_alertlevel",""); _gety = _ge.get("gdacs_eventtype","")
                _gco = _ge.get("gdacs_country","")
                if not _gety:
                    for _kw in ["Earthquake","Tropical Cyclone","Flood","Volcano","Drought","Wildfire"]:
                        if _kw.lower() in _gt.lower(): _gety = _kw; break
                _gico = {"Earthquake":"🌍","Tropical Cyclone":"🌀","Flood":"🌊",
                          "Volcano":"🌋","Drought":"🏜","Wildfire":"🔥"}.get(_gety,"⚠")
                _gcol = {"Red":"#cc3333","Orange":"#cc7700","Green":"#4a9c4a"}.get(_gal,"#888")
                _gevents.append({"title":_gt,"link":_ge.get("link","#"),"date":_gp,
                                  "alert":_gal,"type":_gety,"country":_gco,
                                  "icon":_gico,"color":_gcol})
            cache_set("gdacs", {"events": _gevents, "fetched": _ts()})
        except Exception as e:
            app.logger.warning("[warm_cache] gdacs: %s", e)

    # Govt Intel (FBI/CENTCOM/DOJ/State/Pentagon/DHS) — 2hr TTL
    if force or not cache_get("govt_intel", 7200):
        try:
            _gi_feeds = [
                ("FBI",       "https://www.fbi.gov/feeds/fbi-in-the-news/rss.xml"),
                ("CENTCOM",   "https://news.google.com/rss/search?q=CENTCOM+military+operations+US+Central+Command&hl=en-US&gl=US&ceid=US:en"),
                ("DOJ",       "https://news.google.com/rss/search?q=%22Department+of+Justice%22+press+release+indicted+charged&hl=en-US&gl=US&ceid=US:en"),
                ("State Dept","https://news.google.com/rss/search?q=%22State+Department%22+%22Secretary+Rubio%22+OR+%22foreign+policy%22+US+diplomacy&hl=en-US&gl=US&ceid=US:en"),
                ("Pentagon",  "https://news.google.com/rss/search?q=Pentagon+%22Department+of+Defense%22+military+budget+troops&hl=en-US&gl=US&ceid=US:en"),
                ("DHS",       "https://news.google.com/rss/search?q=%22Department+of+Homeland+Security%22+OR+%22Secretary+Noem%22+border+immigration&hl=en-US&gl=US&ceid=US:en"),
            ]
            _gi_items = []
            for _gs, _gu in _gi_feeds:
                try:
                    _gf = feedparser.parse(_gu)
                    for _ge in _gf.entries[:5]:
                        _gp = _ge.get("published", _ge.get("updated",""))
                        _gi_items.append({"source":_gs,"title":_ge.get("title","")[:140],
                                          "link":_ge.get("link","#"),"date":_gp[:10] if _gp else "",
                                          "date_raw":_gp,
                                          "summary":re.sub(r"<[^>]+>","",_ge.get("summary",""))[:180]})
                except Exception: pass
            _gis = set(); _gid = []
            for _gi in sorted(_gi_items, key=lambda x: x.get("date_raw",""), reverse=True):
                _gk = _gi["title"][:60].lower()
                if _gk not in _gis: _gis.add(_gk); _gid.append(_gi)
                if len(_gid) >= 40: break
            cache_set("govt_intel", {"items": _gid, "fetched": _ts()})
        except Exception as e:
            app.logger.warning("[warm_cache] govt_intel: %s", e)

def _schedule_daily_refresh():
    """Sleep until 06:00 local time then run _warm_cache(force=True) every 24h."""
    while True:
        now = datetime.datetime.now()
        target = now.replace(hour=6, minute=0, second=0, microsecond=0)
        if now >= target:
            target += datetime.timedelta(days=1)
        sleep_secs = (target - now).total_seconds()
        app.logger.info(f"[SCHEDULER] Next refresh in {sleep_secs/3600:.1f}h at {target.strftime('%Y-%m-%d %H:%M')}")
        time.sleep(sleep_secs)
        app.logger.info("[SCHEDULER] Running daily 06:00 cache refresh (forced)")
        _warm_cache(force=True)


# ── Spotify OAuth for DJ Atticus ─────────────────────────────────────────────
import base64, urllib.parse

SPOTIFY_CLIENT_ID     = "5a47aaeae39d45c092986e5ea0d419fd"
SPOTIFY_CLIENT_SECRET = "86e0076e3a1443088971bda52f82d8d2"
SPOTIFY_REDIRECT_URI  = os.environ.get("SPOTIFY_REDIRECT_URI", "")
SPOTIFY_TOKEN_FILE    = "/opt/dj-atticus/spotify_token.json"
SPOTIFY_CONF_FILE     = "/opt/dj-atticus/spotifyd.conf"

def _spotify_update_token(access_token, refresh_token, expires_in):
    import time
    token_data = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": time.time() + expires_in - 60
    }
    with open(SPOTIFY_TOKEN_FILE, "w") as f:
        json.dump(token_data, f)
    # Re-write spotifyd.conf with new token
    try:
        with open(SPOTIFY_CONF_FILE, "r") as f:
            conf = f.read()
        # Remove old password/token lines only — keep username (required for token auth)
        lines = []
        for line in conf.splitlines():
            stripped = line.strip()
            if stripped.startswith("password") or stripped.startswith("token"):
                continue
            lines.append(line)
        # Insert token after [global]
        output = []
        for line in lines:
            output.append(line)
            if line.strip() == "[global]":
                output.append(f'token = "{access_token}"')
        with open(SPOTIFY_CONF_FILE, "w") as f:
            f.write("\n".join(output) + "\n")
        subprocess.run(["sudo", "systemctl", "restart", "dj-atticus"], check=False)
        app.logger.info("[SPOTIFY] Token updated, dj-atticus restarted")
    except Exception as e:
        app.logger.error(f"[SPOTIFY] Failed to update spotifyd.conf: {e}")

@app.route("/spotify-auth")
@login_required
def spotify_auth():
    state = secrets.token_hex(16)
    session["spotify_state"] = state
    params = {
        "client_id": SPOTIFY_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": SPOTIFY_REDIRECT_URI,
        "state": state,
        "scope": "streaming user-read-playback-state user-modify-playback-state user-read-private",
    }
    return redirect("https://accounts.spotify.com/authorize?" + urllib.parse.urlencode(params))

@app.route("/spotify-callback")
def spotify_callback():
    error = request.args.get("error")
    if error:
        return f"<h2>Spotify auth denied: {error}</h2>", 400
    code = request.args.get("code", "")
    if not code:
        return "<h2>No code returned from Spotify</h2>", 400
    try:
        creds_b64 = base64.b64encode(
            f"{SPOTIFY_CLIENT_ID}:{SPOTIFY_CLIENT_SECRET}".encode()).decode()
        resp = requests.post(
            "https://accounts.spotify.com/api/token",
            headers={"Authorization": f"Basic {creds_b64}",
                     "Content-Type": "application/x-www-form-urlencoded"},
            data={"grant_type": "authorization_code",
                  "code": code,
                  "redirect_uri": SPOTIFY_REDIRECT_URI},
            timeout=10
        )
        if not resp.ok:
            return f"<h2>Token exchange failed: {resp.status_code}<br><pre>{resp.text}</pre></h2>", 500
        tokens = resp.json()
        _spotify_update_token(
            tokens["access_token"], tokens.get("refresh_token", ""), tokens.get("expires_in", 3600))
        return "<h2>✅ DJ Atticus authorized! Spotify Connect is now active.<br><a href='/'>Return to dashboard</a></h2>"
    except Exception as e:
        app.logger.error(f"[SPOTIFY] Callback error: {e}", exc_info=True)
        return f"<h2>Error: {e}</h2>", 500

@app.route("/api/spotify_refresh", methods=["POST"])
@login_required
def api_spotify_refresh():
    if not os.path.exists(SPOTIFY_TOKEN_FILE):
        return jsonify({"error": "No token file — authorize first"}), 400
    with open(SPOTIFY_TOKEN_FILE) as f:
        data = json.load(f)
    refresh_token = data.get("refresh_token", "")
    if not refresh_token:
        return jsonify({"error": "No refresh token stored"}), 400
    creds_b64 = base64.b64encode(
        f"{SPOTIFY_CLIENT_ID}:{SPOTIFY_CLIENT_SECRET}".encode()).decode()
    resp = requests.post(
        "https://accounts.spotify.com/api/token",
        headers={"Authorization": f"Basic {creds_b64}",
                 "Content-Type": "application/x-www-form-urlencoded"},
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        timeout=10
    )
    if not resp.ok:
        return jsonify({"error": resp.text}), 500
    tokens = resp.json()
    _spotify_update_token(
        tokens["access_token"],
        tokens.get("refresh_token", refresh_token),
        tokens.get("expires_in", 3600))
    return jsonify({"ok": True, "expires_in": tokens.get("expires_in", 3600)})

@app.route("/api/spotify_status")
@login_required
def api_spotify_status():
    if not os.path.exists(SPOTIFY_TOKEN_FILE):
        return jsonify({"authorized": False})
    import time
    with open(SPOTIFY_TOKEN_FILE) as f:
        data = json.load(f)
    expires_at = data.get("expires_at", 0)
    return jsonify({
        "authorized": True,
        "expired": time.time() > expires_at,
        "expires_in": max(0, int(expires_at - time.time()))
    })

if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(NOTES_DIR, exist_ok=True)
    if not os.path.exists(NOTEPAD_FILE):
        open(NOTEPAD_FILE,"w").close()
    if not os.path.exists(REMINDERS_FILE):
        with open(REMINDERS_FILE,"w") as f:
            json.dump([],f)
    # Seed notes library from notepad.txt if no notes exist yet
    if not any(f.endswith((".txt",".md")) for f in os.listdir(NOTES_DIR)):
        try:
            with open(NOTEPAD_FILE, encoding="utf-8") as f:
                notepad_content = f.read().strip()
            if notepad_content:
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                seed_path = os.path.join(NOTES_DIR, f"{ts}_Notepad_Import.txt")
                with open(seed_path, "w", encoding="utf-8") as f:
                    f.write(notepad_content)
                app.logger.info(f"[NOTES] Seeded notes library from notepad.txt → {seed_path}")
        except Exception as e:
            app.logger.warning(f"[NOTES] Seed failed: {e}")
    threading.Thread(target=_warm_cache, daemon=True).start()
    threading.Thread(target=_schedule_daily_refresh, daemon=True).start()
    app.run(host="127.0.0.1", port=5555, debug=False)
