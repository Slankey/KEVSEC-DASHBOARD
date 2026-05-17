#!/opt/kevsec-dashboard/venv/bin/python3
"""
president_intel_worker.py
Standalone cron worker that fetches presidential intelligence data (White House
RSS feeds + Google News) and writes it to the dashboard disk cache so the page
loads instantly without triggering a live fetch.

Cron: 0 6 * * * slankey /opt/kevsec-dashboard/scripts/president_intel_worker.py
"""

import json
import os
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import feedparser
except ImportError:
    print("feedparser not installed — run: pip install feedparser", file=sys.stderr)
    sys.exit(1)

DISK_CACHE_DIR = "/opt/kevsec-dashboard/data/cache"
CACHE_FILE = os.path.join(DISK_CACHE_DIR, "president_intel.json")

WH_FEEDS = [
    ("WH Actions",  "action",  "https://www.whitehouse.gov/presidential-actions/feed/"),
    ("WH News",     "news",    "https://www.whitehouse.gov/news/feed/"),
    ("WH Remarks",  "remarks", "https://www.whitehouse.gov/remarks/feed/"),
]

GNEWS_QUERIES = [
    ("Schedule",  "Trump presidential schedule today 2026"),
    ("Activity",  "Trump White House meeting signed today 2026"),
    ("Roll Call", "site:rollcall.com Trump 2026"),
]


def _ts():
    import zoneinfo
    ct = datetime.now(tz=zoneinfo.ZoneInfo("America/Chicago"))
    return ct.strftime("%H:%M %Z")


def fetch_wh_feed(label, kind, url):
    out = []
    try:
        feed = feedparser.parse(url)
        for e in feed.entries[:8]:
            pub = getattr(e, "published", None) or getattr(e, "updated", None) or ""
            summary = re.sub(r"<[^>]+>", " ", e.get("summary", "") or "").strip()
            summary = re.sub(r"\s{2,}", " ", summary)[:200]
            out.append({
                "title":   e.get("title", "")[:160],
                "url":     e.get("link", ""),
                "date":    pub[:16] if pub else "",
                "summary": summary,
                "source":  label,
                "kind":    kind,
            })
    except Exception as ex:
        print(f"WH feed {label} failed: {ex}", file=sys.stderr)
    return out


def fetch_gnews(label, q):
    out = []
    try:
        url = f"https://news.google.com/rss/search?q={urllib.parse.quote(q)}&hl=en-US&gl=US&ceid=US:en"
        feed = feedparser.parse(url)
        for e in feed.entries[:5]:
            pub = getattr(e, "published", None) or ""
            out.append({
                "title":   e.get("title", "")[:160],
                "url":     e.get("link", ""),
                "date":    pub[:16] if pub else "",
                "summary": "",
                "source":  label,
                "kind":    "news",
            })
    except Exception as ex:
        print(f"GNews {label} failed: {ex}", file=sys.stderr)
    return out


def main():
    os.makedirs(DISK_CACHE_DIR, exist_ok=True)

    items = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = (
            [ex.submit(fetch_wh_feed, lbl, kind, url) for lbl, kind, url in WH_FEEDS] +
            [ex.submit(fetch_gnews, lbl, q) for lbl, q in GNEWS_QUERIES]
        )
        for fut in as_completed(futs):
            try:
                items.extend(fut.result())
            except Exception as ex_err:
                print(f"future error: {ex_err}", file=sys.stderr)

    if not items:
        print("No items fetched — aborting cache write", file=sys.stderr)
        sys.exit(1)

    seen = set()
    deduped = []
    for it in sorted(items, key=lambda x: x.get("date", ""), reverse=True):
        key = it["title"][:50].lower().strip()
        if key not in seen:
            seen.add(key)
            deduped.append(it)

    result = {
        "schedule":     [],
        "items":        deduped[:30],
        "fetched":      _ts(),
        "schedule_url": "https://www.whitehouse.gov/news/",
    }

    payload = {"_cached_at": time.time(), "_data": result}
    with open(CACHE_FILE, "w") as f:
        json.dump(payload, f)

    print(f"[{datetime.now().isoformat()}] president_intel: wrote {len(deduped)} items to {CACHE_FILE}")


if __name__ == "__main__":
    main()
