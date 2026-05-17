#!/opt/kevsec-dashboard/venv/bin/python3
"""
factbase_worker.py
Scrapes Roll Call / Factbase for presidential schedule (calendar),
Truth Social posts, and recent transcripts. Writes disk cache so the
dashboard panel loads instantly.

Cron: 30 */2 * * * ubuntu /opt/kevsec-dashboard/scripts/factbase_worker.py >> /mnt/hdd/logs/factbase.log 2>&1
"""

import json
import os
import re
import sys
import time
from datetime import datetime, date

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"Missing dep: {e} — run: pip install requests beautifulsoup4", file=sys.stderr)
    sys.exit(1)

DISK_CACHE_DIR = "/opt/kevsec-dashboard/data/cache"
CACHE_FILE = os.path.join(DISK_CACHE_DIR, "factbase.json")
BASE_URL = "https://rollcall.com/wp-json/factbase/v1"
HDRS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}


def _ts():
    import zoneinfo
    ct = datetime.now(tz=zoneinfo.ZoneInfo("America/Chicago"))
    return ct.strftime("%H:%M %Z")


def fetch_calendar():
    """Parse HTML calendar from Roll Call Factbase. Returns list of schedule events."""
    events = []
    try:
        r = requests.get(f"{BASE_URL}/calendar", headers=HDRS, timeout=20)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")

        # Each day is a <table> element
        tables = soup.find_all("table")
        today = date.today()
        days_collected = 0

        for tbl in tables:
            if days_collected >= 5:  # only grab last 5 days
                break
            # Header row = date
            header_row = tbl.find("tr")
            if not header_row:
                continue
            date_spans = header_row.find_all("span")
            day_name = date_spans[0].get_text(strip=True) if len(date_spans) > 0 else ""
            date_str  = date_spans[1].get_text(strip=True) if len(date_spans) > 1 else ""
            if not date_str:
                continue

            # Parse the date to decide if we care about it
            try:
                # e.g. "May 17 2026"
                day_date = datetime.strptime(date_str, "%B %d %Y").date()
            except ValueError:
                try:
                    day_date = datetime.strptime(date_str, "%b %d %Y").date()
                except ValueError:
                    day_date = None

            # Only include today and the next 3 days + yesterday
            if day_date and day_date < today:
                days_collected += 1
                if days_collected > 1:
                    continue

            day_events = []
            item_rows = tbl.find_all("tr")[1:]
            for row in item_rows:
                # Event type from dot title attribute
                dot = row.find("div", class_=lambda c: c and "rounded-full w-3 h-3" in str(c))
                ev_type = dot.get("title", "") if dot else ""

                # Time — find div with EXACTLY "text-sm font-light" (not the desc div which has more classes)
                time_divs = row.find_all("div", class_=lambda c: c == "text-sm font-light")
                time_str = time_divs[-1].get_text(strip=True) if time_divs else ""

                # Description
                desc_div = row.find("div", class_=lambda c: c and "text-gray-600" in str(c))
                if not desc_div:
                    continue
                # Remove duplicate text (the description is often doubled in mobile/desktop spans)
                desc_text = desc_div.get_text(separator=" ", strip=True)
                # Deduplicate doubled text (mobile + desktop versions both appear in get_text())
                m_dedup = re.match(r'^(.{8,}?)\s+\1$', desc_text, re.DOTALL)
                if m_dedup:
                    desc_text = m_dedup.group(1)
                desc_text = desc_text[:200]

                # Location and press access
                loc_spans = row.find_all("span", class_=lambda c: c and "text-[#333333]" in str(c))
                location = loc_spans[0].get_text(strip=True) if len(loc_spans) > 0 else ""
                press    = loc_spans[1].get_text(strip=True) if len(loc_spans) > 1 else ""

                # Transcript link
                link_el = row.find("a", href=True)
                transcript_url = link_el["href"] if link_el else ""

                day_events.append({
                    "type": ev_type,
                    "time": time_str,
                    "desc": desc_text,
                    "location": location,
                    "press": press,
                    "transcript_url": transcript_url,
                })

            if day_events:
                events.append({
                    "day": day_name,
                    "date": date_str,
                    "date_iso": day_date.isoformat() if day_date else "",
                    "events": day_events,
                })
                days_collected += 1

    except Exception as ex:
        print(f"[calendar] ERROR: {ex}", file=sys.stderr)

    return events


def fetch_social_posts():
    """Fetch latest Truth Social posts from Roll Call Factbase API."""
    posts = []
    try:
        r = requests.get(f"{BASE_URL}/twitter", headers={**HDRS, "Accept": "application/json"}, timeout=15)
        r.raise_for_status()
        data = r.json()
        for item in data.get("data", [])[:20]:
            text = item.get("text", "").strip()
            # Skip pure retweet/reshare stubs (no actual content)
            if text.startswith("RT: https://") and len(text) < 50:
                continue
            # Clean up RT prefix to show the URL separately
            rt_url = ""
            if text.startswith("RT: "):
                rt_url = text[4:].strip()
                text = item.get("social", {}).get("full_text", text)

            dt_str = item.get("date", "")
            # Parse and reformat date
            dt_display = ""
            if dt_str:
                try:
                    dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
                    import zoneinfo
                    dt_ct = dt.astimezone(zoneinfo.ZoneInfo("America/Chicago"))
                    dt_display = dt_ct.strftime("%-m/%-d %I:%M %p CT").lstrip("0")
                except Exception:
                    dt_display = dt_str[:16]

            social = item.get("social", {})
            posts.append({
                "text":       text[:400],
                "date":       dt_display,
                "date_raw":   dt_str,
                "platform":   item.get("platform", "Truth Social"),
                "post_url":   item.get("post_url", ""),
                "image_url":  item.get("image_url", ""),
                "rt_url":     rt_url,
                "reposts":    social.get("retweet_count", 0),
                "likes":      social.get("favorite_count", 0),
            })
    except Exception as ex:
        print(f"[social] ERROR: {ex}", file=sys.stderr)
    return posts


def fetch_latest_transcripts():
    """Scrape recent transcript links from the /latest HTML endpoint."""
    transcripts = []
    try:
        r = requests.post(f"{BASE_URL}/latest", headers=HDRS, timeout=15, data={})
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")

        # Find all blocks — each has a source label + title text + optional link
        blocks = soup.find_all("div", class_=lambda c: c and "mb-4 border" in str(c))
        for block in blocks[:10]:
            # Source line (YouTube, Twitter, etc.)
            src_div = block.find("div", class_=lambda c: c and "border-r" in str(c))
            source = src_div.get_text(strip=True) if src_div else ""
            source = re.sub(r"\s+", " ", source).strip()[:60]

            # Time ago
            time_divs = block.find_all("div", class_=lambda c: c and "text-md" in str(c))
            time_ago = ""
            for td in time_divs:
                t = td.get_text(strip=True)
                if "ago" in t or "hour" in t or "minute" in t or "day" in t:
                    time_ago = t
                    break

            # Main content / title
            content_div = block.find("div", class_=lambda c: c and "font-graphik text-" in str(c) and "text-[#2F3C4B" in str(c))
            if not content_div:
                content_div = block.find("div", class_=lambda c: c and "font-graphik" in str(c))
            title = content_div.get_text(strip=True)[:200] if content_div else ""

            # Link to transcript
            link_el = block.find("a", href=re.compile(r"rollcall\.com.*transcript"))
            url = link_el["href"] if link_el else ""

            if title:
                transcripts.append({
                    "source":   source,
                    "title":    title,
                    "time_ago": time_ago,
                    "url":      url,
                })
    except Exception as ex:
        print(f"[transcripts] ERROR: {ex}", file=sys.stderr)
    return transcripts


def main():
    os.makedirs(DISK_CACHE_DIR, exist_ok=True)

    print(f"[{datetime.now().isoformat()}] factbase_worker: starting fetch")

    calendar  = fetch_calendar()
    posts     = fetch_social_posts()
    transcripts = fetch_latest_transcripts()

    if not calendar and not posts and not transcripts:
        print("Nothing fetched — aborting cache write", file=sys.stderr)
        sys.exit(1)

    result = {
        "calendar":    calendar,
        "posts":       posts,
        "transcripts": transcripts,
        "fetched":     _ts(),
        "source_url":  "https://rollcall.com/factbase/donald-trump/",
    }
    payload = {"_cached_at": time.time(), "_data": result}
    with open(CACHE_FILE, "w") as f:
        json.dump(payload, f)

    print(f"[{datetime.now().isoformat()}] factbase_worker: wrote "
          f"{len(calendar)} calendar days, {len(posts)} posts, "
          f"{len(transcripts)} transcripts → {CACHE_FILE}")


if __name__ == "__main__":
    main()
