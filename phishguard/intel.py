"""Threat-intelligence lookups for links found in an email.

Offline (no key, works anywhere):
  * Phishing.Database feeds - github.com/mitchellkrogza/Phishing.Database
      phishing-domains-ACTIVE.txt, phishing-links-ACTIVE.txt
  * any extra plain-text feed you drop in the feeds folder (one URL or domain per line),
    e.g. OpenPhish community feed (openphish.com/feed.txt) or URLhaus text dump.

Online (optional; set the environment variable to turn on):
  * URLhaus API             URLHAUS_KEY   (free key from auth.abuse.ch)
  * Google Safe Browsing v4 GSB_KEY       (free key from Google Cloud console)
  * VirusTotal v3           VT_KEY        (free key, 4 requests/min)
Online results are cached in feeds/cache.json for 24 h.

Update the offline feeds with:  python -m phishguard.intel --update
"""

import base64
import json
import os
import time
import urllib.parse
import urllib.request

from .emailparse import base_domain

FEED_DIR = os.environ.get("PHISHGUARD_FEEDS", os.path.join(os.path.dirname(__file__), "..", "feeds"))
FEED_URLS = {
    "phishing-domains-ACTIVE.txt": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    "phishing-links-ACTIVE.txt": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "openphish.txt": "https://openphish.com/feed.txt",
}
# shared platforms: anyone can host a page here, so only an exact-link match counts
SHARED_SUFFIXES = ("sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "sharepoint.com",
                   "onedrive.live.com", "1drv.ms", "dropbox.com", "github.io", "netlify.app", "vercel.app",
                   "pages.dev", "web.app", "firebaseapp.com", "blogspot.com", "wixsite.com", "weebly.com",
                   "000webhostapp.com", "glitch.me", "notion.site", "canva.site", "ipfs.io", "workers.dev",
                   "bit.ly", "t.co", "tinyurl.com")
TIMEOUT = 8


def _norm_url(u):
    u = u.strip().lower()
    for p in ("https://", "http://"):
        if u.startswith(p):
            u = u[len(p):]
    return u.rstrip("/")


def _host(u):
    try:
        return (urllib.parse.urlparse(u if "://" in u else "http://" + u).hostname or "").lower()
    except ValueError:
        return ""


def _is_shared(host):
    return any(host == s or host.endswith("." + s) for s in SHARED_SUFFIXES)


class ThreatIntel:
    def __init__(self, feed_dir=FEED_DIR, online=True):
        self.feed_dir = feed_dir
        self.online = online
        self.bad_hosts, self.bad_links = set(), set()
        self._load_offline()
        self.cache_path = os.path.join(feed_dir, "cache.json")
        try:
            self.cache = json.load(open(self.cache_path))
        except Exception:
            self.cache = {}

    # ------------------------------------------------------------ offline
    def _load_offline(self):
        if not os.path.isdir(self.feed_dir):
            return
        for name in os.listdir(self.feed_dir):
            if not name.endswith(".txt"):
                continue
            with open(os.path.join(self.feed_dir, name), encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "/" in line:   # a link: only exact-link matches (one bad page != bad site)
                        self.bad_links.add(_norm_url(line))
                    else:
                        self.bad_hosts.add(line.lower())

    def offline_check(self, url):
        h = _host(url)
        if _norm_url(url) in self.bad_links:
            return "exact link is on a phishing blocklist"
        if h and not _is_shared(h):
            if h in self.bad_hosts or (h.startswith("www.") and h[4:] in self.bad_hosts):
                return f"domain {h} is on a phishing blocklist"
        return None

    # ------------------------------------------------------------ online
    def _cached(self, key, fn):
        hit = self.cache.get(key)
        if hit and time.time() - hit["t"] < 86400:
            return hit["v"]
        try:
            v = fn()
        except Exception as ex:  # network down, quota, bad key ...
            return {"error": str(ex)[:120]}
        self.cache[key] = {"t": time.time(), "v": v}
        return v

    def urlhaus(self, url):
        key = os.environ.get("URLHAUS_KEY")
        if not key:
            return None
        def call():
            req = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/url/",
                                         data=urllib.parse.urlencode({"url": url}).encode(),
                                         headers={"Auth-Key": key})
            r = json.load(urllib.request.urlopen(req, timeout=TIMEOUT))
            return {"listed": r.get("query_status") == "ok", "threat": r.get("threat"), "status": r.get("url_status")}
        return self._cached("uh:" + url, call)

    def safe_browsing(self, url):
        key = os.environ.get("GSB_KEY")
        if not key:
            return None
        def call():
            body = {"client": {"clientId": "phishguard", "clientVersion": "0.2"},
                    "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                                   "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                                   "threatEntries": [{"url": url}]}}
            req = urllib.request.Request(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
                                         data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
            r = json.load(urllib.request.urlopen(req, timeout=TIMEOUT))
            m = r.get("matches", [])
            return {"listed": bool(m), "threat": m[0]["threatType"] if m else None}
        return self._cached("gsb:" + url, call)

    def virustotal(self, url):
        key = os.environ.get("VT_KEY")
        if not key:
            return None
        def call():
            uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            req = urllib.request.Request(f"https://www.virustotal.com/api/v3/urls/{uid}", headers={"x-apikey": key})
            try:
                r = json.load(urllib.request.urlopen(req, timeout=TIMEOUT))
            except urllib.error.HTTPError as ex:
                if ex.code == 404:
                    return {"listed": False, "malicious": 0}
                raise
            stats = r["data"]["attributes"]["last_analysis_stats"]
            return {"listed": stats.get("malicious", 0) >= 2, "malicious": stats.get("malicious", 0)}
        return self._cached("vt:" + url, call)

    # ------------------------------------------------------------ main
    def check_urls(self, urls, max_online=5):
        """Return list of {url, source, detail} for every link that a feed flags."""
        hits = []
        for u in urls:
            why = self.offline_check(u)
            if why:
                hits.append({"url": u, "source": "offline feed", "detail": why})
        if self.online:
            for u in urls[:max_online]:
                for name, fn in (("URLhaus", self.urlhaus), ("Google Safe Browsing", self.safe_browsing),
                                 ("VirusTotal", self.virustotal)):
                    r = fn(u)
                    if r and r.get("listed"):
                        hits.append({"url": u, "source": name, "detail": str({k: v for k, v in r.items() if k != "listed"})})
            try:
                os.makedirs(self.feed_dir, exist_ok=True)
                json.dump(self.cache, open(self.cache_path, "w"))
            except Exception:
                pass
        return hits

    def status(self):
        return {"offline_bad_domains": len(self.bad_hosts), "offline_bad_links": len(self.bad_links),
                "urlhaus": bool(os.environ.get("URLHAUS_KEY")), "safe_browsing": bool(os.environ.get("GSB_KEY")),
                "virustotal": bool(os.environ.get("VT_KEY"))}


def update_feeds(feed_dir=FEED_DIR):
    os.makedirs(feed_dir, exist_ok=True)
    for name, url in FEED_URLS.items():
        try:
            data = urllib.request.urlopen(url, timeout=120).read()
            open(os.path.join(feed_dir, name), "wb").write(data)
            print(f"updated {name}: {data.count(b'\n')} lines")
        except Exception as ex:
            print(f"could not fetch {name}: {ex}")


if __name__ == "__main__":
    import sys
    if "--update" in sys.argv:
        update_feeds()
    print(ThreatIntel(online=False).status())
