"""Online threat-intelligence lookups with a safe offline fallback.

Nothing in this module runs unless the caller asks for it:

* ``analyze(url)``                       -> key-based providers only (legacy).
* ``analyze(url, include_keyless=True)`` -> every online provider (online mode).

Providers
---------
* Google Safe Browsing  (needs GOOGLE_SAFE_BROWSING_API_KEY)  sends the URL.
* URLhaus               (needs URLHAUS_AUTH_KEY)               sends the URL.
* OpenPhish community feed (no key)  downloads a public list of phishing URLs
  and compares locally. The scanned URL is NOT sent anywhere. The community
  feed is for non-commercial use only: https://openphish.com/terms.html
* RDAP domain age       (no key)  sends only the registered domain name
  (for example ``example.com``) to look up its registration date. Brand-new
  domains are a strong sign of a fresh phishing site.

The page itself is never downloaded or opened by the server.
"""
from __future__ import annotations

import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

import ipaddress

import requests
import tldextract
from dotenv import load_dotenv

from backend.config import BASE_DIR
from ml.features.extract_features import normalize_url

load_dotenv(BASE_DIR / ".env")


DEFAULT_OPENPHISH_FEED_URL = (
    "https://raw.githubusercontent.com/openphish/public_feed/"
    "refs/heads/main/feed.txt"
)

_extractor = tldextract.TLDExtract(suffix_list_urls=())  # offline suffix list


def _env_flag(name, default=True):
    value = os.getenv(name)

    if value is None or not value.strip():
        return default

    return value.strip().lower() not in ("0", "false", "no", "off")


def _env_int(name, default):
    try:
        return int(os.getenv(name, "").strip())
    except ValueError:
        return default


def _feed_key(url):
    """Return (host, path) used to compare a URL with the feed."""
    text = (url or "").strip()

    if "://" not in text:
        text = "//" + text

    parsed = urlparse(text)
    host = (parsed.hostname or "").lower()

    if host.startswith("www."):
        host = host[4:]

    return host, parsed.path.rstrip("/")


class ThreatIntelligenceService:
    CACHE_TTL_SECONDS = 900
    REQUEST_TIMEOUT_SECONDS = 3.5

    FEED_TTL_SECONDS = 3600            # re-download the feed at most hourly
    FEED_STALE_LIMIT_SECONDS = 86400   # keep using an old copy up to 24 h
    FEED_TIMEOUT_SECONDS = 6.0

    DOMAIN_AGE_TTL_SECONDS = 86400
    INTERNET_CHECK_TTL_SECONDS = 10

    def __init__(self):
        self.google_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
        self.urlhaus_key = os.getenv("URLHAUS_AUTH_KEY", "").strip()

        # An empty OPENPHISH_FEED_URL in .env switches the feed off.
        feed_setting = os.getenv("OPENPHISH_FEED_URL")
        self.feed_url = (
            DEFAULT_OPENPHISH_FEED_URL
            if feed_setting is None
            else feed_setting.strip()
        )

        self.domain_age_enabled = _env_flag("ENABLE_DOMAIN_AGE_CHECK", True)
        self.new_domain_days = _env_int("NEW_DOMAIN_DAYS", 30)

        self._cache = {}
        self._lock = threading.Lock()

        self._feed = None            # (exact_keys, root_hosts)
        self._feed_time = 0.0
        self._feed_lock = threading.Lock()

        self._age_cache = {}
        self._internet = (0.0, False)

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------

    @property
    def configured(self):
        """True when at least one API key is set (legacy meaning)."""
        return bool(self.google_key or self.urlhaus_key)

    @property
    def keyless_enabled(self):
        return bool(self.feed_url or self.domain_age_enabled)

    @property
    def online_capable(self):
        return self.configured or self.keyless_enabled

    def provider_overview(self):
        return [
            {
                "name": "Google Safe Browsing",
                "ready": bool(self.google_key),
                "needs_key": True,
                "shares": "full URL",
            },
            {
                "name": "URLhaus",
                "ready": bool(self.urlhaus_key),
                "needs_key": True,
                "shares": "full URL",
            },
            {
                "name": "OpenPhish feed",
                "ready": bool(self.feed_url),
                "needs_key": False,
                "shares": "nothing (list is downloaded)",
            },
            {
                "name": "RDAP domain age",
                "ready": self.domain_age_enabled,
                "needs_key": False,
                "shares": "domain name only",
            },
        ]

    # ------------------------------------------------------------------
    # Internet connectivity
    # ------------------------------------------------------------------

    def is_online(self):
        """Quick check whether the computer can reach the internet."""
        now = time.time()

        with self._lock:
            checked_at, last_state = self._internet

            if now - checked_at < self.INTERNET_CHECK_TTL_SECONDS:
                return last_state

        reachable = False

        for address in (("1.1.1.1", 443), ("8.8.8.8", 53)):
            try:
                with socket.create_connection(address, timeout=1.5):
                    reachable = True
                    break
            except OSError:
                continue

        with self._lock:
            self._internet = (now, reachable)

        return reachable

    # ------------------------------------------------------------------
    # Providers that need a key
    # ------------------------------------------------------------------

    def _google_safe_browsing(self, url):
        if not self.google_key:
            return {"provider": "Google Safe Browsing", "status": "not_configured", "match": False}

        endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {
            "client": {"clientId": "phishguard-local", "clientVersion": "3.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            response = requests.post(
                endpoint,
                params={"key": self.google_key},
                json=payload,
                timeout=self.REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            matches = response.json().get("matches", [])
            return {
                "provider": "Google Safe Browsing",
                "status": "match" if matches else "no_match",
                "match": bool(matches),
                "details": [m.get("threatType", "unsafe URL") for m in matches],
            }
        except requests.RequestException:
            return {"provider": "Google Safe Browsing", "status": "unavailable", "match": False}
        except (ValueError, TypeError):
            return {"provider": "Google Safe Browsing", "status": "unavailable", "match": False}

    def _urlhaus(self, url):
        if not self.urlhaus_key:
            return {"provider": "URLhaus", "status": "not_configured", "match": False}

        try:
            response = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                headers={"Auth-Key": self.urlhaus_key},
                timeout=self.REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            data = response.json()
            found = data.get("query_status") == "ok"
            return {
                "provider": "URLhaus",
                "status": "match" if found else (
                    "no_match" if data.get("query_status") == "no_results" else "unavailable"
                ),
                "match": found,
                "details": [data.get("threat", "Known malware URL")] if found else [],
            }
        except requests.RequestException:
            return {"provider": "URLhaus", "status": "unavailable", "match": False}
        except (ValueError, TypeError):
            return {"provider": "URLhaus", "status": "unavailable", "match": False}

    # ------------------------------------------------------------------
    # OpenPhish community feed (no key)
    # ------------------------------------------------------------------

    def _load_feed(self):
        """Return the cached feed, downloading it when it is too old.

        If the download fails, an older copy (up to 24 hours) keeps working.
        """
        now = time.time()

        with self._feed_lock:
            fresh = (
                self._feed is not None
                and now - self._feed_time < self.FEED_TTL_SECONDS
            )

            if fresh:
                return self._feed

            try:
                response = requests.get(
                    self.feed_url,
                    timeout=self.FEED_TIMEOUT_SECONDS,
                )
                response.raise_for_status()

                exact_keys = set()
                root_hosts = set()

                for line in response.text.splitlines():
                    line = line.strip()

                    if not line or line.startswith("#"):
                        continue

                    host, path = _feed_key(line)

                    if not host:
                        continue

                    exact_keys.add((host, path))

                    if not path:
                        root_hosts.add(host)

                self._feed = (exact_keys, root_hosts)
                self._feed_time = now

            except (requests.RequestException, ValueError, TypeError):
                stale_ok = (
                    self._feed is not None
                    and now - self._feed_time < self.FEED_STALE_LIMIT_SECONDS
                )

                if not stale_ok:
                    return None

            return self._feed

    def _openphish(self, url):
        provider = "OpenPhish feed"

        if not self.feed_url:
            return {"provider": provider, "status": "not_configured", "match": False}

        feed = self._load_feed()

        if feed is None:
            return {"provider": provider, "status": "unavailable", "match": False}

        exact_keys, root_hosts = feed
        host, path = _feed_key(url)

        # Exact page match, or the feed lists the whole host (no path).
        found = (host, path) in exact_keys or host in root_hosts

        return {
            "provider": provider,
            "status": "match" if found else "no_match",
            "match": found,
            "details": ["Active phishing URL listed in the OpenPhish feed"] if found else [],
        }

    # ------------------------------------------------------------------
    # RDAP domain age (no key)
    # ------------------------------------------------------------------

    def _domain_age(self, url):
        provider = "RDAP domain age"

        if not self.domain_age_enabled:
            return {"provider": provider, "status": "not_configured", "match": False}

        host, _ = _feed_key(url)

        try:
            ipaddress.ip_address(host.strip("[]"))
            return {"provider": provider, "status": "not_applicable", "match": False}
        except ValueError:
            pass

        parts = _extractor(host)

        if not (parts.domain and parts.suffix):
            return {"provider": provider, "status": "not_applicable", "match": False}

        registered = f"{parts.domain}.{parts.suffix}".lower()
        now = time.time()

        with self._lock:
            cached = self._age_cache.get(registered)

        if cached and now - cached[0] < self.DOMAIN_AGE_TTL_SECONDS:
            return dict(cached[1])

        try:
            response = requests.get(
                f"https://rdap.org/domain/{registered}",
                headers={"Accept": "application/rdap+json"},
                timeout=self.REQUEST_TIMEOUT_SECONDS,
            )

            # Some endings (for example many country domains) have no RDAP.
            if response.status_code in (400, 404):
                result = {"provider": provider, "status": "unavailable", "match": False}
            else:
                response.raise_for_status()
                result = self._parse_rdap_age(response.json(), provider)

        except (requests.RequestException, ValueError, TypeError):
            return {"provider": provider, "status": "unavailable", "match": False}

        with self._lock:
            self._age_cache[registered] = (now, result)

        return dict(result)

    def _parse_rdap_age(self, data, provider):
        registered_at = None

        for event in data.get("events", []) if isinstance(data, dict) else []:
            if str(event.get("eventAction", "")).lower() == "registration":
                registered_at = event.get("eventDate")
                break

        if not registered_at:
            return {"provider": provider, "status": "unavailable", "match": False}

        try:
            moment = datetime.fromisoformat(str(registered_at).replace("Z", "+00:00"))
        except ValueError:
            return {"provider": provider, "status": "unavailable", "match": False}

        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)

        age_days = max((datetime.now(timezone.utc) - moment).days, 0)

        return {
            "provider": provider,
            "status": "ok",
            "match": False,            # age is a signal, not a reputation hit
            "age_days": age_days,
            "registered": moment.date().isoformat(),
            "newly_registered": age_days < self.new_domain_days,
        }

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(self, url, include_keyless=False):
        normalized = normalize_url(url)
        cache_key = (normalized, bool(include_keyless))
        now = time.time()

        with self._lock:
            cached = self._cache.get(cache_key)
            if cached and now - cached[0] < self.CACHE_TTL_SECONDS:
                result = dict(cached[1])
                result["cached"] = True
                return result

        jobs = []

        if self.google_key:
            jobs.append(self._google_safe_browsing)
        if self.urlhaus_key:
            jobs.append(self._urlhaus)
        if include_keyless and self.feed_url:
            jobs.append(self._openphish)
        if include_keyless and self.domain_age_enabled:
            jobs.append(self._domain_age)

        checks = []

        if jobs:
            with ThreadPoolExecutor(max_workers=len(jobs)) as executor:
                futures = [executor.submit(job, normalized) for job in jobs]
                for future in as_completed(futures):
                    checks.append(future.result())

        # Keep a stable order in the output.
        order = {"Google Safe Browsing": 0, "URLhaus": 1, "OpenPhish feed": 2, "RDAP domain age": 3}
        checks.sort(key=lambda item: order.get(item["provider"], 9))

        match = any(item.get("match") for item in checks)

        counted = [c for c in checks if c["status"] != "not_applicable"]
        good = ("match", "no_match", "ok")

        if not checks:
            status = "not_configured"
        elif not counted:
            status = "checked_no_match"
        elif any(c["status"] == "unavailable" for c in counted):
            status = "partial" if any(c["status"] in good for c in counted) else "unavailable"
        else:
            status = "match" if match else "checked_no_match"

        age = next((c for c in checks if c["provider"] == "RDAP domain age" and c["status"] == "ok"), None)

        result = {
            "configured": self.configured,
            "status": status,
            "match": match,
            "providers": checks,
            "cached": False,
            "domain_age_days": age["age_days"] if age else None,
            "newly_registered": bool(age and age["newly_registered"]),
        }

        with self._lock:
            self._cache[cache_key] = (now, result)

        return result


_threat_intelligence_service = None


def get_threat_intelligence_service():
    global _threat_intelligence_service
    if _threat_intelligence_service is None:
        _threat_intelligence_service = ThreatIntelligenceService()
    return _threat_intelligence_service
