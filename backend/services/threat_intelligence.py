"""Optional online threat-intelligence lookups with a safe offline fallback."""
from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from dotenv import load_dotenv

from backend.config import BASE_DIR
from ml.features.extract_features import normalize_url

load_dotenv(BASE_DIR / ".env")


class ThreatIntelligenceService:
    CACHE_TTL_SECONDS = 900
    REQUEST_TIMEOUT_SECONDS = 3.5

    def __init__(self):
        self.google_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
        self.urlhaus_key = os.getenv("URLHAUS_AUTH_KEY", "").strip()
        self._cache = {}
        self._lock = threading.Lock()

    @property
    def configured(self):
        return bool(self.google_key or self.urlhaus_key)

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

    def analyze(self, url):
        normalized = normalize_url(url)
        now = time.time()
        with self._lock:
            cached = self._cache.get(normalized)
            if cached and now - cached[0] < self.CACHE_TTL_SECONDS:
                result = dict(cached[1])
                result["cached"] = True
                return result

        checks = []
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = []
            if self.google_key:
                futures.append(executor.submit(self._google_safe_browsing, normalized))
            if self.urlhaus_key:
                futures.append(executor.submit(self._urlhaus, normalized))
            for future in as_completed(futures):
                checks.append(future.result())

        match = any(item.get("match") for item in checks)
        if not self.configured:
            status = "not_configured"
        elif any(item["status"] == "unavailable" for item in checks):
            status = "partial" if any(item["status"] in ("match", "no_match") for item in checks) else "unavailable"
        else:
            status = "match" if match else "checked_no_match"

        result = {
            "configured": self.configured,
            "status": status,
            "match": match,
            "providers": checks,
            "cached": False,
        }
        with self._lock:
            self._cache[normalized] = (now, result)
        return result


_threat_intelligence_service = None


def get_threat_intelligence_service():
    global _threat_intelligence_service
    if _threat_intelligence_service is None:
        _threat_intelligence_service = ThreatIntelligenceService()
    return _threat_intelligence_service
