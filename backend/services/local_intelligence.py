import re

from backend.config import BASE_DIR
from ml.features.extract_features import (
    extract_features,
    parse_url
)

try:
    import tldextract
    _domain_extractor = tldextract.TLDExtract(suffix_list_urls=())
except ImportError:
    _domain_extractor = None

BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "google": {"google.com"},
    "youtube": {"youtube.com"},
    "microsoft": {
        "microsoft.com", "live.com", "office.com",
        "microsoftonline.com", "office365.com", "microsoft365.com"
    },
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.co.jp"},
    "facebook": {"facebook.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "ebay": {"ebay.com"},
    "yahoo": {"yahoo.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "irembo": {"irembo.gov.rw"},
    "rra": {"rra.gov.rw"},
    "mtn": {"mtn.co.rw", "mtn.com"},
    "airtel": {"airtel.co.rw", "airtel.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "att": {"att.com", "att.net"},
} 
BRAND_ACTION_WORDS = (
    "login", "signin", "verify", "verification", "secure", "account",
    "password", "update", "confirm", "recover", "wallet", "support",
    "suspended", "unlock", "billing", "payment", "webscr",
    "refund", "reward", "winner", "promo", "claim", "prize", "giveaway", "help",
)


INTELLIGENCE_DIR = (
    BASE_DIR / "ml" / "dataset" / "intelligence"
)

BLOCKLIST_FILE = INTELLIGENCE_DIR / "blocklist.txt"
ALLOWLIST_FILE = INTELLIGENCE_DIR / "allowlist.txt"


class LocalIntelligenceService:

    def __init__(self):

        INTELLIGENCE_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        BLOCKLIST_FILE.touch(exist_ok=True)
        ALLOWLIST_FILE.touch(exist_ok=True)

        self.blocklist = self._load_domains(BLOCKLIST_FILE)
        self.allowlist = self._load_domains(ALLOWLIST_FILE)

    @staticmethod
    def _normalize_domain(domain):

        domain = domain.strip().lower().rstrip(".")

        domain = domain.removeprefix("*.")

        while domain.startswith("www."):
            domain = domain[4:]

        return domain

    @classmethod
    def _load_domains(cls, file_path):

        domains = set()

        with open(file_path, "r", encoding="utf-8") as file:

            for line in file:

                domain = line.strip()

                if not domain or domain.startswith("#"):
                    continue

                # Support full URLs in domain lists
                if "://" in domain:
                    domain = parse_url(domain).hostname or domain

                domain = cls._normalize_domain(domain)

                if domain:
                    domains.add(domain)

        return domains

    @staticmethod
    def _get_hostname(url):

        parsed = parse_url(url)

        hostname = parsed.hostname or ""

        return LocalIntelligenceService._normalize_domain(
            hostname
        )

    @staticmethod
    def _matches_domain(hostname, domain_set):

        for domain in domain_set:

            if hostname == domain:
                return True

            if hostname.endswith("." + domain):
                return True

        return False

    def reload_lists(self):

        self.blocklist = self._load_domains(BLOCKLIST_FILE)
        self.allowlist = self._load_domains(ALLOWLIST_FILE)

    @staticmethod
    def _registrable_domain(hostname):
        if not hostname:
            return ""
        if _domain_extractor is not None:
            extracted = _domain_extractor(hostname)
            if extracted.top_domain_under_public_suffix:
                return extracted.top_domain_under_public_suffix.lower()
        parts = hostname.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    @classmethod
    def _brand_impersonation(cls, hostname, url):
        """Flag brand names used on unrelated domains, not official domains."""
        if not hostname:
            return None
        registered = cls._registrable_domain(hostname)
        host_compact = hostname.replace("-", "").replace("_", "")
        host_tokens = set(re.split(r"[-_.]", hostname))
        url_lower = url.lower()

        # Identify labels placed BEFORE the registrable domain. A brand used as
        # an exact subdomain label on an unrelated registrable domain is itself
        # a strong impersonation signal (e.g. ebay.scammer.com), even when the
        # URL has no /login or /verify path.
        subdomain_labels = set()
        if registered and hostname.endswith("." + registered):
            subdomain_part = hostname[: -(len(registered) + 1)]
            subdomain_labels = set(subdomain_part.split("."))

        for brand, official_domains in BRAND_DOMAINS.items():
            if any(registered == official or registered.endswith("." + official)
                   for official in official_domains):
                continue

            # Short names (att, rra, mtn) must be a WHOLE word.
            if len(brand) <= 4:
                brand_in_host = brand in host_tokens
            else:
                brand_in_host = brand in host_compact

            exact_brand_subdomain = brand in subdomain_labels
            action_in_url = any(word in url_lower for word in BRAND_ACTION_WORDS)

            # Exact brand subdomain on an unrelated base domain is flagged
            # without requiring an action keyword. Brand-like text elsewhere
            # still requires account/security language to reduce false positives.
            if exact_brand_subdomain or (brand_in_host and action_in_url):
                return {
                    "brand": brand,
                    "domain": registered,
                    "reason": (
                        "Brand name used as a subdomain on an unrelated domain."
                        if exact_brand_subdomain
                        else "Brand name combined with account/security language on an unrelated domain."
                    ),
                }
        return None

    def analyze(self, url):

        features = extract_features(url)

        hostname = self._get_hostname(url)
        brand_match = self._brand_impersonation(hostname, url)

        is_blocklisted = self._matches_domain(
            hostname,
            self.blocklist
        )

        is_allowlisted = self._matches_domain(
            hostname,
            self.allowlist
        )

        score = 0
        indicators = []

        # Blocklist always takes priority
        if is_blocklisted:

            score = 100

            indicators.append({
                "name": "Blocklist match",
                "description": (
                    "This domain exists in the local blocklist."
                ),
                "weight": 100
            })

        # Allowlisted domains skip heuristic rules
        elif not is_allowlisted:

            if features["has_ip"]:

                score += 20

                indicators.append({
                    "name": "IP address",
                    "description": (
                        "The URL uses an IP address instead of a domain."
                    ),
                    "weight": 20
                })

            if features["has_at_symbol"]:

                score += 20

                indicators.append({
                    "name": "At symbol",
                    "description": (
                        "The URL contains an @ symbol."
                    ),
                    "weight": 20
                })

            if features["has_punycode"]:

                score += 25

                indicators.append({
                    "name": "Punycode",
                    "description": (
                        "The domain contains an xn-- encoded label."
                    ),
                    "weight": 25
                })

            if features["uses_shortener"]:

                score += 10

                indicators.append({
                    "name": "URL shortener",
                    "description": (
                        "The URL uses a known URL shortening service."
                    ),
                    "weight": 10
                })

            suspicious_count = min(
                features["suspicious_word_count"],
                3
            )

            if suspicious_count:

                weight = suspicious_count * 5
                score += weight

                indicators.append({
                    "name": "Suspicious keywords",
                    "description": (
                        f"{suspicious_count} suspicious keyword(s) detected."
                    ),
                    "weight": weight
                })

            if features["num_subdomains"] >= 3:

                score += 10

                indicators.append({
                    "name": "Multiple subdomains",
                    "description": (
                        "The URL contains three or more subdomains."
                    ),
                    "weight": 10
                })

            if features["url_length"] > 100:

                score += 5

                indicators.append({
                    "name": "Long URL",
                    "description": (
                        "The URL is unusually long."
                    ),
                    "weight": 5
                })

            if features["url_entropy"] >= 4.2:

                score += 10

                indicators.append({
                    "name": "High URL entropy",
                    "description": (
                        "The URL contains high character randomness."
                    ),
                    "weight": 10
                })

        if brand_match:
            score += 45
            indicators.append({
                "name": "Possible brand impersonation",
                "description": brand_match["reason"],
                "weight": 45
            })

        score = min(score, 100)

        return {
            "domain": hostname,
            "rule_risk_score": score,
            "blocklist_match": is_blocklisted,
            "allowlist_match": is_allowlisted,
            "brand_impersonation_match": bool(brand_match),
            "brand_impersonation": brand_match,
            "indicators": indicators,
            "lists": {
                "blocklist_entries": len(self.blocklist),
                "allowlist_entries": len(self.allowlist)
            }
        }


_local_intelligence = None


def get_local_intelligence_service():

    global _local_intelligence

    if _local_intelligence is None:

        _local_intelligence = LocalIntelligenceService()

    return _local_intelligence
