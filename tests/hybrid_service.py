import ipaddress

from backend.services.model_service import get_model_service
from backend.services.local_intelligence import get_local_intelligence_service
from backend.services.threat_intelligence import get_threat_intelligence_service


RULE_THRESHOLD = 50
PHISHING_ML_THRESHOLD = 80

# Risk bands shown to the user. The label and the number must always agree:
#   LEGITIMATE : below SUSPICIOUS_RISK_MIN
#   SUSPICIOUS : SUSPICIOUS_RISK_MIN up to (but not including) PHISHING_RISK_MIN
#   PHISHING   : PHISHING_RISK_MIN and above
SUSPICIOUS_RISK_MIN = 35
PHISHING_RISK_MIN = PHISHING_ML_THRESHOLD
SUSPICIOUS_RISK_MAX = PHISHING_RISK_MIN - 0.01

# Hosts where anybody can publish content.
SHARED_PLATFORM_HOSTS = (
    "docs.google.com", "sites.google.com", "forms.gle", "drive.google.com",
    "storage.googleapis.com", "storage.cloud.google.com", "script.google.com",
    "s3.amazonaws.com", "amazonaws.com", "ipfs.io", "cloudflare-ipfs.com",
    "web.app", "firebaseapp.com", "github.io", "herokuapp.com", "blogspot.com",
    "weebly.com", "wixsite.com", "000webhostapp.com",
)


def _on_shared_platform(hostname):
    return any(
        hostname == h or hostname.endswith("." + h)
        for h in SHARED_PLATFORM_HOSTS
    )


# Address ranges that only exist inside a home or company network.
# (Documentation ranges such as 192.0.2.0/24 are deliberately NOT listed:
# they are used as stand-ins for public IPs in examples and tests.)
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "fc00::/7",
    )
)


def _is_non_public_ip(hostname):
    """True for IPs that are only reachable inside a local network
    (192.168.x.x, 10.x.x.x, 172.16-31.x.x ...), loopback and link-local.

    These addresses are not websites on the internet, so the ML model alone
    cannot prove they are phishing.
    """
    try:
        address = ipaddress.ip_address((hostname or "").strip("[]"))
    except ValueError:
        return False

    if (
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
    ):
        return True

    return any(
        address.version == network.version and address in network
        for network in _INTERNAL_NETWORKS
    )


class HybridDetectionService:
    def __init__(self):
        self.model_service = get_model_service()
        self.local_service = get_local_intelligence_service()
        self.threat_service = get_threat_intelligence_service()

    def analyze(self, url):
        ml_result = self.model_service.predict(url)
        local_result = self.local_service.analyze(url)
        threat_result = self.threat_service.analyze(url)

        ml_is_phishing = ml_result["prediction"] == "PHISHING"

        rule_is_phishing = (
            local_result["rule_risk_score"] >= RULE_THRESHOLD
            or local_result.get("brand_impersonation_match", False)
        )

        blocklist_match = local_result["blocklist_match"]
        external_match = threat_result["match"]

        brand_match = local_result.get("brand_impersonation_match", False)

        allowlist_match = (
            local_result["allowlist_match"]
            and not _on_shared_platform(local_result["domain"])
        )

        if allowlist_match and not (blocklist_match or external_match):
            ml_is_phishing = False
            rule_is_phishing = False
            brand_match = False

        final_risk_score = max(
            ml_result["risk_score"],
            local_result["rule_risk_score"],
            100 if external_match or blocklist_match else 0,
            85 if brand_match else 0,
        )

        # Round first: the label must be decided from the same number that
        # the user sees (34.996 is shown as 35.0, so it must count as 35).
        final_risk_score = round(final_risk_score, 2)

        # A trusted (allowlisted) domain is neutralised BEFORE the label is
        # chosen, so a high ML score can no longer turn it into SUSPICIOUS.
        # Its risk is shown as 0; the raw ML score stays in ml_result.
        if allowlist_match and not (blocklist_match or external_match):
            final_risk_score = 0

        # Evidence that does not come from the ML model alone.
        indicator_names = {
            item.get("name")
            for item in local_result.get("indicators", [])
        }
        is_shortener = "URL shortener" in indicator_names
        is_non_public_ip = _is_non_public_ip(local_result["domain"])

        strong_evidence = (
            blocklist_match
            or external_match
            or brand_match
            or local_result["rule_risk_score"] >= RULE_THRESHOLD
        )

        # A shortener hides its destination and a private IP is not an
        # internet website. With only the ML score as proof, the honest
        # answer is SUSPICIOUS, not a confirmed PHISHING.
        ml_only_ambiguous = (
            (is_shortener or is_non_public_ip)
            and not strong_evidence
        )

        brand_on_shared_platform = (
            brand_match
            and _on_shared_platform(local_result["domain"])
        )

        # Confirmed threat sources receive the PHISHING classification.
        # Strong ML results can also receive PHISHING.
        if blocklist_match or external_match:
            final_prediction = "PHISHING"

        # A well-known brand name used on a domain that is not the brand's
        # own is the classic phishing pattern. On shared platforms
        # (github.io, web.app ...) anybody can pick any sub-domain, so a
        # brand there is only suspicious.
        elif brand_match and not brand_on_shared_platform:
            final_prediction = "PHISHING"

        elif (
            ml_is_phishing
            and ml_result["risk_score"] >= PHISHING_ML_THRESHOLD
            and not ml_only_ambiguous
        ):
            final_prediction = "PHISHING"

        elif (
            ml_is_phishing
            or rule_is_phishing
            or brand_match
            or final_risk_score >= SUSPICIOUS_RISK_MIN
        ):
            final_prediction = "SUSPICIOUS"

        else:
            final_prediction = "LEGITIMATE"

        # Keep the number inside the band of its label.
        if final_prediction == "PHISHING":
            final_risk_score = max(final_risk_score, PHISHING_RISK_MIN)
        elif final_prediction == "SUSPICIOUS":
            final_risk_score = min(final_risk_score, SUSPICIOUS_RISK_MAX)

        decision_sources = []

        if ml_is_phishing:
            decision_sources.append("Character n-gram ML model")

        if rule_is_phishing:
            decision_sources.append("Local URL and brand-impersonation rules")

        if ml_only_ambiguous and ml_is_phishing:
            if is_shortener:
                decision_sources.append(
                    "Short link hides its real destination"
                )
            else:
                decision_sources.append(
                    "Private network address, not a public website"
                )

        if blocklist_match:
            decision_sources.append("Local blocklist")

        if external_match:
            decision_sources.extend(
                provider["provider"]
                for provider in threat_result["providers"]
                if provider.get("match")
            )

        if allowlist_match and not (blocklist_match or external_match):
            decision_sources.append("Trusted domain (local allowlist)")

        if not decision_sources:
            decision_sources.append(
                "No threat detected by configured checks"
            )

        if threat_result["configured"]:
            detection_mode = "HYBRID_ONLINE_AND_OFFLINE"
        else:
            detection_mode = "OFFLINE_ML_AND_LOCAL_RULES"

        if final_prediction == "PHISHING":
            message = (
                "A phishing threat was detected. Do not open this URL "
                "or enter sensitive information."
            )
        elif final_prediction == "SUSPICIOUS":
            message = (
                "This URL has suspicious indicators. Verify the website "
                "carefully before proceeding."
            )
        else:
            message = (
                "No threat was found by the enabled checks. "
                "This does not guarantee the URL is safe."
            )

        return {
            "url": url,
            "final_prediction": final_prediction,
            "final_risk_score": round(min(final_risk_score, 100), 2),
            "ml_result": ml_result,
            "local_intelligence": local_result,
            "threat_intelligence": threat_result,
            "decision_sources": decision_sources,
            "indicators": (
                list(ml_result.get("indicators", []))
                + [
                    item.get("name", str(item))
                    for item in local_result.get("indicators", [])
                ]
                + (
                    ["Matched an external threat-intelligence database"]
                    if external_match else []
                )
            ),
            "detection_mode": detection_mode,
            "internet_required": False,
            "message": message,
        }


_hybrid_service = None


def get_hybrid_service():
    global _hybrid_service

    if _hybrid_service is None:
        _hybrid_service = HybridDetectionService()

    return _hybrid_service
