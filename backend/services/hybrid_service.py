from backend.services.model_service import get_model_service
from backend.services.local_intelligence import get_local_intelligence_service
from backend.services.threat_intelligence import get_threat_intelligence_service


RULE_THRESHOLD = 50

# Hosts where anybody can publish content. Being on the allowlist (e.g. google.com)
# must NOT make these safe automatically.
SHARED_PLATFORM_HOSTS = (
    "docs.google.com", "sites.google.com", "forms.gle", "drive.google.com",
    "storage.googleapis.com", "storage.cloud.google.com", "script.google.com",
    "s3.amazonaws.com", "amazonaws.com", "ipfs.io", "cloudflare-ipfs.com",
    "web.app", "firebaseapp.com", "github.io", "herokuapp.com", "blogspot.com",
    "weebly.com", "wixsite.com", "000webhostapp.com",
)


def _on_shared_platform(hostname):
    return any(hostname == h or hostname.endswith("." + h) for h in SHARED_PLATFORM_HOSTS)


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

        # A trusted (allowlisted) domain overrides the ML model and the heuristic rules,
        # but never a blocklist / threat-intelligence hit, and never a shared platform.
        allowlist_match = (
            local_result["allowlist_match"]
            and not _on_shared_platform(local_result["domain"])
        )
        if allowlist_match and not (blocklist_match or external_match):
            ml_is_phishing = False
            rule_is_phishing = False

        is_phishing = any((
            ml_is_phishing,
            rule_is_phishing,
            blocklist_match,
            external_match,
        ))
        final_prediction = "PHISHING" if is_phishing else "LEGITIMATE"

        final_risk_score = max(
            ml_result["risk_score"],
            local_result["rule_risk_score"],
            100 if external_match or blocklist_match else 0,
            85 if local_result.get("brand_impersonation_match") else 0,
        )

        if allowlist_match and not is_phishing:
            final_risk_score = 0

        decision_sources = []
        if ml_is_phishing:
            decision_sources.append("Character n-gram ML model")
        if rule_is_phishing:
            decision_sources.append("Local URL and brand-impersonation rules")
        if blocklist_match:
            decision_sources.append("Local blocklist")
        if external_match:
            decision_sources.extend(
                provider["provider"]
                for provider in threat_result["providers"]
                if provider.get("match")
            )
        if allowlist_match and not is_phishing:
            decision_sources.append("Trusted domain (local allowlist)")
        if not decision_sources:
            decision_sources.append("No threat detected by configured checks")

        if threat_result["configured"]:
            detection_mode = "HYBRID_ONLINE_AND_OFFLINE"
        else:
            detection_mode = "OFFLINE_ML_AND_LOCAL_RULES"

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
                + [item.get("name", str(item)) for item in local_result.get("indicators", [])]
                + (["Matched an external threat-intelligence database"] if external_match else [])
            ),
            "detection_mode": detection_mode,
            "internet_required": False,
            "message": (
                "Potential phishing threat detected. Do not open this URL."
                if is_phishing
                else "No threat was found by the enabled checks. This does not guarantee the URL is safe."
            ),
        }


_hybrid_service = None


def get_hybrid_service():
    global _hybrid_service
    if _hybrid_service is None:
        _hybrid_service = HybridDetectionService()
    return _hybrid_service
