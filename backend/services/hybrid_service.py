
from backend.services.model_service import get_model_service
from backend.services.local_intelligence import get_local_intelligence_service
from backend.services.threat_intelligence import get_threat_intelligence_service


RULE_THRESHOLD = 50
PHISHING_ML_THRESHOLD = 80

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

        # A trusted (allowlisted) domain is capped BEFORE the label is chosen.
        # If the cap were applied afterwards, the label would still be decided
        # from the uncapped ML score and a trusted site could be shown as
        # SUSPICIOUS with a risk below the suspicious threshold (34 < 35).
        if allowlist_match and not (blocklist_match or external_match):
            final_risk_score = min(
                ml_result["risk_score"],
                34
            )

        # Confirmed threat sources receive the PHISHING classification.
        # Strong ML results can also receive PHISHING.
        if blocklist_match or external_match:
            final_prediction = "PHISHING"

        elif (
            ml_is_phishing
            and ml_result["risk_score"] >= PHISHING_ML_THRESHOLD
        ):
            final_prediction = "PHISHING"

        # Heuristic rules and brand impersonation alone are suspicious,
        # not automatic proof of confirmed phishing.
        elif (
            ml_is_phishing
            or rule_is_phishing
            or brand_match
            or final_risk_score >= 35
        ):
            final_prediction = "SUSPICIOUS"

        else:
            final_prediction = "LEGITIMATE"

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
