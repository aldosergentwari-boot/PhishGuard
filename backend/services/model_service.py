import json
import joblib
import sklearn

from backend.config import URL_MODEL_PATH, URL_MODEL_METADATA_PATH
from ml.features.extract_features import extract_features, normalize_url, model_input


class PhishingModelService:
    """Lexical URL model backed by character n-grams and numeric features."""

    def __init__(self):
        print("Loading lexical phishing detection model...")

        for path in (URL_MODEL_PATH, URL_MODEL_METADATA_PATH):
            if not path.exists():
                raise FileNotFoundError(f"Required model file not found: {path}")

        with open(URL_MODEL_METADATA_PATH, "r", encoding="utf-8") as file:
            self.metadata = json.load(file)

        expected_version = self.metadata.get("scikit_learn_version")
        if expected_version and expected_version != sklearn.__version__:
            raise RuntimeError(
                "scikit-learn version mismatch: model requires "
                f"{expected_version}, installed version is {sklearn.__version__}. "
                "Install requirements.txt."
            )

        self.model = joblib.load(URL_MODEL_PATH)
        self.threshold = float(self.metadata["threshold"])

        if not 0 < self.threshold < 1:
            raise ValueError("Invalid lexical model threshold.")

        if not hasattr(self.model, "predict_proba"):
            raise TypeError("The URL model must support predict_proba().")

        print("Lexical model loaded successfully.")
        print("Model threshold:", self.threshold)

    def predict(self, url):
        normalized_url = normalize_url(url)
        features = extract_features(normalized_url)

        probabilities = self.model.predict_proba([model_input(url)])
        classes = list(self.model.named_steps["classifier"].classes_)
        phishing_index = classes.index(1)
        phishing_probability = float(probabilities[0][phishing_index])

        is_phishing = phishing_probability >= self.threshold
        prediction = "PHISHING" if is_phishing else "LEGITIMATE"
        # UI risk score: 0-50 below the decision threshold, 50-100 above it.
        # Exactly 50 means "right on the decision boundary".
        if phishing_probability < self.threshold:
            risk_score = 50.0 * phishing_probability / self.threshold
        else:
            risk_score = 50.0 + 50.0 * (phishing_probability - self.threshold) / (1.0 - self.threshold)
        risk_score = max(0.0, min(100.0, risk_score))
        confidence = risk_score if is_phishing else 100.0 - risk_score

        indicators = []
        indicator_map = [
            ("has_ip", "IP address used instead of a domain"),
            ("has_at_symbol", "@ symbol found in URL"),
            ("uses_shortener", "URL shortening service detected"),
            ("has_punycode", "Punycode domain detected"),
        ]
        for key, message in indicator_map:
            if features.get(key):
                indicators.append(message)

        if features.get("suspicious_word_count", 0):
            indicators.append("Suspicious words detected in URL")
        if features.get("num_subdomains", 0) >= 3:
            indicators.append("Multiple subdomains detected")
        if not features.get("has_https"):
            indicators.append("HTTPS not detected")
        if is_phishing and not indicators:
            indicators.append("Suspicious URL character patterns detected by the ML model")

        return {
            "url": url,
            "normalized_url": normalized_url,
            "prediction": prediction,
            "risk_score": round(risk_score, 2),
            "confidence": round(confidence, 2),
            "phishing_probability": phishing_probability,
            "threshold": self.threshold,
            "indicators": indicators,
            "model_name": self.metadata.get("model_name", "URL lexical model"),
        }


_model_service = None


def get_model_service():
    global _model_service
    if _model_service is None:
        _model_service = PhishingModelService()
    return _model_service
