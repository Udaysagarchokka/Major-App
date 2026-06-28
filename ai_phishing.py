"""
ai_phishing.py
Lightweight phishing-URL risk scorer — the AI component used by
qr_verifier.py to catch malicious links that a cryptographic signature
check alone cannot.

This module performs logistic-regression-style inference using weights
that should be trained offline (see train_model.py) on a labeled
phishing-vs-legitimate URL dataset. At runtime it only uses plain Python
arithmetic (no numpy / scikit-learn), which keeps it dependency-free and
easy to package into an Android APK with Buildozer.

NOTE: The WEIGHTS below are reasonable starting values based on common
phishing-URL indicators, not a fully trained model. For your project
report, train_model.py shows how to fit real weights on a public
phishing-URL dataset (e.g. PhishTank, UCI Phishing Websites dataset) and
paste the learned coefficients in here.
"""

import re
import math

WEIGHTS = {
    "bias": -1.2,
    "url_length": 0.015,
    "num_dots": 0.35,
    "num_hyphens": 0.30,
    "has_ip_address": 2.1,
    "has_at_symbol": 1.8,
    "has_https": -1.0,
    "suspicious_keyword": 1.6,
    "num_digits": 0.05,
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update",
    "bank", "confirm", "signin", "free", "bonus",
]

IP_PATTERN = re.compile(r"^(https?://)?(\d{1,3}\.){3}\d{1,3}")


def _extract_features(url: str) -> dict:
    url_lower = url.lower()
    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "has_ip_address": 1 if IP_PATTERN.match(url) else 0,
        "has_at_symbol": 1 if "@" in url else 0,
        "has_https": 1 if url_lower.startswith("https://") else 0,
        "suspicious_keyword": 1 if any(k in url_lower for k in SUSPICIOUS_KEYWORDS) else 0,
        "num_digits": sum(c.isdigit() for c in url),
    }


def _sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def phishing_score(url: str) -> float:
    """Returns a phishing probability between 0 (safe) and 1 (likely phishing)."""
    features = _extract_features(url)
    z = WEIGHTS["bias"]
    for key, value in features.items():
        z += WEIGHTS[key] * value
    return round(_sigmoid(z), 3)


def is_suspicious(url: str, threshold: float = 0.5) -> bool:
    return phishing_score(url) >= threshold


if __name__ == "__main__":
    test_urls = [
        "https://www.amazon.com/order/12345",
        "http://192.168.1.5/login-verify-account",
        "http://secure-bank-update.com/confirm@login",
    ]
    for u in test_urls:
        print(f"{u} -> phishing score: {phishing_score(u)}")
