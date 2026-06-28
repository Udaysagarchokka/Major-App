"""
qr_verifier.py
Scans/decodes a QR code image and determines whether it is genuine,
suspicious, or fake — using a combination of:

  1. Cryptographic signature verification (when the QR was created with
     qr_generator.py and signed by a known issuer's private key)
  2. AI-based phishing-URL detection (ai_phishing.py) for whatever link
     or data is embedded inside

This is the authentication / fake-QR-detection half of the project.
"""

import json
import base64
import hashlib

import cv2
from ecdsa import BadSignatureError

from key_manager import load_public_key
from ai_phishing import phishing_score

try:
    from pyzbar import pyzbar
    from PIL import Image
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False


def detect_content_type(data: str) -> str:
    """
    Classifies the QR's decoded content so the verifier can apply the
    right checks. This is what makes the system work for ANY kind of QR
    code, not just web links or UPI payments — the AI phishing check
    below is only meaningful for web URLs, so other content types skip
    it and rely on the cryptographic signature check instead.
    """
    if not isinstance(data, str):
        return "unknown"
    lower = data.lower().strip()

    if lower.startswith(("http://", "https://")):
        return "url"
    if lower.startswith("upi://"):
        return "upi_payment"
    if lower.startswith("wifi:"):
        return "wifi_config"
    if lower.startswith("mailto:"):
        return "email"
    if lower.startswith("tel:"):
        return "phone_number"
    if lower.startswith(("sms:", "smsto:")):
        return "sms"
    if lower.startswith("begin:vcard"):
        return "contact_card"
    if lower.startswith("geo:"):
        return "location"
    if lower == "":
        return "empty"
    return "plain_text"


def decode_qr(image_path: str) -> str:
    """
    Decodes a QR code from an image, trying pyzbar (ZBar) first when
    available — it is substantially more reliable than OpenCV's
    built-in detector for dense QR codes and real-world photos — then
    falling back to several OpenCV-based strategies. This fallback path
    is what runs on platforms like Android where ZBar's native library
    isn't available.
    """
    # Strategy 0: pyzbar/ZBar — most robust option when available
    if PYZBAR_AVAILABLE:
        try:
            pil_img = Image.open(image_path)
            results = pyzbar.decode(pil_img)
            if results:
                return results[0].data.decode("utf-8")
        except Exception:
            pass  # fall through to OpenCV strategies below

    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"Could not read image: {image_path}")

    detector = cv2.QRCodeDetector()
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    candidates = [img, gray]

    h, w = gray.shape[:2]
    if max(h, w) < 800:
        scale = 800 / max(h, w)
        resized = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
        candidates.append(resized)

    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    candidates.append(clahe.apply(gray))

    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    candidates.append(otsu)

    for candidate in candidates:
        try:
            data, points, _ = detector.detectAndDecode(candidate)
        except cv2.error:
            continue
        if data:
            return data

    raise ValueError(
        "No QR code detected in the image. Try a clearer, well-lit, "
        "more head-on photo, or crop closer to just the QR code."
    )


def verify_qr(image_path: str) -> dict:
    raw_data = decode_qr(image_path)

    result = {
        "raw_data": raw_data,
        "content_type": "unknown",
        "signature_valid": False,
        "phishing_score": None,
        "verdict": "FAKE / INVALID",
        "reason": "",
    }

    inner_data = raw_data

    # Try to interpret the QR as a signed secure bundle from qr_generator.py
    try:
        bundle = json.loads(raw_data)
        payload = bundle["payload"]
        signature = base64.b64decode(bundle["signature"])
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

        public_key = load_public_key()
        try:
            result["signature_valid"] = public_key.verify(
                signature, payload_bytes, hashfunc=hashlib.sha256
            )
        except BadSignatureError:
            result["signature_valid"] = False

        inner_data = payload.get("data", "")
    except (json.JSONDecodeError, KeyError, TypeError):
        # Not a signed bundle — likely a plain, unsigned QR of any kind
        inner_data = raw_data

    content_type = detect_content_type(inner_data)
    result["content_type"] = content_type

    # The AI phishing model was trained specifically on web-URL features
    # (https presence, domain patterns, etc.), so it's only meaningful
    # for "url" type content. Every other QR type — UPI, WiFi, contact
    # cards, plain text, phone numbers — skips this check and relies on
    # the cryptographic signature as its authenticity guarantee instead.
    score = None
    if content_type == "url":
        score = phishing_score(inner_data)
        result["phishing_score"] = score

    if content_type == "url":
        if result["signature_valid"] and score < 0.5:
            result["verdict"] = "GENUINE"
            result["reason"] = "Signature verified and the link looks safe."
        elif result["signature_valid"] and score >= 0.5:
            result["verdict"] = "SUSPICIOUS"
            result["reason"] = "Signature verified, but the embedded link looks risky."
        elif not result["signature_valid"] and score >= 0.5:
            result["verdict"] = "FAKE / PHISHING"
            result["reason"] = "No valid signature, and the link looks like phishing."
        else:
            result["verdict"] = "UNVERIFIED"
            result["reason"] = "No valid signature found for this link."
    else:
        if result["signature_valid"]:
            result["verdict"] = "GENUINE"
            result["reason"] = f"Signature verified for {content_type.replace('_', ' ')} content."
        else:
            result["verdict"] = "UNVERIFIED"
            result["reason"] = (
                f"No valid signature found for this {content_type.replace('_', ' ')} QR code. "
                "It was not issued through a trusted, signed source."
            )

    return result


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "secure_qr.png"
    outcome = verify_qr(path)
    for k, v in outcome.items():
        print(f"{k}: {v}")
