"""
qr_generator.py
Creates a cryptographically signed ("secure") QR code from any input data
(a payment link, ticket ID, message, etc.).

The payload is signed with the issuer's ECDSA private key, and the
signed bundle (payload + signature) is what actually gets encoded into
the QR image. Anyone scanning this QR later can verify, using
qr_verifier.py and the matching public key, that it really came from
this issuer and was not altered.
"""

import json
import base64
import time
import hashlib

import qrcode

from key_manager import load_private_key


def create_secure_qr(data: str, issuer_id: str, output_path: str = "secure_qr.png") -> str:
    private_key = load_private_key()

    payload = {
        "data": data,
        "issuer_id": issuer_id,
        "timestamp": int(time.time()),
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

    signature = private_key.sign(payload_bytes, hashfunc=hashlib.sha256)
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    secure_bundle = {
        "payload": payload,
        "signature": signature_b64,
    }
    secure_bundle_str = json.dumps(secure_bundle)

    # box_size/border kept modest since ECDSA signatures are already
    # short — this keeps the QR's module count low and easy to scan.
    img = qrcode.make(secure_bundle_str, box_size=8, border=4).convert("RGB")
    img.save(output_path)

    print(f"Secure QR created: {output_path}")
    return output_path


def upgrade_existing_qr(input_image_path: str, issuer_id: str, output_path: str = "secure_qr_upgraded.png") -> dict:
    """
    Takes a photo/image of an EXISTING, ordinary QR code (one that has
    no cryptographic signature at all — a normal URL or UPI QR you'd
    find anywhere) and re-issues it as a brand new, signed secure QR
    with the exact same underlying data.

    This is useful for "upgrading" QR codes that are already in
    circulation — e.g. a shop's existing payment QR — into ones your
    verifier can authenticate, without needing to change what the QR
    actually points to or pays into.
    """
    # Imported here (not at module level) to avoid a circular import,
    # since qr_verifier.py does not import this module.
    from qr_verifier import decode_qr

    raw_data = decode_qr(input_image_path)

    # If someone accidentally feeds in a QR that's already one of our
    # signed bundles, extract the original data instead of wrapping a
    # signed bundle inside another signed bundle.
    try:
        bundle = json.loads(raw_data)
        original_data = bundle["payload"]["data"]
        was_already_secure = True
    except (json.JSONDecodeError, KeyError, TypeError):
        original_data = raw_data
        was_already_secure = False

    new_path = create_secure_qr(data=original_data, issuer_id=issuer_id, output_path=output_path)

    return {
        "original_data": original_data,
        "was_already_secure": was_already_secure,
        "new_secure_qr_path": new_path,
    }


if __name__ == "__main__":
    create_secure_qr(
        data="upi://pay?vpa=merchant@bank&amt=500",
        issuer_id="merchant_demo_001",
        output_path="secure_qr.png",
    )
