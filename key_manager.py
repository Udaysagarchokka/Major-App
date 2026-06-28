"""
key_manager.py
Generates and manages the ECDSA key pair used to sign and verify secure
QR codes.

Uses ECDSA (NIST P-256 curve) instead of RSA. This is a deliberate
choice: RSA-2048 signatures are ~256 bytes (~344 characters once
base64-encoded), which makes the resulting QR code very dense — dense
enough that OpenCV's built-in QR detector can fail to even locate the
QR pattern in a photo. ECDSA P-256 signatures are only ~64 bytes
(~88 characters base64-encoded), about 4x shorter — producing a much
less dense, easier-to-scan QR code on any camera, while still being a
cryptographically strong signature scheme.

The `ecdsa` library is pure Python (no C extensions), so this stays
just as easy to package for Android with Buildozer as the previous
`rsa`-based version was.
"""

import os
from ecdsa import SigningKey, VerifyingKey, NIST256p

KEY_DIR = "keys"
PRIVATE_KEY_FILE = os.path.join(KEY_DIR, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(KEY_DIR, "public_key.pem")


def generate_keypair():
    """Generates a new ECDSA (P-256) key pair and saves it to disk."""
    os.makedirs(KEY_DIR, exist_ok=True)
    private_key = SigningKey.generate(curve=NIST256p)
    public_key = private_key.get_verifying_key()

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.to_pem())
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.to_pem())

    print(f"New key pair generated and saved in '{KEY_DIR}/'")
    return public_key, private_key


def load_private_key() -> SigningKey:
    if not os.path.exists(PRIVATE_KEY_FILE):
        raise FileNotFoundError("Private key not found. Run generate_keypair() first.")
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return SigningKey.from_pem(f.read())


def load_public_key() -> VerifyingKey:
    if not os.path.exists(PUBLIC_KEY_FILE):
        raise FileNotFoundError("Public key not found. Run generate_keypair() first.")
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return VerifyingKey.from_pem(f.read())


def keys_exist() -> bool:
    return os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE)


if __name__ == "__main__":
    generate_keypair()
