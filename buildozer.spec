[app]
title = SecureScan
package.name = securescan
package.domain = org.example

source.dir = .
source.include_exts = py,png,jpg,kv,atlas

version = 1.0

# opencv removed — qr_verifier.py already falls back to OpenCV-free
# path automatically when cv2 is not importable (which is the case on
# Android). pyzbar intentionally excluded — no reliable Android recipe.
requirements = python3,kivy==2.3.0,ecdsa,qrcode,pillow,plyer

orientation = portrait
fullscreen = 0

android.permissions = CAMERA,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE
android.api = 33
android.minapi = 24
android.archs = arm64-v8a

[buildozer]
log_level = 2
warn_on_root = 1