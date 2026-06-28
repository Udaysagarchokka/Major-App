[app]
title = SecureScan
package.name = securescan
package.domain = org.example

source.dir = .
source.include_exts = py,png,jpg,kv,atlas

version = 1.0

# Pure-Python ecdsa and qrcode are easy to package. pillow and opencv
# both have maintained python-for-android recipes, but opencv
# significantly increases build time and APK size — remove "opencv"
# and the cv2 import in qr_verifier.py if your build fails, and decode
# QR images on a PC instead for your demo if needed.
# pyzbar is intentionally NOT included here — it needs the native
# libzbar shared library, which has no reliable Android recipe. The
# code already handles this: qr_verifier.py tries pyzbar only if it's
# importable and falls back to OpenCV automatically otherwise, which
# is exactly what happens on Android.
requirements = python3,kivy,ecdsa,qrcode,pillow,opencv,plyer

orientation = portrait
fullscreen = 0

android.permissions = CAMERA,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE

[buildozer]
log_level = 2
warn_on_root = 1
