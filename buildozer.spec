[app]
title = SecureScan
package.name = securescan
package.domain = org.example

source.dir = .
source.include_exts = py,png,jpg,kv,atlas

version = 1.0

requirements = python3,kivy==2.2.1,ecdsa,qrcode,pillow,plyer

orientation = portrait
fullscreen = 0

android.permissions = CAMERA,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE
android.api = 33
android.minapi = 24
android.archs = arm64-v8a

# Pin p4a to a stable commit that has a working kivy 2.2.1 recipe
p4a.branch = master

[buildozer]
log_level = 2
warn_on_root = 1