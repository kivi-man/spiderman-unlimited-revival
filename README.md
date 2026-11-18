# Spider-Man Unlimited 4.6.0c — offline revival patch

Patch tools that make **MARVEL Spider-Man Unlimited 4.6.0c** (Android) run on modern 64-bit phones, fully offline.
A small native library (`libsmfix.so`) is injected into the game and:

- fixes the arm64 crash on Android 11+ (32-bit relative offset allocator issue),
- emulates the shut-down Gameloft servers **inside the game process** (no external server needed):
  recruiting from portals (with animation), duplicates, rank up, team power, VIP portals,
  and the Symbiote World (Venom) event.

**This repository contains no game files.** You need your own copy of the original
`MARVEL+Spider-Man+Unlimited_4.6.0c.apk`. APKs, game libraries and assets are © Gameloft / Marvel
and are not distributed here.

## Build

Requirements: Android NDK, Python 3 with `lief`, apktool, `apksigner`/`zipalign` (Android build-tools), a signing keystore.

1. Put the original APK in the repo root and decompile it with apktool into `decompiled/`.
2. `fix/build_native.sh` — builds `libsmfix.so`.
3. `fix/patch_lib.py` — patches `libSpidermanI.so` to load it.
4. `fix/build_apk.py` — rebuilds and signs the APK (expects `keys/mod-release.jks` and `keys/keystore-password.txt`, which you create yourself).

See [AGENT.md](AGENT.md) for the full technical documentation: hooks, reverse-engineered addresses,
fake server protocol and known gaps.

## Disclaimer

Fan preservation project, not affiliated with Gameloft or Marvel. Use only with a copy of the game you own.
