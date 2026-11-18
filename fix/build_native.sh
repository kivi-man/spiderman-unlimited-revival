#!/bin/sh
# Build libsmfix.so (arm64) and re-patch libSpidermanI.so. Run from Git Bash.
set -e
cd "$(dirname "$0")"
NDK="$LOCALAPPDATA/Android/Sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/windows-x86_64/bin"
"$NDK/clang.exe" --target=aarch64-linux-android21 -O2 -fPIC -shared -Wall -Wextra \
    -fvisibility=hidden -Wl,-z,max-page-size=16384 -Wl,--build-id \
    -o libsmfix.so smfix.c smcommon.c smdebug.c smnet.c smsrv.c smsrv_routes.c smsrv_dev.c smapi.c smjson.c -llog
mkdir -p out
python -E patch_lib.py ../decompiled/native/arm64-v8a/libSpidermanI.so out/libSpidermanI.so
# Hook offsets in smdebug.c / smnet.c assume LIEF shifted the image by exactly 0x1000.
python -I - <<'EOF'
orig = open('../decompiled/native/arm64-v8a/libSpidermanI.so', 'rb').read()
new = open('out/libSpidermanI.so', 'rb').read()
for off in (0x11a753c, 0x1241cd4, 0x1241af4, 0x1207374, 0x12a1b40, 0x12f541c, 0x126d48c, 0x126d1d4):
    assert new[off + 0x1000:off + 0x1040] == orig[off:off + 0x40], hex(off)
print('image shift 0x1000 verified')
EOF
