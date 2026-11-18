"""Build the modded APK from the original one.
Usage: python build_apk.py [--debug] <out.apk>

  - lib/arm64-v8a/libSpidermanI.so -> fix/out/libSpidermanI.so (run patch_lib.py first)
  - adds lib/arm64-v8a/libsmfix.so
  - --debug: android:debuggable=true (fix/out/AndroidManifest.debug.xml), allows `adb shell run-as`
Then zipaligns and signs with keys/mod-release.jks."""
import glob
import os
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_APK = os.path.join(ROOT, 'MARVEL+Spider-Man+Unlimited_4.6.0c.apk')
FIX = os.path.join(ROOT, 'fix')
SDK = os.path.join(os.environ['LOCALAPPDATA'], 'Android', 'Sdk')
BUILD_TOOLS = sorted(glob.glob(os.path.join(SDK, 'build-tools', '*')))[-1]

debug = '--debug' in sys.argv
out = os.path.abspath([a for a in sys.argv[1:] if not a.startswith('--')][0])

replace = {'lib/arm64-v8a/libSpidermanI.so': os.path.join(FIX, 'out', 'libSpidermanI.so')}
add = {'lib/arm64-v8a/libsmfix.so': os.path.join(FIX, 'libsmfix.so')}
if debug:
    replace['AndroidManifest.xml'] = os.path.join(FIX, 'out', 'AndroidManifest.debug.xml')


def is_signature(name):
    base = name.split('/')[-1].upper()
    return name.startswith('META-INF/') and base.endswith(('.SF', '.RSA', '.DSA', '.EC', 'MANIFEST.MF'))


unsigned, aligned = out + '.unsigned', out + '.aligned'
src = zipfile.ZipFile(SRC_APK)
with zipfile.ZipFile(unsigned, 'w') as dst:
    for info in src.infolist():
        if is_signature(info.filename):
            continue
        zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
        zi.compress_type, zi.external_attr = info.compress_type, info.external_attr
        path = replace.get(info.filename)
        dst.writestr(zi, open(path, 'rb').read() if path else src.read(info.filename))
    for name, path in add.items():
        zi = zipfile.ZipInfo(name, date_time=(2026, 10, 21, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_DEFLATED
        dst.writestr(zi, open(path, 'rb').read())

password = open(os.path.join(ROOT, 'keys', 'keystore-password.txt')).read().strip()
subprocess.run([os.path.join(BUILD_TOOLS, 'zipalign.exe'), '-P', '16', '-f', '4', unsigned, aligned], check=True)
subprocess.run([os.path.join(BUILD_TOOLS, 'apksigner.bat'), 'sign', '--ks', os.path.join(ROOT, 'keys', 'mod-release.jks'),
                '--ks-key-alias', 'mod', '--ks-pass', f'pass:{password}', '--key-pass', f'pass:{password}',
                '--out', out, aligned], check=True)
os.remove(unsigned)
os.remove(aligned)
print('built', out, '(debug)' if debug else '')
