#!/bin/sh
# Development loop: [--build] rebuild + install the debug APK, push srv_dev responses,
# restart the game with network logging, wait, then summarise the fake server traffic.
# Usage: sh dev_run.sh [--build] [seconds]
set -e
cd "$(dirname "$0")"
ADB="$LOCALAPPDATA/Android/Sdk/platform-tools/adb.exe"
P=com.gameloft.android.ANMP.GloftSIHM
if [ "$1" = "--build" ]; then
    shift
    sh build_native.sh >/dev/null
    python -I build_apk.py --debug ../build/SpiderManUnlimited_4.6.0c_debug.apk >/dev/null
    "$ADB" shell am force-stop $P
    "$ADB" install -r ../build/SpiderManUnlimited_4.6.0c_debug.apk >/dev/null
fi
WAIT=${1:-20}
sh push_srv.sh >/dev/null
"$ADB" shell am force-stop $P
"$ADB" shell run-as $P touch files/smfix_net files/smfix_dev files/smfix_jsontrace
"$ADB" shell run-as $P rm -f files/smfix_net.log
"$ADB" logcat -b crash -c
"$ADB" shell monkey -p $P -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
"$ADB" shell "sleep $WAIT"
"$ADB" exec-out run-as $P cat files/smfix_net.log > out/net.log
echo "crash lines: $("$ADB" logcat -d -b crash | grep -c GloftSIHM || true)"
python -I srv_summary.py out/net.log
