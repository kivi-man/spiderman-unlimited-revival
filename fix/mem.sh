#!/bin/sh
# Query the fake server's dev endpoints from the PC: sh mem.sh /__str/1bc7cf0
set -e
ADB="$LOCALAPPDATA/Android/Sdk/platform-tools/adb.exe"
PORT=$("$ADB" logcat -d -s smfix:* | sed -n 's/.*fake server on 127.0.0.1:\([0-9]*\).*/\1/p' | tail -1)
"$ADB" forward tcp:18555 tcp:$PORT >/dev/null
for p in "$@"; do printf '%s => ' "$p"; curl -s "http://127.0.0.1:18555/x$p"; echo; done
