#!/bin/sh
# Push fix/srv_dev (development responses) to the app's files/srv on the connected phone.
set -e
cd "$(dirname "$0")"
ADB="$LOCALAPPDATA/Android/Sdk/platform-tools/adb.exe"
P=com.gameloft.android.ANMP.GloftSIHM
tar -cf out/srv.tar -C srv_dev .
MSYS_NO_PATHCONV=1 "$ADB" push out/srv.tar /data/local/tmp/srv.tar >/dev/null
MSYS_NO_PATHCONV=1 "$ADB" shell "run-as $P sh -c 'rm -rf files/srv && mkdir files/srv && tar -xf /data/local/tmp/srv.tar -C files/srv'"
MSYS_NO_PATHCONV=1 "$ADB" shell rm /data/local/tmp/srv.tar
echo "pushed $(find srv_dev -type f | wc -l) response files"
