#!/bin/sh
# Put push-registration reply try N in place: ./npns-try.sh 4
# The running eshop-sniff picks it up on the next request; no restart needed.
set -e
cd "$(dirname "$0")"
src=$(ls sniff-data/npns-tries/"$1"-*.json 2>/dev/null | head -1)
[ -n "$src" ] || { echo "no try $1; have:"; ls sniff-data/npns-tries | grep -v '\.status$'; exit 1; }
dst=sniff-data/responses/l-npns.app.pretendo.cc/api/v1/platforms/3ds/devices.json
mkdir -p "$(dirname "$dst")"
cp "$src" "$dst"
if [ -f "$src.status" ]; then cp "$src.status" "$dst.status"; else rm -f "$dst.status"; fi
echo "now serving $(basename "$src") with status $(cat "$dst.status" 2>/dev/null || echo 200)"
