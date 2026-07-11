#!/bin/sh
# Download the IP→country database and convert it to a compact int-range table.
# Source: sapics/ip-location-db (dbip-country, IPv4) via jsDelivr CDN — free, no token.
# Output: /opt/etc/tacet-geo.dat lines "start_int end_int CC", sorted by start_int.
# Triggered from the UI (Settings → Databases → Update) or run directly.
# (c) Max Grakov 2026, MIT License.
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
URL="https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-country/dbip-country-ipv4.csv"
DAT=/opt/etc/tacet-geo.dat
META=/opt/etc/tacet-geo.meta
TMP=/tmp/tacet-geo.csv.$$
# a killed run must not strand a multi-MB temp on flash
trap 'rm -f "$TMP" "$DAT.tmp.$$" 2>/dev/null' EXIT
trap 'exit 1' INT TERM HUP

curl -sfm180 -o "$TMP" "$URL" || { echo "geo: download failed"; rm -f "$TMP"; exit 1; }
[ -s "$TMP" ] || { echo "geo: empty download"; rm -f "$TMP"; exit 1; }

# sort by start int ourselves (zero-padded lexical key — busybox sort -n
# overflows above 2^31): the merge-join resolver needs strict order, and the
# upstream CSV happens to arrive ordered but nothing guarantees it stays so.
awk -F, 'function i(x, o){split(x,o,"."); if(o[1]>255||o[2]>255||o[3]>255||o[4]>255) return -1; return o[1]*16777216+o[2]*65536+o[3]*256+o[4]}
    { sub(/\r$/, "") }
    NF>=3 && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { a=i($1); b=i($2); if (a>=0 && b>=0) print a, b, $3 }' \
    "$TMP" | awk '{printf "%010.0f\t%s\n", $1, $0}' | sort | cut -f2- > "$DAT.tmp.$$"
rm -f "$TMP"

# guard against a changed CSV format silently wiping a working DB, AND against a
# truncated-but-exit-0 download: require at least half the previous row count
# (from .meta) when one is known, else the fixed floor.
ROWS=$(wc -l < "$DAT.tmp.$$" 2>/dev/null | tr -d ' ')
FLOOR=1000
{ read _ prev _ < "$META"; } 2>/dev/null   # brace group: suppress the "no such file" on first run
case "$prev" in *[!0-9]*|'') ;; *) [ "$prev" -gt 2000 ] && FLOOR=$((prev / 2)) ;; esac
if [ "${ROWS:-0}" -lt "$FLOOR" ]; then
    echo "geo: conversion produced only ${ROWS:-0} rows (floor $FLOOR) — keeping the existing database"
    rm -f "$DAT.tmp.$$"; exit 1
fi
mv "$DAT.tmp.$$" "$DAT"
echo "$(date +%s) $ROWS" > "$META"
echo "geo: $ROWS ranges"
