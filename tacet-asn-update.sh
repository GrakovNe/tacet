#!/bin/sh
# Download the IP→owner (ASN) database and convert it to a compact int-range table.
# Source: sapics/ip-location-db (dbip-asn, IPv4) via jsDelivr CDN — free, no token.
# Output: /opt/etc/tacet-asn.dat lines "start_int end_int AS<num>_<Org_Name>",
# sorted by start_int. The owner is one underscore-joined token so every consumer
# (the collector's binary-search resolver, the cache files, the awk emitters) can
# keep treating values as a single field; the UI turns "_" back into spaces.
# Triggered from the UI (Settings → Databases → Update) or run directly.
# (c) Max Grakov 2026, MIT License.
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
URL="https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-asn/dbip-asn-ipv4.csv"
DAT=/opt/etc/tacet-asn.dat
META=/opt/etc/tacet-asn.meta
TMP=/tmp/tacet-asn.csv.$$
# a killed run must not strand a multi-MB temp on flash
trap 'rm -f "$TMP" "$DAT.tmp.$$" 2>/dev/null' EXIT
trap 'exit 1' INT TERM HUP

curl -sfm300 -o "$TMP" "$URL" || { echo "asn: download failed"; rm -f "$TMP"; exit 1; }
[ -s "$TMP" ] || { echo "asn: empty download"; rm -f "$TMP"; exit 1; }

# CSV: start,end,asn,org — org may be quoted and contain commas ("Amazon.com, Inc.").
# Take everything past the third comma as the name, drop quotes, join with "_".
awk -F, 'function i(x, o){split(x,o,"."); if(o[1]>255||o[2]>255||o[3]>255||o[4]>255) return -1; return o[1]*16777216+o[2]*65536+o[3]*256+o[4]}
    { sub(/\r$/, "") }
    NF>=4 && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $3 ~ /^[0-9]+$/ && i($1) >= 0 && i($2) >= 0 {
        name=$0; sub(/^[^,]*,[^,]*,[^,]*,/, "", name)
        gsub(/"/, "", name); gsub(/[ ,]+/, "_", name); gsub(/_+$/, "", name)
        if (length(name) > 40) name = substr(name, 1, 40)
        if (name == "") name = "unknown"
        print i($1), i($2), "AS" $3 "_" name }' \
    "$TMP" | awk '{printf "%010.0f\t%s\n", $1, $0}' | sort | cut -f2- > "$DAT.tmp.$$"
rm -f "$TMP"

# guard against a changed CSV format silently wiping a working DB, AND against a
# truncated-but-exit-0 download: require at least half the previous row count
# (from .meta) when one is known, else the fixed floor. Sorting above (padded
# lexical key — busybox sort -n overflows at 2^31) protects the merge-join
# resolver from a future out-of-order upstream row.
ROWS=$(wc -l < "$DAT.tmp.$$" 2>/dev/null | tr -d ' ')
FLOOR=1000
{ read _ prev _ < "$META"; } 2>/dev/null   # brace group: suppress the "no such file" on first run
case "$prev" in *[!0-9]*|'') ;; *) [ "$prev" -gt 2000 ] && FLOOR=$((prev / 2)) ;; esac
if [ "${ROWS:-0}" -lt "$FLOOR" ]; then
    echo "asn: conversion produced only ${ROWS:-0} rows (floor $FLOOR) — keeping the existing database"
    rm -f "$DAT.tmp.$$"; exit 1
fi
mv "$DAT.tmp.$$" "$DAT"
# resolved owners may be stale after a refresh — drop the cache, the collector
# refills it. The .gen stamp lets a collector tick that loaded the OLD cache
# notice the wipe and discard its appends instead of re-poisoning the fresh one.
rm -f /opt/var/tacet-asncache
date +%s > /opt/var/tacet-asncache.gen 2>/dev/null
echo "$(date +%s) $ROWS" > "$META"
echo "asn: $ROWS ranges"
