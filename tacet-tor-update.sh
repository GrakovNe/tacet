#!/bin/sh
# Download the Tor exit-relay list — the official bulk exit list published by
# the Tor Project (free, no tokens, ~1-2k addresses, refreshed continuously).
#   -> /opt/etc/tacet-tor.dat, "ip_int ip_int 1" sorted — same int-range shape
#      as the threat DB, so it could feed the shared resolver later if needed.
# When TOR_BAN is on, 50-tacet.sh keeps a live tacet-tor ipset; this script
# swaps a freshly built set in atomically after a download (no matching gap).
# Triggered from the UI (Settings → Databases) or run directly.
# (c) Max Grakov 2026, MIT License.
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
# torproject.org is unreachable on some networks (ISP blocking), so a mirror of
# the same data (FireHOL's tor_exits, hourly-refreshed, via jsDelivr like the
# threat DB) is the fallback. Both are one plain IPv4 per line ('#' comments).
URL="https://check.torproject.org/torbulkexitlist"
URL2="https://cdn.jsdelivr.net/gh/firehol/blocklist-ipsets@master/tor_exits.ipset"
DAT=/opt/etc/tacet-tor.dat
META=/opt/etc/tacet-tor.meta
TMP=/tmp/tacet-tor.txt.$$
# lock: the UI button and the daily auto-update run this same script and share
# the tacet-tor-new temp set — two overlapping runs can flush/swap an empty set
# live, unbanning every relay. mkdir is atomic; steal a lock older than 10 min.
LOCK=/tmp/tacet-tor-update.lock
if ! mkdir "$LOCK" 2>/dev/null; then
    # never steal from a LIVE owner (mtime lies after a boot-time NTP step — a
    # seconds-old run looks decades old); steal a dead one's leftover atomically
    o=$(cat "$LOCK/owner" 2>/dev/null)
    [ -n "$o" ] && [ -d "/proc/$o" ] && grep -q "tacet-tor-update" "/proc/$o/cmdline" 2>/dev/null && \
        { echo "tor: another update is running"; exit 0; }
    [ -n "$(find "$LOCK" -maxdepth 0 -mmin +10 2>/dev/null)" ] && \
        { mv "$LOCK" "$LOCK.dead.$$" 2>/dev/null && rm -rf "$LOCK.dead.$$"; }
    mkdir "$LOCK" 2>/dev/null || { echo "tor: another update is running"; exit 0; }
fi
# PID-stamp so the trap releases only a lock we own (never a thief's);
# also remove our temps so a killed run can't strand them on flash
echo $$ > "$LOCK/owner" 2>/dev/null
trap 'rm -f "$TMP" "$DAT.tmp.$$" 2>/dev/null
      o=$(cat "$LOCK/owner" 2>/dev/null); { [ -z "$o" ] || [ "$o" = "$$" ]; } && rm -rf "$LOCK"' EXIT
trap 'exit 1' INT TERM HUP

curl -sfm30 -o "$TMP" "$URL" || curl -sfm120 -o "$TMP" "$URL2" \
    || { echo "tor: download failed (both sources)"; rm -f "$TMP"; exit 1; }
[ -s "$TMP" ] || { echo "tor: empty download"; rm -f "$TMP"; exit 1; }

# one exit IP per line; anything else means the format changed — filter hard.
# Sort by start int via a zero-padded lexical key (busybox sort -n overflows above
# 2^31, mis-ordering high ranges), then strip the key.
awk 'function i(x, o){split(x,o,"."); if(o[1]>255||o[2]>255||o[3]>255||o[4]>255) return -1; return o[1]*16777216+o[2]*65536+o[3]*256+o[4]}
    { sub(/\r$/, "") }
    $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { n=i($1); if (n >= 0) print n, n, 1 }' \
    "$TMP" | awk '{printf "%010.0f\t%s\n", $1, $0}' | sort | cut -f2- > "$DAT.tmp.$$"
rm -f "$TMP"

# guard against a changed format AND a truncated-but-exit-0 download — this DB
# drives a live ipset swap, so require at least half the previous row count
ROWS=$(wc -l < "$DAT.tmp.$$" 2>/dev/null | tr -d ' ')
FLOOR=100
{ read _ prev _ < "$META"; } 2>/dev/null   # brace group: suppress the "no such file" on first run
case "$prev" in *[!0-9]*|'') ;; *) [ "$prev" -gt 200 ] && FLOOR=$((prev / 2)) ;; esac
if [ "${ROWS:-0}" -lt "$FLOOR" ]; then
    echo "tor: conversion produced only ${ROWS:-0} rows (floor $FLOOR) — keeping the existing database"
    rm -f "$DAT.tmp.$$"; exit 1
fi
mv "$DAT.tmp.$$" "$DAT"
echo "$(date +%s) $ROWS" > "$META"

# if the auto-ban feature is active (the reference set is loaded), refresh it from
# the new list — build a temp set and swap it in atomically (no matching gap)
IPSET=/opt/sbin/ipset
if $IPSET list tacet-tor -terse >/dev/null 2>&1; then
    $IPSET create tacet-tor-new hash:ip hashsize 4096 maxelem 65536 -exist 2>/dev/null
    $IPSET flush tacet-tor-new 2>/dev/null
    # swap ONLY if the whole batch restored (an aborted restore must not put a
    # partial set live)
    if awk '{n=$1; printf "add tacet-tor-new %d.%d.%d.%d\n", int(n/16777216)%256,int(n/65536)%256,int(n/256)%256,n%256}' \
        "$DAT" | $IPSET restore -exist 2>/dev/null; then
        $IPSET swap tacet-tor-new tacet-tor 2>/dev/null
    else
        echo "tor: set reload failed — keeping the live set"
    fi
    $IPSET destroy tacet-tor-new 2>/dev/null
fi
echo "tor: $ROWS exit relays"
