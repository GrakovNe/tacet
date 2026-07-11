#!/bin/sh
# Download the threat databases — two layers, both free, no tokens:
#   1. IPsum (stamparm/ipsum via jsDelivr): aggregate of 30+ abuse feeds.
#      -> /opt/etc/tacet-threat.dat, "ip_int ip_int score" sorted; score = how many
#      blocklists list the IP; only >=MIN kept. Drives the red badge + auto-ban.
#   2. Activity feeds (blocklist.de / CINS / GreenSnow / Feodo): per-category
#      lists that say WHAT the address was seen doing.
#      -> /opt/etc/tacet-activity.dat, "ip_int ip_int bitmask" sorted; bits:
#      1 port scanning · 2 brute-force logins · 4 mail abuse · 8 web attacks ·
#      16 VoIP fraud · 32 botnet C2. Shown in the IP-details popup.
# Single IPs => start==end, so both reuse the geo binary-search resolver in
# tacet-collect.sh. Triggered from the UI (Settings → Databases) or run directly.
# (c) Max Grakov 2026, MIT License.
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
URL="https://cdn.jsdelivr.net/gh/stamparm/ipsum@master/ipsum.txt"
DAT=/opt/etc/tacet-threat.dat
META=/opt/etc/tacet-threat.meta
CACHE=/opt/var/tacet-threatcache
MIN=3
TMP=/tmp/tacet-threat.txt.$$
# lock: the UI button and the daily auto-update run this same script and share
# the tacet-threat-new temp set — two overlapping runs can flush/swap an empty
# set live, unbanning every threat IP. mkdir is atomic. Steal only after 20 min:
# a legitimate worst case is ~13 min (180 s main download + 10 feeds x 60 s), so
# a 10-min steal could kill a live run. PID-stamp the lock so the trap releases
# only a lock we own (or an ownerless one) — never a thief's.
LOCK=/tmp/tacet-threat-update.lock
if ! mkdir "$LOCK" 2>/dev/null; then
    # never steal from a LIVE owner (a run overrunning 20 min would get a peer
    # sharing tacet-threat-new — the empty-swap disaster); steal a dead one's
    # leftover atomically (rename — two stealers can't both win)
    o=$(cat "$LOCK/owner" 2>/dev/null)
    # match THIS script's name, not just "tacet": a recycled owner PID landing on
    # the long-lived tacet lighttpd would otherwise block updates until reboot
    [ -n "$o" ] && [ -d "/proc/$o" ] && grep -q "tacet-threat-update" "/proc/$o/cmdline" 2>/dev/null && \
        { echo "threat: another update is running"; exit 0; }
    [ -n "$(find "$LOCK" -maxdepth 0 -mmin +20 2>/dev/null)" ] && \
        { mv "$LOCK" "$LOCK.dead.$$" 2>/dev/null && rm -rf "$LOCK.dead.$$"; }
    mkdir "$LOCK" 2>/dev/null || { echo "threat: another update is running"; exit 0; }
fi
echo $$ > "$LOCK/owner" 2>/dev/null
# also remove our temps: a killed run would strand multi-MB .tmp.$$ files on flash
trap 'rm -f "$TMP" "$DAT.tmp.$$" /tmp/tacet-act.$$ "/opt/etc/tacet-activity.dat.tmp.$$" 2>/dev/null
      o=$(cat "$LOCK/owner" 2>/dev/null); { [ -z "$o" ] || [ "$o" = "$$" ]; } && rm -rf "$LOCK"' EXIT
trap 'exit 1' INT TERM HUP

curl -sfm180 -o "$TMP" "$URL" || { echo "threat: download failed"; rm -f "$TMP"; exit 1; }
[ -s "$TMP" ] || { echo "threat: empty download"; rm -f "$TMP"; exit 1; }

# ipsum.txt is "IP<tab>count", '#'-prefixed comments; keep count>=MIN as int ranges.
# Sort by start int via a zero-padded lexical key (busybox sort -n overflows above
# 2^31, mis-ordering high ranges), then strip the key.
awk -v min="$MIN" 'function i(x, o){split(x,o,"."); if(o[1]>255||o[2]>255||o[3]>255||o[4]>255) return -1; return o[1]*16777216+o[2]*65536+o[3]*256+o[4]}
    { sub(/\r$/, "") }
    $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && ($2+0) >= min { n=i($1); if (n >= 0) print n, n, $2+0 }' \
    "$TMP" | awk '{printf "%010.0f\t%s\n", $1, $0}' | sort | cut -f2- > "$DAT.tmp.$$"
rm -f "$TMP"

# guard against a changed format AND a truncated-but-exit-0 download — this DB
# drives a live ipset swap, so require at least half the previous row count
ROWS=$(wc -l < "$DAT.tmp.$$" 2>/dev/null | tr -d ' ')
FLOOR=100
{ read _ prev _ < "$META"; } 2>/dev/null   # brace group: suppress the "no such file" on first run
case "$prev" in *[!0-9]*|'') ;; *) [ "$prev" -gt 200 ] && FLOOR=$((prev / 2)) ;; esac
if [ "${ROWS:-0}" -lt "$FLOOR" ]; then
    echo "threat: conversion produced only ${ROWS:-0} rows (floor $FLOOR) — keeping the existing database"
    rm -f "$DAT.tmp.$$"; exit 1
fi
mv "$DAT.tmp.$$" "$DAT"
echo "$(date +%s) $ROWS" > "$META"
# threat status changes over time, so unlike the geo cache the per-IP cache must
# NOT persist stale verdicts — wipe it so the collector re-resolves against the new
# DB. The .gen stamp lets a collector tick that loaded the OLD cache notice the
# wipe and discard its appends instead of re-poisoning the fresh cache.
: > "$CACHE" 2>/dev/null
date +%s > "$CACHE.gen" 2>/dev/null

# if the auto-ban feature is active (the reference set is loaded), refresh it from
# the new list — build a temp set and swap it in atomically (no matching gap)
IPSET=/opt/sbin/ipset
if $IPSET list tacet-threat -terse >/dev/null 2>&1; then
    $IPSET create tacet-threat-new hash:ip hashsize 16384 maxelem 300000 -exist 2>/dev/null
    $IPSET flush tacet-threat-new 2>/dev/null
    # swap ONLY if the whole batch restored — an aborted restore (kernel memory
    # pressure) would otherwise put a partial set live, silently unbanning most
    # reputation-flagged sources until the next update
    if awk '{n=$1; printf "add tacet-threat-new %d.%d.%d.%d\n", int(n/16777216)%256,int(n/65536)%256,int(n/256)%256,n%256}' \
        "$DAT" | $IPSET restore -exist 2>/dev/null; then
        $IPSET swap tacet-threat-new tacet-threat 2>/dev/null
    else
        echo "threat: set reload failed — keeping the live set"
    fi
    $IPSET destroy tacet-threat-new 2>/dev/null
fi
echo "threat: $ROWS entries"

# --- layer 2: activity categories (best effort — a failed feed just drops its
# category for a day; the DB is replaced only if the merge looks sane) ---
ACTDAT=/opt/etc/tacet-activity.dat
ACTTMP=/tmp/tacet-act.$$
: > "$ACTTMP"
feed() {  # $1 = bit, $2 = url — tag every IPv4 line with the category bit.
    # strip \r first: Feodo serves CRLF, and without this its every line fails
    # the $-anchored match — the botnet-C2 category never populated at all.
    # Octets bounded: one malformed upstream "300.1.2.3" would wrap modulo 256
    # into an innocent address downstream.
    curl -sfm60 "$2" 2>/dev/null | awk -v b="$1" '{ sub(/\r$/, "") }
        $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
            split($1,o,"."); if (o[1]>255||o[2]>255||o[3]>255||o[4]>255) next
            print $1, b }' >> "$ACTTMP"
}
feed 1  "https://cinsscore.com/list/ci-badguys.txt"                # port scanning
feed 1  "https://blocklist.greensnow.co/greensnow.txt"             # port scanning
feed 2  "https://lists.blocklist.de/lists/ssh.txt"                 # brute-force logins
feed 2  "https://lists.blocklist.de/lists/bruteforcelogin.txt"
feed 2  "https://lists.blocklist.de/lists/ftp.txt"
feed 2  "https://lists.blocklist.de/lists/imap.txt"
feed 4  "https://lists.blocklist.de/lists/mail.txt"                # mail abuse
feed 8  "https://lists.blocklist.de/lists/apache.txt"              # web attacks
feed 16 "https://lists.blocklist.de/lists/sip.txt"                 # VoIP fraud
feed 32 "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"  # botnet C2

# OR the bits per IP (no or() in busybox awk — collect distinct bits per IP and
# sum them), emit int ranges (start==end) sorted for the shared resolver via a
# zero-padded lexical key (busybox sort -n overflows above 2^31), key then stripped
awk 'function i(x, o){split(x,o,"."); return o[1]*16777216+o[2]*65536+o[3]*256+o[4]}
     { n=i($1); seen[n" "$2]=1; ips[n]=1 }
     END{ for (n in ips){ s=0; for (b=1; b<=32; b*=2) if ((n" "b) in seen) s+=b; print n, n, s } }' \
    "$ACTTMP" | awk '{printf "%010.0f\t%s\n", $1, $0}' | sort | cut -f2- > "$ACTDAT.tmp.$$"
rm -f "$ACTTMP"
AROWS=$(wc -l < "$ACTDAT.tmp.$$" 2>/dev/null | tr -d ' ')
if [ "${AROWS:-0}" -lt 1000 ]; then
    echo "activity: only ${AROWS:-0} rows — keeping the existing database"
    rm -f "$ACTDAT.tmp.$$"
else
    mv "$ACTDAT.tmp.$$" "$ACTDAT"
    rm -f /opt/var/tacet-actcache      # verdicts changed — let the collector re-resolve
    date +%s > /opt/var/tacet-actcache.gen 2>/dev/null   # see the threat .gen note above
    echo "activity: $AROWS entries"
fi
