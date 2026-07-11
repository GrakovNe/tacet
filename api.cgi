#!/bin/sh
# Tacet JSON API (shell CGI). The page shell is the static index.html; all
# rendering happens client-side in tacet.js against these endpoints.
#
#   GET /api.cgi?fn=<endpoint>[&params]
#
# Read endpoints (JSON snapshots): overview | protection | whitelist | settings | export
# Actions (mutate, return {"ok":true}): ban unban white unwhite setnote master loglevel
#   clearlog config geoupdate threatupdate asnupdate torupdate autodb checkupdate doupdate import
# State lives outside this file: ipsets tacet-scan / tacet-flood / tacet-allow,
# config /opt/etc/tacet.conf, whitelist /opt/etc/tacet-allow.list, stats CSV.
# (c) Max Grakov 2026, MIT License.
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
IPSET=/opt/sbin/ipset
IPT=/opt/sbin/iptables
WHITEFILE=/opt/etc/tacet-allow.list
CONF=/opt/etc/tacet.conf
HOOK=/opt/etc/ndm/netfilter.d/50-tacet.sh
CSV=/opt/var/tacet-stats.csv
HL=/proc/net/ipt_hashlimit
EVLOG=/opt/var/tacet-events.log
GEOCACHE=/opt/var/tacet-geocache
THREATCACHE=/opt/var/tacet-threatcache
ASNCACHE=/opt/var/tacet-asncache
ACTCACHE=/opt/var/tacet-actcache
COUNTRIES=/opt/etc/tacet-countries
# the flag-lookup awks take these caches as file arguments — they may not exist yet
# on a fresh install (the collector fills them), and a missing file makes busybox awk
# bail out with no output. Guarantee they exist so the tables always render.
[ -f "$GEOCACHE" ]    || : > "$GEOCACHE"    2>/dev/null
[ -f "$THREATCACHE" ] || : > "$THREATCACHE" 2>/dev/null
[ -f "$ASNCACHE" ]    || : > "$ASNCACHE"    2>/dev/null
[ -f "$ACTCACHE" ]    || : > "$ACTCACHE"    2>/dev/null

# --- 1. request parsing ---
FN=""; IP=""; CAT="closed"; LVL=""
Q_TTLH=""; Q_BURST=""; Q_SVCP=""; Q_SVCB=""; Q_REF=""; Q_SYNTO=""; Q_WAN=""; Q_TC="no"; Q_TO="no"
Q_SNM=""; Q_SNB=""; Q_TS="no"; Q_TB="no"; Q_TRB="no"; Q_RJ="no"; Q_CX="no"; Q_CP=""; Q_CE=""
set -f   # no globbing: the loop below word-splits QUERY_STRING on & — an unquoted
         # value with glob metacharacters must reach the case as-is, not expanded
OIFS="$IFS"; IFS="&"
for kv in $QUERY_STRING; do
    case "$kv" in
        fn=*)       FN="${kv#fn=}" ;;
        ip=*)       IP="${kv#ip=}" ;;
        cat=*)      CAT="${kv#cat=}" ;;
        lvl=*)      LVL="${kv#lvl=}" ;;
        ttlh=*)     Q_TTLH="${kv#ttlh=}" ;;
        burst=*)    Q_BURST="${kv#burst=}" ;;
        svcports=*) Q_SVCP="${kv#svcports=}" ;;
        svcburst=*) Q_SVCB="${kv#svcburst=}" ;;
        wan=*)      Q_WAN="${kv#wan=}" ;;
        refresh=*)  Q_REF="${kv#refresh=}" ;;
        synto=*)    Q_SYNTO="${kv#synto=}" ;;
        tclosed=on) Q_TC="yes" ;;
        topen=on)   Q_TO="yes" ;;
        tsubnet=on) Q_TS="yes" ;;
        tban=on)    Q_TB="yes" ;;
        torban=on)  Q_TRB="yes" ;;
        reject=on)  Q_RJ="yes" ;;
        snmask=*)   Q_SNM="${kv#snmask=}" ;;
        snburst=*)  Q_SNB="${kv#snburst=}" ;;
        compact=on)     Q_CX="yes" ;;
        inc=*)      Q_INC="${kv#inc=}" ;;
        mode=*)     Q_MODE="${kv#mode=}" ;;
        note=*)     Q_NOTE="${kv#note=}" ;;
        compactpct=*)   Q_CP="${kv#compactpct=}" ;;
        compactevery=*) Q_CE="${kv#compactevery=}" ;;
    esac
done
IFS="$OIFS"
set +f   # re-enable globbing now that QUERY_STRING is parsed — the protection
         # endpoint's candidate loop globs the hashlimit htable files ($HL/tct-scan*)

# --- 2. validation & response helpers ---
# IP or CIDR, octets 0-255 and mask 0-32 — a loose [0-9]{1,3} would pass 999.999
# and /99 straight into ipset, which aborts a whole restore batch on the bad line
ok_ip() {
    echo "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' || return 1
    # octets 0-255; a mask, if present, must be 8-32 — a /0-/7 whitelist or ban
    # covers 16M+ addresses (0.0.0.0/0 = the whole internet) and is never intended
    echo "$1" | awk -F'[./]' '{ for(i=1;i<=4;i++) if($i>255) exit 1;
        if (NF==5 && ($5>32 || $5<8)) exit 1 }'
}
ok_num()   { echo "$1" | grep -qE '^[0-9]+$'; }
# each port must be 1-65535: a saved 70000 passes a digit-count check but makes
# iptables reject the trap rule — the flood trap silently never installs
ok_ports() {
    [ -z "$1" ] && return 0
    echo "$1" | grep -qE '^([0-9]{1,5})(,[0-9]{1,5})*$' || return 1
    echo "$1" | awk -F, '{ for (i=1;i<=NF;i++) if ($i+0 < 1 || $i+0 > 65535) exit 1 }'
}
Q_SVCP=$(echo "$Q_SVCP" | sed 's/%2[Cc]/,/g')
IP=$(echo "$IP" | sed 's/%2[Ff]/\//g')  # CIDR from the client: %2F -> /
# whitelist note: full urldecode (free text, any language), then strip the JSON /
# file-format structural chars and cap the length — a note must never be able to
# break a payload or smuggle a second line into the whitelist file
# tr strips: JSON structural chars ("\), the import tokenizer's structural chars
# ({}[]), and — via the [:cntrl:] class — every control byte (a raw 0x1b etc.
# would otherwise land in a JSON string and break every payload that carries it)
Q_NOTE=$(printf '%b' "$(echo "$Q_NOTE" | sed 's/+/ /g; s/%/\\x/g')" 2>/dev/null | \
    tr -d '"\\{}[]' | tr -d '[:cntrl:]' | awk '{ gsub(/^ +| +$/, ""); print substr($0, 1, 96); exit }')
case "$CAT" in open|cnet|fnet) ;; *) CAT="closed" ;; esac
jhead() { printf 'Content-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\n\r\n'; }
jok()   { jhead; printf '{"ok":true}\n'; exit 0; }
jerr()  { jhead; printf '{"ok":false,"err":"%s"}\n' "$1"; exit 0; }

# config — defaults mirror the block in 50-tacet.sh; keep the two in sync.
BAN_TTL=86400; BURST=8; SVC_PORTS="443"; SVC_BURST=60; WAN=ppp0
TRAP_CLOSED=yes; TRAP_OPEN=yes; MASTER=yes; LOG_ENABLED=no; LOG_DROPS=no; REFRESH_SEC=60; SYN_TIMEOUT=60
TRAP_SUBNET=no; SUBNET_MASK=24; SUBNET_BURST=30; AUTO_DB_UPDATE=no; THREAT_BAN=no; TOR_BAN=no; BAN_REJECT=no
COMPACT=no; COMPACT_PCT=5; COMPACT_EVERY=5
# CR-stripped eval, not dot-source: values from a Windows-edited conf carry \r
[ -f "$CONF" ] && eval "$(tr -d '\r' < "$CONF")"
[ "${TRAP_ENABLED:-yes}" = "no" ] && { TRAP_CLOSED=no; TRAP_OPEN=no; TRAP_SUBNET=no; }
# guard every eval'd numeric: the engine and collector clamp these, and this file
# is otherwise the only reader that trusts them — a hand-edited "REFRESH_SEC="
# would emit `"refresh":,` (invalid JSON, dead dashboard) and a garbage BAN_TTL
# is a fatal ash arithmetic error in the settings endpoint.
case "$BAN_TTL"       in ''|*[!0-9]*) BAN_TTL=86400 ;; esac
case "$BURST"         in ''|*[!0-9]*) BURST=8 ;; esac
case "$SVC_BURST"     in ''|*[!0-9]*) SVC_BURST=60 ;; esac
case "$SUBNET_MASK"   in ''|*[!0-9]*) SUBNET_MASK=24 ;; esac
case "$SUBNET_BURST"  in ''|*[!0-9]*) SUBNET_BURST=30 ;; esac
case "$REFRESH_SEC"   in ''|*[!0-9]*) REFRESH_SEC=60 ;; esac
case "$SYN_TIMEOUT"   in ''|*[!0-9]*) SYN_TIMEOUT=60 ;; esac   # empty would emit "synto":,
case "$COMPACT_PCT"   in ''|*[!0-9]*) COMPACT_PCT=5 ;; esac
case "$COMPACT_EVERY" in ''|*[!0-9]*) COMPACT_EVERY=5 ;; esac
# the string conf keys need a read-side guard too: a hand-edited quote/junk would
# emit invalid JSON and kill the settings AND protection payloads
case "$SVC_PORTS"     in *[!0-9,]*) SVC_PORTS=443 ;; esac
# WAN interface: set in the UI (General), stored in tacet.conf, honored by the
# engine too. Interface name only — guard before it feeds ip/iptables and JSON.
case "$WAN" in ''|*[!a-zA-Z0-9._-]*) WAN=ppp0 ;; esac
WANIP=$(ip -4 addr show "$WAN" 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | head -1)

# the config-key inventory, grouped by validation shape. Single source for
# write_conf, the export endpoint and the import validator — add new keys here.
CONF_NUM="BAN_TTL BURST SVC_BURST SUBNET_MASK SUBNET_BURST REFRESH_SEC SYN_TIMEOUT COMPACT_PCT COMPACT_EVERY"
CONF_YN="TRAP_CLOSED TRAP_OPEN TRAP_SUBNET MASTER LOG_ENABLED LOG_DROPS AUTO_DB_UPDATE THREAT_BAN TOR_BAN COMPACT BAN_REJECT"
# ban category token -> ipset name, for everything that walks the four surfaces
CATSETS="closed:tacet-scan open:tacet-flood cnet:tacet-cnet fnet:tacet-fnet"
members() { $IPSET list "$1" 2>/dev/null | sed -n '/Members:/,$p' | tail -n +2; }
# database status for the settings page: "rows date" for a db stem (geo/threat/
# asn/tor), fork-free via read. rows 0 and empty date when the db isn't present.
dbmeta() {
    [ -f "/opt/etc/tacet-$1.dat" ] || { echo "0"; return; }
    w=""; r=""   # a failed read must not carry the PREVIOUS db's values over
    { read w r _ < "/opt/etc/tacet-$1.meta"; } 2>/dev/null
    # a torn meta (power loss mid-write) must not leak garbage into the unquoted
    # "rows":%s JSON slot — that bricks the whole settings tab
    case "$r" in ''|*[!0-9]*) r=0 ;; esac
    case "$w" in *[!0-9]*) w="" ;; esac
    echo "$r $([ -n "$w" ] && date -d "@$w" '+%Y-%m-%d' 2>/dev/null)"
}

write_conf() {  # persist all config keys from the current shell values
    # temp+mv: the engine and collector source this file asynchronously — an
    # in-place `>` truncation would hand them a partial config (traps silently
    # off for that run), and a crash mid-write would gut every setting for good.
    {
        for k in $CONF_NUM $CONF_YN; do eval "echo $k=\$$k"; done
        echo "SVC_PORTS=\"$SVC_PORTS\""
        echo "WAN=\"$WAN\""
        # carry over keys outside the inventory (e.g. the collector-only
        # GEO_EVERY) so a UI save doesn't silently delete a hand-added knob.
        # TRAP_ENABLED is the legacy kill-switch — deliberately dropped.
        [ -f "$CONF" ] && awk -F= -v known=" $CONF_NUM $CONF_YN SVC_PORTS WAN TRAP_ENABLED " \
            '/^[A-Z_][A-Z_0-9]*=/ { if (index(known, " " $1 " ") == 0) print }' "$CONF"
    } > "$CONF.$$" && mv "$CONF.$$" "$CONF"
}
apply_rules() { table=filter type=iptables sh "$HOOK" >/dev/null 2>&1; }
# serialize whitelist-FILE mutations: unwhite/setnote rewrite-and-rename races a
# concurrent white/import append — an append landing between the rewrite's read
# and its rename is silently discarded, and the file (authoritative on the next
# engine run) then loses an entry the set still holds. File ops take ms; steal a
# stale lock (crashed CGI) after ~5 s.
wl_lock() {
    n=0
    until mkdir /tmp/tacet-wl.lock 2>/dev/null; do
        n=$((n+1))
        # steal a stale lock atomically (rename): a bare rm+mkdir lets two waiters
        # both delete-and-recreate, so both rewrite the whitelist file concurrently
        [ "$n" -ge 5 ] && { mv /tmp/tacet-wl.lock /tmp/tacet-wl.lock.dead.$$ 2>/dev/null && rm -rf /tmp/tacet-wl.lock.dead.$$; n=0; }
        sleep 1
    done
}
wl_unlock() { rm -rf /tmp/tacet-wl.lock 2>/dev/null; }
# refresh the on-disk snapshots after a deliberate flush: the engine restores any
# EMPTY set from its .save on the very next run (reconnect, Apply, Master toggle),
# so a stale snapshot would resurrect everything the flush just removed — within
# seconds, reported as success. Same guard shape as the cron persist line.
resave() {
    # PID-unique temp: the cron persist job writes /opt/etc/$s.save.tmp for the
    # same sets — sharing its name would let the two writers interleave into one
    # torn file (or the cron's cleanup rm our temp, silently no-oping the resave)
    for s in "$@"; do
        $IPSET save "$s" > "/opt/etc/$s.save.tmp.$$" 2>/dev/null \
            && grep -q "^create $s " "/opt/etc/$s.save.tmp.$$" \
            && mv "/opt/etc/$s.save.tmp.$$" "/opt/etc/$s.save" \
            || rm -f "/opt/etc/$s.save.tmp.$$"
    done
}
t_log() { [ "$LOG_ENABLED" = "yes" ] && echo "$(date '+%Y-%m-%d %H:%M:%S')  $1  $2" >> "$EVLOG"; }
# Keep the collector's ban baseline in step with a manual change so the same event
# isn't re-logged a minute later as a "scan"/"flood". $1=add|del $2=ip $3=closed|open
sync_prev() {
    [ "$LOG_ENABLED" = "yes" ] || return
    pf="/opt/var/tacet-prev-$3"; [ -f "$pf" ] || return
    if [ "$1" = "add" ]; then
        grep -qxF "$2" "$pf" 2>/dev/null || echo "$2" >> "$pf"
    else
        # pid-suffixed temp: two concurrent CGI unbans must not share one .t file
        grep -vxF "$2" "$pf" > "$pf.$$" 2>/dev/null; mv "$pf.$$" "$pf" 2>/dev/null
    fi
}

# --- 3. actions (mutate, answer {"ok":true}) ---
case "$FN" in
master)
    [ "$MASTER" = "yes" ] && MASTER=no || MASTER=yes
    t_log master "protection turned $([ "$MASTER" = yes ] && echo on || echo off)"
    write_conf; apply_rules; jok ;;
loglevel)
    case "$LVL" in
        off)     LOG_ENABLED=no;  LOG_DROPS=no ;;
        verbose) LOG_ENABLED=yes; LOG_DROPS=yes ;;
        *)       LOG_ENABLED=yes; LOG_DROPS=no ;;   # normal
    esac
    t_log logging "logging level set to $LVL"   # only records when now on (guarded)
    write_conf; jok ;;
clearlog)
    : > "$EVLOG" 2>/dev/null; jok ;;
geoupdate)
    [ -x /opt/etc/tacet-geo-update.sh ] && /opt/etc/tacet-geo-update.sh >/dev/null 2>&1 < /dev/null &
    jok ;;
threatupdate)
    [ -x /opt/etc/tacet-threat-update.sh ] && /opt/etc/tacet-threat-update.sh >/dev/null 2>&1 < /dev/null &
    jok ;;
asnupdate)
    [ -x /opt/etc/tacet-asn-update.sh ] && /opt/etc/tacet-asn-update.sh >/dev/null 2>&1 < /dev/null &
    jok ;;
torupdate)
    [ -x /opt/etc/tacet-tor-update.sh ] && /opt/etc/tacet-tor-update.sh >/dev/null 2>&1 < /dev/null &
    jok ;;
autodb)
    [ "$AUTO_DB_UPDATE" = "yes" ] && AUTO_DB_UPDATE=no || AUTO_DB_UPDATE=yes
    # arm it to fire on the next collector tick when turned on
    [ "$AUTO_DB_UPDATE" = "yes" ] && rm -f /opt/var/tacet-autoupdate.stamp
    t_log config "database auto-update turned $AUTO_DB_UPDATE"
    write_conf; jok ;;
checkupdate)
    [ -x /opt/etc/tacet-update.sh ] && /opt/etc/tacet-update.sh --check >/dev/null 2>&1
    jok ;;
doupdate)
    if [ -x /opt/etc/tacet-update.sh ]; then
        # stamp the start time so a crash/power-loss mid-update can't hide the
        # update controls forever — the reader below ages this out
        echo "updating $(date +%s)" > /opt/var/tacet-update-state
        /opt/etc/tacet-update.sh --apply >/dev/null 2>&1 < /dev/null &
    fi
    jok ;;
import)
    # restore a tacet-export JSON (POST body). mode=append adds entries to the
    # current data; mode=override first wipes each section the FILE carries.
    # The parser is deliberately dumb: split the body at quote-comma boundaries
    # (a comma inside a quoted value survives) plus the other JSON structure
    # chars, then a section state machine validates each token and emits either
    # a "C key value" config line or a ready ipset-restore "add" line — so the
    # whole entry batch loads with one ipset call instead of one per entry.
    [ "$REQUEST_METHOD" = "POST" ] || jerr "use POST"
    case "$Q_MODE" in override) ;; *) Q_MODE=append ;; esac
    CL=${CONTENT_LENGTH:-0}
    ok_num "$CL" && [ "$CL" -gt 2 ] || jerr "empty body"
    [ "$CL" -le 4194304 ] || jerr "file too large"
    TMPI=/tmp/tacet-import.$$
    head -c "$CL" > "$TMPI"
    grep -q '"tacet_export"' "$TMPI" || { rm -f "$TMPI"; jerr "not a tacet export file"; }
    CMDS=/tmp/tacet-import-cmds.$$
    sed 's/",/"\n/g' "$TMPI" | tr '{}[]' '\n' | sed 's/^[[:space:],]*//;s/[[:space:]]*$//' | \
    awk -v def="$BAN_TTL" -v cats="$CATSETS" '
        BEGIN { n=split(cats, cc, " "); for (i=1;i<=n;i++) { split(cc[i], kv, ":"); m[kv[1]]=kv[2] } }
        # "SEC <name>" marks a section as PRESENT (even if empty) so override can
        # flush exactly the sections the file carries, not just the non-empty ones
        /^"config":/    { sec="c"; next }
        /^"whitelist":/ { sec="w"; print "SEC w"; next }
        /^"bans_[a-z]+":/ { sec=$0; sub(/^"bans_/,"",sec); sub(/":.*/,"",sec); print "SEC " sec; next }
        sec=="c" && /^"[A-Z_]+":"[^"]*"$/ {
            k=$0; sub(/^"/,"",k); sub(/":.*/,"",k)
            v=$0; sub(/^"[A-Z_]+":"/,"",v); sub(/"$/,"",v)
            print "C " k " " v; next }
        # whitelist entries may carry a free-text note after the address:
        # the address feeds the set, the whole line ("WN ...") feeds the file
        sec=="w" && /^"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?( [^"]*)?"$/ {
            # strip the same set as the GET note sanitizer (quotes, backslash,
            # control bytes incl. DEL) so an imported note round-trips through export
            x=$0; gsub(/["\\]/,"",x); gsub(/[][{}]/,"",x); gsub(/[\001-\037\177]/,"",x)
            # ^ braces/brackets stripped too (parity with the GET sanitizer): a
            #   note carrying one would split the token on the NEXT import via
            #   the tr braces pass, silently dropping the entry from the restore
            split(x, p, " ")
            split(p[1], o, /[.\/]/)
            if (o[1]>255||o[2]>255||o[3]>255||o[4]>255||(o[5]!=""&&(o[5]>32||o[5]<8))) next
            if (p[1] ~ /\/32$/) { sub(/\/32$/, "", p[1]); sub(/^[^ ]+/, p[1], x) }
            # ^ normalize /32 like the GET path — hash:net stores x and x/32 as
            #   one entry, and an imported /32 file line becomes undeletable
            print "add tacet-allow " p[1]
            print "WN " x; next }
        /^"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?( [0-9]+)?"$/ {
            x=$0; gsub(/"/,"",x)
            if (!(sec in m)) next
            ttl=def
            if (split(x, p, " ") == 2) { x=p[1]; ttl=p[2]+0 }
            # reject an out-of-range address: one bad "add" line aborts the whole
            # ipset restore batch below (bans AND whitelist), so filter it here
            n=split(x, o, /[.\/]/); bad=0
            for (i=1;i<=4;i++) if (o[i]>255) bad=1
            if (n==5 && (o[5]>32 || o[5]<8)) bad=1   # reject /0-/7 (16M+ addresses)
            if (bad) next
            if (ttl < 1) ttl=def; if (ttl > 2592000) ttl=2592000
            # a CIDR must NOT reach a set element-by-element: scan/flood are hash:ip
            # (a CIDR errors and aborts the whole restore batch), and cnet/fnet are
            # hash:ip+netmask (feeding "10.0.0.0/8" ENUMERATES ~16M adds). Route a
            # CIDR aimed at the single-IP surface to its SUBNET set (same as the ban
            # endpoint — a hash:net-era export must not silently lose those bans),
            # then strip the mask to the base for the netmask set.
            dst = m[sec]
            if (n==5) {
                if (dst !~ /net$/) dst = (sec=="closed" ? m["cnet"] : m["fnet"])
                sub(/\/[0-9]+$/, "", x)
            }
            print "add " dst " " x " timeout " ttl
        }' > "$CMDS"
    rm -f "$TMPI"
    FLUSHED=""
    if [ "$Q_MODE" = "override" ]; then
        # the whitelist-file truncation must hold the same lock as every other
        # file rewrite — a concurrent setnote/unwhite rename landing after the
        # truncate would resurrect the pre-override file wholesale
        grep -q '^SEC w$' "$CMDS" && { wl_lock; $IPSET flush tacet-allow 2>/dev/null; : > "$WHITEFILE"; wl_unlock; }
        for c2 in $CATSETS; do
            grep -q "^SEC ${c2%%:*}$" "$CMDS" && { $IPSET flush "${c2##*:}" 2>/dev/null; FLUSHED="$FLUSHED ${c2##*:}"; }
        done
        # refresh the snapshots NOW: apply_rules below runs the engine, which
        # restores any empty set from a stale .save — undoing this flush
        [ -n "$FLUSHED" ] && resave $FLUSHED
    fi
    # config lines: few and validated one by one (key must be in the inventory,
    # value must fit the key's shape) before entering the shell environment
    NC=0
    # numeric keys must also fit the same ranges the config endpoint enforces:
    # shape-only validation let an import smuggle e.g. BAN_TTL above ipset's
    # timeout ceiling — every `ipset create` then fails on the next boot and the
    # router runs wide open. Same table as the config handler; keep in sync.
    imp_range() {  # $1 = key, $2 = value (already digits-only)
        case "$1" in
            BAN_TTL)       [ "$2" -ge 3600 ] && [ "$2" -le 2592000 ] ;;
            BURST)         [ "$2" -ge 1 ] && [ "$2" -le 1000 ] ;;
            SVC_BURST)     [ "$2" -ge 1 ] && [ "$2" -le 10000 ] ;;
            SUBNET_MASK)   [ "$2" -ge 8 ] && [ "$2" -le 30 ] ;;
            SUBNET_BURST)  [ "$2" -ge 1 ] && [ "$2" -le 1000 ] ;;
            REFRESH_SEC)   [ "$2" -eq 0 ] || { [ "$2" -ge 5 ] && [ "$2" -le 3600 ]; } ;;
            SYN_TIMEOUT)   [ "$2" -ge 10 ] && [ "$2" -le 120 ] ;;
            COMPACT_PCT)   [ "$2" -ge 1 ] && [ "$2" -le 100 ] ;;
            COMPACT_EVERY) [ "$2" -ge 1 ] && [ "$2" -le 1440 ] ;;
            *) true ;;
        esac
    }
    while read -r typ a b _; do
        [ "$typ" = "C" ] || continue
        ok=""
        case " $CONF_NUM " in *" $a "*) ok_num "$b" && imp_range "$a" "$b" && ok=1 ;; esac
        case " $CONF_YN "  in *" $a "*) case "$b" in yes|no) ok=1 ;; esac ;; esac
        [ "$a" = "SVC_PORTS" ] && ok_ports "$b" && ok=1
        [ "$a" = "WAN" ] && case "$b" in ''|*[!a-zA-Z0-9._-]*) ;; *) [ "${#b}" -le 16 ] && ok=1 ;; esac
        [ -n "$ok" ] && { eval "$a=\"\$b\""; NC=$((NC+1)); }
    done < "$CMDS"
    # apply the imported CONFIG before restoring entries: a changed SUBNET_MASK
    # rebuilds cnet/fnet — entries restored under the OLD mask would first collapse
    # to wrong (transiently much wider) blocks and then be dropped by the rebuild.
    # With the flush-resave above, the engine run cannot resurrect stale snapshots.
    [ "$NC" -gt 0 ] && { write_conf; apply_rules; }
    # entry lines: one batched restore for everything (bans + whitelist set).
    # ipset restore aborts at the first bad line, so capture the outcome — a
    # silent partial restore after an override flush would claim full success
    # over a half-empty ban list.
    NW=$(grep -c '^add tacet-allow ' "$CMDS")
    NB=$(( $(grep -c '^add ' "$CMDS") - NW ))
    RESTFAIL=""
    if [ $((NW + NB)) -gt 0 ]; then
        grep '^add ' "$CMDS" | $IPSET restore -exist 2>/dev/null || RESTFAIL=1
    fi
    # mirror the whitelist ("WN address [note]" lines) into its file, deduped by
    # address in one pass. CMDS goes first because it is guaranteed non-empty
    # here — an empty first file would silently shift the NR==FNR block onto
    # the second one
    if [ "$NW" -gt 0 ]; then
        wl_lock; touch "$WHITEFILE"
        awk 'NR==FNR { if ($1=="WN" && !d[$2]++) { ip[++n]=$2; line[n]=substr($0,4) } next }
             { seen[$1] }
             END { for (i=1;i<=n;i++) if (!(ip[i] in seen)) print line[i] }' \
            "$CMDS" "$WHITEFILE" >> "$WHITEFILE"
        wl_unlock
    fi
    # an override whose file carries EMPTY ban sections still flushed the sets
    # (SEC markers) with NB=0 — those baselines are stale too
    SECB=""
    [ "$Q_MODE" = "override" ] && grep -qE '^SEC (closed|open|cnet|fnet)$' "$CMDS" && SECB=1
    rm -f "$CMDS"
    # drop the collector's ban-diff baselines — its next tick re-baselines
    # silently (documented first-run behavior), so the import lands in the log
    # as the single line below instead of hundreds of ban/release events
    { [ "$NB" -gt 0 ] || [ -n "$SECB" ]; } && rm -f /opt/var/tacet-prev-closed /opt/var/tacet-prev-open /opt/var/tacet-prev-cnet /opt/var/tacet-prev-fnet
    # (config already written and applied ABOVE, before the entry restore)
    if [ -n "$RESTFAIL" ]; then
        # the whitelist FILE is complete (the engine re-adds from it on its next
        # run, self-healing that set), but the ban sets may be partial — say so
        t_log config "import ($Q_MODE) INCOMPLETE: entry restore failed mid-batch"
        jerr "entry restore failed mid-batch — re-run the import"
    fi
    t_log config "import ($Q_MODE): $NC settings, $NW whitelist entries, $NB bans"
    jhead; printf '{"ok":true,"config":%s,"wl":%s,"bans":%s}\n' "$NC" "$NW" "$NB"; exit 0 ;;
config)
    # 10000 is the kernel's --hashlimit-burst ceiling; a higher value makes iptables
    # reject the rule, so the open trap would silently fail to install.
    # REJECT out-of-range values (like ttlh below) instead of silently replacing
    # them with defaults: the old clamp-to-default answered {ok:true}, the UI
    # flashed "Saved", and the user's number quietly became something else.
    ok_num "$Q_SVCB" && [ "$Q_SVCB" -ge 1 ] && [ "$Q_SVCB" -le 10000 ] || jerr "validation failed"
    { ok_num "$Q_REF" && { [ "$Q_REF" -eq 0 ] || { [ "$Q_REF" -ge 5 ] && [ "$Q_REF" -le 3600 ]; }; }; } || jerr "validation failed"
    ok_num "$Q_SYNTO" && [ "$Q_SYNTO" -ge 10 ] && [ "$Q_SYNTO" -le 120 ] || jerr "validation failed"
    ok_num "$Q_SNM" && [ "$Q_SNM" -ge 8 ] && [ "$Q_SNM" -le 30 ] || jerr "validation failed"
    # burst cap 1000 also keeps the hashlimit bucket name under the kernel's 15-char limit
    ok_num "$Q_SNB" && [ "$Q_SNB" -ge 1 ] && [ "$Q_SNB" -le 1000 ] || jerr "validation failed"
    ok_num "$Q_CP" && [ "$Q_CP" -ge 1 ] && [ "$Q_CP" -le 100 ] || jerr "validation failed"     # fold density %
    ok_num "$Q_CE" && [ "$Q_CE" -ge 1 ] && [ "$Q_CE" -le 1440 ] || jerr "validation failed"    # sweep cadence (min)
    # WAN is an interface name (ppp0 / eth3 / eth2.2 …): letters, digits, . _ - only.
    # Absent (a partial save that omits it) means leave the current WAN untouched —
    # only validate when a value is actually present.
    if [ -n "$Q_WAN" ]; then
        case "$Q_WAN" in *[!a-zA-Z0-9._-]*) jerr "validation failed" ;; esac
        [ "${#Q_WAN}" -le 16 ] || jerr "validation failed"
    fi
    if ok_num "$Q_TTLH" && [ "$Q_TTLH" -ge 1 ] && [ "$Q_TTLH" -le 720 ] && \
       ok_num "$Q_BURST" && [ "$Q_BURST" -ge 1 ] && [ "$Q_BURST" -le 1000 ] && ok_ports "$Q_SVCP"; then
        BAN_TTL=$((Q_TTLH * 3600)); BURST=$Q_BURST; SVC_PORTS=$Q_SVCP; SVC_BURST=$Q_SVCB; [ -n "$Q_WAN" ] && WAN=$Q_WAN
        TRAP_CLOSED=$Q_TC; TRAP_OPEN=$Q_TO; REFRESH_SEC=$Q_REF; SYN_TIMEOUT=$Q_SYNTO
        TRAP_SUBNET=$Q_TS; SUBNET_MASK=$Q_SNM; SUBNET_BURST=$Q_SNB; THREAT_BAN=$Q_TB; TOR_BAN=$Q_TRB; BAN_REJECT=$Q_RJ
        COMPACT=$Q_CX; COMPACT_PCT=$Q_CP; COMPACT_EVERY=$Q_CE
        # arm compaction to sweep on the next collector tick (picks up a new % at once)
        [ "$COMPACT" = "yes" ] && rm -f /opt/var/tacet-compact.stamp
        # LOG_ENABLED / MASTER are preserved — they have their own instant toggles
        t_log config "settings changed"
        write_conf; apply_rules
        jok
    fi
    jerr "validation failed" ;;
ban|unban|white|unwhite|setnote)
    # cat -> ban set. Bans are grouped by surface (closed / open); each surface
    # has a single-IP set and a whole-subnet (netmask) set. A row action carries
    # the exact set token (closed|open|cnet|fnet); "unban whole category" carries
    # the surface (closed|open) and flushes both its sets.
    case "$CAT" in
        open)  TARGET=tacet-flood ;;
        cnet)  TARGET=tacet-cnet ;;
        fnet)  TARGET=tacet-fnet ;;
        *)     TARGET=tacet-scan ;;   # closed
    esac
    if [ "$FN" = "unban" ] && [ "$IP" = "ALLCAT" ]; then
        [ "$CAT" = "open" ] && SETS="tacet-flood tacet-fnet" || SETS="tacet-scan tacet-cnet"
        N=0
        for s in $SETS; do
            N=$((N + $(members "$s" | grep -c '[0-9]')))
            $IPSET flush "$s" 2>/dev/null
        done
        # drop the collector's diff baselines for this surface, or its next tick
        # diffs the stale snapshots and logs a mass release burst on top of the
        # single summary line below (single unban keeps them in step via sync_prev)
        if [ "$CAT" = "open" ]; then rm -f /opt/var/tacet-prev-open /opt/var/tacet-prev-fnet
        else rm -f /opt/var/tacet-prev-closed /opt/var/tacet-prev-cnet; fi
        resave $SETS   # or the next engine run resurrects the category from .save
        t_log release "the whole $CAT-port category unbanned manually ($N entries)"
        jok
    fi
    ok_ip "$IP" || jerr "bad address"
    IP=${IP%/32}   # drop a redundant /32 so we never carry a mask into a hash:ip set
    # a CIDR ban on the single-IP surface must go to that surface's SUBNET set:
    # scan/flood are hash:ip and reject a CIDR, and even a hash:net set would let the
    # SET trap widen later. Route closed->cnet, open->fnet (masked to SUBNET_MASK).
    case "$IP:$CAT" in
        */*:closed) CAT=cnet; TARGET=tacet-cnet ;;
        */*:open)   CAT=fnet; TARGET=tacet-fnet ;;
    esac
    # netmask sets (cnet/fnet) store the masked base, so strip /N for them; the
    # plain scan/flood sets (hash:ip) store a bare /32
    case "$CAT" in cnet|fnet) DIP="${IP%%/*}" ;; *) DIP="$IP" ;; esac
    case "$FN" in
        unban) $IPSET del "$TARGET" "$DIP" 2>/dev/null
               t_log release "$IP unbanned manually"; sync_prev del "$DIP" "$CAT" ;;
        ban)   if $IPSET test tacet-allow "$IP" 2>/dev/null; then
                   t_log ban "$IP not banned — it is whitelisted"   # kernel exempts it anyway
                   jerr "whitelisted"
               fi
               if [ "$CAT" = "cnet" ] || [ "$CAT" = "fnet" ]; then
                   # mask to the block base ourselves. The kernel would mask a bare
                   # IP anyway, but a CIDR fed to a hash:ip set is ENUMERATED
                   # element by element (a /8 = 16M adds pegging the CPU); the
                   # base is one entry either way — and sync_prev then baselines
                   # the same spelling the set stores, not the raw input.
                   IP=$(echo "${IP%%/*}" | awk -F. -v m="$SUBNET_MASK" '{
                       if (m < 8 || m > 30) m = 24
                       ip = $1*16777216 + $2*65536 + $3*256 + $4
                       b = 2^(32-m); ip = int(ip/b)*b
                       printf "%d.%d.%d.%d", int(ip/16777216)%256, int(ip/65536)%256, int(ip/256)%256, ip%256 }')
               fi
               $IPSET add "$TARGET" "$IP" -exist 2>/dev/null
               t_log ban "$IP banned manually"; sync_prev add "$IP" "$CAT" ;;
        white)
               # remove any verbatim single-IP bans; a COVERING subnet ban in
               # cnet/fnet is deliberately left alone — deleting via a netmask set
               # masks the address first, so it would lift the ban for the WHOLE
               # block, not this host. The `! --match-set tacet-allow` on every
               # drop rule already exempts the whitelisted address by itself.
               for s in tacet-scan tacet-flood; do $IPSET del "$s" "$IP" 2>/dev/null; done         # bare /32s (hash:ip)
               $IPSET add tacet-allow "$IP" -exist 2>/dev/null
               # file line: "address" or "address note"; dedupe by address only.
               # Legacy files (pre-normalization) may spell this address "x/32" —
               # match both forms or a duplicate bare line piles up beside it.
               E=$(echo "$IP" | sed 's/\./\\./g')
               wl_lock; touch "$WHITEFILE"
               grep -qE "^${E}(/32)?( |$)" "$WHITEFILE" || echo "$IP${Q_NOTE:+ $Q_NOTE}" >> "$WHITEFILE"
               wl_unlock
               t_log whitelist "$IP added to the whitelist" ;;
        unwhite)
               $IPSET del tacet-allow "$IP" 2>/dev/null
               # delete the legacy "/32" spelling too: the set entry is gone either
               # way, but a surviving file line is re-added by the engine on its
               # next run — an entry the UI can never remove
               E=$(echo "$IP" | sed 's/\./\\./g')
               wl_lock
               [ -f "$WHITEFILE" ] && sed -i -e "\|^${E}\$|d" -e "\|^${E} |d" \
                   -e "\|^${E}/32\$|d" -e "\|^${E}/32 |d" "$WHITEFILE"
               wl_unlock
               t_log whitelist "$IP removed from the whitelist" ;;
        setnote)
               # rewrite the entry's line, keeping the address; empty note clears it.
               # awk compares the field literally — no regex escaping to get wrong.
               # Refuse (don't fake success) when the address isn't in the file.
               E=$(echo "$IP" | sed 's/\./\\./g')
               [ -f "$WHITEFILE" ] && grep -qE "^${E}(/32)?( |\$)" "$WHITEFILE" \
                   || jerr "not in the whitelist"
               wl_lock
               if awk -v ip="$IP" -v note="$Q_NOTE" '
                   $1 == ip || $1 == ip "/32" { print (note == "" ? ip : ip " " note); next } { print }
               ' "$WHITEFILE" > "$WHITEFILE.n" 2>/dev/null && mv "$WHITEFILE.n" "$WHITEFILE"; then
                   wl_unlock
               else rm -f "$WHITEFILE.n"; wl_unlock; jerr "write failed"; fi
               if [ -n "$Q_NOTE" ]; then t_log whitelist "note for $IP set: $Q_NOTE"
               else t_log whitelist "note for $IP cleared"; fi ;;
    esac
    jok ;;
esac

# --- 4. shared data helpers (read endpoints) ---
# whitelist entries as a JSON array — the IP-details popup notes when an address
# is covered by one (the list is small and user-managed, so it ships whole).
# Only well-formed IP/CIDR lines pass: a hand-edited stray line must not be able
# to break the JSON of every payload. wl_items is shared with the export endpoint.
wl_items() {
    awk '$1 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$/ {printf "%s\"%s\"", s, $1; s=","}' "$WHITEFILE" 2>/dev/null
}
emit_wl() { printf ',"wl":['; wl_items; printf ']'; }
TVER=$(cat /opt/etc/tacet-version 2>/dev/null | tr -d ' \r\n'); TVER=${TVER:-dev}

# "last seen" per IP from the conntrack countdown (age = state's base timeout − remaining)
CTFILE=/tmp/tacet-connmap.$$
conn_map() {
    EST=$(cat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established 2>/dev/null || echo 1200)
    awk -v est="$EST" '
    BEGIN{ B["ESTABLISHED"]=est; B["SYN_SENT"]=120; B["SYN_RECV"]=60; B["TIME_WAIT"]=120;
           B["CLOSE_WAIT"]=60; B["CLOSE"]=10; B["FIN_WAIT"]=120; B["LAST_ACK"]=30 }
    { st=$6; b=(st in B)?B[st]:120; age=b-$5; if(age<0)age=0; s="";d="";
      for(i=1;i<=NF;i++){ if($i~/^src=/&&s==""){s=substr($i,5)} if($i~/^dst=/&&d==""){d=substr($i,5)} }
      if(s!=""&&(!(s in m)||age<m[s]))m[s]=age
      if(d!=""&&d!=s&&(!(d in m)||age<m[d]))m[d]=age
    } END { for(k in m) print k, m[k] }' /proc/net/nf_conntrack > "$CTFILE" 2>/dev/null
}
# awk prelude shared by the JSON emitters: geo/name/age lookups + json escaping + ago()
JP='function esc(s){gsub(/[\001-\037]/,"",s);gsub(/\\/,"\\\\\\\\",s);gsub(/"/,"\\\\\"",s);return s}
    function ago(a){ if(a<5)return "now"; if(a<60)return a"s ago"; if(a<3600)return int(a/60)"m ago"; return int(a/3600)"h ago" }
    function cc(ip){ return (ip in GC)?GC[ip]:"" }
    function cn(c){ return (c in NM)?NM[c]:c }
    function threat(ip){ return (ip in TH)?TH[ip]+0:0 }
    function org(ip, o){ o=(ip in OR)?OR[ip]:""; if(o=="?")o=""; gsub(/_/," ",o); return o }
    function activity(ip){ return (ip in AC)?AC[ip]+0:0 }
    FILENAME==cf{ GC[$1]=$2; next } FILENAME==nf{ NM[$1]=substr($0,4); next }
    FILENAME==tf{ AG[$1]=$2; next } FILENAME==df{ TH[$1]=$2; next }
    FILENAME==af{ OR[$1]=$2; next } FILENAME==xf{ AC[$1]=$2; next }'

# current external peers from conntrack: "count ip", busiest first
conns() {
    grep -E 'tcp.* ESTABLISHED' /proc/net/nf_conntrack 2>/dev/null | awk -v me="$WANIP" '{
        ip="";
        for(i=1;i<=NF;i++) if($i ~ /^(src|dst)=/){
            v=substr($i,index($i,"=")+1);
            if(v !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) continue;   # IPv6 peers: no flag data, and Ban would only ever reject them
            if(v ~ /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|0\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)/) continue;
            if(v==me) continue; ip=v; break;
        }
        if(ip!="") c[ip]++
    } END { for(i in c) print c[i], i }' | sort -rn
}

# --- 5. read endpoints ---
case "$FN" in
overview)
    # bans are grouped by surface; each surface = its single-IP set + its subnet
    # set. One awk over the two concatenated listings counts a surface in ~3 forks
    # instead of ~12 (members()×2 through grep -c) — this runs on every poll.
    cnt2() { { $IPSET list "$1"; $IPSET list "$2"; } 2>/dev/null | \
        awk '/^Members:/{m=1;next} /^[A-Z]/{m=0} m&&/[0-9]/{c++} END{print c+0}'; }
    NCLOSED=$(cnt2 tacet-scan tacet-cnet)
    NOPEN=$(cnt2 tacet-flood tacet-fnet)
    # packets dropped over the last 24 h (the "today" tile): sum of per-minute
    # deltas with the same reset handling as the chart, so it survives rule
    # rebuilds instead of resetting to ~0 like the live iptables counter does.
    DROPPED=$(tail -n 1440 "$CSV" 2>/dev/null | awk -F, '{d=(NR>1)?(($4>=p)?$4-p:$4+0):0; s+=d; p=$4+0} END{print s+0}')
    PEAK=$(tail -n 720 "$CSV" 2>/dev/null | awk -F, '{t=$2+$3+$5+$6; if(t>m)m=t} END{print m+0}'); PEAK=${PEAK:-0}
    if   [ "$PEAK" -le 5 ]; then AXMAX=5
    elif [ "$PEAK" -le 9 ]; then AXMAX=10
    else AXMAX=$(( ((PEAK+1+9)/10)*10 )); fi
    jhead
    printf '{"version":"%s","master":%s,"refresh":%s,' "$TVER" \
        "$([ "$MASTER" = yes ] && echo true || echo false)" "$REFRESH_SEC"
    printf '"counts":{"total":%s,"closed":%s,"open":%s,"dropped":%s},' \
        "$((NCLOSED+NOPEN))" "$NCLOSED" "$NOPEN" "$DROPPED"
    printf '"chart":{"max":%s,"buckets":[' "$AXMAX"
    # 12 h window, 48 buckets of 15 min; a bucket takes its last sample (bans are a
    # level). Two series per surface: closed = closed+cnet, open = open+fnet.
    tail -n 720 "$CSV" 2>/dev/null | awk -F, -v B=48 '
        { c[NR]=$2+$5+0; o[NR]=$3+$6+0; ep[NR]=$1 }
        END{ n=NR; if(n<1)exit; bs=int((n+B-1)/B); if(bs<1)bs=1; s="";
             for(i=1;i<=n;i+=bs){ e=i+bs-1; if(e>n)e=n;
                 printf "%s[%d,%d,%d]", s, ep[e], c[e], o[e]; s="," } }'
    printf ']},"drops":['
    # dropped packets are a cumulative counter — chart the per-bucket delta. The
    # counter resets on any rules rebuild; a decrease means "fresh start", so the
    # minute contributes its whole new value (same treatment as the verbose log).
    tail -n 720 "$CSV" 2>/dev/null | awk -F, -v B=48 '
        { d[NR]=(NR>1)?(($4>=p)?$4-p:$4+0):0; p=$4+0; ep[NR]=$1 }
        END{ n=NR; if(n<1)exit; bs=int((n+B-1)/B); if(bs<1)bs=1; s="";
             for(i=1;i<=n;i+=bs){ e=i+bs-1; if(e>n)e=n; v=0;
                 for(k=i;k<=e;k++)v+=d[k];
                 printf "%s[%d,%d]", s, ep[e], v; s="," } }'
    printf '],"conns":['
    conns | head -20 | awk -v cf="$GEOCACHE" -v nf="$COUNTRIES" -v tf=/dev/null -v df="$THREATCACHE" -v af="$ASNCACHE" -v xf="$ACTCACHE" "$JP"'
        { c=cc($2); printf "%s{\"ip\":\"%s\",\"n\":%d,\"cc\":\"%s\",\"country\":\"%s\",\"threat\":%d,\"org\":\"%s\",\"act\":%d}", s0, $2, $1, c, esc(cn(c)), threat($2), esc(org($2)), activity($2); s0="," }' \
        "$GEOCACHE" "$COUNTRIES" "$THREATCACHE" "$ASNCACHE" "$ACTCACHE" -
    printf ']'; emit_wl; printf '}\n'
    exit 0 ;;
protection)
    conn_map
    # a category = its single-IP set + its whole-subnet set, merged into one array
    # sorted by remaining time. Each row carries its own "cat" token so the row
    # actions hit the right set; subnet rows (bare network) are shown as CIDR.
    # cap how many ban rows the payload carries: a heavily-attacked router can hold
    # thousands of bans, and shipping+rendering all of them every poll is wasteful
    # (the whole-category unban still acts on all of them; the count reports the rest)
    BANCAP=500
    emit_cat() {  # $1 = IP set, $2 = IP cat, $3 = net set, $4 = net cat; sets CATN = true total
        # sort by remaining timeout ascending (soonest-to-expire on top). busybox
        # sort ignores -k here, so move the timeout to the front, sort -n, strip it.
        CATF=/tmp/tct-cat.$$
        { members "$1" | sed "s/^/$2 /"; members "$3" | sed "s/^/$4 /"; } > "$CATF"
        CATN=$(grep -c '[0-9]' "$CATF")
        awk '{print $4, $0}' "$CATF" | sort -n | cut -d' ' -f2- | head -n "$BANCAP" \
          | awk -v cf="$GEOCACHE" -v nf="$COUNTRIES" -v tf="$CTFILE" -v df="$THREATCACHE" -v af="$ASNCACHE" -v xf="$ACTCACHE" -v mask="$SUBNET_MASK" "$JP"'
            { cat=$1; ip=$2; sec=$4+0; isnet=(cat=="cnet"||cat=="fnet");
              shown=isnet? ip"/"mask : ip;
              last=(isnet || shown ~ /\//)? "—" : (ip in AG ? ago(AG[ip]) : "—");
              c=cc(ip); t=isnet?0:threat(ip);
              printf "%s{\"ip\":\"%s\",\"cat\":\"%s\",\"last\":\"%s\",\"exp\":\"%dh %dm\",\"cc\":\"%s\",\"country\":\"%s\",\"threat\":%d,\"org\":\"%s\",\"act\":%d}", \
                  s0, shown, cat, last, int(sec/3600), int((sec%3600)/60), c, esc(cn(c)), t, esc(org(ip)), isnet?0:activity(ip); s0="," }' \
            "$GEOCACHE" "$COUNTRIES" "$CTFILE" "$THREATCACHE" "$ASNCACHE" "$ACTCACHE" -
        rm -f "$CATF"
    }
    # candidates = sources tripping the traps but NOT already banned (so banning one
    # makes its row drop out on the next refresh, instead of lingering in the htable).
    BANF=/tmp/tacet-cand.$$
    members tacet-scan  | awk '{print $1}' >  "$BANF"
    members tacet-flood | awk '{print $1}' >> "$BANF"
    CAND=$(for f in $HL/tct-scan* $HL/tof*; do
            [ -f "$f" ] || continue
            b=$(basename "$f"); p=closed
            [ "${b#tof}" != "$b" ] && { p=${b#tof}; p=${p%%_*}; }   # open per-port trap: tof<port>_<burst>
            awk -v p="$p" '$5>0{ split($2,a,":"); u=($4-$3)/$5; if(u>=1) print a[1], u, p }' "$f"
        done | awk '{ ip=$1; if($2>r[ip])r[ip]=$2;
            if(index(","pp[ip]",", ","$3",")==0) pp[ip]=(pp[ip]==""?$3:pp[ip]","$3) }
            END{ for(ip in r) printf "%s %d %s\n", ip, r[ip], pp[ip] }' \
        | awk -v bf="$BANF" 'FILENAME==bf{b[$1]=1;next} !($1 in b)' "$BANF" - \
        | awk '{printf "%08d %s\n", $2, $0}' | sort -r | cut -d' ' -f2- | head -20)
        # ^ busybox sort ignores -k (see emit_cat below): prepend a zero-padded
        #   rate key and whole-line sort, or "busiest first" is actually
        #   "numerically-highest IP first" and the top attacker falls off the 20
    rm -f "$BANF"
    jhead
    printf '{"version":"%s","refresh":%s,"burst":%s,"svcburst":%s,"svcports":"%s","snmask":%s,"snburst":%s,"tsubnet":%s,"candidates":[' \
        "$TVER" "${REFRESH_SEC:-60}" "$BURST" "$SVC_BURST" "$SVC_PORTS" "$SUBNET_MASK" "$SUBNET_BURST" \
        "$([ "$TRAP_SUBNET" = yes ] && echo true || echo false)"
    echo "$CAND" | awk -v cf="$GEOCACHE" -v nf="$COUNTRIES" -v tf=/dev/null -v df="$THREATCACHE" -v af="$ASNCACHE" -v xf="$ACTCACHE" "$JP"'
        NF>=2 { c=cc($1); pts=$3; gsub(/,/, ", ", pts);
          printf "%s{\"ip\":\"%s\",\"synmin\":%d,\"ports\":\"%s\",\"cc\":\"%s\",\"country\":\"%s\",\"threat\":%d,\"org\":\"%s\",\"act\":%d}", s0, $1, $2, pts, c, esc(cn(c)), threat($1), esc(org($1)), activity($1); s0="," }' \
        "$GEOCACHE" "$COUNTRIES" "$THREATCACHE" "$ASNCACHE" "$ACTCACHE" -
    printf '],"closed":['; emit_cat tacet-scan  closed tacet-cnet cnet; NCLOSED=$CATN
    printf '],"open":[';   emit_cat tacet-flood open   tacet-fnet fnet; NOPEN=$CATN
    printf '],"closedn":%s,"openn":%s' "$NCLOSED" "$NOPEN"; emit_wl; printf '}\n'
    rm -f "$CTFILE"
    exit 0 ;;
whitelist)
    conn_map
    jhead
    printf '{"version":"%s","refresh":%s,"items":[' "$TVER" "${REFRESH_SEC:-60}"
    awk '{a[NR]=$0} END{for(i=NR;i>=1;i--)print a[i]}' "$WHITEFILE" 2>/dev/null | \
    awk -v cf="$GEOCACHE" -v nf="$COUNTRIES" -v tf="$CTFILE" -v df="$THREATCACHE" -v af="$ASNCACHE" -v xf="$ACTCACHE" "$JP"'
        function ip2n(ip, p){ split(ip, p, "."); return ((p[1]*256+p[2])*256+p[3])*256+p[4] }
        # a subnet was "seen" when any address inside it was: min age over the conntrack map
        function cidrage(ip, m,lo,size,k,a,best){ split(ip, m, "/"); size=2^(32-m[2]);
          lo=ip2n(m[1]); lo-=lo%size; best=-1;
          for(k in AG){ a=ip2n(k); if(a>=lo && a<lo+size && (best<0 || AG[k]<best)) best=AG[k] }
          return best }
        /^#/ || NF==0 { next }
        $1 !~ /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$/ { next }   # skip a hand-edited malformed line; its raw ip would break the JSON
        { ip=$1; base=ip; sub(/\/.*/, "", base);   # lookups go by the bare address — CIDR keys never match the caches
          note=$0; if (!sub(/^[^ ]+ +/, "", note)) note="";   # the rest of the line is the user note
          if(ip ~ /\//){ a=cidrage(ip); last=(a<0)?"—":ago(a) }
          else last=(base in AG ? ago(AG[base]) : "—"); c=cc(base);
          printf "%s{\"ip\":\"%s\",\"note\":\"%s\",\"last\":\"%s\",\"cc\":\"%s\",\"country\":\"%s\",\"threat\":%d,\"org\":\"%s\",\"act\":%d}", s0, ip, esc(note), last, c, esc(cn(c)), threat(base), esc(org(base)), activity(base); s0="," }' \
        "$GEOCACHE" "$COUNTRIES" "$CTFILE" "$THREATCACHE" "$ASNCACHE" "$ACTCACHE" -
    printf ']'; emit_wl; printf '}\n'
    rm -f "$CTFILE"
    exit 0 ;;
export)
    # selective backup: inc = comma-list of config,whitelist,bans. Served as a
    # download; the import action above restores it. Ban entries keep their
    # remaining idle-out ("ip ttl"), whitelist ships verbatim from its file.
    has() { echo ",$Q_INC," | grep -q ",$1,"; }
    set_json() {  # $1 = ipset name -> "ip ttl","ip ttl",...
        members "$1" | awk '$1 ~ /^[0-9]/ {printf "%s\"%s %s\"", s, $1, ($3==""?0:$3); s=","}'
    }
    printf 'Content-Type: application/json; charset=utf-8\r\n'
    printf 'Content-Disposition: attachment; filename="tacet-export-%s.json"\r\n' "$(date +%Y%m%d-%H%M)"
    printf 'Cache-Control: no-store\r\n\r\n'
    printf '{"tacet_export":1,"version":"%s","created":"%s"' "$TVER" "$(date '+%F %T')"
    if has config; then
        printf ',\n"config":{'
        s=""
        for k in $CONF_NUM $CONF_YN SVC_PORTS WAN; do
            eval v=\$$k
            printf '%s"%s":"%s"' "$s" "$k" "$v"; s=","
        done
        printf '}'
    fi
    if has whitelist; then
        # full lines ("address note"), unlike the bare-address wl_items payload —
        # the note travels with the backup. Quotes/backslashes never enter the
        # file (the note sanitizer strips them), so the line embeds as-is —
        # but a pre-sanitizer or hand-edited line may still carry control bytes
        # (a TAB is enough to make the JSON invalid), so filter those too.
        printf ',\n"whitelist":['
        awk '$1 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$/ && $0 !~ /["\\]/ && $0 !~ /[\001-\037\177]/ \
            {printf "%s\"%s\"", s, $0; s=","}' "$WHITEFILE" 2>/dev/null
        printf ']'
    fi
    if has bans; then
        for c2 in $CATSETS; do
            printf ',\n"bans_%s":[' "${c2%%:*}"; set_json "${c2##*:}"; printf ']'
        done
    fi
    printf '}\n'
    exit 0 ;;
settings)
    TTLH=$((BAN_TTL / 3600))
    set -- $(dbmeta geo);    GROWS=${1:-0}; GDATE=$2   # date empty -> UI shows "recently"
    set -- $(dbmeta threat); TROWS=${1:-0}; TDATE=$2
    set -- $(dbmeta asn);    AROWS=${1:-0}; ADATE=$2
    set -- $(dbmeta tor);    RROWS=${1:-0}; RDATE=$2
    NCACHE=$(grep -c '[0-9]' "$GEOCACHE" 2>/dev/null); NCACHE=${NCACHE:-0}   # grep -c prints 0 but exits 1 on no match — don't double-count
    KLST=""; KLVER=""; KLTIME=""
    [ -f /opt/var/tacet-latest ] && read KLST KLVER KLTIME < /opt/var/tacet-latest
    UST=$(cat /opt/var/tacet-update-state 2>/dev/null)
    # clear on ANY "done", not only "done <installed version>": if the release tag
    # and the tree's VERSION ever disagree, the exact-match form leaves the state
    # file behind forever and the UI re-offers the same update in a loop
    case "$UST" in "done "*) rm -f /opt/var/tacet-update-state; UST="" ;; esac
    # normalise "updating <epoch>": while fresh (<5 min) report the bare "updating"
    # the UI expects; once stale the updater died — surface it as failed so the
    # update controls come back instead of vanishing forever
    case "$UST" in
        "updating "*)
            UAGE=$(( $(date +%s) - ${UST#updating } ))
            # 900 s cutoff: a legitimately slow run is up to ~40 s of version
            # discovery + a 300 s download + the install step — declaring failure
            # at 300 s (the old value) raced the downloader's own timeout and
            # invited a second concurrent --apply. A NEGATIVE age means the clock
            # stepped backwards mid-update (NTP on an RTC-less router) — the run
            # is still live; declaring it failed re-offered the Update button and
            # invited a concurrent --apply over the running one.
            if [ "$UAGE" -lt 900 ]; then UST="updating"
            else UST="failed: update did not finish"; rm -f /opt/var/tacet-update-state; fi ;;
        "failed:"*)
            # a failed state used to persist forever (only "done" was cleared),
            # overriding even a fresh "you are up to date" — age it out after 1 h
            [ -n "$(find /opt/var/tacet-update-state -mmin +60 2>/dev/null)" ] && \
                { rm -f /opt/var/tacet-update-state; UST=""; } ;;
    esac
    NEV=$(grep -c '[0-9]' "$EVLOG" 2>/dev/null); NEV=${NEV:-0}
    jhead
    printf '{"version":"%s","config":{"ttlh":%s,"refresh":%s,"burst":%s,"svcports":"%s","svcburst":%s,"synto":%s,"wan":"%s","tclosed":%s,"topen":%s,"tsubnet":%s,"snmask":%s,"snburst":%s,"tban":%s,"torban":%s,"reject":%s,"compact":%s,"compactpct":%s,"compactevery":%s},' \
        "$TVER" "$TTLH" "$REFRESH_SEC" "$BURST" "$SVC_PORTS" "$SVC_BURST" "$SYN_TIMEOUT" "$WAN" \
        "$([ "$TRAP_CLOSED" = yes ] && echo true || echo false)" \
        "$([ "$TRAP_OPEN" = yes ] && echo true || echo false)" \
        "$([ "$TRAP_SUBNET" = yes ] && echo true || echo false)" "$SUBNET_MASK" "$SUBNET_BURST" \
        "$([ "$THREAT_BAN" = yes ] && echo true || echo false)" \
        "$([ "$TOR_BAN" = yes ] && echo true || echo false)" \
        "$([ "$BAN_REJECT" = yes ] && echo true || echo false)" \
        "$([ "$COMPACT" = yes ] && echo true || echo false)" "$COMPACT_PCT" "$COMPACT_EVERY"
    # WAN-interface picker: the real up interfaces the router has, so the settings
    # dropdown offers actual names instead of free text. No name guessing — every
    # exclusion is a structural fact from /sys: a WAN is never the loopback, never a
    # bridge (that is the LAN), never enslaved to one (LAN ports / wifi APs bridged
    # into it), and never a wireless radio. What remains is the uplink candidates
    # (ppp0, raw/VLAN WAN ports, tunnels, VPN). The configured WAN is always kept.
    emit_ifaces() {
        { ip -o link show up 2>/dev/null | awk -F': ' '{n=$2; sub(/@.*/,"",n); print n}' \
            | while read n; do
                  p=/sys/class/net/$n
                  [ "$n" = lo ] && continue                          # loopback
                  [ -e "$p/bridge" ] && continue                     # a bridge = the LAN
                  [ -e "$p/master" ] && continue                     # bridged in (LAN port / AP)
                  { [ -e "$p/wireless" ] || [ -e "$p/phy80211" ]; } && continue   # wifi radio
                  echo "$n"
              done
          echo "$WAN"; } | awk 'NF && !seen[$0]++ {printf "%s\"%s\"", s, $0; s=","}'
    }
    printf '"ifaces":['; emit_ifaces; printf '],'
    # single-IP bans per surface, so the settings UI can preview live how many
    # /snmask blocks the fold would collapse. Two separate lists — the fold is
    # per-reason (a block lands in cnet OR fnet), so the preview must count the
    # same way or it promises folds the engine will rightly refuse.
    # cap the fold-preview sample: this payload is refetched every REFRESH_SEC and
    # regrouped client-side on every keystroke — shipping all 65k of a heavily
    # attacked set would make the settings tab the most expensive page. 4000 is a
    # representative sample for the preview (the real fold runs in the collector).
    emit_ips() { members "$1" 2>/dev/null | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {printf "%s\"%s\"", s, $1; s=","; if (++c>=4000) exit}'; }
    printf '"banscan":['; emit_ips tacet-scan
    printf '],"banflood":['; emit_ips tacet-flood
    printf '],'
    printf '"geo":{"rows":%s,"date":"%s","cache":%s},' "$GROWS" "$GDATE" "$NCACHE"
    ACTROWS=$(wc -l < /opt/etc/tacet-activity.dat 2>/dev/null | tr -d ' '); ACTROWS=${ACTROWS:-0}
    printf '"threat":{"rows":%s,"date":"%s","act":%s},"asn":{"rows":%s,"date":"%s"},"tor":{"rows":%s,"date":"%s"},"autodb":%s,' \
        "$TROWS" "$TDATE" "$ACTROWS" "$AROWS" "$ADATE" "$RROWS" "$RDATE" \
        "$([ "$AUTO_DB_UPDATE" = yes ] && echo true || echo false)"
    LVLNOW=off; [ "$LOG_ENABLED" = yes ] && { LVLNOW=normal; [ "$LOG_DROPS" = yes ] && LVLNOW=verbose; }
    printf '"loglevel":"%s","nev":%s,"events":[' "$LVLNOW" "$NEV"
    awk '{a[NR]=$0} END{for(i=NR;i>=1;i--)print a[i]}' "$EVLOG" 2>/dev/null | awk '
        function esc(s){gsub(/[\001-\037]/,"",s);gsub(/\\/,"\\\\\\\\",s);gsub(/"/,"\\\\\"",s);return s}
        { when=$1" "$2; typ=$3; det=$0; sub(/^[^ ]+ +[^ ]+ +[^ ]+ +/,"",det)
          # esc() on ALL three fields: a torn log line (power loss mid-append) can
          # put a quote/backslash in the time or type slot and brick the whole
          # settings payload — with the Clear-log button on the tab that no longer renders
          printf "%s{\"n\":%d,\"time\":\"%s\",\"type\":\"%s\",\"detail\":\"%s\"}", s0, NR, esc(when), esc(typ), esc(det); s0="," }'
    printf '],"update":{"cur":"%s","lst":"%s","latest":"%s","checked":"%s","state":"%s"}}\n' \
        "$TVER" "$KLST" "$KLVER" "$KLTIME" "$(echo "$UST" | sed 's/"/\\"/g')"
    exit 0 ;;
esac

jerr "unknown endpoint"
