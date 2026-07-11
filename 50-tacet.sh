#!/bin/sh
# Tacet engine: auto-ban on WAN (ppp0). Bans are organised by REASON (which
# surface was abused); each reason bans single IPs and, optionally, whole subnets:
#   CLOSED router ports (INPUT):  tacet-scan  (per IP) + tacet-cnet (per subnet)
#   OPEN forwarded ports (FWD):   tacet-flood (per IP) + tacet-fnet (per subnet)
# The *-net sets are hash:ip with a kernel netmask, so one entry covers a whole
# /SUBNET_MASK block; the plain scan/flood sets are hash:ip (single /32s — the SET
# trap target can only add /32 safely; CIDR bans are routed to the *-net sets).
# The subnet traps (hashlimit --srcmask) meter a whole block in aggregate, so a
# scan/flood spread thin across a range still trips and bans the entire block.
# Run by ndm on every netfilter rebuild (/opt/etc/ndm/netfilter.d/); idempotent.
# Manual run: table=filter sh 50-tacet.sh
# Settings: /opt/etc/tacet.conf (edited from the UI on :5050)
# (c) Max Grakov 2026, MIT License.

[ -n "$type" ] && [ "$type" != "iptables" ] && exit 0
[ -n "$table" ] && [ "$table" != "filter" ] && exit 0

IPT=/opt/sbin/iptables
IPSET=/opt/sbin/ipset
SAVE=/opt/etc/tacet-scan.save          # closed-port bans (single IP)
SAVE_SVC=/opt/etc/tacet-flood.save  # open-port bans (single IP)
SAVE_CNET=/opt/etc/tacet-cnet.save  # closed-port bans (whole subnet)
SAVE_FNET=/opt/etc/tacet-fnet.save  # open-port bans (whole subnet)
WHITELIST=/opt/etc/tacet-allow.list
WAN=ppp0             # WAN interface — default PPPoE (ppp0); set to eth3 / eth2.2 / …
                    # for IPoE/DHCP in the UI (General → WAN interface). Overridden
                    # by WAN= in tacet.conf, which the eval below applies.

# defaults; overridden by the config file. Mirrored by the default blocks in
# api.cgi and (a subset) tacet-collect.sh — keep the three in sync. REFRESH_SEC
# is UI-only (lives in api.cgi) and unused here.
BAN_TTL=86400       # ban duration, seconds
BURST=8             # SYN/min before a ban for knocking on a closed port
SVC_PORTS="443"     # forwarded TCP ports under rate protection (comma-separated; empty = off)
SVC_BURST=60        # SYN/min before a ban for flooding a forwarded port
TRAP_CLOSED=yes     # closed-port trap on/off (INPUT)
TRAP_OPEN=yes       # open-port traps on/off (FORWARD)
TRAP_SUBNET=no      # subnet trap on/off (INPUT, metered per /SUBNET_MASK)
SUBNET_MASK=24      # CIDR prefix the subnet trap groups and bans by (8-30)
SUBNET_BURST=30     # combined SYN/min from a whole subnet before it is banned
THREAT_BAN=no       # auto-ban IPs on the threat list outright (0 connections, no threshold)
TOR_BAN=no          # auto-ban Tor exit relays outright (same shape as THREAT_BAN)
BAN_REJECT=no       # answer banned sources: no = silent DROP (stealthy), yes = REJECT
                    # (tcp-reset / port-unreachable) — ends their retransmit storm but
                    # confirms a host exists at this address
MASTER=yes          # master switch: no = remove ALL rules, protection fully off
SYN_TIMEOUT=60      # nf_conntrack SYN-SENT timeout (sec); lower clears half-open floods
                    # faster. empty leaves the system default (mirrored as 60 in api.cgi)
# eval a CR-stripped copy instead of dot-sourcing: a conf edited on Windows carries
# \r that survives sourcing inside every value ("no\r" != no), silently flipping
# flags the wrong way. eval executes exactly what sourcing would, minus the CRs.
[ -f /opt/etc/tacet.conf ] && eval "$(tr -d '\r' < /opt/etc/tacet.conf)"

# clamp rate thresholds to the kernel's --hashlimit-burst ceiling (1-10000): an
# out-of-range value makes iptables reject the trap rule, silently dropping that
# protection. Guards a hand-edited config; the UI already validates these.
clamp() { case "$1" in ''|*[!0-9]*) echo "$2" ;; *) [ "$1" -gt 10000 ] && echo 10000 || { [ "$1" -lt 1 ] && echo 1 || echo "$1"; } ;; esac; }
BURST=$(clamp "$BURST" 8)
SVC_BURST=$(clamp "$SVC_BURST" 60)
SUBNET_BURST=$(clamp "$SUBNET_BURST" 30)
# guard the values that feed `ipset create` and the trap masks: an empty or
# non-numeric BAN_TTL/SUBNET_MASK from a truncated or hand-edited tacet.conf would
# make `ipset create … timeout $BAN_TTL` / `--hashlimit-srcmask $SUBNET_MASK` fail,
# the sets never exist, and every ban rule referencing them silently no-ops — the
# router would run wide open with a green exit. Fall back to sane defaults instead.
case "$BAN_TTL" in ''|*[!0-9]*) BAN_TTL=86400 ;; esac
# upper clamp: ipset rejects timeouts above 4294967 at CREATE time — an oversized
# TTL (hand-edited or imported) would make every `ipset create` fail on the next
# boot and leave the router wide open. 2592000 = the UI's 720 h ceiling.
[ "$BAN_TTL" -gt 2592000 ] && BAN_TTL=2592000
[ "$BAN_TTL" -lt 60 ] && BAN_TTL=60
# the one string value that feeds iptables: a hand-edited stray character would
# make --dport reject the rule, silently dropping that port's flood trap
case "$SVC_PORTS" in *[!0-9,]*) SVC_PORTS=443 ;; esac
# WAN interface name feeds every `-i $WAN` rule: a bad value silently binds the
# traps to nothing (router unprotected). Guard to a plausible ifname, else ppp0.
case "$WAN" in ''|*[!a-zA-Z0-9._-]*) WAN=ppp0 ;; esac
case "$SUBNET_MASK" in ''|*[!0-9]*) SUBNET_MASK=24 ;; *) { [ "$SUBNET_MASK" -lt 8 ] || [ "$SUBNET_MASK" -gt 30 ]; } && SUBNET_MASK=24 ;; esac

# apply the half-open (SYN-SENT) conntrack timeout — how long dropped attempts linger
[ -n "$SYN_TIMEOUT" ] && [ -w /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_sent ] && \
    echo "$SYN_TIMEOUT" > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_sent 2>/dev/null
# legacy: a single TRAP_ENABLED=no disables all categories
[ "${TRAP_ENABLED:-yes}" = "no" ] && { TRAP_CLOSED=no; TRAP_OPEN=no; TRAP_SUBNET=no; }
# master off overrides everything
[ "$MASTER" = "no" ] && { TRAP_CLOSED=no; TRAP_OPEN=no; TRAP_SUBNET=no; THREAT_BAN=no; TOR_BAN=no; }

# delete every INPUT/FORWARD rule that references ban set $1 (used before a set is
# rebuilt or its rules are repositioned)
drop_rules_for() {
    for ch in INPUT FORWARD; do
        $IPT -S "$ch" 2>/dev/null | grep -E "(match-set|add-set) $1 " \
            | sed 's/^-A //' | while read -r r; do $IPT -D $r 2>/dev/null; done
    done
}
# true when ipset $1 has no members — peeks the first member and stops (grep -m1
# SIGPIPEs the listing), so it never formats a 300k-entry set just to ask "empty?"
set_empty() {
    [ -z "$($IPSET list "$1" 2>/dev/null | sed -n '/^Members:/,$p' | grep -m1 '[0-9]')" ]
}

# xt_hashlimit is not auto-loaded (no modprobe in this firmware)
lsmod | grep -q xt_hashlimit || insmod /lib/modules/$(uname -r)/xt_hashlimit.ko 2>/dev/null

# serialize engine runs. netfilter.d fires this hook several times in a burst on a
# PPPoE reconnect; two concurrent rebuilds race the -swap sets (one destroys the set
# the other is copying from — the whole ban list evaporates) and double-insert the
# trap rules (two rules sharing one named hashlimit htable drain the bucket twice,
# halving the effective threshold). Design:
#   - mkdir is the only creator; a steal is an ATOMIC rename (mv) so two stealers
#     can never both proceed — only one mv can win, the loser retries mkdir.
#   - an owner whose PID is a LIVE tacet process is never stolen (a TTL rebuild
#     over thousands of entries legitimately runs minutes). The cmdline check
#     avoids wedging forever on PID reuse.
#   - a dead/foreign owner is stolen at once; an ownerless dir (a winner caught
#     between mkdir and the owner stamp) gets a few seconds' grace first.
#   - if we give up waiting on a live peer, leave a rerun marker: that peer read
#     the conf before our config-save landed, so it re-applies once on exit —
#     a settings change that lost the race is never silently dropped.
ELOCK=/tmp/tacet-engine.lock
steal() { mv "$ELOCK" "$ELOCK.dead.$$" 2>/dev/null && rm -rf "$ELOCK.dead.$$"; }
n=0; ne=0
until mkdir "$ELOCK" 2>/dev/null; do
    o=$(cat "$ELOCK/owner" 2>/dev/null)
    if [ -z "$o" ]; then
        ne=$((ne+1)); [ "$ne" -ge 4 ] && { steal; ne=0; }; sleep 1   # husk grace
    elif [ -d "/proc/$o" ] && grep -q "50-tacet" "/proc/$o/cmdline" 2>/dev/null; then
        # ^ match THIS script's name, not just "tacet": a recycled PID landing on
        #   the long-lived tacet lighttpd would freeze the engine forever
        ne=0; n=$((n+1)); [ "$n" -ge 45 ] && { : > "$ELOCK.rerun"; exit 0; }
        sleep 1
    else
        ne=0; steal                                  # dead PID or PID reused by a non-tacet process
    fi
done
echo $$ > "$ELOCK/owner" 2>/dev/null
# release only a lock we own; on exit, honor a rerun request left by a peer that
# gave up waiting (re-applies the possibly-newer conf once, detached). Signal traps
# too: busybox ash skips the EXIT trap on SIGTERM/SIGINT.
trap '[ "$(cat "$ELOCK/owner" 2>/dev/null)" = "$$" ] && rm -rf "$ELOCK"
      [ -f "$ELOCK.rerun" ] && { rm -f "$ELOCK.rerun"; table=filter type=iptables sh "$0" >/dev/null 2>&1 & }' EXIT
trap 'exit 1' INT TERM HUP

# scan/flood MUST be hash:ip, not hash:net. The `-j SET --add-set` target adds a
# source at the set's *longest current prefix* (kernel INIT_CIDR), NOT /32 — so in
# a hash:net set holding any CIDR ban, the closed-port trap would ban a scanner as
# that whole CIDR (verified: a set with only a /16 turned one scanner into a /16
# ban). hash:ip forces every trap-add to /32. Whole-subnet bans live in cnet/fnet
# (hash:ip+netmask); a hand-typed CIDR on the closed/open surface is routed there
# by api.cgi. This reverses the earlier (mistaken) hash:ip->hash:net migration.
migrate_to_ip() {  # $1 = set name
    t=$($IPSET list "$1" -terse 2>/dev/null | sed -n 's/^Type: //p')
    [ "$t" = "hash:ip" ] && return   # already correct
    [ -n "$t" ] || return            # doesn't exist yet — the create below makes it
    drop_rules_for "$1"
    $IPSET list "$1" | sed -n '/Members:/,$p' | tail -n +2 > /tmp/abmig.$1
    $IPSET destroy "$1" 2>/dev/null
    $IPSET create "$1" hash:ip timeout $BAN_TTL maxelem 65536
    # net set to relocate any CIDR members into (cnet for scan, fnet for flood)
    case "$1" in *scan) net=tacet-cnet ;; *) net=tacet-fnet ;; esac
    while read ip _ sec; do
        [ -z "$ip" ] && continue
        [ "$sec" = "0" ] && continue
        [ -n "$sec" ] && [ "$sec" -gt "$BAN_TTL" ] && sec=$BAN_TTL
        case "$ip" in
            */*) $IPSET add "$net" "${ip%%/*}" timeout "${sec:-$BAN_TTL}" -exist 2>/dev/null ;;  # CIDR -> subnet set
            *)   $IPSET add "$1"  "$ip"        timeout "${sec:-$BAN_TTL}" -exist ;;
        esac
    done < /tmp/abmig.$1
    rm -f /tmp/abmig.$1
}
migrate_to_ip tacet-scan
migrate_to_ip tacet-flood

$IPSET create tacet-scan  hash:ip timeout $BAN_TTL maxelem 65536 -exist
$IPSET create tacet-flood hash:ip timeout $BAN_TTL maxelem 65536 -exist
$IPSET create tacet-allow hash:net -exist

# subnet ban sets (one per reason): hash:ip with a kernel-side netmask — any /32
# the trap adds is masked to its /$SUBNET_MASK network, so a single entry bans the
# whole block. netmask (like the default timeout) is a create-time parameter, so a
# change to either rebuilds the set: referencing rules are dropped (reinstalled
# below), members are re-masked by the kernel on re-add and their remainders trimmed.
ensure_netset() {  # $1 = set name, $2 = its .save snapshot
    hdr=$($IPSET list "$1" -terse 2>/dev/null | sed -n 's/^Header: //p')
    [ -z "$hdr" ] && { $IPSET create "$1" hash:ip netmask $SUBNET_MASK timeout $BAN_TTL maxelem 65536; return; }
    oldmask=$(echo "$hdr" | sed -n 's/.*netmask \([0-9]*\).*/\1/p')
    oldttl=$(echo "$hdr" | sed -n 's/.*timeout \([0-9]*\).*/\1/p')
    [ "$oldmask" = "$SUBNET_MASK" ] && [ "$oldttl" = "$BAN_TTL" ] && return   # unchanged
    drop_rules_for "$1"
    # carry members over ONLY on a timeout-only change. On a MASK change the stored
    # networks belong to the old mask; re-adding them re-masks each to a DIFFERENT
    # block — widening (24→8) would blackhole ~16M innocent addresses, narrowing
    # (16→24) would silently un-ban the rest — so drop them and let the traps
    # re-form bans under the new mask. The on-disk snapshot holds the SAME old-mask
    # members, and restore_set below fires on any empty set — delete it too, or the
    # flush is undone seconds later from disk (cron re-saves under the new mask
    # within 30 min).
    if [ "$oldmask" = "$SUBNET_MASK" ]; then
        $IPSET list "$1" | sed -n '/Members:/,$p' | tail -n +2 > /tmp/tct-renet.$$
    else
        : > /tmp/tct-renet.$$
        rm -f "$2"
    fi
    $IPSET destroy "$1" 2>/dev/null
    $IPSET create "$1" hash:ip netmask $SUBNET_MASK timeout $BAN_TTL maxelem 65536
    while read ip _ sec; do
        [ -z "$ip" ] && continue
        [ "$sec" = "0" ] && continue   # in its last second: re-adding 0 = permanent
        [ -n "$sec" ] && [ "$sec" -gt "$BAN_TTL" ] && sec=$BAN_TTL
        $IPSET add "$1" "$ip" timeout "${sec:-$BAN_TTL}" -exist
    done < /tmp/tct-renet.$$
    rm -f /tmp/tct-renet.$$
}
ensure_netset tacet-cnet "$SAVE_CNET"
ensure_netset tacet-fnet "$SAVE_FNET"

# threat reference list: every flagged IP from the threat DB, loaded into one set
# (permanent membership — it's the reputation list, not a ban). When THREAT_BAN is
# on, a rule below adds any of these that shows up to the surface ban set, so it is
# dropped outright with no threshold. Loaded once (skipped when already populated);
# tacet-threat-update.sh reloads it after a fresh download.
THREATDAT=/opt/etc/tacet-threat.dat
if [ "$THREAT_BAN" = "yes" ]; then
    $IPSET create tacet-threat hash:ip hashsize 16384 maxelem 300000 -exist
    if set_empty tacet-threat && [ -f "$THREATDAT" ]; then
        awk '{n=$1; printf "add tacet-threat %d.%d.%d.%d\n", int(n/16777216)%256,int(n/65536)%256,int(n/256)%256,n%256}' \
            "$THREATDAT" | $IPSET restore -exist 2>/dev/null
    fi
fi
# Tor exit-relay reference list — same machinery as the threat list above;
# tacet-tor-update.sh reloads it after a fresh download.
TORDAT=/opt/etc/tacet-tor.dat
if [ "$TOR_BAN" = "yes" ]; then
    $IPSET create tacet-tor hash:ip hashsize 4096 maxelem 65536 -exist
    if set_empty tacet-tor && [ -f "$TORDAT" ]; then
        awk '{n=$1; printf "add tacet-tor %d.%d.%d.%d\n", int(n/16777216)%256,int(n/65536)%256,int(n/256)%256,n%256}' \
            "$TORDAT" | $IPSET restore -exist 2>/dev/null
    fi
fi
# one-time migration: fold a legacy combined tacet-subnet set into the closed-port
# subnet set (its members were predominantly closed-port scanners), then drop it.
if $IPSET list tacet-subnet -terse >/dev/null 2>&1; then
    drop_rules_for tacet-subnet
    $IPSET list tacet-subnet | sed -n '/Members:/,$p' | tail -n +2 | while read ip _ sec; do
        [ -z "$ip" ] && continue
        [ "$sec" = "0" ] && continue   # in its last second: re-adding 0 = permanent
        [ -n "$sec" ] && [ "$sec" -gt "$BAN_TTL" ] && sec=$BAN_TTL
        $IPSET add tacet-cnet "$ip" timeout "${sec:-$BAN_TTL}" -exist 2>/dev/null
    done
    $IPSET destroy tacet-subnet 2>/dev/null
    rm -f /opt/etc/tacet-subnet.save
fi
# Whitelist lives entirely in $WHITELIST so it is fully editable from the UI.
# Seed the private ranges only on first run; afterwards the file is authoritative.
# (Add any WAN peers your clients talk to via the UI so they don't self-ban.)
if [ ! -f "$WHITELIST" ]; then
    cat > "$WHITELIST" << EOF
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
EOF
fi
# first token only — anything after the address is the user's note.
# `|| [ -n "$ip" ]` also processes a final line lacking a trailing newline
# (a hand-appended entry): read returns 1 there but still fills $ip.
# tr -d '\r' first: a Windows-edited (CRLF) file leaves \r glued to a bare
# address, `ipset add "1.2.3.4\r"` fails, and EVERY entry silently drops —
# the user's own IP then self-bans, the exact thing the whitelist prevents.
tr -d '\r' < "$WHITELIST" | while read ip _ || [ -n "$ip" ]; do
    case "$ip" in ""|\#*) ;; *) $IPSET add tacet-allow "$ip" -exist ;; esac
done

# restore bans after a reboot: only when the live set is actually empty
# (this ipset build reports no entry count in the header, so peek the members)
restore_set() {  # $1 = set name, $2 = snapshot file, $3 = paired net set ('' = none)
    if [ -f "$2" ] && set_empty "$1"; then
        # netmask guard (boot path): a snapshot taken under a DIFFERENT netmask
        # must not be replayed — the kernel re-masks each member to the new mask,
        # widening one stale /24 ban into a whole /8 (or silently un-banning the
        # remainder on narrowing). ensure_netset guards the live-change path by
        # deleting the save; this guards the hand-edit-then-reboot path, where
        # the set is created fresh at the new mask before any comparison ran.
        snapm=$(sed -n "s/^create $1 .*netmask \([0-9]*\).*/\1/p" "$2" | head -1)
        livem=$($IPSET list "$1" -terse 2>/dev/null | sed -n 's/.*netmask \([0-9]*\).*/\1/p')
        if [ -n "$snapm" ] && [ -n "$livem" ] && [ "$snapm" != "$livem" ]; then
            rm -f "$2"   # stale-mask snapshot; the traps re-form bans, cron re-saves
            return
        fi
        # trim each restored timeout to the current BAN_TTL — a snapshot taken under
        # a larger TTL must not outlive a since-lowered limit.
        # skip entries snapshotted in their last second (timeout 0): restoring one
        # re-adds it as PERMANENT, surviving every future TTL trim.
        # a CIDR line (hash:net-era snapshot) would make `ipset restore` ABORT on
        # the hash:ip scan/flood sets, losing every ban after it — relocate it to
        # the paired SUBNET set instead (base address; the kernel masks it). On a
        # reboot straight into the new engine migrate_to_ip never saw those bans,
        # so this is the only path that preserves them.
        grep "^add $1 " "$2" | awk -v m="$BAN_TTL" -v net="$3" \
            '{ for(i=1;i<NF;i++) if($i=="timeout") { if($(i+1)+0==0) next; if($(i+1)+0>m) $(i+1)=m }
               if ($3 ~ /\//) { if (net == "") next; $2 = net; sub(/\/[0-9]+$/, "", $3) }
               print }' \
            | $IPSET restore -exist 2>/dev/null
    fi
}
# net sets FIRST: scan/flood may relocate CIDR lines into them, and a set made
# non-empty by a relocation would skip its own snapshot (restore fires on empty only)
restore_set tacet-cnet  "$SAVE_CNET" ""
restore_set tacet-fnet  "$SAVE_FNET" ""
restore_set tacet-scan  "$SAVE"      tacet-cnet
restore_set tacet-flood "$SAVE_SVC"  tacet-fnet

# TTL changed — recreate the set with the new default, trimming the remainder to it
retimeout_set() {  # $1 = set name
    cur=$($IPSET list "$1" -terse | sed -n 's/.*timeout \([0-9]*\).*/\1/p' | head -1)
    [ -z "$cur" ] || [ "$cur" = "$BAN_TTL" ] && return
    $IPSET destroy "$1-swap" 2>/dev/null
    $IPSET create "$1-swap" hash:ip timeout $BAN_TTL maxelem 65536   # scan/flood are hash:ip
    $IPSET swap "$1" "$1-swap"
    $IPSET list "$1-swap" | sed -n '/Members:/,$p' | tail -n +2 | while read ip _ sec; do
        [ -z "$ip" ] && continue
        [ "$sec" = "0" ] && continue   # in its last second: re-adding 0 = permanent
        [ -n "$sec" ] && [ "$sec" -gt "$BAN_TTL" ] && sec=$BAN_TTL   # guard empty sec (permanent entry) against the -gt integer test
        $IPSET add "$1" "$ip" timeout "${sec:-$BAN_TTL}" -exist
    done
    $IPSET destroy "$1-swap"
}
retimeout_set tacet-scan
retimeout_set tacet-flood

# --- INPUT: refresh + drop banned (both categories), then the closed-port trap ---
# Rebuilt by parse: delete every rule we own from INPUT (drops, refreshes, trap —
# any past shape), then reinstall in order. This converges on rule changes instead
# of leaving duplicates behind. The whitelist is exempt from the drop, so a
# whitelisted address is never cut off (not by a manual ban, not by a covering subnet).
# Before each drop sits a "refresh" rule: SET --add-set … --exist resets the ban's
# timeout on every packet we are about to drop, so a source that keeps knocking never
# leaves the ban list — the ban lapses only after BAN_TTL of SILENCE, not on a fixed clock.
$IPT -S INPUT 2>/dev/null | grep -E -- "match-set tacet-(scan|flood|cnet|fnet|allow) src|add-set tacet-(scan|flood|cnet|fnet) src" \
    | sed 's/^-A //' | while read -r rule; do $IPT -D $rule 2>/dev/null; done
if [ "$MASTER" = "yes" ]; then
    # refresh (sticky) then drop, for all four ban sets
    N=1
    for s in tacet-scan tacet-flood tacet-cnet tacet-fnet; do
        $IPT -I INPUT $N -i $WAN -m set --match-set $s src -m set ! --match-set tacet-allow src -m state ! --state RELATED,ESTABLISHED -j SET --add-set $s src --exist
        N=$((N + 1))
    done
    # banned traffic is cut per BAN_REJECT: silent DROP (default) or an explicit
    # REJECT — tcp-reset for TCP so the source stops retrying at once, generic
    # port-unreachable for everything else
    for s in tacet-scan tacet-flood tacet-cnet tacet-fnet; do
        if [ "$BAN_REJECT" = "yes" ]; then
            $IPT -I INPUT $N -i $WAN -p tcp -m set --match-set $s src -m set ! --match-set tacet-allow src -m state ! --state RELATED,ESTABLISHED -j REJECT --reject-with tcp-reset
            N=$((N + 1))
            $IPT -I INPUT $N -i $WAN -m set --match-set $s src -m set ! --match-set tacet-allow src -m state ! --state RELATED,ESTABLISHED -j REJECT
        else
            $IPT -I INPUT $N -i $WAN -m set --match-set $s src -m set ! --match-set tacet-allow src -m state ! --state RELATED,ESTABLISHED -j DROP
        fi
        N=$((N + 1))
    done
    # threat auto-ban: a flagged IP knocking on the router → ban it in the closed-port
    # category on its first SYN (no threshold). Inserted FIRST so the ban lands before
    # the drops above run in the same packet traversal, cutting it outright (0 conns).
    # the "! --match-set tacet-cnet" keeps a flagged source that is ALREADY covered
    # by a closed-port subnet ban from endlessly re-earning a redundant /32 in
    # tacet-scan (it is dropped by the subnet ban anyway); saves the collector from
    # absorbing that churn every sweep.
    if [ "$THREAT_BAN" = "yes" ]; then
        $IPT -I INPUT 1 -i $WAN -p tcp --syn -m set --match-set tacet-threat src -m set ! --match-set tacet-allow src -m set ! --match-set tacet-cnet src -j SET --add-set tacet-scan src --exist
    fi
    # Tor auto-ban: same shape — an exit relay knocking on the router is banned
    # in the closed-port category on its first SYN
    if [ "$TOR_BAN" = "yes" ]; then
        $IPT -I INPUT 1 -i $WAN -p tcp --syn -m set --match-set tacet-tor src -m set ! --match-set tacet-allow src -m set ! --match-set tacet-cnet src -j SET --add-set tacet-scan src --exist
    fi
fi
# closed-port trap — threshold baked into the htable name (xt_hashlimit caches by name)
if [ "$TRAP_CLOSED" = "yes" ]; then
    $IPT -A INPUT -i $WAN -p tcp --syn -m set ! --match-set tacet-allow src \
        -m hashlimit --hashlimit-above 1/min --hashlimit-burst $BURST --hashlimit-mode srcip \
        --hashlimit-name "tct-scan$BURST" --hashlimit-htable-expire 120000 \
        -j SET --add-set tacet-scan src --exist
fi
# subnet trap (closed ports) — the same closed-port metering, but the bucket is
# keyed by the /$SUBNET_MASK network (--hashlimit-srcmask): abuse spread across a
# whole block drains one shared bucket, and the SET target lands in tacet-cnet
# (the closed-port subnet set), banning the entire block in one entry. Mask and
# threshold are baked into the bucket name so a settings change starts a fresh
# meter. The matching forwarded-port half lives in the FORWARD section below.
if [ "$TRAP_SUBNET" = "yes" ]; then
    $IPT -A INPUT -i $WAN -p tcp --syn -m set ! --match-set tacet-allow src \
        -m hashlimit --hashlimit-above 1/min --hashlimit-burst $SUBNET_BURST \
        --hashlimit-mode srcip --hashlimit-srcmask $SUBNET_MASK \
        --hashlimit-name "tcn${SUBNET_MASK}_${SUBNET_BURST}" --hashlimit-htable-expire 120000 \
        -j SET --add-set tacet-cnet src --exist
fi

# --- FORWARD: refresh + drop banned + rate traps on forwarded ports ---
# Same shape as INPUT. Rules go BEFORE the forwarding rule, rebuilt positionally.
$IPT -S FORWARD 2>/dev/null | grep -E "match-set tacet-(scan|flood|cnet|fnet|allow) src|add-set tacet-(scan|flood|cnet|fnet) src" \
    | sed 's/^-A //' | while read -r rule; do $IPT -D $rule 2>/dev/null; done
if [ "$MASTER" = "yes" ]; then
    # refresh (sticky) then drop, for all four ban sets
    IDX=1
    for s in tacet-scan tacet-flood tacet-cnet tacet-fnet; do
        $IPT -I FORWARD $IDX -i $WAN -m set --match-set $s src -m set ! --match-set tacet-allow src -j SET --add-set $s src --exist
        IDX=$((IDX + 1))
    done
    # same DROP/REJECT choice as INPUT (see BAN_REJECT above)
    for s in tacet-scan tacet-flood tacet-cnet tacet-fnet; do
        if [ "$BAN_REJECT" = "yes" ]; then
            $IPT -I FORWARD $IDX -i $WAN -p tcp -m set --match-set $s src -m set ! --match-set tacet-allow src -j REJECT --reject-with tcp-reset
            IDX=$((IDX + 1))
            $IPT -I FORWARD $IDX -i $WAN -m set --match-set $s src -m set ! --match-set tacet-allow src -j REJECT
        else
            $IPT -I FORWARD $IDX -i $WAN -m set --match-set $s src -m set ! --match-set tacet-allow src -j DROP
        fi
        IDX=$((IDX + 1))
    done
    # rate traps on protected ports, before the forwarding rule. Two independent
    # meters per port, gated by their own toggles:
    #   per-address  (TRAP_OPEN)   -> bans the single flooding IP      (tacet-flood)
    #   per-subnet   (TRAP_SUBNET) -> bans the whole /SUBNET_MASK block (tacet-fnet)
    # The subnet meter shares ONE bucket across all forwarded ports (name has no
    # port), so a block hammering several services aggregates into one verdict.
    if [ -n "$SVC_PORTS" ] && { [ "$TRAP_OPEN" = "yes" ] || [ "$TRAP_SUBNET" = "yes" ]; }; then
        for port in $(echo "$SVC_PORTS" | tr ',' ' '); do
            if [ "$TRAP_OPEN" = "yes" ]; then
                # bucket name must stay <=15 chars (kernel IFNAMSIZ), so the prefix
                # is terse: "tof<port>_<burst>" fits the widest case (tof65535_10000).
                $IPT -I FORWARD $IDX -i $WAN -p tcp --dport "$port" --syn \
                    -m set ! --match-set tacet-allow src \
                    -m hashlimit --hashlimit-above 1/min --hashlimit-burst $SVC_BURST --hashlimit-mode srcip \
                    --hashlimit-name "tof${port}_${SVC_BURST}" --hashlimit-htable-expire 120000 \
                    -j SET --add-set tacet-flood src --exist
                IDX=$((IDX + 1))
            fi
            if [ "$TRAP_SUBNET" = "yes" ]; then
                $IPT -I FORWARD $IDX -i $WAN -p tcp --dport "$port" --syn \
                    -m set ! --match-set tacet-allow src \
                    -m hashlimit --hashlimit-above 1/min --hashlimit-burst $SUBNET_BURST \
                    --hashlimit-mode srcip --hashlimit-srcmask $SUBNET_MASK \
                    --hashlimit-name "tfn${SUBNET_MASK}_${SUBNET_BURST}" --hashlimit-htable-expire 120000 \
                    -j SET --add-set tacet-fnet src --exist
                IDX=$((IDX + 1))
            fi
        done
    fi
    # threat auto-ban: a flagged IP reaching a forwarded service → ban it in the
    # open-port category on its first SYN (no threshold), then the drops above cut it.
    # Inserted FIRST so the ban lands before those drops in the same traversal.
    # ! --match-set tacet-fnet: skip a source already covered by an open-port subnet
    # ban (see the INPUT/tacet-cnet note above)
    if [ "$THREAT_BAN" = "yes" ]; then
        $IPT -I FORWARD 1 -i $WAN -p tcp --syn -m set --match-set tacet-threat src -m set ! --match-set tacet-allow src -m set ! --match-set tacet-fnet src -j SET --add-set tacet-flood src --exist
    fi
    # Tor auto-ban: an exit relay reaching a forwarded service → open-port ban
    if [ "$TOR_BAN" = "yes" ]; then
        $IPT -I FORWARD 1 -i $WAN -p tcp --syn -m set --match-set tacet-tor src -m set ! --match-set tacet-allow src -m set ! --match-set tacet-fnet src -j SET --add-set tacet-flood src --exist
    fi
fi   # MASTER

# free the reference lists when their feature is off (the rules are gone by now)
[ "$THREAT_BAN" = "yes" ] || $IPSET destroy tacet-threat 2>/dev/null
[ "$TOR_BAN" = "yes" ] || $IPSET destroy tacet-tor 2>/dev/null
exit 0   # a failed cleanup above must not fail the whole hook (ndm checks our exit code)
