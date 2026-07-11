#!/bin/sh
# Tacet stats snapshot to CSV for the charts. Run by cron once a minute.
# Line format: epoch,closed,open,dropped,cnet,fnet
#   closed  — single-IP bans for knocking closed ports  (|tacet-scan|)
#   open    — single-IP bans for flooding forwarded ports (|tacet-flood|)
#   dropped — total packets dropped from banned sources (cumulative, INPUT+FORWARD)
#   cnet    — whole-subnet bans for closed-port abuse    (|tacet-cnet|)
#   fnet    — whole-subnet bans for open-port abuse      (|tacet-fnet|)
# The chart sums per surface: closed-port = closed+cnet, open-port = open+fnet.
# (c) Max Grakov 2026, MIT License.
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
# single-run lock: a slow tick (cold 350k-row resolve over flash) can overrun the
# minute, and two overlapping collectors corrupt the CSV, double-run compaction
# and log phantom events. mkdir is atomic; steal a lock older than 3 min so a
# killed run can never wedge the collector forever.
LOCK=/tmp/tacet-collect.lock
if ! mkdir "$LOCK" 2>/dev/null; then
    # steal only when the recorded owner is DEAD (its PID gone, or reused by a
    # non-collector process — bare /proc/$o would wedge until reboot on PID reuse).
    # mtime alone lies both ways: a forward NTP step at boot makes a fresh lock look
    # decades old. Steal atomically (rename) so two ticks can't both win.
    o=$(cat "$LOCK/owner" 2>/dev/null)
    [ -n "$o" ] && [ -d "/proc/$o" ] && grep -q tacet-collect "/proc/$o/cmdline" 2>/dev/null && exit 0
    [ -z "$o" ] && [ -z "$(find "$LOCK" -maxdepth 0 -mmin +3 2>/dev/null)" ] && exit 0   # ownerless husk grace
    mv "$LOCK" "$LOCK.dead.$$" 2>/dev/null && rm -rf "$LOCK.dead.$$"
    mkdir "$LOCK" 2>/dev/null || exit 0
fi
# stamp our ownership: if a later run steals this lock (the >3 min path above), our
# EXIT trap must NOT remove the thief's lock — that would let a third run start
# concurrently, exactly what the lock prevents. The trap checks the token is ours.
echo $$ > "$LOCK/owner" 2>/dev/null; LOCKTOKEN=$$
CSV=/opt/var/tacet-stats.csv
KEEP=1500          # ~25 hours at 1-minute steps
EVLOG=/opt/var/tacet-events.log
EVKEEP=500
EVBURST=40         # more than this many bans/releases in one tick logs a single
                   # summary line instead of one entry per IP — a DDoS that adds
                   # thousands of bans in a minute must not make the collector
                   # spend 40s writing (and threat-looking-up) each one
members() { ipset list "$1" 2>/dev/null | sed -n '/Members:/,$p' | tail -n +2 | awk '{print $1}' | grep '[0-9]'; }

# dump each set ONCE up front (a 5-process pipeline per set is expensive on a
# router, and the counts and the resolver both need these lists). log_diff and
# compaction below deliberately re-list live — they run after compaction may
# have mutated the sets, so they need current membership, not this snapshot.
MSCAN=/tmp/tct-mscan.$$; MFLOOD=/tmp/tct-mflood.$$; MCNET=/tmp/tct-mcnet.$$; MFNET=/tmp/tct-mfnet.$$
# release the lock only if it is still OURS (see the ownership stamp above), and
# clean up every per-run temp this script may have created (T1 + compaction temps
# on /tmp, which is RAM-backed) so an aborted run doesn't leak them
trap 'rm -f "$MSCAN" "$MFLOOD" "$MCNET" "$MFNET" /tmp/tacet-ips.$$ /tmp/tacet-new.$$ /tmp/tacet-new.$$.s /tmp/tct-cmp.$$ /tmp/tct-net.$$ /tmp/tct-fold.$$ /tmp/tct-pa.$$ /tmp/tct-add.$$ /tmp/tct-del.$$ 2>/dev/null;
      o=$(cat "$LOCK/owner" 2>/dev/null); { [ -z "$o" ] || [ "$o" = "$LOCKTOKEN" ]; } && rm -rf "$LOCK" 2>/dev/null' EXIT
members tacet-scan > "$MSCAN"; members tacet-flood > "$MFLOOD"
members tacet-cnet > "$MCNET"; members tacet-fnet > "$MFNET"
CLOSED=$(awk 'END{print NR}' "$MSCAN"); OPEN=$(awk 'END{print NR}' "$MFLOOD")
CNET=$(awk 'END{print NR}' "$MCNET");  FNET=$(awk 'END{print NR}' "$MFNET")
# count DROP rules only — the refresh (SET) rules sit on the same match and see
# the same packets, so summing every match-set line would double the total
# -x = exact counts: without it iptables abbreviates ">99999" as "100K", which
# awk would read as 100 — collapsing the drop total once a source is hammering
DROPPED=$(iptables -L INPUT -v -x -n 2>/dev/null | awk '($3=="DROP" || $3=="REJECT") && /match-set tacet-(scan|flood|cnet|fnet) src/ {s+=$1} END{print s+0}')
FWD=$(iptables -L FORWARD -v -x -n 2>/dev/null | awk '($3=="DROP" || $3=="REJECT") && /match-set tacet-(scan|flood|cnet|fnet) src/ {s+=$1} END{print s+0}')
DROPPED=$((DROPPED + FWD))

echo "$(date +%s),$CLOSED,$OPEN,$DROPPED,$CNET,$FNET" >> "$CSV"
[ "$(wc -l < "$CSV" 2>/dev/null || echo 0)" -gt "$KEEP" ] && { tail -n "$KEEP" "$CSV" > "$CSV.tmp" && mv "$CSV.tmp" "$CSV"; }

# --- config drives the sections below ---
LOG_ENABLED=no; LOG_DROPS=no; SUBNET_MASK=24; AUTO_DB_UPDATE=no; THREAT_BAN=no
BAN_TTL=86400; COMPACT=no; COMPACT_PCT=5; COMPACT_EVERY=5
GEO_EVERY=5   # minutes between geo/owner re-resolves (cosmetic flags/owner; not a UI setting)
# CR-stripped eval, not dot-source: values from a Windows-edited conf carry \r
[ -f /opt/etc/tacet.conf ] && eval "$(tr -d '\r' < /opt/etc/tacet.conf)"
# guard the values compaction/ipset arithmetic depends on — an empty or bad
# BAN_TTL/SUBNET_MASK/COMPACT_PCT from a truncated tacet.conf would otherwise make
# `timeout ""` fail or (COMPACT_PCT="" -> 0) fold a /24 at just 2 bans, mass-blocking
# innocent addresses. Same fallbacks the engine uses.
case "$BAN_TTL" in ''|*[!0-9]*) BAN_TTL=86400 ;; esac
case "$SUBNET_MASK" in ''|*[!0-9]*) SUBNET_MASK=24 ;; *) { [ "$SUBNET_MASK" -lt 8 ] || [ "$SUBNET_MASK" -gt 30 ]; } && SUBNET_MASK=24 ;; esac
case "$COMPACT_PCT" in ''|*[!0-9]*) COMPACT_PCT=5 ;; *) { [ "$COMPACT_PCT" -lt 1 ] || [ "$COMPACT_PCT" -gt 100 ]; } && COMPACT_PCT=5 ;; esac
# these two feed $(( )) directly — non-numeric would be a fatal ash arith error
case "$GEO_EVERY" in ''|*[!0-9]*) GEO_EVERY=5 ;; esac
case "$COMPACT_EVERY" in ''|*[!0-9]*) COMPACT_EVERY=5 ;; esac

# --- geo / threat / owner / activity resolution (background): resolve the visible
# IPs into small caches so the UI only ever reads the caches, never the big DBs —
# and so a fresh ban already has its threat score cached when the event log runs
# below. Same machinery for all four: geo -> country code, threat -> IPsum score
# (0 = not listed), asn -> owner ("AS15169_Google_LLC"), act -> abuse-category
# bitmask. ---
GEODAT=/opt/etc/tacet-geo.dat;       GEOCACHE=/opt/var/tacet-geocache
THREATDAT=/opt/etc/tacet-threat.dat; THREATCACHE=/opt/var/tacet-threatcache
ASNDAT=/opt/etc/tacet-asn.dat;       ASNCACHE=/opt/var/tacet-asncache
ACTDAT=/opt/etc/tacet-activity.dat;  ACTCACHE=/opt/var/tacet-actcache
if [ -f "$GEODAT" ] || [ -f "$THREATDAT" ] || [ -f "$ASNDAT" ] || [ -f "$ACTDAT" ]; then
    T1=/tmp/tacet-ips.$$
    { cat "$MSCAN" "$MFLOOD" "$MCNET" "$MFNET"          # the sets, already dumped above
      # whitelist entries too (base address for CIDRs), so their rows get flags/
      # owners. Take field 1 first: a bare IP may carry a trailing note now, and
      # a plain "sed s|/.*||" would leave the note attached and fail the filter
      awk '{ip=$1; sub(/\/.*/,"",ip); print ip}' /opt/etc/tacet-allow.list 2>/dev/null
      awk '{for(i=1;i<=NF;i++)if($i~/^(src|dst)=/)print substr($i,index($i,"=")+1)}' /proc/net/nf_conntrack
      # candidates too: sources tripping a trap but not yet banned. They show up in
      # the protection panel, and without pre-resolving them here the UI renders
      # them flag-less (no cache entry). Same htable files the CGI reads for the
      # candidate list — first field of $2 ("ip:...") is the source address.
      for hf in /proc/net/ipt_hashlimit/tct-scan* /proc/net/ipt_hashlimit/tof*; do
          [ -f "$hf" ] && awk '{split($2,a,":"); print a[1]}' "$hf"
      done
    } 2>/dev/null | awk -F. 'NF==4 && /^[0-9.]+$/ && $1<=255 && $2<=255 && $3<=255 && $4<=255' | sort -u > "$T1"
    # ^ octets bounded to 255: an out-of-range address (a hand-edited/imported bad
    #   whitelist line) would exceed uint32, and its %010.0f sort key below would be
    #   >10 digits, breaking the fixed-width order the merge-join resolve() relies on
    # $1=dat (int ranges "start end value", sorted by start) $2=cache $3=miss-value.
    # Resolve only the not-yet-cached IPs by MERGE-JOIN: sort the (small) new-IP set
    # by integer and stream the dat once with a pointer — O(new-IPs) memory and no
    # 350k-row awk array build, so it is ~40% faster than the old load-and-binary-
    # search. Correctness needs both sides integer-ordered: the dats are (geo/asn
    # arrive sorted, threat/tor/activity are %010.0f-sorted by their updaters), and
    # the query set is %010.0f-sorted here — a plain "sort -n" would overflow above
    # 2^31 and mis-order high IPs, exactly the disorder that made an earlier naive
    # merge mis-resolve. Ranges are non-overlapping, as the binary search assumed.
    resolve() {
        [ -f "$1" ] || return; touch "$2"
        TN=/tmp/tacet-new.$$
        # match by FILENAME, not FNR==NR — the cache can be empty on first run
        awk -v cf="$2" 'FILENAME==cf{seen[$1]=1;next} !($1 in seen)' "$2" "$T1" > "$TN"
        if [ -s "$TN" ]; then
            awk 'function i2(x,o){split(x,o,".");return o[1]*16777216+o[2]*65536+o[3]*256+o[4]}
                 {printf "%010.0f %s\n", i2($1), $1}' "$TN" | sort > "$TN.s"
            awk -v miss="$3" '
                BEGIN { j=1 }
                FNR==NR { qi[FNR]=$1+0; qp[FNR]=$2; nq=FNR; next }   # queries: int, ip (int-sorted)
                { while (j<=nq && qi[j] <  $1) { print qp[j], miss; j++ }   # below this range -> miss
                  while (j<=nq && qi[j] <= $2) { print qp[j], $3;   j++ }    # inside [start,end] -> value
                  if (j > nq) exit }                                        # all resolved -> stop reading the dat
                END { while (j<=nq) { print qp[j], miss; j++ } }
            ' "$TN.s" "$1" >> "$2"
            rm -f "$TN.s"
            [ "$(wc -l < "$2")" -gt 4000 ] && { tail -n 3000 "$2" > "$2.t" && mv "$2.t" "$2"; }
        fi
        rm -f "$TN"
    }
    # threat + activity are cheap (small DBs) and security-relevant — the red
    # badge / abuse category — so resolve them every tick. geo + owner (ASN) are
    # the big DBs (355k + 398k rows, ~3.7s to stream) and purely cosmetic (flag,
    # owner name), so gate them to every GEO_EVERY minutes: a new address's flag
    # appears a few minutes late, but its ban is immediate and its threat badge
    # is fresh. This is the collector's single biggest cost — see DOCS/validation.md.
    # gen guard: if the threat updater wipes the cache mid-tick (we loaded the OLD
    # cache into seen[]), our appends carry verdicts from yesterday's DB — and once
    # cached they are never re-resolved. Discard them; the next tick starts clean.
    TGEN0=$(cat "$THREATCACHE.gen" 2>/dev/null)
    resolve "$THREATDAT" "$THREATCACHE" "0"
    [ "$(cat "$THREATCACHE.gen" 2>/dev/null)" != "$TGEN0" ] && : > "$THREATCACHE" 2>/dev/null
    AGEN0=$(cat "$ACTCACHE.gen" 2>/dev/null)
    resolve "$ACTDAT"    "$ACTCACHE"    "0"
    [ "$(cat "$ACTCACHE.gen" 2>/dev/null)" != "$AGEN0" ] && : > "$ACTCACHE" 2>/dev/null
    GSTAMP=/opt/var/tacet-geo-resolve.stamp
    GNOW=$(date +%s)
    GLAST=$(cat "$GSTAMP" 2>/dev/null); GLAST=${GLAST:-0}
    case "$GLAST" in *[!0-9]*) GLAST=0 ;; esac
    [ "$GLAST" -gt "$GNOW" ] && GLAST=0   # clock stepped back: don't freeze the cadence
    if [ $(( GNOW - GLAST )) -ge $(( ${GEO_EVERY:-5} * 60 )) ]; then
        date +%s > "$GSTAMP"
        resolve "$GEODAT" "$GEOCACHE" "?"
        NGEN0=$(cat "$ASNCACHE.gen" 2>/dev/null)
        resolve "$ASNDAT" "$ASNCACHE" "?"
        [ "$(cat "$ASNCACHE.gen" 2>/dev/null)" != "$NGEN0" ] && : > "$ASNCACHE" 2>/dev/null
    fi
    rm -f "$T1"
fi

# --- ban-list compaction (COMPACT): fold blocks that have quietly accumulated many
# single-IP bans into ONE whole-subnet ban. Complements the live subnet trap: that
# meters rate and catches fast distributed scans; this is retrospective and catches
# the slow drip — a block whose members each knock rarely never trips the rate meter
# but piles up dozens of single bans in one /SUBNET_MASK. A block folds when the share
# of it already banned reaches COMPACT_PCT (density scales with the mask, so the same
# percent stays sane at any prefix). The -net sets are hash:ip with a kernel netmask,
# so adding any one address folds it to its network; we add one per block and drop the
# singles. Runs every COMPACT_EVERY minutes. To keep the event log honest we
# PRE-ACKNOWLEDGE the diff snapshots before log_diff runs below, so the fold shows as a
# single "fold" line, not a phantom subnet ban plus N phantom releases. ---
if [ "$COMPACT" = "yes" ]; then
    CSTAMP=/opt/var/tacet-compact.stamp
    CLAST=$(cat "$CSTAMP" 2>/dev/null); CLAST=${CLAST:-0}; CNOW=$(date +%s)
    case "$CLAST" in *[!0-9]*) CLAST=0 ;; esac
    [ "$CLAST" -gt "$CNOW" ] && CLAST=0   # clock stepped back: don't freeze the cadence
    if [ $(( CNOW - CLAST )) -ge $(( ${COMPACT_EVERY:-5} * 60 )) ]; then
        echo "$CNOW" > "$CSTAMP"
        CTS=$(date '+%Y-%m-%d %H:%M:%S')
        compact_pass() {  # $1=single set  $2=net set  $3=prev-single  $4=prev-net  $5=label
            # group by THIS net set's ACTUAL kernel netmask, not the conf's
            # SUBNET_MASK: the two desync when the conf is edited but the engine
            # hasn't recreated the set yet (a hand-edit fires no engine run) — and
            # cnet/fnet can even disagree with each other if one recreate failed.
            # Folding by the wrong mask silently widens the ban (group a /24's
            # worth of evidence, the kernel masks the add to a /16). Read it live,
            # per set, right here.
            CMASK=$(ipset list "$2" -terse 2>/dev/null | sed -n 's/.*netmask \([0-9]*\).*/\1/p')
            case "$CMASK" in ''|*[!0-9]*) CMASK=$SUBNET_MASK ;; esac   # conf value is already clamped 8-30
            # block size and fold threshold, integer math: need = ceil(bs*pct/100)
            CBS=$(( 1 << (32 - CMASK) ))
            CNEED=$(( (CBS * COMPACT_PCT + 99) / 100 )); [ "$CNEED" -lt 2 ] && CNEED=2
            members "$1" > /tmp/tct-cmp.$$ 2>/dev/null
            [ -s /tmp/tct-cmp.$$ ] || { rm -f /tmp/tct-cmp.$$; return; }
            # absorb singles already covered by an existing subnet ban of this surface
            # (e.g. the rate trap banned the block after they were caught one by one).
            # The threshold fold below would never claim them, and the refresh rules
            # keep both entries alive forever — so they'd sit as duplicates until now.
            members "$2" > /tmp/tct-net.$$ 2>/dev/null
            if [ -s /tmp/tct-net.$$ ]; then
                ABS=$(awk -v bs="$CBS" '
                    function i2(x, o){ split(x,o,"."); return o[1]*16777216+o[2]*65536+o[3]*256+o[4] }
                    NR==FNR { net[i2($1)]=1; next }
                    /\// { next }
                    /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { v=i2($1); if ((v - v % bs) in net) print $1 }
                ' /tmp/tct-net.$$ /tmp/tct-cmp.$$)
                if [ -n "$ABS" ]; then
                    ACNT=0
                    for ip in $ABS; do ipset del "$1" "$ip" 2>/dev/null; ACNT=$((ACNT+1)); done
                    [ "$LOG_ENABLED" = "yes" ] && \
                        echo "$CTS  fold  $ACNT $5 absorbed into existing subnet bans" >> "$EVLOG"
                    # pre-acknowledge their removal so the diff below stays silent.
                    # The count check (not "&&"): an EMPTY result is legitimate and
                    # must still replace, but a TRUNCATED one (grep died on a full
                    # disk) must not — it would drop arbitrary baseline entries and
                    # spray phantom events next tick.
                    if [ -f "$3" ]; then
                        printf '%s\n' $ABS > /tmp/tct-pa.$$
                        grep -vxF -f /tmp/tct-pa.$$ "$3" > "$3.pa" 2>/dev/null
                        if [ "$(wc -l < "$3.pa" 2>/dev/null)" -ge $(( $(wc -l < "$3") - $(wc -l < /tmp/tct-pa.$$) )) ] 2>/dev/null; then
                            mv "$3.pa" "$3" 2>/dev/null
                        else rm -f "$3.pa"; fi
                        rm -f /tmp/tct-pa.$$
                    fi
                    members "$1" > /tmp/tct-cmp.$$ 2>/dev/null   # rebuild for the fold grouping
                fi
            fi
            rm -f /tmp/tct-net.$$
            # group by /SUBNET_MASK; emit "<network> <count> <ip ip ...>" for blocks
            # whose banned share >= COMPACT_PCT (need >= 2, never fold a lone address)
            awk -v bs="$CBS" -v need="$CNEED" '
                function i2(x, o){ split(x,o,"."); return o[1]*16777216+o[2]*65536+o[3]*256+o[4] }
                /\// { next }                                    # skip hand-typed CIDR bans
                /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { v=i2($1); n = v - (v % bs); cnt[n]++; ips[n]=ips[n]" "$1 }
                END{ for (n in cnt) if (cnt[n] >= need)
                        printf "%d.%d.%d.%d %d%s\n", int(n/16777216)%256,int(n/65536)%256,int(n/256)%256,n%256, cnt[n], ips[n] }
            ' /tmp/tct-cmp.$$ > /tmp/tct-fold.$$
            while read -r netaddr count ips; do
                [ -n "$netaddr" ] || continue
                # only proceed if the subnet ban actually took — otherwise deleting
                # the singles below would unblock them with NO covering ban. A failed
                # add (net set at maxelem) leaves the singles in place; the next sweep
                # retries. Without this, a fold could silently unban its members.
                ipset add "$2" "$netaddr" timeout "$BAN_TTL" -exist 2>/dev/null || continue
                for ip in $ips; do ipset del "$1" "$ip" 2>/dev/null; done
                [ "$LOG_ENABLED" = "yes" ] && \
                    echo "$CTS  fold  $netaddr/$CMASK — $count $5 merged into one subnet" >> "$EVLOG"
                # pre-acknowledge: the folded network is now known in the net snapshot,
                # and the folded singles are gone from the single snapshot — so the diff
                # below sees no change for either and stays silent about this fold
                [ -f "$4" ] && { grep -qxF "$netaddr" "$4" 2>/dev/null || echo "$netaddr" >> "$4"; }
                if [ -f "$3" ]; then
                    printf '%s\n' $ips > /tmp/tct-pa.$$
                    # count check, not "&&": grep exits 1 when the result is EMPTY
                    # (every prev entry folded) and that must still replace the
                    # snapshot — but a TRUNCATED result (grep died on a full disk)
                    # must not, or the next tick sprays phantom events
                    grep -vxF -f /tmp/tct-pa.$$ "$3" > "$3.pa" 2>/dev/null
                    if [ "$(wc -l < "$3.pa" 2>/dev/null)" -ge $(( $(wc -l < "$3") - $(wc -l < /tmp/tct-pa.$$) )) ] 2>/dev/null; then
                        mv "$3.pa" "$3" 2>/dev/null
                    else rm -f "$3.pa"; fi
                    rm -f /tmp/tct-pa.$$
                fi
            done < /tmp/tct-fold.$$
            rm -f /tmp/tct-cmp.$$ /tmp/tct-fold.$$
        }
        compact_pass tacet-scan  tacet-cnet /opt/var/tacet-prev-closed /opt/var/tacet-prev-cnet "closed-port scanners"
        compact_pass tacet-flood tacet-fnet /opt/var/tacet-prev-open   /opt/var/tacet-prev-fnet "open-port flooders"
    fi
fi

# --- ban-event log (LOG_ENABLED): the router firmware has no iptables LOG target,
# so instead of per-packet logs we record ban EVENTS by diffing set membership. ---
if [ "$LOG_ENABLED" = "yes" ]; then
    TS=$(date '+%Y-%m-%d %H:%M:%S')
    # a newly-banned IP that's also on the threat list earns a note; its score is
    # in the threat cache, freshly resolved above (0/absent = not listed)
    flagged() { [ -s "$THREATCACHE" ] && awk -v ip="$1" '$1==ip && $2+0>0{print;exit}' "$THREATCACHE" 2>/dev/null; }
    # verbose mode: the firmware can't log packets, so log the per-minute count of
    # packets the drop rules discarded (delta of the cumulative counter). A rules
    # rebuild resets the counter, so a negative delta is treated as a fresh start.
    if [ "$LOG_DROPS" = "yes" ]; then
        PREVF=/opt/var/tacet-prev-drops
        if [ -f "$PREVF" ]; then
            PREV=$(cat "$PREVF" 2>/dev/null); PREV=${PREV:-0}
            # torn flash write can leave garbage here; a non-numeric PREV is a
            # FATAL ash arithmetic error that kills the collector every tick
            # before it can rewrite the file — it would never self-heal
            case "$PREV" in *[!0-9]*) PREV=0 ;; esac
            DELTA=$((DROPPED - PREV)); [ "$DELTA" -lt 0 ] && DELTA=$DROPPED
            [ "$DELTA" -gt 0 ] && echo "$TS  drop  dropped $DELTA packets from banned sources in the last minute" >> "$EVLOG"
        fi
        echo "$DROPPED" > "$PREVF"
    fi
    log_diff() {  # $1 = set, $2 = category label, $3 = prev-snapshot file
        members "$1" | sort > "$3.now"
        # boot window: the prev-baseline lives on flash and survives a reboot, but
        # the sets start empty until the netfilter hook restores them — a tick in
        # that gap would log every persisted ban as a phantom "release" and then
        # re-log them all as fresh bans. Skip the diff (keep the baseline) while
        # the box is young and the set still empty; a real drain-to-zero on a
        # long-running box is unaffected.
        if [ ! -s "$3.now" ] && [ -s "$3" ] && [ "$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 999)" -lt 300 ]; then
            rm -f "$3.now"; return
        fi
        # first run just sets a baseline (no flood of existing bans); later runs log
        # additions (ban) and removals (release). Net categories store bare network
        # addresses — show them as CIDR.
        sfx=""
        # net categories: label with the set's LIVE kernel netmask, same reason as
        # compact_pass — the conf mask can desync, and the log must describe the
        # ban the kernel actually holds
        case "$2" in
            closed) why="a closed-port scan";  lbl="closed-port" ;;
            open)   why="an open-port flood";  lbl="open-port" ;;
            cnet|fnet)
                LMASK=$(ipset list "$1" -terse 2>/dev/null | sed -n 's/.*netmask \([0-9]*\).*/\1/p')
                case "$LMASK" in ''|*[!0-9]*) LMASK=$SUBNET_MASK ;; esac
                sfx="/$LMASK"
                if [ "$2" = "cnet" ]; then why="a closed-port scan"; lbl="closed-port subnet"
                else why="an open-port flood"; lbl="open-port subnet"; fi ;;
        esac
        if [ -f "$3" ]; then
            # additions / removals via awk hash-join (O(n); grep -vxF -f was O(n*m)
            # and cost seconds per tick once a set held thousands of entries)
            ADDF=/tmp/tct-add.$$; DELF=/tmp/tct-del.$$
            # FILENAME match, not NR==FNR: with an EMPTY first file NR==FNR stays
            # true through the second one and the diff comes out empty — bans that
            # arrive right after the list drained to zero were never logged
            awk -v f="$3"     'FILENAME==f{a[$0]=1;next} !($0 in a)' "$3"     "$3.now" > "$ADDF"
            awk -v f="$3.now" 'FILENAME==f{a[$0]=1;next} !($0 in a)' "$3.now" "$3"     > "$DELF"
            NA=$(grep -c . "$ADDF"); ND=$(grep -c . "$DELF")
            if [ "$NA" -gt "$EVBURST" ]; then
                echo "$TS  ban  $NA sources banned for $why (burst)" >> "$EVLOG"
            elif [ "$NA" -gt 0 ]; then
                while read -r ip; do
                    [ -n "$ip" ] || continue
                    # a flagged source is banned outright by reputation when THREAT_BAN
                    # is on (first packet, no threshold); otherwise it merely also happens
                    # to be listed
                    note=""
                    if [ -n "$(flagged "$ip")" ]; then
                        [ "$THREAT_BAN" = "yes" ] && note=" immediately due to IP reputation" \
                                                 || note=" (also on the threat list)"
                    fi
                    echo "$TS  ban  $ip$sfx banned for $why$note" >> "$EVLOG"
                done < "$ADDF"
            fi
            if [ "$ND" -gt "$EVBURST" ]; then
                echo "$TS  release  $ND sources left the $lbl ban list" >> "$EVLOG"
            elif [ "$ND" -gt 0 ]; then
                while read -r ip; do
                    [ -n "$ip" ] && echo "$TS  release  $ip$sfx left the $lbl ban list (expired or unbanned)" >> "$EVLOG"
                done < "$DELF"
            fi
            rm -f "$ADDF" "$DELF"
        fi
        mv "$3.now" "$3"
    }
    log_diff tacet-scan  closed /opt/var/tacet-prev-closed
    log_diff tacet-flood open   /opt/var/tacet-prev-open
    log_diff tacet-cnet  cnet   /opt/var/tacet-prev-cnet
    log_diff tacet-fnet  fnet   /opt/var/tacet-prev-fnet
    [ -f "$EVLOG" ] && [ "$(wc -l < "$EVLOG")" -gt "$EVKEEP" ] && { tail -n "$EVKEEP" "$EVLOG" > "$EVLOG.tmp" && mv "$EVLOG.tmp" "$EVLOG"; }
fi

# --- daily auto-update of the geo/threat databases (background), when enabled ---
if [ "$AUTO_DB_UPDATE" = "yes" ]; then
    STAMP=/opt/var/tacet-autoupdate.stamp
    LAST=$(cat "$STAMP" 2>/dev/null); LAST=${LAST:-0}; NOW=$(date +%s)
    case "$LAST" in *[!0-9]*) LAST=0 ;; esac
    [ "$LAST" -gt "$NOW" ] && LAST=0   # clock stepped back: don't freeze the daily update
    if [ $((NOW - LAST)) -ge 86400 ]; then
        # claim the slot NOW so the next tick doesn't start a second run while this
        # one downloads; on failure the subshell back-dates the stamp so the retry
        # comes in ~1 h instead of a full day (a flaky network shouldn't strand the DBs)
        echo "$NOW" > "$STAMP"
        {
            ok=1
            [ -x /opt/etc/tacet-geo-update.sh ]    && { /opt/etc/tacet-geo-update.sh    || ok=0; }
            [ -x /opt/etc/tacet-threat-update.sh ] && { /opt/etc/tacet-threat-update.sh || ok=0; }
            [ -x /opt/etc/tacet-asn-update.sh ]    && { /opt/etc/tacet-asn-update.sh    || ok=0; }
            # the Tor list only matters once it has been fetched at least once (TOR_BAN's
            # first download comes from the UI button) — don't pull it for nothing
            [ -x /opt/etc/tacet-tor-update.sh ] && [ -f /opt/etc/tacet-tor.dat ] && { /opt/etc/tacet-tor-update.sh || ok=0; }
            [ "$ok" = 1 ] || echo $(( $(date +%s) - 82800 )) > "$STAMP"
        } >/dev/null 2>&1 &
    fi
fi
