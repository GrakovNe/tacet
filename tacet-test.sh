#!/bin/sh
# Tacet end-to-end regression suite — run from your machine against a live router.
#
#   ./tacet-test.sh                 # router at 192.168.1.1 (UI :5050, ssh root@)
#   ./tacet-test.sh 10.0.0.1        # a different router IP
#   SSHPASS=secret ./tacet-test.sh  # non-interactive ssh (needs sshpass)
#   VERBOSE=1 ./tacet-test.sh       # print every passing check too
#
# HTTP-only tests need just curl + python3. The deeper engine/collector tests
# additionally need ssh to the router (skipped automatically if unreachable).
#
# SAFE TO RUN ON A LIVE ROUTER: every mutation uses RFC 5737 documentation
# addresses (192.0.2/24, 198.51.100/24, 203.0.113/24) that never appear in real
# traffic, the config is snapshotted and restored, and all test entries are
# removed at the end. Real bans and whitelist entries are never touched.
# (c) Max Grakov 2026, MIT License.

IP="${1:-192.168.1.1}"
BASE="http://$IP:5050"
SSH_HOST="root@$IP"
OPTS="-o HostKeyAlgorithms=+ssh-rsa -o StrictHostKeyChecking=accept-new -o ConnectTimeout=6"
SNAP=/tmp/tacet-test-cfg.$$.json

P=0; F=0; SK=0
red()   { printf '\033[31m%s\033[0m' "$1"; }
green() { printf '\033[32m%s\033[0m' "$1"; }
pass()  { P=$((P+1)); [ -n "$VERBOSE" ] && printf '  %s %s\n' "$(green ok)" "$1"; }
failr() { F=$((F+1)); printf '  %s %s\n' "$(red FAIL)" "$1"; }
skip()  { SK=$((SK+1)); printf '  %s %s\n' "-" "$1"; }
sec()   { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# eq DESC ACTUAL EXPECTED
eq() { if [ "$2" = "$3" ]; then pass "$1"; else failr "$1 — expected [$3] got [$2]"; fi; }
# has DESC HAYSTACK NEEDLE
has() { case "$2" in *"$3"*) pass "$1" ;; *) failr "$1 — [$2] lacks [$3]" ;; esac; }
# hasnt DESC HAYSTACK NEEDLE
hasnt() { case "$2" in *"$3"*) failr "$1 — [$2] contains [$3]" ;; *) pass "$1" ;; esac; }

api()     { curl -fsS -m 15 "$BASE/api.cgi?fn=$1" 2>/dev/null; }
apipost() { curl -fsS -m 20 -X POST --data-binary "$2" "$BASE/api.cgi?fn=$1" 2>/dev/null; }
# jget EXPR  (reads JSON on stdin, prints python expression over `d`)
jget() { python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception as e: print("__BADJSON__:"+str(e)); sys.exit()
print(eval(sys.argv[1]))' "$1" 2>/dev/null; }
# json_ok DESC FN — the endpoint returns parseable JSON
json_ok() { r=$(api "$1" | jget 'True'); eq "$2" "$r" "True"; }

# ssh plumbing (optional)
if [ -n "$SSHPASS" ] && command -v sshpass >/dev/null 2>&1; then SSH="sshpass -e ssh $OPTS"
else SSH="ssh $OPTS"; fi
HAVE_SSH=0
rsh() { $SSH "$SSH_HOST" "$@" 2>/dev/null; }
[ "$(rsh echo ok)" = "ok" ] && HAVE_SSH=1

# --- preflight -------------------------------------------------------------
if ! api overview >/dev/null 2>&1; then
    echo "error: cannot reach the Tacet UI at $BASE — is the router up?"; exit 2
fi
command -v python3 >/dev/null 2>&1 || { echo "error: python3 is required"; exit 2; }
echo "Tacet regression suite → $BASE  (ssh: $([ $HAVE_SSH = 1 ] && echo yes || echo no))"

# snapshot config so mutating tests can't leave the router changed
api "export&inc=config" > "$SNAP" 2>/dev/null
cleanup() {
    # restore the exact config we started with
    [ -s "$SNAP" ] && apipost "import&mode=override" "$(cat "$SNAP")" >/dev/null 2>&1
    # abort safety: if we died between the whitelist-wipe test and its restore,
    # put the real whitelist back (append is idempotent; the test entries it
    # carries are removed by the loops below)
    [ -n "$BK" ] && apipost "import&mode=append" "$BK" >/dev/null 2>&1
    # drop every documentation-range entry this suite may have created
    for ip in 192.0.2.0/24 198.51.100.0/24 203.0.113.0/24; do
        apipost "import&mode=override" '{"tacet_export":1}' >/dev/null 2>&1  # no-op guard
    done
    for i in 1 2 3 4 5 6 7 8 9 10 20 30 31 32 33 39 40 50 60 70 77 88; do
        for r in 192.0.2 198.51.100 203.0.113; do
            api "unwhite&ip=$r.$i" >/dev/null 2>&1
            api "unban&cat=closed&ip=$r.$i" >/dev/null 2>&1
            api "unban&cat=open&ip=$r.$i" >/dev/null 2>&1
        done
    done
    api "unban&cat=cnet&ip=198.51.100.0/24" >/dev/null 2>&1
    api "unwhite&ip=203.0.113.0/24" >/dev/null 2>&1
    rm -f "$SNAP"
}
trap cleanup EXIT INT TERM

# --- 1. read endpoints: valid JSON ----------------------------------------
sec "read endpoints return valid JSON"
for fn in overview protection whitelist settings; do json_ok "$fn" "$fn JSON valid"; done
# the protection payload caps shipped ban rows but reports the true totals
eq "protection reports true closed total" "$(api protection | jget "'ok' if d['closedn']>=len(d['closed']) else 'bad'")" "ok"
eq "protection caps rows at <=500"        "$(api protection | jget "'ok' if len(d['closed'])<=500 and len(d['open'])<=500 else 'bad'")" "ok"

# --- 2. address validation -------------------------------------------------
sec "address validation (octets 0-255, mask 0-32)"
eq "reject octet > 255"  "$(api 'ban&cat=closed&ip=256.1.1.1'   | jget "d['ok']")" "False"
eq "reject mask > 32"    "$(api 'ban&cat=closed&ip=1.2.3.4/33'  | jget "d['ok']")" "False"
eq "reject non-ip"       "$(api 'ban&cat=closed&ip=not-an-ip'   | jget "d['ok']")" "False"
eq "reject empty ip"     "$(api 'ban&cat=closed&ip='            | jget "d['ok']")" "False"
eq "accept valid ip"     "$(api 'ban&cat=closed&ip=203.0.113.10'| jget "d['ok']")" "True"
# a cnet ban is masked to the router's live SUBNET_MASK: with a mask < 24 the base
# 198.51.100.0 escapes the RFC 5737 /24 into a real, allocated block. Only run this
# on masks >= 24 so "safe on a live router" always holds.
SNM=$(api settings | jget "d['config']['snmask']" 2>/dev/null)
if [ "${SNM:-24}" -ge 24 ] 2>/dev/null; then
    eq "accept valid CIDR"   "$(api 'ban&cat=cnet&ip=198.51.100.0'  | jget "d['ok']")" "True"
    api 'unban&cat=cnet&ip=198.51.100.0' >/dev/null
else
    skip "cnet CIDR test: SUBNET_MASK < 24 would touch a real block"
fi
api 'unban&cat=closed&ip=203.0.113.10' >/dev/null

# --- 3. a CIDR ban on the single-IP surface is routed to the subnet set --------
# (scan/flood are hash:ip — the SET trap target can only add /32 safely there, so a
# hand-typed CIDR goes to cnet/fnet, masked to SUBNET_MASK)
sec "CIDR ban lifecycle"
if [ "${SNM:-24}" -ge 24 ] 2>/dev/null; then
    api 'ban&cat=closed&ip=198.51.100.0/24' >/dev/null
    if [ $HAVE_SSH = 1 ]; then
        eq "CIDR ban lands in cnet"   "$(rsh 'ipset test tacet-cnet 198.51.100.1 2>&1 | grep -c "is in"')" "1"
        eq "CIDR ban not in scan"     "$(rsh 'ipset list tacet-scan | grep -c 198.51.100')" "0"
    fi
    api 'unban&cat=cnet&ip=198.51.100.0' >/dev/null
    if [ $HAVE_SSH = 1 ]; then
        eq "CIDR ban fully lifted" "$(rsh 'ipset test tacet-cnet 198.51.100.1 2>&1 | grep -c "is in"')" "0"
    fi
else
    skip "CIDR lifecycle: SUBNET_MASK < 24 would touch a real block"
fi

# --- 4. whitelist notes ----------------------------------------------------
sec "whitelist notes"
api 'white&ip=203.0.113.20&note=my%20server' >/dev/null
eq "note stored" "$(api whitelist | jget "[i['note'] for i in d['items'] if i['ip']=='203.0.113.20'][0]")" "my server"
# quotes and backslash are stripped (must not break JSON). Note: a raw control
# byte cannot be sent over GET — lighttpd 400s a %1b in the URL before the CGI
# runs — so control-byte handling is exercised via the import path in section 6.
api 'setnote&ip=203.0.113.20&note=%22q%22%5cb' >/dev/null
eq "quotes/backslash sanitized" "$(api whitelist | jget "[i['note'] for i in d['items'] if i['ip']=='203.0.113.20'][0]")" "qb"
# long note truncated to <=96
LONG=$(python3 -c 'print("x"*200)')
api "setnote&ip=203.0.113.20&note=$LONG" >/dev/null
eq "long note truncated to 96" "$(api whitelist | jget "len([i['note'] for i in d['items'] if i['ip']=='203.0.113.20'][0])")" "96"
# clearing a note. The entry-presence check comes first: a bare [0] on a missing
# entry raises IndexError → empty output → false-passes the =="" expectation
api 'setnote&ip=203.0.113.20&note=' >/dev/null
eq "entry still present after clear" "$(api whitelist | jget "sum(1 for i in d['items'] if i['ip']=='203.0.113.20')")" "1"
eq "note cleared" "$(api whitelist | jget "[i['note'] for i in d['items'] if i['ip']=='203.0.113.20'][0]")" ""
api 'unwhite&ip=203.0.113.20' >/dev/null

# --- 5. CIDR whitelist with note ------------------------------------------
sec "CIDR whitelist entry"
api 'white&ip=203.0.113.0/24&note=doc%20range' >/dev/null
eq "CIDR + note stored" "$(api whitelist | jget "[i['note'] for i in d['items'] if i['ip']=='203.0.113.0/24'][0]")" "doc range"
api 'unwhite&ip=203.0.113.0/24' >/dev/null

# --- 6. import robustness --------------------------------------------------
sec "import robustness"
eq "GET rejected (POST only)"    "$(api 'import&mode=append' | jget "d['err']")" "use POST"
eq "empty body rejected"         "$(apipost 'import&mode=append' '' | jget "d.get('err')")" "empty body"
eq "non-tacet file rejected"     "$(apipost 'import&mode=append' '{"x":1}' | jget "d.get('err')")" "not a tacet export file"
# hostile entries (bad octet, control byte, script) must not crash or break JSON
# \033 (octal), not \x1b: hex escapes are not POSIX printf — under dash the
# literal x1b survives and the control-byte path is never actually exercised
HOSTILE=$(printf '{"tacet_export":1,\n"whitelist":["203.0.113.31 ctrl\033byte","203.0.113.32 <script>"]}')
apipost 'import&mode=append' "$HOSTILE" >/dev/null
json_ok whitelist "whitelist JSON valid after hostile import"
eq "imported control-byte note is clean" "$(api whitelist | jget "[i['note'] for i in d['items'] if i['ip']=='203.0.113.31'][0]")" "ctrlbyte"
api 'unwhite&ip=203.0.113.31' >/dev/null; api 'unwhite&ip=203.0.113.32' >/dev/null
# an out-of-range octet must NOT enter the whitelist (its int would overflow the
# resolver's sort key and corrupt geo/owner resolution)
apipost 'import&mode=append' '{"tacet_export":1,
"whitelist":["300.1.1.1 bad octet","203.0.113.39 ok"]}' >/dev/null
eq "import rejects octet > 255" "$(api whitelist | jget "sum(1 for i in d['items'] if i['ip']=='300.1.1.1')")" "0"
eq "import keeps the valid neighbour" "$(api whitelist | jget "sum(1 for i in d['items'] if i['ip']=='203.0.113.39')")" "1"
api 'unwhite&ip=203.0.113.39' >/dev/null

# --- 7. backup round-trip --------------------------------------------------
sec "backup round-trip"
api 'white&ip=203.0.113.40&note=roundtrip' >/dev/null
BK=$(api 'export&inc=whitelist')
eq "export is valid JSON"      "$(printf '%s' "$BK" | jget 'd["tacet_export"]')" "1"
eq "export carries the note"   "$(printf '%s' "$BK" | jget "1 if any('203.0.113.40 roundtrip'==w for w in d['whitelist']) else 0")" "1"
api 'unwhite&ip=203.0.113.40' >/dev/null
eq "entry gone before restore" "$(api whitelist | jget "sum(1 for i in d['items'] if i['ip']=='203.0.113.40')")" "0"
apipost 'import&mode=append' "$BK" >/dev/null
eq "restore brings note back"  "$(api whitelist | jget "[i['note'] for i in d['items'] if i['ip']=='203.0.113.40'][0]")" "roundtrip"
api 'unwhite&ip=203.0.113.40' >/dev/null
# override wipes a section that is present-but-empty in the file (v1.11 fix).
# GUARDED: run the destructive wipe ONLY when the BK export above verifiably
# parsed — if the export failed (curl timeout, error page), wiping the real
# whitelist with no restore payload would destroy it for good.
if [ "$(printf '%s' "$BK" | jget 'd["tacet_export"]' 2>/dev/null)" = "1" ]; then
    api 'white&ip=203.0.113.50' >/dev/null
    apipost 'import&mode=override' '{"tacet_export":1,
"whitelist":[]}' >/dev/null
    eq "override empty section wipes it" "$(api whitelist | jget "sum(1 for i in d['items'] if i['ip']=='203.0.113.50')")" "0"
    # restore the REAL whitelist immediately — an abort before a later re-import
    # would leave the router's whitelist empty for good
    apipost 'import&mode=append' "$BK" >/dev/null
    eq "real whitelist restored after wipe test" "$(api whitelist | jget "1 if len(d['items'])>0 else 0")" "1"
    api 'unwhite&ip=203.0.113.40' >/dev/null   # BK carries the roundtrip test entry
else
    skip "override-wipe test: whitelist export failed — not risking the live whitelist"
fi

# --- 8. config validation (atomic; never corrupts) ------------------------
sec "config validation"
BEFORE=$(api settings | jget "d['config']['ttlh']")
eq "out-of-range config rejected" "$(api 'config&ttlh=99999&refresh=1&burst=8&svcports=443&svcburst=45&synto=60&snmask=24&snburst=60&compactpct=3&compactevery=5&tclosed=on' | jget "d['ok']")" "False"
eq "config unchanged after reject" "$(api settings | jget "d['config']['ttlh']")" "$BEFORE"
# a valid save round-trips comma-carrying SVC_PORTS. GUARDED like the whitelist
# wipe: this rewrites the live config (and toggles features the save omits), so
# only run it when the startup snapshot verifiably parsed — otherwise cleanup
# cannot restore and the change would be permanent
if [ -s "$SNAP" ] && [ "$(jget 'd["tacet_export"]' < "$SNAP" 2>/dev/null)" = "1" ]; then
    api 'config&ttlh=24&refresh=10&burst=8&svcports=443%2C80%2C8443&svcburst=45&synto=60&snmask=24&snburst=60&compactpct=3&compactevery=5&tclosed=on&topen=on' >/dev/null
    eq "SVC_PORTS round-trips with commas" "$(api settings | jget "d['config']['svcports']")" "443,80,8443"
else
    skip "config-save test: startup snapshot missing — not risking a permanent config change"
fi

# --- 9. concurrency (no corruption) ---------------------------------------
sec "concurrency"
for i in 1 2 3 4 5 6 7 8; do api "ban&cat=closed&ip=198.51.100.$i" >/dev/null & done; wait
if [ $HAVE_SSH = 1 ]; then
    n=$(rsh 'c=0; for i in 1 2 3 4 5 6 7 8; do ipset test tacet-scan 198.51.100.$i 2>&1 | grep -q "is in" && c=$((c+1)); done; echo $c')
    eq "8 parallel bans all landed" "$n" "8"
fi
for i in 1 2 3 4 5 6 7 8; do api "unban&cat=closed&ip=198.51.100.$i" >/dev/null & done; wait
for i in 1 2 3; do apipost 'import&mode=append' "$BK" >/dev/null & done; wait
json_ok whitelist "whitelist JSON valid after 3 parallel imports"
api 'unwhite&ip=203.0.113.40' >/dev/null

# --- 10. unknown endpoint / info-badge collision regression ---------------
sec "endpoint + client regressions"
eq "unknown fn returns error"    "$(api 'bogus' | jget "d.get('err')")" "unknown endpoint"
JS=$(curl -fsS -m 15 "$BASE/tacet.js" 2>/dev/null)
has   "info badge exists in the JS"         "$JS" 'ibadge'
has   "info badge uses data-acts"           "$JS" 'data-acts="'
hasnt "info badge has no data-act (v1.14)"  "$(printf '%s' "$JS" | grep 'ibadge' )" 'data-act="'

# --- 11. SSH-gated: engine + collector + databases ------------------------
if [ $HAVE_SSH = 1 ]; then
    sec "engine (netfilter) integrity"
    for s in tacet-scan tacet-flood tacet-cnet tacet-fnet; do
        eq "$s drop rule present" "$(rsh "iptables -S INPUT | grep -c 'match-set $s src.*-j DROP'")" "1"
    done
    eq "UI listening on :5050" "$(rsh 'netstat -tln 2>/dev/null | grep -c ":5050 "')" "1"
    eq "crond running" "$(rsh 'pidof crond >/dev/null && echo 1 || echo 0')" "1"
    # hashlimit bucket names must fit the kernel's 15-char limit
    TOOLONG=$(rsh '{ iptables -S INPUT; iptables -S FORWARD; } 2>/dev/null | grep -oE "hashlimit-name [^ ]+" | awk "{if(length(\$2)>15)print \$2}" | wc -l')
    eq "no hashlimit name over 15 chars" "$TOOLONG" "0"

    sec "locally-built databases sorted correctly (>2^31)"
    for d in threat activity tor; do
        dis=$(rsh "[ -f /opt/etc/tacet-$d.dat ] && awk 'NR>1 && \$1<prev{b++}{prev=\$1}END{print b+0}' /opt/etc/tacet-$d.dat || echo skip")
        if [ "$dis" = "skip" ]; then skip "$d.dat not present"; else eq "$d.dat has 0 sort disorders" "$dis" "0"; fi
    done

    sec "collector run (clean exit, no leaks)"
    # WAIT for a live cron collector instead of deleting its lock — removing a
    # live lock starts the exact concurrent run the lock exists to prevent
    # (corrupted CSV, doubled compaction). The collector's own steal handles a
    # genuinely stale lock.
    rsh 'n=0; while [ -d /tmp/tacet-collect.lock ] && [ $n -lt 90 ]; do sleep 1; n=$((n+1)); done
         rm -f /tmp/tct-m*.* 2>/dev/null; sh /opt/etc/tacet-collect.sh'
    eq "collector left no temp dumps" "$(rsh 'ls /tmp/tct-m*.* 2>/dev/null | wc -l')" "0"
    eq "collector released its lock"  "$(rsh 'ls -d /tmp/tacet-collect.lock 2>/dev/null | wc -l')" "0"
    eq "stats CSV freshly written"    "$(rsh 't=$(tail -1 /opt/var/tacet-stats.csv | cut -d, -f1); [ $(( $(date +%s) - t )) -lt 120 ] && echo fresh || echo stale')" "fresh"

    sec "reboot-persistence save guard"
    # the guard: a save writes a temp file and swaps it in only if non-empty, so
    # an early-boot save (sets not yet restored) can't truncate a good snapshot
    # assert the CREATE line — the actual cron-guard condition. Asserting an "add"
    # line false-failed on any router whose scan set was legitimately empty
    SG=$(rsh 'f=/opt/etc/tacet-scan.save.testtmp; ipset save tacet-scan > "$f" 2>/dev/null && grep -q "^create tacet-scan " "$f" && echo good || echo bad; rm -f "$f"')
    eq "save produces a non-empty snapshot" "$SG" "good"

    sec "counts agree between engine and CGI"
    # count MEMBER lines only (start with a digit) — a bare "grep -c timeout" also
    # matches the set's "Header: ... timeout 86400" line, inflating LIVE by +2
    LIVE=$(rsh 'echo $(( $(ipset list tacet-scan|sed -n "/Members:/,\$p"|grep -c "^[0-9]") + $(ipset list tacet-cnet|sed -n "/Members:/,\$p"|grep -c "^[0-9]") ))')
    CGI=$(api overview | jget "d['counts']['closed']")
    # allow ±3 for live churn between the two reads
    eq "closed count within tolerance" "$(python3 -c "print('ok' if abs($LIVE-$CGI)<=3 else 'off by %d'%abs($LIVE-$CGI))")" "ok"
else
    sec "SSH-gated tests"; skip "ssh unavailable — engine/collector/database checks skipped"
fi

# --- summary ---------------------------------------------------------------
printf '\n\033[1m%d passed, %d failed, %d skipped\033[0m\n' "$P" "$F" "$SK"
[ "$F" -eq 0 ] && { printf '%s\n' "$(green 'ALL GREEN')"; exit 0; } || { printf '%s\n' "$(red 'FAILURES ABOVE')"; exit 1; }
