#!/bin/sh
# Tacet installer / updater. Runs ON the router (Keenetic + Entware), as root.
#
# Fresh install — download this file to the router and run it:
#   curl -fsSL https://raw.githubusercontent.com/GrakovNe/tacet/main/install.sh -o /tmp/tacet-install.sh
#   sh /tmp/tacet-install.sh
# Safe to re-run. Run it without the repo tree next to it and it fetches the latest release.
#
# It asks a few questions, installs everything, and prints the UI address.
# Safe to re-run. `install.sh --update` is the non-interactive mode used by the
# in-UI updater: refreshes the files, keeps your config, re-applies the rules.
# (c) Max Grakov 2026, MIT License.

export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
REPO="GrakovNe/tacet"
API="https://api.github.com/repos/$REPO"
RAW="https://raw.githubusercontent.com/$REPO/main"
DIR="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-install}"

say()  { echo "$@"; }
die()  { echo "error: $*" >&2; exit 1; }

# --- standalone bootstrap: no repo files next to me -> fetch the release ------
if [ ! -f "$DIR/50-tacet.sh" ]; then
    say "== fetching the latest Tacet release"
    V=$(curl -sfLm20 "$API/releases/latest" 2>/dev/null \
        | sed -n 's/.*"tag_name"[^"]*"v\{0,1\}\([0-9.]*\)".*/\1/p' | head -1)
    [ -n "$V" ] || V=$(curl -sfm20 "$RAW/VERSION" 2>/dev/null | tr -d ' \r\n')
    [ -n "$V" ] || die "cannot reach GitHub to discover the latest version"
    rm -rf /tmp/tacet-src; mkdir -p /tmp/tacet-src
    curl -sfLm300 -o /tmp/tacet-src.tgz "https://codeload.github.com/$REPO/tar.gz/refs/tags/v$V" \
        || die "download of release v$V failed"
    tar -xzf /tmp/tacet-src.tgz -C /tmp/tacet-src || die "cannot extract the release archive"
    rm -f /tmp/tacet-src.tgz
    exec sh /tmp/tacet-src/*/install.sh "$MODE"
fi

VER=$(cat "$DIR/VERSION" 2>/dev/null | tr -d ' \r\n'); VER=${VER:-unknown}

# --- environment checks --------------------------------------------------------
[ "$(id -u)" = "0" ] || die "run as root"
[ -d /opt/etc/ndm/netfilter.d ] || die "no /opt/etc/ndm/netfilter.d — is this a Keenetic with Entware?"

# Is there a controlling terminal to prompt on? A headless SSH session (a very
# common way to install on a router) has none — reading /dev/tty then fails, and
# in busybox ash the "can't open /dev/tty" error leaks even with 2>/dev/null
# because the redirect is opened before stderr is redirected. Probe once, in a
# subshell whose stderr is discarded, and fall back to defaults silently.
if (exec < /dev/tty) 2>/dev/null; then HAS_TTY=1; else HAS_TTY=0; fi
[ -x /opt/sbin/ipset ]    || die "ipset missing: opkg install ipset"
[ -x /opt/sbin/iptables ] || die "iptables missing: opkg install iptables"
if [ ! -x /opt/sbin/lighttpd ] || [ ! -f /opt/lib/lighttpd/mod_cgi.so ]; then
    if [ "$MODE" = "--update" ]; then die "lighttpd/mod_cgi missing"; fi
    say "lighttpd + mod_cgi are required for the UI."
    if [ "$HAS_TTY" = 1 ]; then
        printf "Install them now via opkg? [Y/n]: "
        { read -r a < /dev/tty; } 2>/dev/null || a=Y
    else a=Y; say "installing lighttpd + mod_cgi (no terminal to ask)"; fi
    case "$a" in n|N) die "cannot continue without lighttpd" ;; esac
    opkg update && opkg install lighttpd lighttpd-mod-cgi || die "opkg install failed"
fi

# --- shared: install the files (atomic cp+mv so running scripts survive) -------
inst() {  # $1 = source (relative to $DIR), $2 = destination, $3 = mode
    cp "$DIR/$1" "$2.new" && mv "$2.new" "$2" && chmod "$3" "$2" || die "installing $2 failed"
}
install_files() {
    mkdir -p /opt/share/tacet /opt/var/spool/cron/crontabs /opt/var/run /opt/var/log
    inst 50-tacet.sh      /opt/etc/ndm/netfilter.d/50-tacet.sh 755
    inst tacet-collect.sh /opt/etc/tacet-collect.sh            755
    inst tacet-geo-update.sh   /opt/etc/tacet-geo-update.sh              755
    inst tacet-threat-update.sh /opt/etc/tacet-threat-update.sh          755
    inst tacet-asn-update.sh   /opt/etc/tacet-asn-update.sh              755
    inst tacet-tor-update.sh   /opt/etc/tacet-tor-update.sh              755
    inst tacet-update.sh       /opt/etc/tacet-update.sh                  755
    inst tacet-countries       /opt/etc/tacet-countries                  644
    inst index.html         /opt/share/tacet/index.html      644
    inst api.cgi            /opt/share/tacet/api.cgi         755
    inst assets/tacet.css      /opt/share/tacet/tacet.css          644
    inst assets/tacet.js       /opt/share/tacet/tacet.js           644
    inst S85tacet-ui      /opt/etc/init.d/S85tacet-ui          755
    # S10crond is SHARED Entware infrastructure, not ours to own: overwriting an
    # existing one (a user's custom ARGS / crontab dir) would silently break every
    # other package's cron jobs on the next restart. Install only when absent.
    [ -f /opt/etc/init.d/S10crond ] || inst S10crond /opt/etc/init.d/S10crond 755
    # version marker LAST: every inst ends in "|| die", so writing it only after
    # all files land keeps a half-failed update repairable — cur != latest still
    # holds, so the UI keeps offering the update instead of declaring "done"
    inst VERSION            /opt/etc/tacet-version                    644
    # crontab: append our lines once, never touching other entries
    CT=/opt/var/spool/cron/crontabs/root
    touch "$CT" && chmod 600 "$CT"
    if ! grep -qF tacet-collect.sh "$CT"; then
        # append only the JOB lines, never crontab-root's comment block — appending
        # the comments accumulates unbounded cruft across reinstalls
        grep -vE '^#|^[[:space:]]*$' "$DIR/crontab-root" >> "$CT"
    else
        # upgrade: re-sync the persist line to the shipped version, whatever it is
        # (four-set save, the temp+mv safe form, …) — delete the old one, append new.
        # Match BOTH "ipset save" and "tacet" on the line: a bare 'ipset save'
        # pattern would also delete the user's own unrelated persistence jobs.
        grep -vE 'ipset save.*tacet|tacet.*ipset save' "$CT" > "$CT.n" && mv "$CT.n" "$CT"
        grep -E '^[^#].*ipset save' "$DIR/crontab-root" >> "$CT"
        # ^ ^[^#]: crontab-root's COMMENT block also mentions "ipset save"; a bare
        #   -F match appended one orphaned comment line per upgrade, forever
    fi
    # (re)start crond so it reloads the crontab. A crond already running (which most
    # Entware setups have) does NOT pick up file changes on its own — start-if-absent
    # would leave our lines dormant until a reboot, so restart unconditionally.
    /opt/etc/init.d/S10crond restart >/dev/null 2>&1 || /opt/etc/init.d/S10crond start >/dev/null 2>&1
}
# (re)lay the web-server config and (re)start the UI. Always runs, so a conf change
# ships in updates and the conf is created when missing.
# bind/port priority: explicit args (fresh install) > existing conf > template default.
setup_ui() {  # $1 = bind (optional), $2 = port (optional)
    C=/opt/etc/lighttpd-tacet.conf
    B="$1"; P="$2"
    if [ -f "$C" ]; then
        [ -n "$B" ] || B=$(sed -n 's/^server.bind.*"\(.*\)".*/\1/p' "$C" | head -1)
        [ -n "$P" ] || P=$(sed -n 's/^server.port[^0-9]*\([0-9]*\).*/\1/p' "$C" | head -1)
    fi
    inst lighttpd-tacet.conf "$C" 644
    [ -n "$B" ] && sed -i "s|^server.bind.*|server.bind          = \"$B\"|" "$C"
    [ -n "$P" ] && sed -i "s|^server.port.*|server.port          = $P|" "$C"
    /opt/etc/init.d/S85tacet-ui restart >/dev/null 2>&1
}
apply_rules() { table=filter type=iptables sh /opt/etc/ndm/netfilter.d/50-tacet.sh >/dev/null 2>&1; }

# --- update mode: refresh files, keep config, done ------------------------------
if [ "$MODE" = "--update" ]; then
    install_files
    setup_ui
    apply_rules
    say "updated to v$VER"
    exit 0
fi

# --- fresh install: a few questions --------------------------------------------
say ""
say "Tacet v$VER — auto-ban for scanners and flooders on Keenetic."
say "A few questions (Enter accepts the default):"
say ""

ask() {  # $1 = prompt, $2 = default -> $A
    if [ "$HAS_TTY" != 1 ]; then A="$2"; return; fi
    printf "%s [%s]: " "$1" "$2"
    { read -r A < /dev/tty; } 2>/dev/null || A=""
    [ -n "$A" ] || A="$2"
}
[ "$HAS_TTY" = 1 ] || say "(no terminal — installing with default settings)"

ask "UI port" 5050
UIPORT=$A
# range check, not digit-count: 99999 passed the old {2,5} regex and lighttpd
# then failed to bind with only a vague "finished with warnings"
{ echo "$UIPORT" | grep -qE '^[0-9]{1,5}$' && [ "$UIPORT" -ge 1 ] && [ "$UIPORT" -le 65535 ]; } || UIPORT=5050

ask "Forwarded TCP ports to rate-protect (comma-separated, empty = none)" "443"
SVCP=$(echo "$A" | tr -d ' ')
echo "$SVCP" | grep -qE '^([0-9]{1,5})(,[0-9]{1,5})*$|^$' || SVCP="443"

ask "Ban duration, hours" 24
TTLH=$A
echo "$TTLH" | grep -qE '^[0-9]+$' && [ "$TTLH" -ge 1 ] && [ "$TTLH" -le 720 ] || TTLH=24

LANIP=$(ip -4 addr show br0 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | head -1)
[ -n "$LANIP" ] || die "could not detect the LAN IP (br0)"

say ""
say "== installing files"
install_files
setup_ui "$LANIP" "$UIPORT"   # lay the web-server config with this router's bind/port and start the UI

# seed the config only if there is none (re-install keeps the user's settings)
if [ ! -f /opt/etc/tacet.conf ]; then
    cat > /opt/etc/tacet.conf << CONF
BAN_TTL=$((TTLH * 3600))
WAN=ppp0
BURST=8
SVC_PORTS="$SVCP"
SVC_BURST=60
TRAP_CLOSED=yes
TRAP_OPEN=yes
TRAP_SUBNET=no
SUBNET_MASK=24
SUBNET_BURST=30
COMPACT=no
COMPACT_PCT=5
COMPACT_EVERY=5
THREAT_BAN=no
TOR_BAN=no
BAN_REJECT=no
MASTER=yes
LOG_ENABLED=yes
LOG_DROPS=no
REFRESH_SEC=60
SYN_TIMEOUT=60
AUTO_DB_UPDATE=no
CONF
fi

say "== applying firewall rules"
apply_rules

say "== starting services"   # the UI + crond are already (re)started by install_files/setup_ui
sleep 1

say "== seeding the geo + threat + owner databases in the background"
[ -f /opt/etc/tacet-geo.dat ]    || /opt/etc/tacet-geo-update.sh    >/dev/null 2>&1 &
[ -f /opt/etc/tacet-threat.dat ] || /opt/etc/tacet-threat-update.sh >/dev/null 2>&1 &
[ -f /opt/etc/tacet-asn.dat ]    || /opt/etc/tacet-asn-update.sh    >/dev/null 2>&1 &

# establish the event-log baseline now (sets are empty on a fresh install, or hold
# restored bans on reinstall) so the FIRST real bans get logged, not silently baselined
[ -x /opt/etc/tacet-collect.sh ] && /opt/etc/tacet-collect.sh >/dev/null 2>&1

ok=0
iptables -S INPUT 2>/dev/null | grep -q 'match-set tacet-scan src' && say "  + drop rule present" || ok=1
netstat -tln 2>/dev/null | grep -q ":$UIPORT " && say "  + UI listening on :$UIPORT" || ok=1
pidof crond >/dev/null && say "  + crond running" || ok=1
say ""
if [ "$ok" = "0" ]; then
    say "Done: http://$LANIP:$UIPORT"
else
    say "Finished with warnings — check the lines above. UI: http://$LANIP:$UIPORT"
fi
