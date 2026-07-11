#!/bin/sh
# Tacet in-place updater. Called from the UI (Settings → Updates).
#   --check   discover the latest release; write /opt/var/tacet-latest ("ok VER HH:MM" | "err - HH:MM")
#   --apply   download the latest release and install it over the current one
#             (keeps config; progress in /opt/var/tacet-update-state: updating | done VER | failed: msg)
# Version source: the latest GitHub RELEASE (releases/latest → tag_name); the raw
# VERSION file on main is only a fallback for when the API flakes. Tarballs via codeload.
# (c) Max Grakov 2026, MIT License.

export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
REPO="GrakovNe/tacet"
API="https://api.github.com/repos/$REPO"
RAW="https://raw.githubusercontent.com/$REPO/main"
LATEST=/opt/var/tacet-latest
STATE=/opt/var/tacet-update-state
LOG=/opt/var/tacet-update.log

now() { date '+%H:%M'; }
cur() { cat /opt/etc/tacet-version 2>/dev/null | tr -d ' \r\n'; }
fetch_ver() {
    v=$(curl -sfLm20 "$API/releases/latest" 2>/dev/null \
        | sed -n 's/.*"tag_name"[^"]*"v\{0,1\}\([0-9.]*\)".*/\1/p' | head -1)
    [ -n "$v" ] || v=$(curl -sfm20 "$RAW/VERSION" 2>/dev/null | tr -d ' \r\n')
    echo "$v"
}

case "$1" in
--check)
    V=$(fetch_ver)
    if echo "$V" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "ok $V $(now)" > "$LATEST"
    else
        echo "err - $(now)" > "$LATEST"; exit 1
    fi
    ;;
--apply)
    # timestamped so the settings reader can age a crashed update out (a bare
    # "updating" would never match its staleness check and hide the update UI forever)
    echo "updating $(date +%s)" > "$STATE"
    fail() { echo "failed: $1" > "$STATE"; echo "$(date '+%F %T') failed: $1" >> "$LOG"; exit 1; }
    V=$(fetch_ver)
    echo "$V" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' || fail "version check failed"
    echo "ok $V $(now)" > "$LATEST"
    [ "$V" = "$(cur)" ] && { echo "done $V" > "$STATE"; exit 0; }
    rm -rf /tmp/tacet-up; mkdir -p /tmp/tacet-up
    curl -sfLm300 -o /tmp/tacet-up.tgz "https://codeload.github.com/$REPO/tar.gz/refs/tags/v$V" \
        || fail "download of v$V failed"
    tar -xzf /tmp/tacet-up.tgz -C /tmp/tacet-up || fail "extract failed"
    rm -f /tmp/tacet-up.tgz
    # heartbeat: re-stamp after the (slow) download so the settings reader's
    # staleness cutoff measures the install step, not download + install combined
    echo "updating $(date +%s)" > "$STATE"
    sh /tmp/tacet-up/*/install.sh --update >> "$LOG" 2>&1 || fail "install step failed (see tacet-update.log)"
    rm -rf /tmp/tacet-up
    echo "$(date '+%F %T') updated to v$V" >> "$LOG"
    echo "done $V" > "$STATE"
    ;;
*)
    echo "usage: tacet-update.sh --check | --apply"; exit 2
    ;;
esac
